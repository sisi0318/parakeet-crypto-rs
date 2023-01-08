use crate::{
    interfaces::{DecryptorError, StreamDecryptor},
    utils::xor_helper,
};

use super::{key_expansion, key_normalization};

const CIPHER_PAGE_SIZE: usize = 0x7fff;

#[derive(Debug)]
pub struct QmcV1 {
    offset: usize,
    key: [u8; 128],
}

impl QmcV1 {
    pub fn new_static(key: &[u8]) -> Option<Self> {
        match key.len() {
            58 => Some(Self::new_static_key58(key.try_into().unwrap())),
            128 => Some(Self::new_static_key128(key.try_into().unwrap())),
            256 => Some(Self::new_static_key256(key.try_into().unwrap())),
            _ => None,
        }
    }

    pub fn new_map(key: &[u8]) -> Option<Self> {
        match key.len() {
            128 => Some(Self::new_map_key128(key.try_into().unwrap())),
            256..=usize::MAX => Some(Self::new_map_key256(&key[..256].try_into().unwrap())),
            _ => None,
        }
    }

    pub fn new_key128(key: &[u8; 128]) -> Self {
        Self {
            offset: 0,
            key: *key,
        }
    }

    pub fn new_static_key58(key: &[u8; 58]) -> Self {
        Self::new_static_key128(&key_expansion::expand_key58_to_key128(key))
    }

    pub fn new_static_key128(key: &[u8; 128]) -> Self {
        Self::new_key128(&key_normalization::normalize_static_key128(key))
    }

    pub fn new_static_key256(key: &[u8; 256]) -> Self {
        Self::new_key128(&key_normalization::normalize_static_key256(key))
    }

    pub fn new_map_key128(key: &[u8; 128]) -> Self {
        Self::new_key128(&key_normalization::normalize_map_key128(key))
    }

    pub fn new_map_key256(key: &[u8; 256]) -> Self {
        Self::new_key128(&key_normalization::normalize_map_key256(key))
    }
}

impl StreamDecryptor for QmcV1 {
    fn decrypt_block(&mut self, dst: &mut [u8], src: &[u8]) -> Result<usize, DecryptorError> {
        if dst.len() < src.len() {
            return Err(DecryptorError::OutputBufferTooSmall);
        }

        let offset = self.offset;
        xor_helper::xor_block_from_offset(
            &mut dst[..src.len()],
            src,
            CIPHER_PAGE_SIZE,
            &self.key,
            offset,
        )?;

        // Off-by-1 fix at the first page.
        if CIPHER_PAGE_SIZE >= offset && CIPHER_PAGE_SIZE - offset < src.len() {
            let boundary_index = CIPHER_PAGE_SIZE - offset;
            dst[boundary_index] = src[boundary_index] ^ self.key[CIPHER_PAGE_SIZE % self.key.len()];
        }

        self.offset = offset + src.len();

        Ok(src.len())
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::*;

    const TEST_KEY58: [u8; 58] = [
        0xFF, 0xFE, //
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, //
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, //
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, //
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, //
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, //
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, //
    ];

    const TEST_KEY128: [u8; 128] = [
        0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
        0xfe, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, //
        0xff, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, //
        0xfe, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, //
        0xff, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, //
        0xfe, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, //
        0xff, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, //
        0xfe, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, //
        0xff, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, //
        0xfe, 0x31, 0x30, 0x2f, 0x2e, 0x2d, 0x2c, 0x2b, //
        0xff, 0x2a, 0x29, 0x28, 0x27, 0x26, 0x25, 0x24, //
        0xfe, 0x23, 0x22, 0x21, 0x20, 0x1f, 0x1e, 0x1d, //
        0xff, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, //
        0xfe, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 0x0f, //
        0xff, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, //
        0xfe, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, //
    ];

    fn run_test_qmc1_static(key: &[u8]) {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let path_encrypted = d.join("sample/test_qmc1.qmcogg");
        let path_source = d.join("sample/test_121529_32kbps.ogg");

        let mut qmc1 = super::QmcV1::new_static(key).unwrap();

        let file_encrypted = fs::read(path_encrypted).unwrap();
        let source_content = fs::read(path_source.as_path()).unwrap();
        let mut decrypted_content = vec![0u8; source_content.len()];
        qmc1.decrypt_block(&mut decrypted_content, &file_encrypted)
            .unwrap();

        assert_eq!(source_content, decrypted_content, "mismatched content");
    }

    #[test]
    fn test_qmc1_key128() {
        run_test_qmc1_static(&TEST_KEY128);
    }

    #[test]
    fn test_qmc1_key58() {
        run_test_qmc1_static(&TEST_KEY58);
    }
}
