use std::{
    io::{Read, Seek, SeekFrom, Write},
    mem::swap,
};

use crate::interfaces::{DecryptorError, StreamDecryptor};

use super::{
    kgm_crypto::{KGMCrypto, KGMCryptoConfig},
    kgm_crypto_factory::{create_kgm_decryptor, create_kgm_encryptor},
    kgm_header::KGMHeader,
};

enum KGMState {
    ParseMinimalHeader([u8; 0x3C]),
    WaitForFullHeader((usize, Option<Box<dyn KGMCrypto>>)),
    DecryptContent(Box<dyn KGMCrypto>),
}

pub struct KGM {
    config: KGMCryptoConfig,

    offset: usize,
    state: KGMState,
}

impl KGM {
    pub fn new(config: &KGMCryptoConfig) -> Self {
        Self {
            config: config.clone(),
            offset: 0,
            state: KGMState::ParseMinimalHeader([0u8; 0x3C]),
        }
    }

    pub fn encrypt<R, W>(
        &self,
        header: &mut KGMHeader,
        from: &mut R,
        to: &mut W,
    ) -> Result<(), DecryptorError>
    where
        R: Read + Seek,
        W: Write,
    {
        from.seek(SeekFrom::Start(0))?;
        let mut encryptor = create_kgm_encryptor(header, &self.config)?;

        let header = header.to_bytes();
        to.write_all(&header)?;

        let mut bytes_left = from.seek(SeekFrom::End(0))?;

        from.seek(SeekFrom::Start(0))?;

        let mut offset = 0;
        let mut buffer = [0u8; 0x1000];
        while bytes_left > 0 {
            let bytes_read = from.read(&mut buffer)?;
            encryptor.encrypt(offset, &mut buffer[..bytes_read]);
            to.write_all(&buffer[..bytes_read])?;
            offset += bytes_read as u64;
            bytes_left -= bytes_read as u64;
        }

        Ok(())
    }
}

impl StreamDecryptor for KGM {
    fn decrypt_block(&mut self, dst: &mut [u8], src: &[u8]) -> Result<usize, DecryptorError> {
        let mut src = src;
        while !src.is_empty() {
            match &mut self.state {
                KGMState::ParseMinimalHeader(header) => {
                    if self.offset < header.len() {
                        // Copy data from source
                        let copy_len = std::cmp::min(header.len() - self.offset, src.len());
                        header[self.offset..self.offset + copy_len]
                            .copy_from_slice(&src[..copy_len]);

                        src = &src[copy_len..];
                        self.offset += copy_len;
                    }

                    if self.offset == header.len() {
                        let header = KGMHeader::from_bytes(header)?;
                        let decryptor = create_kgm_decryptor(&header, &self.config)?;
                        self.state = KGMState::WaitForFullHeader((
                            header.offset_to_data as usize,
                            Some(decryptor),
                        ));
                    }
                }
                KGMState::WaitForFullHeader((n, decryptor)) => {
                    let n = *n;
                    if self.offset < n {
                        let seek_len = std::cmp::min(n - self.offset, src.len());
                        src = &src[seek_len..];
                        self.offset += seek_len;
                    }

                    if self.offset == n {
                        let mut container = None;
                        swap(&mut container, decryptor);
                        self.state = KGMState::DecryptContent(container.unwrap());
                        self.offset = 0;
                    }
                }
                KGMState::DecryptContent(decryptor) => {
                    if dst.len() < src.len() {
                        return Err(DecryptorError::OutputBufferTooSmallWithHint(src.len()));
                    }

                    let block = &mut dst[..src.len()];
                    block.copy_from_slice(src);
                    decryptor.decrypt(self.offset as u64, block);
                    self.offset += src.len();
                    return Ok(src.len());
                }
            }
        }

        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        path::PathBuf,
    };

    use crate::interfaces::Decryptor;

    use super::*;

    const TEST_SLOT_KEY1: [u8; 4] = *b"09AZ";

    fn test_kgm_file(kgm_type: &str) {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let path_encrypted = d.join(format!("sample/test_kgm_{}.kgm", kgm_type));
        let path_source = d.join("sample/test_121529_32kbps.ogg");
        let path_v4_filekey_table = d.join("sample/test_kgm_v4_filekey_table.bin");
        let path_v4_slotkey_table = d.join("sample/test_kgm_v4_slotkey_table.bin");

        let mut decrypted_content = Vec::new();

        let mut file_encrypted = File::open(path_encrypted).unwrap();
        let source_content = fs::read(path_source.as_path()).unwrap();
        let v4_filekey_table = fs::read(path_v4_filekey_table.as_path()).unwrap();
        let v4_slotkey_table = fs::read(path_v4_slotkey_table.as_path()).unwrap();

        let mut config = KGMCryptoConfig::default();
        config.slot_keys.insert(1, TEST_SLOT_KEY1.into());
        config.v4_file_key_expand_table = v4_filekey_table.into();
        config.v4_slot_key_expand_table = v4_slotkey_table.into();

        let mut kgm = super::KGM::new(&config);
        kgm.decrypt(&mut file_encrypted, &mut decrypted_content)
            .unwrap();

        assert_eq!(source_content, decrypted_content, "mismatched content");
    }

    #[test]
    fn test_kgm_enc_v2() {
        test_kgm_file("v2");
    }

    #[test]
    fn test_kgm_enc_v3() {
        test_kgm_file("v3");
    }

    #[test]
    fn test_kgm_enc_v4() {
        test_kgm_file("v4");
    }
}
