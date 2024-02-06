use crate::crypto::byte_offset_cipher::{ByteOffsetCipher, ByteOffsetDecipher};
use crate::utils::md5;

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct Mode3 {
    slot_key_hash: [u8; 16],
    file_key_hash: [u8; 17],
}

impl Mode3 {
    pub fn new<T: AsRef<[u8]>, T2: AsRef<[u8]>>(slot_key: T, file_key: T2) -> Self {
        let slot_key_hash = Self::hash_key(slot_key);

        let mut file_key_hash = [0u8; 17];
        file_key_hash[..16].copy_from_slice(&Self::hash_key(file_key));
        file_key_hash[16] = b'k';

        Self {
            slot_key_hash,
            file_key_hash,
        }
    }

    fn hash_key<T: AsRef<[u8]>>(buffer: T) -> [u8; 16] {
        let digest = md5(buffer);

        let transformed = digest
            .chunks_exact(2)
            .rev()
            .flat_map(|chunk| chunk.iter())
            .cloned()
            .collect::<Vec<u8>>();

        let mut result = [0u8; 16];
        result.copy_from_slice(&transformed);
        result
    }

    pub fn calc_offset_checksum(offset: u32) -> u8 {
        offset.to_ne_bytes().iter().fold(0, |acc, x| acc ^ x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_key() {
        let key = b"hello world";
        let result = Mode3::hash_key(key);

        assert_eq!(result.len(), 16);
        assert_eq!(
            result,
            *b"\xCD\xC3\x8F\x5A\x22\xBB\x93\xCB\xEE\xD0\xE0\x1E\x3B\xBB\x5E\xB6"
        );
    }
}

impl ByteOffsetCipher for Mode3 {
    fn encrypt_byte(&self, offset: usize, datum: u8) -> u8 {
        let offset_checksum = Self::calc_offset_checksum(offset as u32);
        let slot_key = self.slot_key_hash[offset % self.slot_key_hash.len()];
        let file_key = self.file_key_hash[offset % self.file_key_hash.len()];

        let mut datum = datum;
        datum ^= offset_checksum;
        datum ^= slot_key;
        datum ^= datum << 4;
        datum ^= file_key;
        datum
    }
}

impl ByteOffsetDecipher for Mode3 {
    fn decrypt_byte(&self, offset: usize, datum: u8) -> u8 {
        let offset_checksum = Self::calc_offset_checksum(offset as u32);
        let slot_key = self.slot_key_hash[offset % self.slot_key_hash.len()];
        let file_key = self.file_key_hash[offset % self.file_key_hash.len()];

        let mut datum = datum;
        datum ^= file_key;
        datum ^= datum << 4;
        datum ^= slot_key;
        datum ^= offset_checksum;

        datum
    }
}
