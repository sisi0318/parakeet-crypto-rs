use crate::{interfaces::decryptor::DecryptorError, utils::md5};

use super::{
    kgm_crypto::{KGMCrypto, KGMCryptoConfig},
    utils::xor_u32_bytes,
};

#[derive(Debug, Default, Clone)]
pub struct KGMCryptoType3 {
    slot_key: [u8; 16],
    file_key: [u8; 17],
}

impl KGMCryptoType3 {
    fn custom_md5<T: AsRef<[u8]>>(buffer: T) -> [u8; 16] {
        let digest = md5(buffer);
        let mut result = [0u8; 16];

        for i in (0..16).step_by(2) {
            result[i] = digest[14 - i];
            result[i + 1] = digest[14 - i + 1];
        }

        result
    }
}

impl KGMCrypto for KGMCryptoType3 {
    fn configure(&mut self, _config: &KGMCryptoConfig) -> Result<(), DecryptorError> {
        Ok(())
    }

    fn expand_slot_key(&mut self, key: &[u8]) {
        self.slot_key = Self::custom_md5(&key);
    }

    fn expand_file_key(&mut self, key: &[u8]) {
        self.file_key[..16].copy_from_slice(&Self::custom_md5(&key));
        self.file_key[16] = 0x6b;
    }

    fn decrypt(&mut self, offset: u64, buffer: &mut [u8]) {
        let mut offset = offset;

        let key1 = self.slot_key;
        let key2 = self.file_key;

        let key1_len = self.slot_key.len();
        let key2_len = self.file_key.len();

        for item in buffer.iter_mut() {
            // XOR all bytes of a "u32" integer.
            let offset_key = xor_u32_bytes(offset as u32);

            let offset_usize = offset as usize;
            let key1_index = offset_usize % key1_len;
            let key2_index = offset_usize % key2_len;

            let mut temp = *item;
            temp ^= key2[key2_index];
            temp ^= temp << 4;
            temp ^= key1[key1_index];
            temp ^= offset_key;
            *item = temp;

            offset += 1;
        }
    }

    fn encrypt(&mut self, offset: u64, buffer: &mut [u8]) {
        let mut offset = offset;

        let key1 = self.slot_key;
        let key2 = self.file_key;

        let key1_len = self.slot_key.len();
        let key2_len = self.file_key.len();

        for item in buffer.iter_mut() {
            // XOR all bytes of a "u32" integer.
            let offset_key = xor_u32_bytes(offset as u32);

            let offset_usize = offset as usize;
            let key1_index = offset_usize % key1_len;
            let key2_index = offset_usize % key2_len;

            let mut temp = *item;
            temp ^= offset_key;
            temp ^= key1[key1_index];
            temp ^= temp << 4;
            temp ^= key2[key2_index];
            *item = temp;

            offset += 1;
        }
    }
}
