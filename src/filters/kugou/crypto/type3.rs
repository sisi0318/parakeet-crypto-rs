use crate::utils::{md5, LoopIter};

use super::{
    super::{KGMCrypto, KGMCryptoConfig},
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

    fn transform<const IS_ENCRYPT: bool>(&self, offset: u64, buffer: &mut [u8]) {
        let mut offset = offset;
        let mut slot_key = LoopIter::new(&self.slot_key, offset as usize);
        let mut file_key = LoopIter::new(&self.file_key, offset as usize);

        for item in buffer.iter_mut() {
            let mut temp = *item;

            // XOR all bytes of a "u32" integer.
            let offset_key = xor_u32_bytes(offset as u32);

            if IS_ENCRYPT {
                temp ^= offset_key;
                temp ^= slot_key.get_and_next();
                temp ^= temp.wrapping_shl(4);
                temp ^= file_key.get_and_next();
            } else {
                temp ^= file_key.get_and_next();
                temp ^= temp.wrapping_shl(4);
                temp ^= slot_key.get_and_next();
                temp ^= offset_key;
            }

            *item = temp;
            offset += 1;
        }
    }
}

impl KGMCrypto for KGMCryptoType3 {
    fn configure(&mut self, _config: &KGMCryptoConfig, slot_key: &[u8], file_key: &[u8]) {
        self.slot_key = Self::custom_md5(slot_key);

        self.file_key[..16].copy_from_slice(&Self::custom_md5(file_key));
        self.file_key[16] = 0x6b;
    }

    fn decrypt(&mut self, offset: u64, buffer: &mut [u8]) {
        self.transform::<false>(offset, buffer)
    }

    fn encrypt(&mut self, offset: u64, buffer: &mut [u8]) {
        self.transform::<true>(offset, buffer)
    }
}
