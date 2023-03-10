use crate::utils::LoopIter;

use super::super::{KGMCrypto, KGMCryptoConfig};

// Transparent encryption.

#[derive(Debug, Default, Clone)]
pub struct KGMCryptoType2 {
    key: Box<[u8]>,
}

impl KGMCryptoType2 {
    fn transform<const IS_ENCRYPT: bool>(&self, offset: u64, buffer: &mut [u8]) {
        let mut key_iter = LoopIter::new(&self.key, offset as usize);

        for item in buffer.iter_mut() {
            let mut temp = *item;

            if IS_ENCRYPT {
                temp ^= key_iter.get_and_next();
                temp ^= temp << 4;
            } else {
                temp ^= temp << 4;
                temp ^= key_iter.get_and_next();
            }

            *item = temp;
        }
    }
}

impl KGMCrypto for KGMCryptoType2 {
    fn configure(&mut self, _config: &KGMCryptoConfig, slot_key: &[u8], _file_key: &[u8]) {
        self.key = slot_key.into();
    }

    fn encrypt(&mut self, offset: u64, buffer: &mut [u8]) {
        self.transform::<true>(offset, buffer);
    }

    fn decrypt(&mut self, offset: u64, buffer: &mut [u8]) {
        self.transform::<false>(offset, buffer);
    }
}
