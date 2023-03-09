use crate::utils::LoopIter;

use super::scramble_key::create_scramble_key;

pub const SCRAMBLE_HEADER_LEN: usize = 1024;

#[derive(Debug)]
pub struct XimalayaCrypto {
    content_key: Vec<u8>,
    scramble_key: [u16; SCRAMBLE_HEADER_LEN],
}

impl XimalayaCrypto {
    /// Create a crypto handler for X2M/X3M
    pub fn new(content_key: &[u8], scramble_key: &[u16; SCRAMBLE_HEADER_LEN]) -> Self {
        Self {
            content_key: content_key.to_vec(),
            scramble_key: *scramble_key,
        }
    }

    /// Create a crypto handler for X2M/X3M, with scramble_key generated from parameters.
    pub fn new_from_param(content_key: &[u8], mul_init: f64, mul_step: f64) -> Self {
        let mut scramble_key = [0u16; SCRAMBLE_HEADER_LEN];
        create_scramble_key(&mut scramble_key, mul_init, mul_step);
        Self::new(content_key, &scramble_key)
    }

    pub fn decrypt(&self, encrypted: &[u8; SCRAMBLE_HEADER_LEN]) -> [u8; SCRAMBLE_HEADER_LEN] {
        let mut plain = *encrypted;

        let mut key_iter = LoopIter::new(&self.content_key, 0);
        for (i, &scramble_idx) in self.scramble_key.iter().enumerate() {
            plain[i] = encrypted[scramble_idx as usize] ^ key_iter.get_and_move();
        }

        plain
    }

    pub fn encrypt(&self, plain: &[u8; SCRAMBLE_HEADER_LEN]) -> [u8; SCRAMBLE_HEADER_LEN] {
        let mut encrypted = *plain;

        let mut key_iter = LoopIter::new(&self.content_key, 0);
        for (i, &scramble_idx) in self.scramble_key.iter().enumerate() {
            encrypted[scramble_idx as usize] = plain[i] ^ key_iter.get_and_move();
        }

        encrypted
    }
}
