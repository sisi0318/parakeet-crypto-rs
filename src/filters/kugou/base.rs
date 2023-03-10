use std::collections::HashMap;

#[derive(Debug, Default, Clone)]
pub struct KGMCryptoConfig {
    pub slot_keys: HashMap<u32, Vec<u8>>,
    pub v4_slot_key_expand_table: Vec<u8>,
    pub v4_file_key_expand_table: Vec<u8>,
}

pub trait KGMCrypto {
    fn configure(&mut self, config: &KGMCryptoConfig, slot_key: &[u8], file_key: &[u8]);

    fn decrypt(&mut self, offset: u64, buffer: &mut [u8]);
    fn encrypt(&mut self, offset: u64, buffer: &mut [u8]);
}
