use crate::utils::{md5, PeekIter};
use base64::{engine::general_purpose::STANDARD as Base64, Engine as _};

use super::{
    super::{KGMCrypto, KGMCryptoConfig},
    utils::xor_u32_bytes,
};

#[derive(Debug, Default, Clone)]
pub struct KGMCryptoType4 {
    file_key: Vec<u8>,
    slot_key: Vec<u8>,
}

const V4_DIGEST_SIZE: usize = 31;
const DIGEST_INDEXES: [usize; V4_DIGEST_SIZE] = [
    0x05, 0x0e, 0x0d, 0x02, 0x0c, 0x0a, 0x0f, 0x0b, //
    0x03, 0x08, 0x05, 0x06, 0x09, 0x04, 0x03, 0x07, //
    0x00, 0x0e, 0x0d, 0x06, 0x02, 0x0c, 0x0a, 0x0f, //
    0x01, 0x0b, 0x08, 0x07, 0x09, 0x04, 0x01,
];

impl KGMCryptoType4 {
    fn custom_md5(data: &[u8]) -> [u8; V4_DIGEST_SIZE] {
        let md5_key = md5(data);

        let mut md5_final = [0u8; V4_DIGEST_SIZE];
        for (i, v) in md5_final.iter_mut().enumerate() {
            *v = md5_key[DIGEST_INDEXES[i]];
        }

        md5_final
    }

    fn key_expansion(table: &[u8], key: &[u8]) -> Vec<u8> {
        if table.is_empty() {
            panic!("kugou::crypto::type4::key_expansion: table is empty, check your config.")
        }

        let md5_final = Self::custom_md5(key);

        let final_key_size = 4 * (md5_final.len() - 1) * (key.len() - 1);
        let mut expanded_key = Vec::<u8>::with_capacity(final_key_size);
        for (i, &j) in md5_final.iter().enumerate().skip(1) {
            let temp = (i as u32).wrapping_mul(j as u32);

            for (k, &l) in table.iter().enumerate().skip(1) {
                let temp = temp.wrapping_mul(k as u32).wrapping_mul(l as u32);
                let bytes = temp.to_le_bytes();

                // (LittleEndian)   0x12345678
                // Memory:  [78] [56] [34] [12]
                //
                //    SHR:   00   08   10   18
                //       = 0x78 0x56 0x34 0x12
                //  Index:    0    1    2    3

                expanded_key.push(bytes[0]); // temp >> 0x00
                expanded_key.push(bytes[3]); // temp >> 0x18
                expanded_key.push(bytes[2]); // temp >> 0x10
                expanded_key.push(bytes[1]); // temp >> 0x08
            }
        }

        expanded_key
    }

    fn expand_slot_key(table: &[u8], key: &[u8]) -> Vec<u8> {
        let key = md5(key);
        let key = hex::encode(key);
        let key = Base64.encode(key);
        let key = key.as_bytes();

        Self::key_expansion(table, key)
    }

    fn expand_file_key(table: &[u8], key: &[u8]) -> Vec<u8> {
        Self::key_expansion(table, key)
    }

    fn transform<const IS_ENCRYPT: bool>(&self, offset: u64, buffer: &mut [u8]) {
        let mut offset = offset;

        let mut slot_key_iter = PeekIter::new(&self.slot_key, offset as usize);
        let mut file_key_iter =
            PeekIter::new(&self.file_key, (offset as usize) / self.slot_key.len());

        for item in buffer.iter_mut() {
            let mut temp = *item;

            // XOR all bytes of a "u32" integer.
            let offset_key = xor_u32_bytes(offset as u32);

            if IS_ENCRYPT {
                temp ^= offset_key;
                temp ^= slot_key_iter.get();
                temp ^= temp.wrapping_shl(4);
                temp ^= file_key_iter.get();
            } else {
                temp ^= file_key_iter.get();
                temp ^= temp.wrapping_shl(4);
                temp ^= slot_key_iter.get();
                temp ^= offset_key;
            }

            *item = temp;

            offset += 1;
            if slot_key_iter.next() {
                file_key_iter.next();
            }
        }
    }
}

impl KGMCrypto for KGMCryptoType4 {
    fn configure(&mut self, config: &KGMCryptoConfig, slot_key: &[u8], file_key: &[u8]) {
        self.file_key = Self::expand_file_key(&config.v4_file_key_expand_table, file_key);
        self.slot_key = Self::expand_slot_key(&config.v4_slot_key_expand_table, slot_key);
    }

    fn decrypt(&mut self, offset: u64, buffer: &mut [u8]) {
        self.transform::<false>(offset, buffer)
    }

    fn encrypt(&mut self, offset: u64, buffer: &mut [u8]) {
        self.transform::<true>(offset, buffer)
    }
}
