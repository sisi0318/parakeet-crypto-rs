use crate::crypto::byte_offset_cipher::{ByteOffsetDecipher, ByteOffsetEncipher};

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct QMCv2Map {
    key: [u8; 128],
}

fn qmc2_key_to_qmc1(key_blob: &[u8]) -> [u8; 128] {
    let mut key128 = [0u8; 128];

    if !key_blob.is_empty() {
        let mut long_key = vec![0u8; key_blob.len()];

        let mut shift_counter = 4u32;
        for (i, key) in long_key.iter_mut().enumerate() {
            let value = key_blob[i];
            *key = value.wrapping_shl(shift_counter) | value.wrapping_shr(shift_counter);
            shift_counter = shift_counter.wrapping_add(1) & 0b0111;
        }

        for (i, key) in key128.iter_mut().enumerate() {
            *key = long_key[(i * i + 0x1162e) % long_key.len()];
        }
    }

    key128
}

impl QMCv2Map {
    pub fn new(file_key: &[u8]) -> Self {
        let key = qmc2_key_to_qmc1(file_key);
        Self { key }
    }
}

impl ByteOffsetDecipher for QMCv2Map {
    fn decipher_byte(&self, offset: usize, datum: u8) -> u8 {
        datum ^ super::map_l(&self.key, offset)
    }
}

impl ByteOffsetEncipher for QMCv2Map {
    fn encipher_byte(&self, offset: usize, datum: u8) -> u8 {
        self.decipher_byte(offset, datum)
    }
}
