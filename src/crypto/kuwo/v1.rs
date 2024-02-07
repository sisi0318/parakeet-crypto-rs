use crate::crypto::byte_offset_cipher::{ByteOffsetDecipher, ByteOffsetEncipher};

pub const KEY_SIZE: usize = 0x20;
const SCRAMBLE_KEY: [u8; KEY_SIZE] = *include_bytes!("v1_key.bin");

pub type ResourceKey = [u8; KEY_SIZE];

#[derive(Debug, Copy, Clone, Default, Ord, PartialOrd, Eq, PartialEq)]
pub struct KWMv1 {
    key: ResourceKey,
}

impl KWMv1 {
    pub fn from_resource_id(rid: u32) -> Self {
        let rid = rid.to_string();
        let rid_iter = rid.as_bytes().iter().cycle();
        let key_stream = rid_iter.zip(SCRAMBLE_KEY).map(|(&a, b)| a ^ b);

        let mut key = [0u8; KEY_SIZE];
        for (k, item) in key.iter_mut().zip(key_stream) {
            *k = item;
        }

        Self { key }
    }
}

impl ByteOffsetDecipher for KWMv1 {
    fn decipher_byte(&self, offset: usize, datum: u8) -> u8 {
        self.key[offset % KEY_SIZE] ^ datum
    }
}

impl ByteOffsetEncipher for KWMv1 {
    fn encipher_byte(&self, offset: usize, datum: u8) -> u8 {
        self.decipher_byte(offset, datum)
    }
}
