use crate::crypto::byte_offset_cipher::{ByteOffsetDecipher, ByteOffsetEncipher};

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct Mode2 {
    slot_key: Box<[u8]>,
}

impl Mode2 {
    pub fn new<T: AsRef<[u8]>>(slot_key: T) -> Self {
        Self {
            slot_key: Box::from(slot_key.as_ref()),
        }
    }
}

impl ByteOffsetEncipher for Mode2 {
    fn encipher_byte(&self, offset: usize, datum: u8) -> u8 {
        let key = self.slot_key[offset % self.slot_key.len()];
        let mut datum = datum;
        datum ^= key;
        datum ^= datum << 4;
        datum
    }
}

impl ByteOffsetDecipher for Mode2 {
    fn decipher_byte(&self, offset: usize, datum: u8) -> u8 {
        let key = self.slot_key[offset % self.slot_key.len()];
        let mut datum = datum;
        datum ^= datum << 4;
        datum ^= key;
        datum
    }
}
