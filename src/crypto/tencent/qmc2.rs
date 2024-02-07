use crate::crypto::byte_offset_cipher::{ByteOffsetDecipher, ByteOffsetEncipher};
use crate::crypto::tencent::{QMCv2Map, QMCv2RC4};

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum QMCv2 {
    Map(QMCv2Map),
    RC4(QMCv2RC4),
}

/// A wrapper for QMCv2 decryption support
impl QMCv2 {
    pub fn from_key<T: AsRef<[u8]>>(key: T) -> Self {
        let key = key.as_ref();
        if key.len() > 300 {
            QMCv2::RC4(QMCv2RC4::new(key))
        } else {
            QMCv2::Map(QMCv2Map::new(key))
        }
    }

    pub fn decrypt<T: AsMut<[u8]>>(&self, offset: usize, buffer: &mut T) {
        match self {
            Self::Map(d) => d.decipher_buffer(offset, buffer.as_mut()),
            Self::RC4(d) => d.decipher_buffer(offset, buffer.as_mut()),
        }
    }
}

impl ByteOffsetDecipher for QMCv2 {
    fn decipher_byte(&self, offset: usize, datum: u8) -> u8 {
        match self {
            Self::Map(d) => d.decipher_byte(offset, datum),
            Self::RC4(d) => d.decipher_byte(offset, datum),
        }
    }

    fn decipher_buffer<T: AsMut<[u8]> + ?Sized>(&self, offset: usize, buffer: &mut T) {
        match self {
            Self::Map(d) => d.decipher_buffer(offset, buffer),
            Self::RC4(d) => d.decipher_buffer(offset, buffer),
        }
    }
}

impl ByteOffsetEncipher for QMCv2 {
    fn encipher_byte(&self, offset: usize, datum: u8) -> u8 {
        self.decipher_byte(offset, datum)
    }

    fn encipher_buffer<T: AsMut<[u8]> + ?Sized>(&self, offset: usize, buffer: &mut T) {
        self.decipher_buffer(offset, buffer)
    }
}
