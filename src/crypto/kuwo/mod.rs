use thiserror::Error;

use crate::crypto::byte_offset_cipher::{ByteOffsetDecipher, ByteOffsetEncipher};
use crate::crypto::kuwo::header::HeaderParseError;

pub mod header;
pub mod v1;
pub mod v2;

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum Kuwo {
    KWMv1(v1::KWMv1),
    KWMv2(v2::KWMv2),
}

#[derive(Debug, Error)]
pub enum InitCipherError {
    #[error("Failed to parse header: {0}")]
    HeaderParseError(HeaderParseError),

    #[error("KWMv2 require a decrypted ekey")]
    KWMv2KeyRequired,

    #[error("Header contains unsupported version: {0}")]
    UnsupportedVersion(u32),
}

impl From<HeaderParseError> for InitCipherError {
    fn from(error: HeaderParseError) -> Self {
        Self::HeaderParseError(error)
    }
}

impl Kuwo {
    pub fn from_header<K>(hdr: &header::KuwoHeader, key: Option<K>) -> Result<Self, InitCipherError>
    where
        K: AsRef<[u8]>,
    {
        let cipher = match hdr.version {
            1 => Self::KWMv1(v1::KWMv1::from_resource_id(hdr.resource_id)),
            2 => match key {
                None => Err(InitCipherError::KWMv2KeyRequired)?,
                Some(key) => Self::KWMv2(v2::KWMv2::from_key(key)),
            },
            version => Err(InitCipherError::UnsupportedVersion(version))?,
        };
        Ok(cipher)
    }

    pub fn from_header_bytes<T, K>(hdr: &[u8], key: Option<K>) -> Result<Self, InitCipherError>
    where
        T: AsRef<[u8]>,
        K: AsRef<[u8]>,
    {
        let hdr = header::KuwoHeader::from_bytes(hdr)?;
        Self::from_header(&hdr, key)
    }
}

impl ByteOffsetDecipher for Kuwo {
    fn decipher_byte(&self, offset: usize, datum: u8) -> u8 {
        match self {
            Kuwo::KWMv1(m) => m.decipher_byte(offset, datum),
            Kuwo::KWMv2(m) => m.decipher_byte(offset, datum),
        }
    }

    fn decipher_buffer<T: AsMut<[u8]> + ?Sized>(&self, offset: usize, buffer: &mut T) {
        match self {
            Kuwo::KWMv1(m) => m.decipher_buffer(offset, buffer),
            Kuwo::KWMv2(m) => m.decipher_buffer(offset, buffer),
        }
    }
}

impl ByteOffsetEncipher for Kuwo {
    fn encipher_byte(&self, offset: usize, datum: u8) -> u8 {
        match self {
            Kuwo::KWMv1(m) => m.encipher_byte(offset, datum),
            Kuwo::KWMv2(m) => m.encipher_byte(offset, datum),
        }
    }

    fn encipher_buffer<T: AsMut<[u8]> + ?Sized>(&self, offset: usize, buffer: &mut T) {
        match self {
            Kuwo::KWMv1(m) => m.encipher_buffer(offset, buffer),
            Kuwo::KWMv2(m) => m.encipher_buffer(offset, buffer),
        }
    }
}
