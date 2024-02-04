use std::io::{BufReader, Error, Read, Write};

use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum MediaType {
    #[default]
    KGM,
    VPR,
}

const KGM_HEADER_MAGIC: [u8; 16] = *include_bytes!("data/header_kgm.bin");
const KGM_CHALLENGE: [u8; 16] = *include_bytes!("data/test_vector_kgm.bin");
const VPR_HEADER_MAGIC: [u8; 16] = *include_bytes!("data/header_vpr.bin");
const VPR_CHALLENGE: [u8; 16] = *include_bytes!("data/test_vector_vpr.bin");

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Header {
    pub magic: [u8; 16],
    pub header_len: u32,
    pub crypto_version: u32,
    pub key_slot: u32,
    pub encrypted_test_data: [u8; 16],
    pub file_key: [u8; 16],
}

#[derive(Debug, Error)]
pub enum HeaderError {
    #[error("Could not deserialize header from bytes: {0}")]
    SerializationIoError(std::io::Error),
    #[error("Could not deserialize header from bytes: {0}")]
    HeaderLenTooSmall(usize),
    #[error("Does not include a valid magic header")]
    InvalidMagic,
}

impl From<std::io::Error> for HeaderError {
    fn from(err: Error) -> Self {
        HeaderError::SerializationIoError(err)
    }
}

pub type HeaderResult<T> = Result<T, HeaderError>;

impl Header {
    pub fn get_file_type(&self) -> Option<MediaType> {
        if self.magic == KGM_HEADER_MAGIC {
            Some(MediaType::KGM)
        } else if self.magic == VPR_HEADER_MAGIC {
            Some(MediaType::VPR)
        } else {
            None
        }
    }

    pub fn get_challenge(&self) -> Option<[u8; 16]> {
        if self.magic == KGM_HEADER_MAGIC {
            Some(KGM_CHALLENGE)
        } else if self.magic == VPR_HEADER_MAGIC {
            Some(VPR_CHALLENGE)
        } else {
            None
        }
    }

    pub fn from_bytes<T: AsRef<[u8]>>(data: T) -> HeaderResult<Self> {
        let data = data.as_ref();

        let mut hdr = Self::default();
        let mut reader = BufReader::new(data);
        reader.read_exact(&mut hdr.magic)?;
        hdr.header_len = reader.read_u32::<LE>()?;
        hdr.crypto_version = reader.read_u32::<LE>()?;
        hdr.key_slot = reader.read_u32::<LE>()?;
        reader.read_exact(&mut hdr.encrypted_test_data)?;
        reader.read_exact(&mut hdr.file_key)?;

        match hdr.get_file_type() {
            Some(_) => Ok(hdr),
            None => Err(HeaderError::InvalidMagic),
        }
    }

    pub fn to_bytes(&self) -> HeaderResult<Vec<u8>> {
        let mut data = vec![];
        let header_len = self.header_len as usize;
        data.reserve(header_len);

        data.write_all(&self.magic)?;
        data.write_u32::<LE>(self.header_len)?;
        data.write_u32::<LE>(self.crypto_version)?;
        data.write_u32::<LE>(self.key_slot)?;
        data.write_all(&self.encrypted_test_data)?;
        data.write_all(&self.file_key)?;

        if header_len < data.len() {
            Err(HeaderError::HeaderLenTooSmall(header_len))
        } else {
            data.resize(header_len, 0);
            Ok(data)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let hdr = Header::default();

        assert_eq!(hdr.magic, [0; 16]);
        assert_eq!(hdr.header_len, 0);
        assert_eq!(hdr.crypto_version, 0);
        assert_eq!(hdr.key_slot, 0);
        assert_eq!(hdr.encrypted_test_data, [0; 16]);
        assert_eq!(hdr.file_key, [0; 16]);
    }

    #[test]
    fn test_conversion() {
        let original_hdr = Header {
            magic: [1; 16],
            header_len: 1024,
            crypto_version: 2,
            key_slot: 3,
            encrypted_test_data: [4; 16],
            file_key: [5; 16],
        };

        let serialized_hdr = original_hdr.to_bytes().unwrap();
        assert_eq!(serialized_hdr.len(), 1024);

        let deserialized_hdr = Header::from_bytes(serialized_hdr).unwrap();
        assert_eq!(original_hdr, deserialized_hdr);
    }
}
