use std::io::{BufRead, BufReader, Error, Read};

use byteorder::{ReadBytesExt, LE};
use thiserror::Error;

pub const MAGIC_1: [u8; 16] = *b"yeelion-kuwo-tme";
pub const MAGIC_2: [u8; 16] = *b"yeelion-kuwo\0\0\0\0";

pub const HEADER_PARSE_REQUIRED_LEN: usize = 0x3C;
pub const HEADER_FIXED_LEN: usize = 0x400;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Default)]
pub struct KuwoHeader {
    /// Either `MAGIC_1` or `MAGIC_2`
    pub magic: [u8; 16],
    /// 1: Legacy KWM format
    /// 2: QMCv2 format (mflac/mgg)
    pub version: u32,

    /// Numeric ID of the resource.
    pub resource_id: u32,

    /// Format name, e.g. b"2000FLAC" or b"20900kmflac" (padded with b'\0')
    pub format_name: [u8; 12],
}

#[derive(Debug, Error)]
pub enum HeaderParseError {
    #[error("Need more bytes to parse: expected {0} bytes")]
    NeedMoreBytes(usize),

    #[error("I/O error: {0}")]
    IoError(std::io::Error),

    #[error("File header does not contain a valid magic header")]
    InvalidMagic,

    #[error("File header declares an unsupported version: {0}")]
    UnsupportedVersion(u32),
}

impl From<std::io::Error> for HeaderParseError {
    fn from(error: Error) -> Self {
        Self::IoError(error)
    }
}

impl KuwoHeader {
    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, HeaderParseError> {
        let bytes = bytes.as_ref();
        if bytes.len() < HEADER_PARSE_REQUIRED_LEN {
            Err(HeaderParseError::NeedMoreBytes(HEADER_PARSE_REQUIRED_LEN))?;
        }

        let mut reader = BufReader::new(bytes);
        let mut result = Self::default();

        reader.read_exact(&mut result.magic)?;
        result.version = reader.read_u32::<LE>()?;
        reader.consume(0x04);
        result.resource_id = reader.read_u32::<LE>()?;
        reader.consume(0x14);
        reader.read_exact(&mut result.format_name)?;
        if result.magic != MAGIC_1 && result.magic != MAGIC_2 {
            Err(HeaderParseError::InvalidMagic)?;
        }

        Ok(result)
    }

    /// Get the quality id.
    ///
    /// This id can be used to lookup from mmkv database.
    ///
    /// # Examples
    ///
    /// ```
    /// use parakeet_crypto::crypto::kuwo::header::KuwoHeader;
    ///
    /// let mut hdr = KuwoHeader::default();
    /// hdr.format_name = *b"20900kmflac\0";
    /// assert_eq!(hdr.get_quality_id(), 20900);
    /// hdr.format_name = *b"2000FLAC\0\0\0\0";
    /// assert_eq!(hdr.get_quality_id(), 2000);
    /// ```
    pub fn get_quality_id(&self) -> u32 {
        self.format_name
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .fold(0, |sum, &n| sum * 10 + u32::from(n - b'0'))
    }
}
