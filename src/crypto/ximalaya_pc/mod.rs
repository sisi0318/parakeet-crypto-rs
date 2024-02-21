use aes::cipher::block_padding::UnpadError;
use hex::FromHexError;
use std::num::ParseIntError;
use thiserror::Error;

mod cipher;
mod header;

pub use cipher::decipher_part_2;
pub use header::Header;

#[derive(Debug, Error)]
pub enum Error {
    #[error("file does not begin with a valid ID3 header")]
    InvalidId3Header,

    #[error("Input buffer too small. Expected at least {0} bytes, got {0} bytes.")]
    InputTooSmall(usize, usize),

    #[error("Unexpected EOF while parsing header at offset {0}")]
    UnexpectedHeaderEof(usize),

    #[error("Could not deserialize an integer: {0}")]
    DeserializeHeaderValueInt(ParseIntError),

    #[error("Could not deserialize a hex str to vec: {0}")]
    DeserializeHeaderValueHex(FromHexError),

    #[error("Could not deserialize a base64 str to vec: {0}")]
    DeserializeHeaderValueBase64(base64::DecodeError),

    #[error("Failed to parse at offset: {0}")]
    InvalidData(usize),

    #[error("Failed to decrypt data (stage 1, pkcs#7 padding error): {0}")]
    Stage1PadError(UnpadError),

    #[error("Failed to decrypt data (stage 1, b64 decode)")]
    Stage1CipherDecodeError(base64::DecodeError),

    #[error("Failed to decrypt data (stage 2, pkcs#7 padding error): {0}")]
    Stage2PadError(UnpadError),

    #[error("Failed to decrypt data (stage 2, b64 decode)")]
    Stage2CipherDecodeError(base64::DecodeError),
}
