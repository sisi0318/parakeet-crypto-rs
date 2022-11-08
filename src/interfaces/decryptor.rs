use base64::DecodeError;
use std::{io::{Read, Seek, Write}, str::Utf8Error};
use thiserror::Error;

// FIXME: better handling error messages.
//   e.g. https://boats.gitlab.io/failure/
#[derive(Debug, Error)]
pub enum DecryptorError {
    #[error("io error, {0}")]
    IOError(#[from] std::io::Error),
    #[error("{0} not implement")]
    NotImplementedError(String),
    #[error("QMC parse error - footer magic: {}",hex::encode(.0.to_be_bytes()))]
    QMCInvalidFooter(u32),
    #[error("Parsing 'STag' file failed.")]
    QMCAndroidSTag,
    #[error("Parsing 'QTag' file failed.")]
    QMCAndroidQTagInvalid,
    #[error("string encode error, {0}")]
    StringEncodeError(#[from] Utf8Error),
    #[error("base64 decode error, {0}")]
    Base64DecodeError(#[from] DecodeError),
    #[error("TEA key error (is your key correct?)")]
    TEADecryptError,

    
    #[error("invalid kugou key slot: {0}")]
    KGMInvalidKeySlotError(u32),
    #[error("invalid kugou file key")]
    KGMInvalidFileKey,
    #[error("unsupported kgm magic header")]
    KGMUnsupportedMagic,
    #[error("unsupport kugou encryption type: {0}")]
    KGMUnsupportedEncryptionType(u32),
    #[error("both kugou v4 expansion tables are required.")]
    KGMv4ExpansionTableRequired,

    #[error("Ximalaya cound not find implementation")]
    XimalayaCountNotFindImplementation,
}

pub trait Decryptor {
    fn check<R>(&self, from: &mut R) -> Result<(), DecryptorError>
    where
        R: Read + Seek;

    fn decrypt<R, W>(&self, from: &mut R, to: &mut W) -> Result<(), DecryptorError>
    where
        R: Read + Seek,
        W: Write;
}
