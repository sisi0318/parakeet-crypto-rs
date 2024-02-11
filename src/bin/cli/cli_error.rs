use thiserror::Error;

use parakeet_crypto::crypto::{kugou, kuwo, tencent};

#[derive(Debug, Error)]
pub enum ParakeetCliError {
    #[error("Source io error: {0}")]
    SourceIoError(std::io::Error),
    #[error("Destination io error: {0}")]
    DestinationIoError(std::io::Error),
    #[error("Other I/O Error '{0}': {1}")]
    OtherIoError(std::path::PathBuf, std::io::Error),

    #[error("QMC tail parse error: {0}")]
    QMCTailParseError(tencent::metadata::TailParseError),
    #[error("QMC EKey decryption failed: {0}")]
    QMCKeyDecryptionError(tencent::ekey::KeyDecryptError),
    #[error("Unable to extract key from QMC tail")]
    QMCKeyRequired,

    #[error("Unable to parse mmkv file")]
    MMKVParseError(mmkv_parser::Error),

    #[error("Unable to deserialize header: {0}")]
    KugouHeaderDeserializeError(kugou::HeaderDeserializeError),
    #[error("Cipher error: {0}")]
    KugouCipherError(kugou::CipherError),

    #[error("Failed to parse header.")]
    KuwoHeaderParseError(kuwo::header::HeaderParseError),
    #[error("Failed to init kuwo cipher: {0}")]
    KuwoCipherInitError(kuwo::InitCipherError),

    #[error("Unspecified error (placeholder)")]
    #[allow(dead_code)]
    UnspecifiedError,
}

impl From<kugou::CipherError> for ParakeetCliError {
    fn from(error: kugou::CipherError) -> Self {
        Self::KugouCipherError(error)
    }
}

impl From<kuwo::header::HeaderParseError> for ParakeetCliError {
    fn from(error: kuwo::header::HeaderParseError) -> Self {
        Self::KuwoHeaderParseError(error)
    }
}

impl From<kuwo::InitCipherError> for ParakeetCliError {
    fn from(error: kuwo::InitCipherError) -> Self {
        Self::KuwoCipherInitError(error)
    }
}
