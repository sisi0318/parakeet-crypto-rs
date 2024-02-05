use parakeet_crypto::crypto::kugou;
use parakeet_crypto::crypto::tencent::ekey;
use parakeet_crypto::crypto::tencent::metadata::TailParseError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParakeetCliError {
    #[error("Source io error: {0}")]
    SourceIoError(std::io::Error),
    #[error("Destination io error: {0}")]
    DestinationIoError(std::io::Error),

    #[error("QMC tail parse error: {0}")]
    QMCTailParseError(TailParseError),
    #[error("QMC EKey decryption failed: {0}")]
    QMCKeyDecryptionError(ekey::KeyDecryptError),
    #[error("Unable to extract key from QMC tail")]
    QMCKeyRequired,

    #[error("Unable to deserialize header: {0}")]
    KugouHeaderDeserializeError(kugou::HeaderDeserializeError),
    #[error("Cipher error: {0}")]
    KugouCipherError(kugou::CipherError),

    #[error("Unspecified error (placeholder)")]
    #[allow(dead_code)]
    UnspecifiedError,
}

impl From<kugou::CipherError> for ParakeetCliError {
    fn from(error: kugou::CipherError) -> Self {
        Self::KugouCipherError(error)
    }
}
