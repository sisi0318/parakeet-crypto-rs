mod mode2;
mod mode3;
mod mode4;

use crate::crypto::byte_offset_cipher::{ByteOffsetCipher, ByteOffsetDecipher};
use crate::crypto::kugou::{modes, Header, HeaderDeserializeError};
use thiserror::Error;

pub use mode2::Mode2;
pub use mode3::Mode3;
pub use mode4::Mode4;

use lazy_static::lazy_static;
use std::collections::HashMap;

lazy_static! {
    /// Slot keys corresponds to the keys specified in the header.
    pub static ref SLOT_KEYS: HashMap<u32, Box<[u8]>> = {
        let mut m = HashMap::new();
        m.insert(1, Box::from(*include_bytes!("../data/slot_01.bin")));
        m
    };
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub enum CipherModes {
    Mode2(Mode2),
    Mode3(Mode3),
    Mode4(Mode4),
}

impl CipherModes {
    pub fn new(hdr: &Header) -> Result<Self, CipherError> {
        let challenge = hdr
            .get_challenge()
            .ok_or(CipherError::CouldNotGenerateChallenge)?;
        let slot_key = SLOT_KEYS
            .get(&hdr.key_slot)
            .ok_or_else(|| CipherError::SlotKeyMissing(hdr.key_slot))?;

        let cipher = match hdr.crypto_version {
            2 => CipherModes::Mode2(modes::Mode2::new(slot_key)),
            3 => CipherModes::Mode3(modes::Mode3::new(slot_key, hdr.file_key)),
            4 => CipherModes::Mode4(modes::Mode4::new(slot_key, hdr.file_key)),
            version => Err(CipherError::UnsupportedCipherVersion(version))?,
        };

        let mut decrypted = hdr.encrypted_test_data;
        cipher.decrypt(0, &mut decrypted);
        if challenge != decrypted {
            let challenge = challenge.into();
            let decrypted = decrypted.into();
            Err(CipherError::ChallengeValidationFail(challenge, decrypted))?;
        }

        Ok(cipher)
    }

    pub fn decrypt<T: AsMut<[u8]>>(&self, offset: usize, buffer: &mut T) {
        match self {
            CipherModes::Mode2(m) => m.decrypt(offset, buffer),
            CipherModes::Mode3(m) => m.decrypt(offset, buffer),
            CipherModes::Mode4(m) => m.decrypt(offset, buffer),
        }
    }

    pub fn encrypt<T: AsMut<[u8]>>(&self, offset: usize, buffer: &mut T) {
        match self {
            CipherModes::Mode2(m) => m.encrypt(offset, buffer),
            CipherModes::Mode3(m) => m.encrypt(offset, buffer),
            CipherModes::Mode4(m) => m.encrypt(offset, buffer),
        }
    }
}

#[derive(Error, Debug)]
pub enum CipherError {
    #[error("Parse header error: {0}")]
    ParseHeaderFail(HeaderDeserializeError),
    #[error("Could not generate challenge - is file magic correct?")]
    CouldNotGenerateChallenge,
    #[error("Requested slot key does not exist: {0}")]
    SlotKeyMissing(u32),
    #[error("Requested unsupported cipher version: {0}")]
    UnsupportedCipherVersion(u32),
    #[error("Failed to solve challenge: expected {0:?}, got {1:?}")]
    ChallengeValidationFail(Vec<u8>, Vec<u8>),
    #[error("Not enough data, expect at least {0} bytes.")]
    NotEnoughData(usize),
}

impl From<HeaderDeserializeError> for CipherError {
    fn from(error: HeaderDeserializeError) -> Self {
        CipherError::ParseHeaderFail(error)
    }
}
