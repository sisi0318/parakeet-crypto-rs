use crate::interfaces::DecryptorError;

use super::{
    base::{KGMCrypto, KGMCryptoConfig},
    file_constants::{
        KGM_EXPECTED_DECRYPTION_RESULT, KGM_HEADER, VPR_EXPECTED_DECRYPTION_RESULT, VPR_HEADER,
    },
    file_header::KGMHeader,
    KGMCryptoType2, KGMCryptoType3, KGMCryptoType4,
};

#[inline]
fn create_kgm_crypto(
    header: &KGMHeader,
    config: &KGMCryptoConfig,
) -> Result<Box<dyn KGMCrypto>, DecryptorError> {
    if let Some(slot_key) = config.slot_keys.get(&header.key_slot) {
        let mut kgm_crypto: Box<dyn KGMCrypto> = match header.crypto_version {
            2 => Box::from(KGMCryptoType2::default()),
            3 => Box::from(KGMCryptoType3::default()),
            4 => Box::from(KGMCryptoType4::default()),
            _ => {
                return Err(DecryptorError::KGMUnsupportedEncryptionType(
                    header.crypto_version,
                ))
            }
        };

        kgm_crypto.configure(config, slot_key, &header.file_key);
        Ok(kgm_crypto)
    } else {
        Err(DecryptorError::KGMInvalidKeySlotError(header.key_slot))
    }
}

#[inline]
fn kgm_select_challenge_data(file_magic: &[u8; 16]) -> Result<[u8; 16], DecryptorError> {
    if *file_magic == KGM_HEADER {
        Ok(KGM_EXPECTED_DECRYPTION_RESULT)
    } else if *file_magic == VPR_HEADER {
        Ok(VPR_EXPECTED_DECRYPTION_RESULT)
    } else {
        Err(DecryptorError::KGMUnsupportedMagic)
    }
}

pub fn create_kgm_decryptor(
    header: &KGMHeader,
    config: &KGMCryptoConfig,
) -> Result<Box<dyn KGMCrypto>, DecryptorError> {
    let mut decryptor = create_kgm_crypto(header, config)?;
    let challenge_data = kgm_select_challenge_data(&header.magic)?;

    // Decryption test
    let mut test_data = header.decryptor_test_data;
    decryptor.decrypt(0, &mut test_data);
    if challenge_data == test_data {
        Ok(decryptor)
    } else {
        Err(DecryptorError::KGMInvalidFileKey)
    }
}

pub fn create_kgm_encryptor(
    header: &mut KGMHeader,
    config: &KGMCryptoConfig,
) -> Result<Box<dyn KGMCrypto>, DecryptorError> {
    let mut encryptor = create_kgm_crypto(header, config)?;
    let mut challenge_data = kgm_select_challenge_data(&header.magic)?;

    // Key verification signature generation
    encryptor.encrypt(0, &mut challenge_data);
    header.decryptor_test_data = challenge_data;

    Ok(encryptor)
}
