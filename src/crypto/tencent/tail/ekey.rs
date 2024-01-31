use std::ops::Mul;

use base64::{engine::general_purpose::STANDARD as Base64, Engine as _};

pub const MAX_EKEY_LEN: usize = 0x500;
pub const EKEY_V2_PREFIX: &[u8; 24] = b"UVFNdXNpYyBFbmNWMixLZXk6";

lazy_static! {
    static ref V2_TEA_KEY: [u8; 32] = *include_bytes!("ekey.bin");
}

#[derive(Debug, Clone, PartialEq)]
pub enum KeyDecryptError {
    EkeyTooShort,
    FailDecryptV1,
    FailDecryptV2,
    Base64Decoding,
}

pub fn make_simple_key<const N: usize>() -> [u8; N] {
    let mut result = [0u8; N];

    for (i, v) in result.iter_mut().enumerate() {
        let i = i as f32;
        let value = 106.0 + i * 0.1;
        let value = value.tan().abs().mul(100.0);
        *v = value as u8;
    }

    result
}

pub fn decrypt_v1(ekey: &[u8]) -> Result<Box<[u8]>, KeyDecryptError> {
    if ekey.len() < 12 {
        return Err(KeyDecryptError::EkeyTooShort);
    }

    let ekey = base64_decode(ekey)?;
    let (header, cipher) = ekey.split_at(8);

    let simple_key = make_simple_key::<8>();
    let tea_key = simple_key
        .iter()
        .zip(header)
        .flat_map(|(&simple_part, &header_part)| [simple_part, header_part])
        .collect::<Vec<_>>();

    let plaintext = tc_tea::decrypt(cipher, tea_key).ok_or(KeyDecryptError::FailDecryptV1)?;
    Ok([header, &plaintext].concat().into())
}

fn base64_decode(ekey: &[u8]) -> Result<Box<[u8]>, KeyDecryptError> {
    Base64
        .decode(ekey)
        .map(|decoded| decoded.into())
        .map_err(|_| KeyDecryptError::Base64Decoding)
}

pub fn decrypt_v2(ekey: &[u8]) -> Result<Box<[u8]>, KeyDecryptError> {
    let (key1, key2) = V2_TEA_KEY.split_at(16);
    let ekey = base64_decode(ekey)?;
    let ekey = tc_tea::decrypt(ekey, key1).ok_or(KeyDecryptError::FailDecryptV2)?;
    let ekey = tc_tea::decrypt(ekey, key2).ok_or(KeyDecryptError::FailDecryptV2)?;

    let mut ekey = ekey.to_vec();
    if let Some(p) = ekey.iter().rposition(|&x| x != 0) {
        ekey.truncate(p + 1);
    }

    decrypt_v1(&ekey)
}

pub fn decrypt_ekey<T: AsRef<[u8]>>(ekey: T) -> Result<Box<[u8]>, KeyDecryptError> {
    let ekey = ekey.as_ref();
    match ekey.strip_prefix(EKEY_V2_PREFIX) {
        Some(v2_ekey) => decrypt_v2(v2_ekey),
        None => decrypt_v1(ekey),
    }
}
