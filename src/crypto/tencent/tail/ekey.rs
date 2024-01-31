use base64::{engine::general_purpose::STANDARD as Base64, Engine as _};
use std::ops::Mul;

pub const MAX_EKEY_LEN: usize = 0x500;
pub const EKEY_V2_PREFIX: &[u8; 24] = b"UVFNdXNpYyBFbmNWMixLZXk6";

const V2_TEA_KEY_1: &[u8; 16] = b"386ZJY!@#*$%^&)(";
const V2_TEA_KEY_2: &[u8; 16] = b"**#!(#$%&^a1cZ,T";

pub enum KeyDecryptError {
    EkeyTooShort,
    FailDecryptV1,
    FailDecryptV2,
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
    if ekey.len() < 5 {
        return Err(KeyDecryptError::EkeyTooShort);
    }

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

pub fn decrypt_v2(ekey: &[u8]) -> Result<Box<[u8]>, KeyDecryptError> {
    let ekey = tc_tea::decrypt(ekey, V2_TEA_KEY_1).ok_or(KeyDecryptError::FailDecryptV2)?;
    let ekey = tc_tea::decrypt(ekey, V2_TEA_KEY_2).ok_or(KeyDecryptError::FailDecryptV2)?;

    // Strip nil bytes at the end.
    let ekey = match ekey.iter().rposition(|&x| x != 0) {
        Some(pos) => {
            let mut ekey_vec = ekey.to_vec();
            ekey_vec.truncate(pos + 1);
            ekey_vec.into()
        }
        None => ekey,
    };

    match Base64.decode(ekey) {
        Ok(ekey) => decrypt_v1(&ekey),
        _ => Err(KeyDecryptError::FailDecryptV2),
    }
}

pub fn decrypt_ekey<T: AsRef<[u8]>>(ekey: T) -> Result<Box<[u8]>, KeyDecryptError> {
    let ekey = ekey.as_ref();
    match ekey.strip_prefix(EKEY_V2_PREFIX) {
        Some(v2_ekey) => decrypt_v2(v2_ekey),
        None => decrypt_v1(ekey),
    }
}
