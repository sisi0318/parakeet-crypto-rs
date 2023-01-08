use std::ops::Mul;

use crate::interfaces::DecryptorError;

use super::QMCTailParser;

pub trait QMCTailKeyDecryptor {
    fn decrypt_key_v1(&self, embed_key: &[u8]) -> Result<Box<[u8]>, DecryptorError>;
    fn decrypt_key_v2(&self, embed_key: &[u8]) -> Result<Box<[u8]>, DecryptorError>;
}

/// Used by the "QMC2 footer parser", used to derive the file key.
pub fn make_simple_key(seed: u8, size: usize) -> Box<[u8]> {
    let seed = seed as f32;
    let mut result = vec![0u8; size].into_boxed_slice();

    for (i, v) in result.iter_mut().enumerate() {
        let i = i as f32;
        let angle = seed + i * 0.1;
        *v = angle.tan().abs().mul(100.0) as u8;
    }

    result
}

impl QMCTailKeyDecryptor for QMCTailParser {
    fn decrypt_key_v1(&self, embed_key: &[u8]) -> Result<Box<[u8]>, DecryptorError> {
        let (header, body) = embed_key.split_at(8);
        let simple_key = make_simple_key(self.seed, 8);

        let mut tea_key = [0u8; 16];
        for i in (0..16).step_by(2) {
            tea_key[i] = simple_key[i / 2];
            tea_key[i + 1] = header[i / 2];
        }

        let final_key = tc_tea::decrypt(body, tea_key).ok_or(DecryptorError::TEADecryptError)?;

        Ok([header, &final_key].concat().into())
    }

    fn decrypt_key_v2(&self, embed_key: &[u8]) -> Result<Box<[u8]>, DecryptorError> {
        let key = tc_tea::decrypt(embed_key, self.enc_v2_key_stage1)
            .and_then(|key| tc_tea::decrypt(key, self.enc_v2_key_stage2))
            .ok_or(DecryptorError::TEADecryptError)?;
        let key = std::str::from_utf8(&key)?;
        let key = base64::decode(key)?;

        self.decrypt_key_v1(&key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_key() {
        let expected: &[u8] = b"\x33\x41\x50\x62\x78\x94\xba\xf1";
        let key = make_simple_key(123, 8);
        assert_eq!(&key[..], expected)
    }
}
