use crate::interfaces::DecryptorError;
use std::io::{Read, Seek, SeekFrom};
use std::str;

use super::{guess_type, parse_tail_pc, parse_tail_qtag, ClientType, QMCTailKeyDecryptor};

const ENC_V2_PREFIX_TAG: &[u8] = b"QQMusic EncV2,Key:";

/// QMC2's file footer parser.
/// This parser is used to extract the file key for decryption, as well as the
///   number of bytes to ignore in the end of the file.
pub struct QMCTailParser {
    pub(super) seed: u8,
    pub(super) enc_v2_key_stage1: [u8; 16],
    pub(super) enc_v2_key_stage2: [u8; 16],
}

impl QMCTailParser {
    pub fn new(seed: u8) -> QMCTailParser {
        QMCTailParser {
            seed,
            enc_v2_key_stage1: [0u8; 16],
            enc_v2_key_stage2: [0u8; 16],
        }
    }

    pub fn new_enc_v2(
        seed: u8,
        enc_v2_key_stage1: [u8; 16],
        enc_v2_key_stage2: [u8; 16],
    ) -> QMCTailParser {
        QMCTailParser {
            seed,
            enc_v2_key_stage1,
            enc_v2_key_stage2,
        }
    }

    pub fn set_seed(&mut self, seed: u8) {
        self.seed = seed;
    }

    pub fn set_key_stage1(&mut self, key: [u8; 16]) {
        self.enc_v2_key_stage1 = key;
    }

    pub fn set_key_stage2(&mut self, key: [u8; 16]) {
        self.enc_v2_key_stage2 = key;
    }

    pub fn parse_from_buffer(&self, tail: &[u8]) -> Result<(usize, Box<[u8]>), DecryptorError> {
        if tail.len() < 4 {
            return Err(DecryptorError::QMCTailBufferTooSmall);
        }

        let mut tail_magic = [0u8; 4];
        tail_magic.copy_from_slice(&tail[tail.len() - 4..]);

        let client_type = guess_type(&tail_magic)
            .ok_or_else(|| DecryptorError::QMCInvalidFooter(Box::new(tail_magic)))?;

        let (full_tail_len, encrypted_key) = match client_type {
            ClientType::AndroidSTag => return Err(DecryptorError::QMCAndroidSTag),
            ClientType::AndroidQTag => parse_tail_qtag(tail),
            ClientType::PC => parse_tail_pc(tail),
        }
        .ok_or_else(|| DecryptorError::QMCInvalidFooter(Box::new(tail_magic)))?;

        let encrypted_key = str::from_utf8(&encrypted_key)?.trim_end_matches(char::from(0));
        let encrypted_key = base64::decode(encrypted_key)?;

        let key = if encrypted_key.starts_with(ENC_V2_PREFIX_TAG) {
            self.decrypt_key_v2(&encrypted_key[ENC_V2_PREFIX_TAG.len()..])
        } else {
            self.decrypt_key_v1(&encrypted_key)
        }?;

        Ok((full_tail_len, key))
    }

    pub fn parse_from_stream<R>(&self, input: &mut R) -> Result<(usize, Box<[u8]>), DecryptorError>
    where
        R: Read + Seek,
    {
        let file_len = input.seek(SeekFrom::End(0))? as usize;

        // known largest tail size is 0x225 (549) bytes.
        const BUFFER_TAIL_DEFAULT_READ_LEN: usize = 0x400;

        let read_len = std::cmp::min(file_len, BUFFER_TAIL_DEFAULT_READ_LEN);
        let mut buffer_full_tail = vec![0u8; read_len];
        input.seek(SeekFrom::End(-(read_len as i64)))?;
        input.read_exact(&mut buffer_full_tail)?;

        self.parse_from_buffer(&buffer_full_tail[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{interfaces::DecryptorError, qmc2::tails::make_simple_key};
    use std::io::Cursor;

    const TEST_KEY_SEED: u8 = 123;
    const TEST_KEY_STAGE1: &[u8; 16] = &[
        11, 12, 13, 14, 15, 16, 17, 18, 21, 22, 23, 24, 25, 26, 27, 28,
    ];
    const TEST_KEY_STAGE2: &[u8; 16] = &[
        31, 32, 33, 34, 35, 36, 37, 38, 41, 42, 43, 44, 45, 46, 47, 48,
    ];

    fn create_default_key_v1() -> Box<[u8]> {
        let (header, body) = b"12345678Some Key".split_at(8);

        let simple_key = make_simple_key(TEST_KEY_SEED, 8);
        let mut tea_key = [0u8; 16];
        for i in (0..16).step_by(2) {
            tea_key[i] = simple_key[i / 2];
            tea_key[i + 1] = header[i / 2];
        }

        let second_half_encrypted = tc_tea::encrypt(body, tea_key).unwrap();
        let embed_key = [header, &second_half_encrypted].concat();

        base64::encode(embed_key).as_bytes().into()
    }

    fn create_default_key_v2() -> Box<[u8]> {
        let embed_key_v1 = create_default_key_v1();

        let embed_key_v2 = tc_tea::encrypt(embed_key_v1, TEST_KEY_STAGE2)
            .and_then(|key| tc_tea::encrypt(key, TEST_KEY_STAGE1))
            .unwrap();

        let embed_key_v2 = [ENC_V2_PREFIX_TAG, &embed_key_v2].concat();

        base64::encode(embed_key_v2).as_bytes().into()
    }

    #[test]
    fn parse_v1_pc() {
        let parser = QMCTailParser::new(TEST_KEY_SEED);
        let mut footer = create_default_key_v1().to_vec();
        let mut footer_len = (footer.len() as u32).to_le_bytes().to_vec();
        footer.append(&mut footer_len);

        let expected_trim_right = footer.len();
        let mut stream = Cursor::new(footer);

        let (trim_right, decrypted) = parser.parse_from_stream(&mut stream).unwrap();
        assert_eq!(trim_right, expected_trim_right);
        assert_eq!(decrypted.to_vec(), b"12345678Some Key".to_vec());
    }

    #[test]
    fn parse_v2_pc() {
        let parser = QMCTailParser::new_enc_v2(TEST_KEY_SEED, *TEST_KEY_STAGE1, *TEST_KEY_STAGE2);
        let mut footer = create_default_key_v2().to_vec();
        let mut footer_len = (footer.len() as u32).to_le_bytes().to_vec();
        footer.append(&mut footer_len);

        let expected_trim_right = footer.len();
        let mut stream = Cursor::new(footer);

        let (trim_right, decrypted) = parser.parse_from_stream(&mut stream).unwrap();
        assert_eq!(trim_right, expected_trim_right);
        assert_eq!(decrypted.to_vec(), b"12345678Some Key".to_vec());
    }

    #[test]
    fn parse_v2_q_tag() {
        let parser = QMCTailParser::new_enc_v2(TEST_KEY_SEED, *TEST_KEY_STAGE1, *TEST_KEY_STAGE2);
        let mut footer = create_default_key_v2().to_vec();
        let mut tmp = Vec::from(b",12345,2" as &[u8]);
        footer.append(&mut tmp);
        let mut footer_len = (footer.len() as u32).to_be_bytes().to_vec();
        footer.append(&mut footer_len);
        let mut tmp = Vec::from(b"QTag" as &[u8]);
        footer.append(&mut tmp);

        let expected_trim_right = footer.len();
        let mut stream = Cursor::new(footer);

        let (trim_right, decrypted) = parser.parse_from_stream(&mut stream).unwrap();
        assert_eq!(trim_right, expected_trim_right);
        assert_eq!(decrypted.to_vec(), b"12345678Some Key".to_vec());
    }

    #[test]
    fn parse_non_sense() {
        let parser = QMCTailParser::new(0);
        let footer = vec![0xff, 0xff, 0xff, 0xff];
        let mut stream = Cursor::new(footer);
        assert!(
            parser.parse_from_stream(&mut stream).is_err(),
            "should not allow 0xffffffff magic"
        )
    }

    #[test]
    fn parse_android_s_tag() {
        let parser = QMCTailParser::new(0);
        let footer = b"unused padding ..... 1111STag".to_vec();
        let mut stream = Cursor::new(footer);
        //使用 `matches!` 来匹配enum
        assert!(matches!(
            parser.parse_from_stream(&mut stream).unwrap_err(),
            DecryptorError::QMCAndroidSTag
        ));
    }
}
