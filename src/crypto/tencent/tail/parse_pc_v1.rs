use super::ekey::{decrypt_ekey, MAX_EKEY_LEN};
use super::metadata::{PcLegacyMetadata, TailParseError, TailParseResult};
use crate::utils::validate::is_base64_str;
use byteorder::ByteOrder;

pub fn parse_pc_v1(raw: &[u8]) -> Result<TailParseResult, TailParseError> {
    if raw.len() < 8 {
        return Err(TailParseError::NeedMoreBytes(8));
    }

    let key_len = byteorder::LE::read_u32(&raw[raw.len() - 4..]) as usize;
    let tail_len = key_len + 4;

    // If the key is too long, probably not an ekey.
    if key_len > MAX_EKEY_LEN {
        return Err(TailParseError::InvalidTail);
    }

    // Check if we have enough bytes
    if raw.len() < tail_len {
        return Err(TailParseError::NeedMoreBytes(tail_len));
    }

    // Extract the ekey segment
    let mut ekey = raw[raw.len() - 4 - key_len..raw.len() - 4].to_vec();
    if let Some(non_nil_idx) = ekey.iter().rposition(|&x| x != 0) {
        ekey.truncate(non_nil_idx + 1)
    }

    // Validate ekey
    if !is_base64_str(&ekey) {
        // Check if the ekey contains invalid characters.
        return Err(TailParseError::InvalidTail);
    }

    let key = decrypt_ekey(ekey).map_err(TailParseError::EKeyDecryptionFailure)?;
    Ok(TailParseResult::PcLegacy(PcLegacyMetadata {
        tail_len,
        key,
    }))
}
