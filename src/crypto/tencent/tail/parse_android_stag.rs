use byteorder::ByteOrder;

use crate::crypto::tencent::ekey::decrypt;
use crate::crypto::tencent::tail::metadata::TailParseError::NeedMoreBytes;
use crate::crypto::tencent::tail::metadata::{
    AndroidQTagMetadata, TailParseError, TailParseResult,
};
use crate::utils::validate::is_base64_str;

pub fn parse_android_stag(raw: &[u8]) -> Result<TailParseResult, TailParseError> {
    if raw.len() < 8 {
        Err(NeedMoreBytes(8))?;
    }
    if !raw.ends_with(b"QTag") {
        Err(TailParseError::InvalidTail)?;
    }
    let (payload, tail_magic) = raw.split_at(raw.len() - 8);
    let payload_len = byteorder::BE::read_u32(tail_magic) as usize;
    let tail_len = payload_len + 8;

    // CSV: ekey,resource_id,version
    let payload_str = String::from_utf8_lossy(&payload[payload.len() - payload_len..]);
    let parts = payload_str.split(',').collect::<Vec<_>>();

    if parts.len() != 3 {
        Err(TailParseError::InvalidTail)?;
    }

    let (ekey, id, version) = (parts[0], parts[1], parts[2]);
    if !is_base64_str(ekey) || version != "2" {
        Err(TailParseError::InvalidTail)?;
    }

    let id = match id.parse::<u64>() {
        Ok(id) => id,
        Err(_) => Err(TailParseError::InvalidTail)?,
    };

    let key = decrypt(ekey).map_err(TailParseError::EKeyDecryptionFailure)?;
    Ok(TailParseResult::AndroidQTag(AndroidQTagMetadata {
        tail_len,
        key,
        tag_version: 2,
        resource_id: id,
    }))
}

#[cfg(test)]
mod tests {
    use crate::crypto::tencent::parse_tail;

    use super::*;

    #[test]
    fn test_android_qtag() {
        let footer = *include_bytes!("__fixtures__/ekey_android_qtag.bin");
        let actual = parse_tail(&footer);
        let expected = Ok(TailParseResult::AndroidQTag(AndroidQTagMetadata {
            key: Box::from(*include_bytes!("__fixtures__/ekey_android_qtag_result.bin")),
            tail_len: 0x02D4,
            resource_id: 326454301,
            tag_version: 2,
        }));
        assert_eq!(actual, expected, "failed to parse enc_v2_map sample");
    }
}
