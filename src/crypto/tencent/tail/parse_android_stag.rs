use byteorder::ByteOrder;

use crate::crypto::tencent::tail::metadata::TailParseError::NeedMoreBytes;
use crate::crypto::tencent::tail::metadata::{
    AndroidSTagMetadata, TailParseError, TailParseResult,
};
use crate::utils::validate::ValidatorTrait;

pub fn parse_android_stag(raw: &[u8]) -> Result<TailParseResult, TailParseError> {
    if raw.len() < 8 {
        Err(NeedMoreBytes(8))?;
    }
    if !raw.ends_with(b"STag") {
        Err(TailParseError::InvalidTail)?;
    }
    let (payload, tail_magic) = raw.split_at(raw.len() - 8);
    let payload_len = byteorder::BE::read_u32(tail_magic) as usize;
    let tail_len = payload_len + 8;

    // CSV: resource_id,version,file_media_mid
    let payload_str = String::from_utf8_lossy(&payload[payload.len() - payload_len..]);
    let parts = payload_str.split(',').collect::<Vec<_>>();

    if parts.len() != 3 {
        Err(TailParseError::InvalidTail)?;
    }

    let (id, version, media_mid) = (parts[0], parts[1], parts[2]);
    if !id.is_digits() || version != "2" {
        Err(TailParseError::InvalidTail)?;
    }

    let id = match id.parse::<u64>() {
        Ok(id) => id,
        Err(_) => Err(TailParseError::InvalidTail)?,
    };

    Ok(TailParseResult::AndroidSTag(AndroidSTagMetadata {
        tail_len,
        tag_version: 2,
        media_mid: media_mid.into(),
        media_numeric_id: id,
    }))
}

#[cfg(test)]
mod tests {
    use crate::crypto::tencent::parse_tail;

    use super::*;

    #[test]
    fn test_android_stag() {
        let footer = *include_bytes!("__fixtures__/ekey_android_stag.bin");
        let actual = parse_tail(&footer);
        let expected = Ok(TailParseResult::AndroidSTag(AndroidSTagMetadata {
            tail_len: 0x20,
            tag_version: 2,
            media_mid: "001y7CaR29k6YP".into(),
            media_numeric_id: 5177785,
        }));
        assert_eq!(actual, expected, "failed to parse enc_v2_map sample");
    }
}
