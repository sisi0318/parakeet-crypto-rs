use bincode::Options;
use byteorder::ByteOrder;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use super::metadata::{PcMusicExMetadata, TailParseError, TailParseResult};

pub fn parse_pc_v2(raw: &[u8]) -> Result<TailParseResult, TailParseError> {
    if raw.len() < 16 {
        return Err(TailParseError::NeedMoreBytes(16));
    }

    let (tail, tail_identifier) = raw.split_at(raw.len() - 12);
    if !tail_identifier.ends_with(b"musicex\x00") {
        return Err(TailParseError::InvalidTail);
    }

    match byteorder::LE::read_u32(&tail_identifier[..4]) {
        1 => parse_musicex_v1(tail),
        version => Err(TailParseError::UnsupportedMusicExVersion(version)),
    }
}

/// Convert UTF-16 LE string (within ASCII char range) to UTF-8
fn from_ascii_utf16(data: &[u16]) -> String {
    let data = data
        .iter()
        .take_while(|&&wide| wide != 0)
        .map(|&wide| wide as u8)
        .collect::<Vec<_>>();
    String::from_utf8_lossy(&data).to_string()
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[repr(C, packed)]
struct MusicExV1 {
    /// unused & unknown
    unknown_0: u32,
    /// unused & unknown
    unknown_1: u32,
    /// unused & unknown
    unknown_2: u32,

    /// Media ID
    mid: [u16; 30],
    /// Media file name
    #[serde(with = "BigArray")]
    media_filename: [u16; 50],

    /// unused; uninitialized memory?
    unknown_3: u32,
}

fn parse_musicex_v1(tail: &[u8]) -> Result<TailParseResult, TailParseError> {
    let (payload, len) = tail.split_at(tail.len() - 4);
    let payload_len = byteorder::LE::read_u32(len) as usize;
    if payload_len != 0xC0 {
        return Err(TailParseError::UnsupportedMusicExPayloadSize(payload_len));
    }
    let payload = &payload[payload.len() - payload_len..];

    let decoded = bincode::options()
        .with_little_endian()
        .deserialize::<MusicExV1>(payload)
        .map_err(|_| TailParseError::CountNotDeserialize)?;

    let mid = decoded.mid;
    let mid = from_ascii_utf16(&mid);

    let media_filename = decoded.media_filename;
    let media_filename = from_ascii_utf16(&media_filename);

    Ok(TailParseResult::PcMusicEx(PcMusicExMetadata {
        tail_len: payload_len + 0x0C,
        tag_version: 1,
        mid,
        media_filename,
    }))
}
