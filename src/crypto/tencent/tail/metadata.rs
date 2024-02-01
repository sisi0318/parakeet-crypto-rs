use crate::crypto::tencent::ekey::KeyDecryptError;

/// Tail metadata extracted from "v1" and "v2" QMPC, up to v19.51
/// "v2" introduced an extra key scrambler. The `key` field in this struct will have
/// the unscrambled ekey.
#[derive(Debug, Clone, PartialEq)]
pub struct PcLegacyMetadata {
    /// Size of the payload to trim off the end of the file.
    pub tail_len: usize,
    /// Embedded ekey.
    pub key: Box<[u8]>,
}

/// Tail metadata extracted from "v3" QMPC, first introduced in QMPC v19.57
/// The raw metadata contains `media_id` and `media_filename` in UTF16-LE encoding,
/// and it has been downgraded to ASCII (which is UTF-8 compatible).
#[derive(Debug, Clone, PartialEq)]
pub struct PcMusicExMetadata {
    /// Size of the payload to trim off the end of the file.
    pub tail_len: usize,
    /// Should always be `1`.
    pub tag_version: u32,
    /// Resource identifier (`.mid`)
    pub mid: String,
    /// The actual file name used for `ekey` lookup (`.file.media_mid` + extension).
    pub media_filename: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AndroidQTagMetadata {
    /// Size of the payload to trim off the end of the file.
    pub tail_len: usize,
    /// Embedded ekey.
    pub key: Box<[u8]>,
    /// Tag version associated to the metadata. Should be `2`.
    pub tag_version: u32,
    /// The old, numeric of the resource (`.id`).
    pub resource_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AndroidSTag {
    /// Size of the payload to trim off the end of the file.
    pub tail_len: usize,
    /// Should always be `2`.
    pub tag_version: u32,
    /// Resource identifier (aka. `file.media_mid`).
    pub media_mid: String,
    /// Numeric id.
    pub media_numeric_id: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TailParseResult {
    /// Tail parsed from legacy "v1" and "v2" encoded file, used in QMPC up to 19.51.
    PcLegacy(PcLegacyMetadata),
    /// Tail parsed from "v3" encoded file, used since QMPC v19.57.
    /// The metadata had magic `"musicex\x00"` in the end.
    PcMusicEx(PcMusicExMetadata),
    /// Tail parsed with "QTag" in the end.
    /// The `key` is embedded to the metadata.
    AndroidQTag(AndroidQTagMetadata),
    /// Tail parsed with "QTag" in the end.
    /// One should look at their app internal database and lookup the filename.
    AndroidSTag(AndroidSTag),
}

#[derive(Debug, Clone, PartialEq)]
pub enum TailParseError {
    /// No valid/supported metadata metadata found.
    InvalidTail,

    /// Error when decoding the ekey.
    EKeyDecryptionFailure(KeyDecryptError),

    /// Found a musicex tag but unsupported version
    UnsupportedMusicExVersion(u32),
    /// Found a supported musicex tag, but the size is not supported.
    UnsupportedMusicExPayloadSize(usize),
    CountNotDeserialize,

    /// Need more bytes. The first parameter is the size it required.
    NeedMoreBytes(usize),
}
