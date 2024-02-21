use base64::{engine::general_purpose::STANDARD as Base64, Engine as _};
use byteorder::{ByteOrder, BE};
use std::str::FromStr;

fn parse_safe_sync_u32(v: u32) -> u32 {
    let a = v & 0x00_00_00_7f;
    let b = (v & 0x00_00_7f_00) >> 1;
    let c = (v & 0x00_7f_00_00) >> 2;
    let d = (v & 0x7f_00_00_00) >> 3;
    a | b | c | d
}

fn from_utf16_le(data: &[u8]) -> Vec<u8> {
    data.chunks(2)
        .map_while(|chunk| match chunk[0] {
            0 => None,
            v => Some(v),
        })
        .collect()
}

pub struct Header {
    pub data_start_offset: usize,
    pub encrypted_header_len: usize,
    pub stage_1_iv: [u8; 16],
    /// aes-192, key length = 24-bytes (first 16 byte is also re-used as its iv)
    pub stage_2_key: [u8; 24],
    pub stolen_header_bytes: Box<[u8]>,
}

const MAGIC_ID3: [u8; 3] = *b"ID3";

impl Header {
    pub fn from_bytes<T: AsRef<[u8]>>(data: T) -> Result<Self, super::Error> {
        let data = data.as_ref();
        if data.len() < 10 {
            Err(super::Error::InputTooSmall(10, data.len()))?;
        }
        if !data.starts_with(&MAGIC_ID3) {
            Err(super::Error::InvalidId3Header)?;
        }
        let hdr_size = parse_safe_sync_u32(BE::read_u32(&data[6..]));
        let data_start_offset = hdr_size as usize + 10;
        if data.len() < data_start_offset {
            Err(super::Error::InputTooSmall(data_start_offset, data.len()))?;
        }

        let mut offset = 10usize;

        let mut result = Self {
            data_start_offset,
            encrypted_header_len: 0,
            stage_1_iv: [0u8; 16],
            stage_2_key: [0u8; 24],
            stolen_header_bytes: Box::new([]),
        };

        while offset < data_start_offset {
            if offset + 10 >= data_start_offset {
                Err(super::Error::UnexpectedHeaderEof(offset))?;
            }

            let tag_name = &data[offset..offset + 4];
            offset += 4;
            let tag_size = BE::read_u32(&data[offset..]) as usize;
            offset += 4;

            offset += 2; // flags - not used/ignored

            if offset + tag_size > data_start_offset {
                Err(super::Error::UnexpectedHeaderEof(offset))?;
            }

            // 01 ff fe ignored - those are encoding marks. All fields are in unicode anyway...
            // src: https://web.archive.org/web/2020/https://id3.org/id3v2.3.0#ID3v2_frame_overview
            // > If ISO-8859-1 is used this byte should be $00, if Unicode is used it should be $01.
            // > Unicode strings must begin with the Unicode BOM ($FF FE or $FE FF) to identify the byte order.
            let tag_data = &data[offset + 3..offset + tag_size];
            offset += tag_size;

            match tag_name {
                b"TSIZ" => {
                    let tag_len_str = from_utf16_le(tag_data);
                    let tag_len_str = String::from_utf8_lossy(tag_len_str.as_slice());
                    let header_len = u32::from_str(&tag_len_str)
                        .map_err(super::Error::DeserializeHeaderValueInt)?;
                    result.encrypted_header_len = header_len as usize;
                }
                b"TSRC" | b"TENC" => {
                    let tag_data = from_utf16_le(tag_data);
                    let buf_stage1_key =
                        hex::decode(tag_data).map_err(super::Error::DeserializeHeaderValueHex)?;
                    if buf_stage1_key.len() != result.stage_1_iv.len() {
                        Err(super::Error::InvalidData(offset))?;
                    }
                    result.stage_1_iv.copy_from_slice(&buf_stage1_key);
                }
                b"TSSE" => {
                    let tag_data = from_utf16_le(tag_data);
                    let stolen_header = Base64
                        .decode(tag_data)
                        .map_err(super::Error::DeserializeHeaderValueBase64)?;
                    result.stolen_header_bytes = stolen_header.into_boxed_slice();
                }
                b"TRCK" => {
                    let mut tag_data = from_utf16_le(tag_data);
                    let mut key = *b"123456781234567812345678";
                    if tag_data.len() > 24 {
                        tag_data.drain(..24 - tag_data.len());
                    }
                    let left = key.len() - tag_data.len();
                    key[left..].copy_from_slice(&tag_data);
                    result.stage_2_key = key;
                }
                _ => {
                    // ignored
                }
            }
        }

        Ok(result)
    }
}
