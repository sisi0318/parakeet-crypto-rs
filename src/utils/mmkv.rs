use std::collections::HashMap;

use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MMKVParseError {
    #[error("Unexpected End-of-File while parsing")]
    UnexpectedEof,
}

/// Parse u64 from a given buffer snippet.
/// Return `(bytes_consumed, result)`.
pub fn read_u64(buffer: &[u8]) -> Result<(&[u8], u64), MMKVParseError> {
    let mut result = 0;
    let mut shift = 0;

    for (i, &byte) in buffer.iter().enumerate() {
        result |= (u64::from(byte) & 0x7f) << shift;
        shift += 7;

        if byte & 0x80 == 0 {
            return Ok((&buffer[i + 1..], result));
        }
    }

    Err(MMKVParseError::UnexpectedEof)
}

pub fn read_container(buffer: &[u8]) -> Result<(&[u8], &[u8]), MMKVParseError> {
    let (buffer, len) = read_u64(buffer)?;
    let (result, buffer) = buffer.split_at(len as usize);
    Ok((buffer, result))
}

pub fn read_string(buffer: &[u8]) -> Result<String, MMKVParseError> {
    let (_, result) = read_container(buffer)?;
    Ok(String::from_utf8_lossy(result).into())
}

pub type ParsedMap<'a> = HashMap<&'a [u8], &'a [u8]>;

pub enum ParseControl {
    Continue,
    Stop,
}

/// Callback style parser.
#[allow(clippy::needless_lifetimes)]
pub fn parse_callback<'a, F>(buffer: &'a [u8], mut callback: F) -> Result<(), MMKVParseError>
where
    F: FnMut(&'a [u8], &'a [u8]) -> ParseControl,
{
    let mut buffer = buffer;

    while !buffer.is_empty() {
        let (next, key) = read_container(buffer)?;
        let (next, value) = read_container(next)?;
        buffer = next;

        match callback(key, value) {
            ParseControl::Continue => continue,
            ParseControl::Stop => break,
        }
    }

    Ok(())
}

pub fn parse(buffer: &[u8]) -> Result<ParsedMap, MMKVParseError> {
    let mut result = HashMap::new();
    parse_callback(buffer, |k, v| {
        result.insert(k, v);
        ParseControl::Continue
    })?;
    Ok(result)
}

pub fn parse_str_map(buffer: &[u8]) -> Result<HashMap<String, String>, MMKVParseError> {
    let mut result = HashMap::new();
    let mut parse_err = Ok(());
    parse_callback(buffer, |k, v| match read_string(v) {
        Ok(value) => {
            let k = String::from_utf8_lossy(k);
            result.insert(k.into(), value);
            ParseControl::Continue
        }
        Err(err) => {
            parse_err = Err(err);
            ParseControl::Stop
        }
    })
    .and(parse_err)?;
    Ok(result)
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::utils::mmkv;

    #[test]
    fn test_read_u64() {
        let buffer = [0xff, 0x81, 0x01, 0x00];
        let value = mmkv::read_u64(&buffer);
        assert_eq!(value, Ok((&buffer[3..], 16639)));

        let buffer = [0x81, 0xAA];
        let value = mmkv::read_u64(&buffer);
        assert_eq!(value, Err(mmkv::MMKVParseError::UnexpectedEof));

        let buffer = [0x80, 0x00, 0xff];
        let value = mmkv::read_u64(&buffer);
        assert_eq!(value, Ok((&buffer[2..], 0)));
    }

    #[test]
    fn test_read_container() {
        let buffer = [0x03, b'A', b'B', b'C', 0];
        let value = mmkv::read_container(&buffer);
        assert_eq!(value, Ok((&buffer[4..], &b"ABC"[..])));

        let buffer = [0x00, b'A', b'B', b'C', 0];
        let value = mmkv::read_container(&buffer);
        assert_eq!(value, Ok((&buffer[1..], &b""[..])));
    }

    #[test]
    fn test_parse() {
        let buffer = [
            0x03, b'A', b'B', b'C', 0, //
            0x03, b'D', b'E', b'F', //
            0x05, 0x04, b'1', b'2', b'3', b'4',
        ];
        let value = mmkv::parse(&buffer);
        let mut map = HashMap::new();
        map.insert(&b"ABC"[..], &b""[..]);
        map.insert(&b"DEF"[..], &b"\x041234"[..]);
        assert_eq!(value, Ok(map));
    }
}
