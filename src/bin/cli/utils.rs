use std::io::{Read, Write};
use std::{fs, path::Path};

use argh::FromArgValue;
use base64::{engine::general_purpose::STANDARD as Base64, Engine as _};

use parakeet_crypto::crypto::byte_offset_cipher::ByteOffsetDecipher;

use crate::cli::cli_error::ParakeetCliError;
use crate::cli::logger::CliLogger;

pub const DECRYPTION_BUFFER_SIZE: usize = 2 * 1024 * 1024;

pub fn parse_binary_data_from_string(value: &str) -> Option<Box<[u8]>> {
    if let Some(value) = value.strip_prefix('@') {
        Some(fs::read(Path::new(value)).ok()?.into())
    } else if let Some(value) = value.strip_prefix("base64:") {
        Some(Base64.decode(value).ok()?.into())
    } else if let Some(value) = value.strip_prefix("hex:") {
        Some(hex::decode(value.replace(' ', "")).ok()?.into())
    } else if let Some(value) = value.strip_prefix("raw:") {
        Some(value.as_bytes().into())
    } else if !value.is_empty() {
        Some(value.as_bytes().into())
    } else {
        None
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct CliBinaryContent {
    pub content: Box<[u8]>,
}

impl FromArgValue for CliBinaryContent {
    fn from_arg_value(value: &str) -> Result<Self, String> {
        if let Some(parsed) = parse_binary_data_from_string(value) {
            Ok(Self { content: parsed })
        } else {
            Err(String::from("could not parse"))
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct CliBinaryArray<const SIZE: usize> {
    pub content: [u8; SIZE],
}

impl<const SIZE: usize> FromArgValue for CliBinaryArray<SIZE> {
    fn from_arg_value(value: &str) -> Result<Self, String> {
        if let Some(parsed) = parse_binary_data_from_string(value) {
            if parsed.len() == SIZE {
                let mut buffer = [0u8; SIZE];
                buffer.copy_from_slice(&parsed);
                Ok(Self { content: buffer })
            } else {
                Err(format!(
                    "parameter size mismatch, expected {} bytes, got {}",
                    SIZE,
                    parsed.len()
                ))
            }
        } else {
            Err(String::from("could not binary data"))
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct CliFilePath {
    pub path: Box<Path>,
}

impl FromArgValue for CliFilePath {
    fn from_arg_value(value: &str) -> Result<Self, String> {
        Ok(Self {
            path: Box::from(Path::new(value)),
        })
    }
}

pub fn decrypt_file_stream<C, R, W>(
    log: &CliLogger,
    cipher: C,
    writer: &mut W,
    reader: &mut R,
    offset: usize,
    len: Option<usize>,
) -> Result<usize, ParakeetCliError>
where
    C: ByteOffsetDecipher,
    R: Read + ?Sized,
    W: Write + ?Sized,
{
    let mut buffer = vec![0u8; DECRYPTION_BUFFER_SIZE];
    let mut dst_write_error = Ok(());
    let bytes_written = cipher
        .decipher_stream_ex(&mut buffer, offset, reader, len, |block| {
            log.debug(format!("decrypt: process {} bytes", block.len()));
            dst_write_error = writer
                .write_all(block)
                .map_err(ParakeetCliError::DestinationIoError);

            dst_write_error.as_ref().into()
        })
        .map_err(ParakeetCliError::SourceIoError)?;
    dst_write_error?;
    Ok(bytes_written)
}
