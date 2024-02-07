use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use argh::FromArgs;
use parakeet_crypto::crypto::kuwo::{header, Kuwo};
use parakeet_crypto::crypto::tencent::ekey;

use crate::cli::cli_error::ParakeetCliError;
use crate::cli::utils::{decrypt_file_stream, QMCKeyType};

use super::{
    logger::CliLogger,
    utils::{CliBinaryContent, CliFilePath},
};

// TODO: Add support to read from mmkv store.

/// Handle Kuwo KWMv1 & KWMv2 files.
#[derive(Debug, Eq, PartialEq, FromArgs)]
#[argh(subcommand, name = "kuwo")]
pub struct Options {
    /// kwm_v2: encryption key
    #[argh(option, short = 'k')]
    key: Option<CliBinaryContent>,

    /// kwm_v2: encryption key type, default to "ekey".
    #[argh(option, short = 't', default = "QMCKeyType::EKey")]
    key_type: QMCKeyType,

    /// input file name/path
    #[argh(option, short = 'i', long = "input")]
    input_file: CliFilePath,

    /// output file name/path
    #[argh(option, short = 'o', long = "output")]
    output_file: CliFilePath,
}

pub fn handle(args: Options) -> Result<(), ParakeetCliError> {
    let log = CliLogger::new("KWM");

    let mut src = File::open(args.input_file.path).map_err(ParakeetCliError::SourceIoError)?;
    let mut dst =
        File::create(args.output_file.path).map_err(ParakeetCliError::DestinationIoError)?;

    // Parse header
    let mut header_buf = [0u8; header::HEADER_PARSE_REQUIRED_LEN];
    src.read(&mut header_buf)
        .map_err(ParakeetCliError::SourceIoError)?;
    src.seek(SeekFrom::Start(header::HEADER_FIXED_LEN as u64))
        .map_err(ParakeetCliError::SourceIoError)?;

    let hdr = header::KuwoHeader::from_bytes(header_buf)?;
    log.info(format!(
        "kwm(version={}, resource_id={}, quality_id={})",
        hdr.version,
        hdr.resource_id,
        hdr.get_quality_id()
    ));

    let key = args
        .key
        .map(|user_key| match args.key_type {
            QMCKeyType::Key => Ok(user_key.content),
            QMCKeyType::EKey => {
                ekey::decrypt(user_key.content).map_err(ParakeetCliError::QMCKeyDecryptionError)
            }
        })
        .transpose()?;

    #[cfg(debug_assertions)]
    if let Some(key_inner) = &key {
        log.debug(format!("key accepted (key_len={})", key_inner.len()));
    }

    let cipher = Kuwo::from_header(&hdr, key)?;

    let bytes_written = decrypt_file_stream(&log, cipher, &mut dst, &mut src, 0, None)?;
    log.info(format!("decrypt: done, written {} bytes", bytes_written));

    Ok(())
}
