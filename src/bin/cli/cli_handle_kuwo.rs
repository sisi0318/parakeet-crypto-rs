use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

use argh::FromArgs;
use mmkv_parser::mmkv::ParseControl;

use parakeet_crypto::crypto::kuwo::{header, Kuwo};
use parakeet_crypto::crypto::tencent::ekey;
use parakeet_crypto::utils::validate::is_digits_str;

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

    /// path to the mmkv store
    #[argh(option, short = 'm', long = "mmkv")]
    mmkv_path: Option<PathBuf>,

    /// input file name/path
    #[argh(option, short = 'i', long = "input")]
    input_file: CliFilePath,

    /// output file name/path
    #[argh(option, short = 'o', long = "output")]
    output_file: CliFilePath,
}

fn find_key(
    log: &CliLogger,
    hdr: &header::KuwoHeader,
    mmkv_path: &PathBuf,
) -> Result<Option<Box<[u8]>>, ParakeetCliError> {
    let mut mmkv_data = Vec::with_capacity(4096);
    File::open(&mmkv_path)
        .map_err(|err| ParakeetCliError::OtherIoError(mmkv_path.clone(), err))?
        .read_to_end(&mut mmkv_data)
        .map_err(|err| ParakeetCliError::OtherIoError(mmkv_path.clone(), err))?;
    let needle = format!("sec_ekey#{}-{}", hdr.resource_id, hdr.get_quality_id());
    log.debug(format!("ekey search needle: {}", needle));
    let mut result = None;
    mmkv_parser::mmkv::parse_callback(&mmkv_data, |k, v| {
        if let Some(suffix) = k.strip_prefix(needle.as_bytes()) {
            if suffix.is_empty() || !is_digits_str(&suffix[..1]) {
                log.debug(format!("pick ekey from: {}", String::from_utf8_lossy(k)));
                result = Some(v);
            } else {
                log.debug(format!("ignore [{}]", String::from_utf8_lossy(k)));
            }
        }
        ParseControl::Continue
    })
    .map_err(ParakeetCliError::MMKVParseError)?;

    let result = match result {
        None => None,
        Some(mmkv_ekey) => {
            let (_, mmkv_ekey) = mmkv_parser::mmkv::read_container(mmkv_ekey)
                .map_err(ParakeetCliError::MMKVParseError)?;
            Some(ekey::decrypt(mmkv_ekey).map_err(ParakeetCliError::QMCKeyDecryptionError)?)
        }
    };

    Ok(result)
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

    // Key from cli has priority
    let key = match args.key {
        // we got a key, let's use it.
        Some(user_key) => match args.key_type {
            QMCKeyType::Key => Some(user_key.content),
            QMCKeyType::EKey => Some(
                ekey::decrypt(user_key.content).map_err(ParakeetCliError::QMCKeyDecryptionError)?,
            ),
        },
        // no key? try mmkv
        None => match args.mmkv_path {
            // no mmkv? ignore
            None => None,
            // try to find the ekey and get its decrypted form
            Some(mmkv_path) => find_key(&log, &hdr, &mmkv_path)?,
        },
    };

    #[cfg(debug_assertions)]
    if let Some(key_inner) = &key {
        log.debug(format!("key accepted (key_len={})", key_inner.len()));
    }

    let cipher = Kuwo::from_header(&hdr, key)?;

    let bytes_written = decrypt_file_stream(&log, cipher, &mut dst, &mut src, 0, None)?;
    log.info(format!("decrypt: done, written {} bytes", bytes_written));

    Ok(())
}
