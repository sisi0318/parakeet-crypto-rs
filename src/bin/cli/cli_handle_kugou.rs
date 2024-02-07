use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use argh::FromArgs;

use parakeet_crypto::crypto::kugou;

use crate::cli::cli_error::ParakeetCliError;
use crate::cli::logger::CliLogger;
use crate::cli::utils::{decrypt_file_stream, CliFilePath};

/// Handle Kugou encryption/decryption.
#[derive(Debug, Eq, PartialEq, FromArgs)]
#[argh(subcommand, name = "kugou")]
pub struct Options {
    /// input file name/path
    #[argh(option, short = 'i', long = "input")]
    input_file: CliFilePath,

    /// output file name/path
    #[argh(option, short = 'o', long = "output")]
    output_file: CliFilePath,
}

pub fn handle(args: Options) -> Result<(), ParakeetCliError> {
    let log = CliLogger::new("Kugou");

    let mut src = File::open(args.input_file.path).map_err(ParakeetCliError::SourceIoError)?;
    let mut dst =
        File::create(args.output_file.path).map_err(ParakeetCliError::DestinationIoError)?;

    let mut hdr_bytes = vec![0u8; 1024];
    src.read_exact(&mut hdr_bytes)
        .map_err(ParakeetCliError::SourceIoError)?;
    let hdr = kugou::Header::from_bytes(hdr_bytes)
        .map_err(ParakeetCliError::KugouHeaderDeserializeError)?;
    log.debug(format!(
        "header: crypto=v{}, hdr_len={}, key_slot={}",
        hdr.crypto_version, hdr.header_len, hdr.key_slot
    ));
    let cipher = kugou::CipherModes::new(&hdr)?;

    src.seek(SeekFrom::Start(hdr.header_len.into()))
        .map_err(ParakeetCliError::SourceIoError)?;

    let bytes_written = decrypt_file_stream(&log, cipher, &mut dst, &mut src, 0, None)?;
    log.info(format!("decrypt: done, written {} bytes", bytes_written));

    Ok(())
}
