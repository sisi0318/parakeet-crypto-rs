use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use crate::cli::cli_error::ParakeetCliError;
use crate::cli::logger::CliLogger;
use crate::cli::utils::{CliFilePath, DECRYPTION_BUFFER_SIZE};
use argh::FromArgs;
use parakeet_crypto::crypto::kugou;

/// Handle Kugou encryption/decryption.
#[derive(Debug, Eq, PartialEq, FromArgs)]
#[argh(subcommand, name = "kugou")]
pub struct KugouOptions {
    /// input file name/path
    #[argh(option, short = 'i', long = "input")]
    input_file: CliFilePath,

    /// output file name/path
    #[argh(option, short = 'o', long = "output")]
    output_file: CliFilePath,
}

pub fn cli_handle_kugou(args: KugouOptions) -> Result<(), ParakeetCliError> {
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

    let mut offset = 0usize;
    let mut buffer = vec![0u8; DECRYPTION_BUFFER_SIZE];
    loop {
        let n = src
            .read(&mut buffer)
            .map_err(ParakeetCliError::SourceIoError)?;
        if n == 0 {
            break;
        }
        log.debug(format!("decrypt: offset={}, n={}", offset, n));
        let mut block = &mut buffer[..n];
        cipher.decrypt(offset, &mut block);
        dst.write_all(&block)
            .map_err(ParakeetCliError::DestinationIoError)?;
        offset += n;
    }
    log.info("Decryption OK.");

    Ok(())
}
