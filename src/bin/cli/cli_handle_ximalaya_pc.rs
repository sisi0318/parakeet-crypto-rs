use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use argh::FromArgs;

use parakeet_crypto::crypto::ximalaya_pc;

use crate::cli::cli_error::ParakeetCliError;
use crate::cli::logger::CliLogger;
use crate::cli::utils::CliFilePath;

/// Handle Ximalaya PC encryption/decryption.
#[derive(Debug, Eq, PartialEq, FromArgs)]
#[argh(subcommand, name = "ximalaya-pc")]
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

    let mut buffer = vec![0u8; 1024];
    src.read_exact(&mut buffer)
        .map_err(ParakeetCliError::SourceIoError)?;

    let hdr = match ximalaya_pc::Header::from_bytes(&buffer) {
        // in case our buffer was too small...
        Err(ximalaya_pc::Error::InputTooSmall(n, _)) => {
            buffer.resize(n, 0);

            src.seek(SeekFrom::Start(0))
                .and_then(|_| src.read_exact(&mut buffer))
                .map_err(ParakeetCliError::SourceIoError)?;
            ximalaya_pc::Header::from_bytes(&buffer)?
        }
        res => res?,
    };

    log.debug(format!(
        "cipher: len(stolen_bytes)={}, cipher_len={}, data_start={}",
        hdr.stolen_header_bytes.len(),
        hdr.encrypted_header_len,
        hdr.data_start_offset,
    ));

    // read encrypted part 2 data, and decrypt it
    buffer.resize(hdr.encrypted_header_len, 0);
    src.seek(SeekFrom::Start(hdr.data_start_offset as u64))
        .and_then(|_| src.read_exact(&mut buffer))
        .map_err(ParakeetCliError::SourceIoError)?;
    let decrypted_part_2 = ximalaya_pc::decipher_part_2(&hdr, &buffer)?;

    // write all parts to dst.
    dst.write_all(&hdr.stolen_header_bytes)
        .and_then(|_| dst.write_all(&decrypted_part_2))
        .and_then(|_| std::io::copy(&mut src, &mut dst))
        .map_err(ParakeetCliError::DestinationIoError)?;

    let bytes_written = dst
        .stream_position()
        .map_err(ParakeetCliError::DestinationIoError)?;
    log.info(format!("decrypt: done, written {} bytes", bytes_written));

    Ok(())
}
