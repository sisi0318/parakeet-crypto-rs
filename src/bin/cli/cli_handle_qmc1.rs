use std::fs::File;
use std::io::{Read, Write};

use argh::FromArgs;

use parakeet_crypto::crypto::tencent::decrypt_qmc1;

use crate::cli::cli_error::ParakeetCliError;
use crate::cli::utils::DECRYPTION_BUFFER_SIZE;
use crate::cli::{logger::CliLogger, utils::CliFilePath};

/// Handle QMC1 File.
#[derive(Debug, Eq, PartialEq, FromArgs)]
#[argh(subcommand, name = "qmc1")]
pub struct QMC1Options {
    /// input file name/path
    #[argh(option, short = 'i', long = "input")]
    input_file: CliFilePath,

    /// output file name/path
    #[argh(option, short = 'o', long = "output")]
    output_file: CliFilePath,
}

pub fn cli_handle_qmc1(args: QMC1Options) -> Result<(), ParakeetCliError> {
    let log = CliLogger::new("QMCv1");

    let mut src = File::open(args.input_file.path).map_err(ParakeetCliError::SourceIoError)?;
    let mut dst =
        File::create(args.output_file.path).map_err(ParakeetCliError::DestinationIoError)?;

    let mut buffer = vec![0u8; DECRYPTION_BUFFER_SIZE];
    let mut offset = 0usize;
    loop {
        let n = src
            .read(&mut buffer)
            .map_err(ParakeetCliError::SourceIoError)?;
        if n == 0 {
            break;
        }
        log.debug(format!("decrypt: offset={}, n={}", offset, n));
        decrypt_qmc1(offset, &mut buffer[..n]);
        dst.write_all(&buffer[..n])
            .map_err(ParakeetCliError::DestinationIoError)?;
        offset += n;
    }

    log.info("Decryption OK.");
    Ok(())
}
