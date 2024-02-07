use std::fs::File;

use argh::FromArgs;

use parakeet_crypto::crypto::tencent::QMCv1;

use crate::cli::cli_error::ParakeetCliError;
use crate::cli::utils::decrypt_file_stream;
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

    let bytes_written = decrypt_file_stream(&log, QMCv1, &mut dst, &mut src, 0, None)?;
    log.info(format!("decrypt: done, written {} bytes", bytes_written));

    Ok(())
}
