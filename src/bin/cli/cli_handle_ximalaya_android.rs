use std::fs::File;
use std::io::{Read, Write};

use argh::{FromArgValue, FromArgs};

use parakeet_crypto::crypto::ximalaya;
use parakeet_crypto::crypto::ximalaya::keys::SCRAMBLED_HEADER_LEN;

use crate::cli::cli_error::ParakeetCliError;
use crate::cli::{logger::CliLogger, utils::CliFilePath};

#[derive(Debug, PartialEq, Copy, Clone)]
struct XimalayaType(ximalaya::keys::Type);

impl FromArgValue for XimalayaType {
    fn from_arg_value(value: &str) -> Result<Self, String> {
        match value.to_lowercase().as_str() {
            "x2m" => Ok(Self(ximalaya::keys::Type::X2M)),
            "x3m" => Ok(Self(ximalaya::keys::Type::X3M)),
            _ => Err("Invalid type".into()),
        }
    }
}

/// Handle x2m/x3m encryption/decryption.
#[derive(Debug, PartialEq, FromArgs)]
#[argh(subcommand, name = "ximalaya-android")]
pub struct XimalayaAndroidOptions {
    /// x2m / x3m key. Accepted values are "x2m" and "x3m".
    #[argh(option, short = 't', long = "type")]
    key_type: XimalayaType,

    /// input file name/path
    #[argh(option, short = 'i', long = "input")]
    input: CliFilePath,

    /// output file name/path
    #[argh(option, short = 'o', long = "output")]
    output: CliFilePath,
}

pub fn cli_handle_ximalaya_android(args: XimalayaAndroidOptions) -> Result<(), ParakeetCliError> {
    let log = CliLogger::new("Ximalaya (Android)");

    let mut src = File::open(args.input.path).map_err(ParakeetCliError::SourceIoError)?;
    let mut dst = File::create(args.output.path).map_err(ParakeetCliError::DestinationIoError)?;

    let mut hdr = [0u8; SCRAMBLED_HEADER_LEN];
    src.read_exact(&mut hdr)
        .map_err(ParakeetCliError::SourceIoError)?;

    let (content_key, scramble_table) = ximalaya::keys::get_key(args.key_type.0);
    let hdr = ximalaya::decrypt_header(&hdr, content_key, scramble_table);

    dst.write_all(&hdr)
        .map_err(ParakeetCliError::DestinationIoError)?;
    std::io::copy(&mut src, &mut dst).map_err(ParakeetCliError::DestinationIoError)?;

    log.info("Decryption OK.");
    Ok(())
}
