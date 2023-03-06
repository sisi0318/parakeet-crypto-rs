use std::fs::File;

use argh::FromArgs;
use parakeet_crypto::filters::{QMC1Static, QMC1StaticReader};

use super::{
    logger::CliLogger,
    utils::{CliBinaryContent, CliFilePath},
};

/// Handle QMC1 File.
#[derive(Debug, Eq, PartialEq, FromArgs)]
#[argh(subcommand, name = "qmc1")]
pub struct QMC1Options {
    /// static key for QMC1 decryption.
    #[argh(option)]
    static_key: CliBinaryContent,

    /// input file name/path
    #[argh(positional)]
    input_file: CliFilePath,

    /// output file name/path
    #[argh(positional)]
    output_file: CliFilePath,
}

pub fn cli_handle_qmc1(args: QMC1Options) {
    let log = CliLogger::new("QMC1");

    let qmc1 = match args.static_key.content.len() {
        128 => QMC1Static::new(args.static_key.content[..].try_into().unwrap()),
        256 => QMC1Static::new_key256(args.static_key.content[..].try_into().unwrap()),
        _ => {
            log.error("key rejected -- invalid length");
            return;
        }
    };

    log.info(&format!(
        "Static key accepted (key{})",
        args.static_key.content.len()
    ));

    let mut src = File::open(args.input_file.path).unwrap();
    let mut reader = QMC1StaticReader::new(qmc1, &mut src);
    let mut dst = File::create(args.output_file.path).unwrap();
    std::io::copy(&mut reader, &mut dst).unwrap();

    log.info("Decryption OK.");
}
