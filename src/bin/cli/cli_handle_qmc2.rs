use std::{fs::File, process};

use argh::FromArgs;
use parakeet_crypto::filters::{QMC2Map, QMC2Reader, QMCFooterParser, QMC2RC4};

use crate::cli::logger::CliLogger;

use super::utils::{CliBinaryArray, CliFilePath};

/// Handle QMC2 File.
#[derive(Debug, Eq, PartialEq, FromArgs)]
#[argh(subcommand, name = "qmc2")]
pub struct QMC2Options {
    /// embed key decryption seed.
    #[argh(option)]
    seed: u8,

    /// mix key 1 (aka stage 1 key) for EncV2.
    #[argh(option)]
    key1: Option<CliBinaryArray<16>>,

    /// mix key 2 (aka stage 2 key) for EncV2.
    #[argh(option)]
    key2: Option<CliBinaryArray<16>>,

    /// input file path.
    #[argh(positional)]
    input_file: CliFilePath,

    /// output file path.
    #[argh(positional)]
    output_file: CliFilePath,
}

pub fn cli_handle_qmc2(args: QMC2Options) {
    let log = CliLogger::new("QMC2");

    let mut parser = QMCFooterParser::new(args.seed);

    if let Some(key1) = args.key1 {
        parser.set_key_stage1(key1.content);
        log.info("(EncV2) Stage 1 key accepted.");
    }

    if let Some(key2) = args.key2 {
        parser.set_key_stage2(key2.content);
        log.info("(EncV2) Stage 2 key accepted.");
    }

    if args.input_file.path == args.output_file.path {
        log.error("Decrypt the file in-place will not work.");
        process::exit(1);
    }

    let mut src = File::open(args.input_file.path).unwrap();
    let mut dst = File::create(args.output_file.path).unwrap();

    let mut qmc2_map = QMC2Map::new_default();
    let mut qmc2_rc4 = QMC2RC4::new_default();

    let mut qmc2_reader = QMC2Reader::new(&mut parser, &mut qmc2_map, &mut qmc2_rc4, &mut src)
        .unwrap_or_else(|err| {
            log.error(&format!("init qmc2 reader failed: {err}"));
            process::exit(1)
        });

    std::io::copy(&mut qmc2_reader, &mut dst).unwrap_or_else(|err| {
        log.error(&format!("transform failed: {err}"));
        process::exit(1)
    });

    log.info("Decryption OK.");
}
