use std::{fs::File, io::copy, process};

use crate::cli::cli_error::ParakeetCliError;
use argh::FromArgs;
use parakeet_crypto::filters::{
    file_header::KGMHeader, KGMCryptoConfig, KugouDecryptReader, KugouEncryptReader,
};

use super::{
    logger::CliLogger,
    utils::{CliBinaryContent, CliFilePath},
};

/// Handle Kugou encryption/decryption.
#[derive(Debug, Eq, PartialEq, FromArgs)]
#[argh(subcommand, name = "kugou")]
pub struct KugouOptions {
    /// slot key 1 content.
    #[argh(option)]
    slot_key_1: CliBinaryContent,

    /// enable encrypt mode, with specified template header.
    /// signature will be re-generated for given key in the template.
    #[argh(option)]
    encrypt_header: Option<CliBinaryContent>,

    /// file key expansion table for encryption schema v4.
    #[argh(option)]
    v4_file_key_expansion_table: Option<CliBinaryContent>,

    /// slot key expansion table for encryption schema v4.
    #[argh(option)]
    v4_slot_key_expansion_table: Option<CliBinaryContent>,

    /// input file path.
    #[argh(positional)]
    input_file: CliFilePath,

    /// output file path.
    #[argh(positional)]
    output_file: CliFilePath,
}

pub fn cli_handle_kugou(args: KugouOptions) -> Result<(), ParakeetCliError> {
    let log = CliLogger::new("Kugou");

    let mut config = KGMCryptoConfig::default();

    if let Some(table) = args.v4_file_key_expansion_table {
        config.v4_file_key_expand_table = table.content.to_vec();
        log.info("(v4) file key expansion table accepted.");
    }

    if let Some(table) = args.v4_slot_key_expansion_table {
        config.v4_slot_key_expand_table = table.content.to_vec();
        log.info("(v4) slot key expansion table accepted.");
    }

    // Configure key slots
    config.slot_keys.insert(1, args.slot_key_1.content.to_vec());

    let mut input_file = File::open(args.input_file.path).unwrap();
    let mut output_file = File::create(args.output_file.path).unwrap();

    let operation = if args.encrypt_header.is_some() {
        "Encryption"
    } else {
        "Decryption"
    };

    if let Some(encrypt_header) = args.encrypt_header {
        let header = KGMHeader::from_bytes(&encrypt_header.content).unwrap_or_else(|err| {
            log.error(&format!("Could not parse header: {:?}", err));
            process::exit(1)
        });

        let mut kgm_reader = KugouEncryptReader::new(&config, &header, &mut input_file).unwrap();
        copy(&mut kgm_reader, &mut output_file)
    } else {
        let mut kgm_reader = KugouDecryptReader::new(&config, &mut input_file).unwrap();
        copy(&mut kgm_reader, &mut output_file)
    }
    .unwrap_or_else(|err| {
        log.error(&format!("{operation} failed: {err}"));
        process::exit(1)
    });

    log.info(&format!("{} OK.", operation));
    Ok(())
}
