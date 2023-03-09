use std::{fs::File, process};

use argh::FromArgs;
use parakeet_crypto::filters::{XimalayaCrypto, XimalayaReader, SCRAMBLE_HEADER_LEN};

use super::{
    logger::CliLogger,
    utils::{CliBinaryContent, CliFilePath},
};

/// Handle x2m/x3m encryption/decryption.
#[derive(Debug, PartialEq, FromArgs)]
#[argh(subcommand, name = "xmly")]
pub struct XimalayaOptions {
    /// scramble table (u16 x 1024 items, little-endian)
    /// when size mismatch, revert to generator.
    #[argh(option)]
    scramble_table: Option<CliBinaryContent>,

    /// initial value (scramble-table gen)
    #[argh(option)]
    mul_init: Option<f64>,

    /// step value (scramble-table gen)
    #[argh(option)]
    mul_step: Option<f64>,

    /// X2M/X3M key.
    /// 4-bytes = X2M
    /// 32-bytes = X3M
    #[argh(option)]
    key: CliBinaryContent,

    /// encrypt instead of decrypt.
    /// default to decrypt.
    #[argh(switch)]
    encrypt: bool,

    /// input file path.
    #[argh(positional)]
    input_file: CliFilePath,

    /// output file path.
    #[argh(positional)]
    output_file: CliFilePath,
}

pub fn cli_handle_xmly(args: XimalayaOptions) {
    let log = CliLogger::new("XMLY");

    let xmly_crypto = if let Some(scramble_table_arg) = args.scramble_table {
        let scramble_table_bin = scramble_table_arg.content;
        if scramble_table_bin.len() != SCRAMBLE_HEADER_LEN * 2 {
            log.error(&format!(
                "expecting scramble-table to have a size of {} but got {} instead.",
                SCRAMBLE_HEADER_LEN * 2,
                scramble_table_bin.len()
            ));
            process::exit(1);
        }

        log.info("using scramble-table for xmly.");

        let mut scramble_table = [0u16; SCRAMBLE_HEADER_LEN];
        let mut buffer = [0u8; 2];
        for (i, item) in scramble_table.iter_mut().enumerate() {
            buffer.copy_from_slice(&scramble_table_bin[i * 2..i * 2 + 2]);
            *item = u16::from_le_bytes(buffer);
        }
        XimalayaCrypto::new(&args.key.content, &scramble_table)
    } else if args.mul_init.is_some() && args.mul_step.is_some() {
        XimalayaCrypto::new_from_param(
            &args.key.content,
            args.mul_init.unwrap(),
            args.mul_step.unwrap(),
        )
    } else {
        log.error("you should specify (--scramble-table) or (--mul-init, --mul-step).");
        process::exit(1);
    };

    let operation = match args.encrypt {
        true => "Encryption",
        false => "Decryption",
    };

    let mut input_file = File::open(args.input_file.path).unwrap();
    let mut output_file = File::create(args.output_file.path).unwrap();

    let mut xmly_reader = match args.encrypt {
        true => XimalayaReader::new_encrypt(xmly_crypto, &mut input_file),
        false => XimalayaReader::new_decrypt(xmly_crypto, &mut input_file),
    };

    std::io::copy(&mut xmly_reader, &mut output_file).unwrap_or_else(|err| {
        log.error(&format!("{operation} failed: {err}"));
        process::exit(1)
    });

    log.info(&format!("{} OK.", operation));
}
