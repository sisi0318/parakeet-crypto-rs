use std::cmp::min;
use std::fs::File;
use std::io::{Error, ErrorKind, Read, Seek, SeekFrom, Write};
use std::str::FromStr;

use argh::FromArgs;

use parakeet_crypto::crypto::tencent;
use parakeet_crypto::crypto::tencent::{ekey, QMCv2};

use crate::cli::cli_error::ParakeetCliError;
use crate::cli::utils::DECRYPTION_BUFFER_SIZE;

use super::{
    logger::CliLogger,
    utils::{CliBinaryContent, CliFilePath},
};

#[derive(Debug, Eq, PartialEq)]
enum QMCKeyType {
    EKey = 1,
    Key = 0,
}

impl FromStr for QMCKeyType {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ekey" => Ok(QMCKeyType::EKey),
            "key" => Ok(QMCKeyType::Key),
            _ => Err(Self::Err::new(ErrorKind::InvalidInput, "invalid key type")),
        }
    }
}

/// Handle QMCv2 File.
#[derive(Debug, Eq, PartialEq, FromArgs)]
#[argh(subcommand, name = "qmc2")]
pub struct QMC2Options {
    /// encryption key
    #[argh(option, short = 'k')]
    key: Option<CliBinaryContent>,

    /// key type, default to "ekey".
    /// when absent, this will attempt to extract from tail.
    #[argh(option, short = 't', default = "QMCKeyType::EKey")]
    key_type: QMCKeyType,

    /// number of bytes to trim off the tail.
    /// when key is provided, this will default to 0.
    /// when key is absent, this will auto-detect from tail.
    #[argh(option)]
    tail_trim: Option<i64>,

    /// input file name/path
    #[argh(option, short = 'i', long = "input")]
    input_file: CliFilePath,

    /// output file name/path
    #[argh(option, short = 'o', long = "output")]
    output_file: CliFilePath,
}

const TAIL_BUF_LEN: usize = 1024;

pub fn cli_handle_qmc2(args: QMC2Options) -> Result<(), ParakeetCliError> {
    let log = CliLogger::new("QMCv2");

    let mut src = File::open(args.input_file.path).map_err(ParakeetCliError::SourceIoError)?;
    let mut dst =
        File::create(args.output_file.path).map_err(ParakeetCliError::DestinationIoError)?;

    // Parse input file tail first
    let mut tail_buf = vec![0u8; TAIL_BUF_LEN].into_boxed_slice();
    src.seek(SeekFrom::End(-(TAIL_BUF_LEN as i64)))
        .map_err(ParakeetCliError::SourceIoError)?;
    src.read(&mut tail_buf)
        .map_err(ParakeetCliError::SourceIoError)?;
    let file_size = src
        .stream_position()
        .map_err(ParakeetCliError::SourceIoError)?;
    src.seek(SeekFrom::Start(0))
        .map_err(ParakeetCliError::SourceIoError)?;

    let tail_result = tencent::parse_tail(&tail_buf);

    let (key, tail_len) = match args.key {
        Some(user_key) => {
            let key = match args.key_type {
                QMCKeyType::Key => user_key.content,
                QMCKeyType::EKey => ekey::decrypt(user_key.content)
                    .map_err(ParakeetCliError::QMCKeyDecryptionError)?,
            };
            let tail_len = match args.tail_trim {
                Some(value) => value as usize,
                None => match tail_result {
                    Ok(m) => m.get_tail_len(),
                    _ => 0,
                },
            };
            (key, tail_len)
        }
        None => {
            let tail_result = tail_result.map_err(ParakeetCliError::QMCTailParseError)?;
            let tail_key = tail_result
                .get_key()
                .ok_or(ParakeetCliError::QMCKeyRequired)?;
            (Box::from(tail_key), tail_result.get_tail_len())
        }
    };

    log.info(&format!(
        "key accepted (key_len={}, tail_len={})",
        key.len(),
        tail_len
    ));

    let qmc2 = QMCv2::from_key(key);
    let mut buffer = vec![0u8; DECRYPTION_BUFFER_SIZE];
    let mut offset: usize = 0;
    let file_size = file_size as usize;
    let mut bytes_to_decrypt = file_size - tail_len;
    log.info("begin decryption...");
    while bytes_to_decrypt > 0 {
        let block_len = min(buffer.len(), bytes_to_decrypt);
        log.debug(format!(
            "decrypt: offset={}, bytes_to_decrypt={}, block_len={}, file_size={}",
            offset, bytes_to_decrypt, block_len, file_size
        ));

        let mut block = &mut buffer[..block_len];
        src.read_exact(block)
            .map_err(ParakeetCliError::SourceIoError)?;
        qmc2.decrypt(offset, &mut block);
        dst.write_all(block)
            .map_err(ParakeetCliError::DestinationIoError)?;
        offset += block_len;
        bytes_to_decrypt -= block_len;
    }
    log.info("Decryption OK.");
    Ok(())
}
