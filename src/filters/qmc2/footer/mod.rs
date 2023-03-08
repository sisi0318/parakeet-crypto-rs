mod android;
mod guess_type;
mod pc;

mod parser;
pub use parser::QMCFooterParser;

mod decrypt_key;
use decrypt_key::QMCFooterKeyDecryptor;
