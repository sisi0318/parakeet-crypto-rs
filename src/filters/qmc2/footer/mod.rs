mod guess_type;
pub use guess_type::{guess_type, ClientType};

mod android;
pub use android::parse_footer_qtag;

mod pc;
pub use pc::parse_footer_pc;

mod parser;
pub use parser::QMCFooterParser;

mod decrypt_key;
use decrypt_key::QMCFooterKeyDecryptor;

#[cfg(test)]
pub(super) use decrypt_key::make_simple_key;
