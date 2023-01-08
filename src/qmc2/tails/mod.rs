mod guess_type;
pub use guess_type::{guess_type, ClientType};

mod android;
pub use android::parse_tail_qtag;

mod pc;
pub use pc::parse_tail_pc;

mod parser;
pub use parser::QMCTailParser;

mod decrypt_key;
use decrypt_key::QMCTailKeyDecryptor;

#[cfg(test)]
pub(super) use decrypt_key::make_simple_key;
