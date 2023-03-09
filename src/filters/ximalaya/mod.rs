mod scramble_key;
pub use scramble_key::create_scramble_key;

mod xmly_crypto;
pub use xmly_crypto::{XimalayaCrypto, SCRAMBLE_HEADER_LEN};

mod reader;
pub use reader::XimalayaReader;

#[cfg(test)]
mod test;
