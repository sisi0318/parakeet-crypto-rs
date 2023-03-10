mod base;
pub use base::{KGMCrypto, KGMCryptoConfig};

pub mod file_constants;
pub mod file_header;

mod crypto;
pub(self) use crypto::{KGMCryptoType2, KGMCryptoType3, KGMCryptoType4};

mod crypto_factory;
pub use crypto_factory::{create_kgm_decryptor, create_kgm_encryptor};

mod reader_decrypt;
pub use reader_decrypt::KugouDecryptReader;

mod reader_encrypt;
pub use reader_encrypt::KugouEncryptReader;

#[cfg(test)]
mod test;
