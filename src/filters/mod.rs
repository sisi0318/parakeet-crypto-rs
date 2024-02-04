mod kugou;
pub use kugou::{
    file_constants, file_header, KGMCrypto, KGMCryptoConfig, KugouDecryptReader, KugouEncryptReader,
};

mod ximalaya;
pub use ximalaya::{create_scramble_key, XimalayaCrypto, XimalayaReader, SCRAMBLE_HEADER_LEN};
