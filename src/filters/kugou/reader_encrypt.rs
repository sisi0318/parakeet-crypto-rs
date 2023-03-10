use std::io::Read;

use crate::interfaces::DecryptorError;

use super::{create_kgm_encryptor, file_header::KGMHeader, KGMCrypto, KGMCryptoConfig};

pub struct KugouEncryptReader<'a, R>
where
    R: Read,
{
    crypto: Box<dyn KGMCrypto>,
    source: &'a mut R,
    offset: u64,
    header: Vec<u8>,
}

impl<'a, R> KugouEncryptReader<'a, R>
where
    R: Read,
{
    pub fn new(
        config: &KGMCryptoConfig,
        header: &KGMHeader,
        prev_reader: &'a mut R,
    ) -> Result<Self, DecryptorError> {
        let mut header = *header;
        let crypto = create_kgm_encryptor(&mut header, config)?;

        Ok(Self {
            crypto,
            source: prev_reader,
            offset: 0,
            header: header.to_bytes(),
        })
    }
}

impl<R> Read for KugouEncryptReader<'_, R>
where
    R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut processed_len = 0;
        let mut buf = buf;

        if !self.header.is_empty() {
            let header_len = std::cmp::min(buf.len(), self.header.len());
            for (i, value) in self.header.drain(..header_len).enumerate() {
                buf[i] = value;
            }
            buf = &mut buf[header_len..];
            processed_len += header_len;
        }

        {
            let bytes_read = self.source.read(buf)?;
            processed_len += bytes_read;
            self.crypto.encrypt(self.offset, &mut buf[..bytes_read]);
            self.offset += bytes_read as u64;
        }

        Ok(processed_len)
    }
}
