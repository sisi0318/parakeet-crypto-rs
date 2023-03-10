use std::io::{Read, Seek, SeekFrom};

use crate::interfaces::DecryptorError;

use super::{create_kgm_decryptor, file_header::KGMHeader, KGMCrypto, KGMCryptoConfig};

pub struct KugouDecryptReader<'a, R>
where
    R: Read,
{
    crypto: Box<dyn KGMCrypto>,
    source: &'a mut R,
    offset: u64,
}

impl<'a, R> KugouDecryptReader<'a, R>
where
    R: Read + Seek,
{
    pub fn new(config: &KGMCryptoConfig, prev_reader: &'a mut R) -> Result<Self, DecryptorError> {
        let header = KGMHeader::from_reader(prev_reader)?;
        let crypto = create_kgm_decryptor(&header, config)?;
        prev_reader.seek(SeekFrom::Start(header.offset_to_data.into()))?;

        Ok(Self {
            crypto,
            source: prev_reader,
            offset: 0,
        })
    }
}

impl<R> Read for KugouDecryptReader<'_, R>
where
    R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes_read = self.source.read(buf)?;
        self.crypto.decrypt(self.offset, &mut buf[..bytes_read]);
        self.offset += buf.len() as u64;
        Ok(bytes_read)
    }
}
