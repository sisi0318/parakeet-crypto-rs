use std::io::Read;

use super::xmly_crypto::{XimalayaCrypto, SCRAMBLE_HEADER_LEN};

pub enum XimalayaMode {
    Encrypt,
    Decrypt,
}

pub struct XimalayaReader<'a, R>
where
    R: Read,
{
    crypto: XimalayaCrypto,
    reader: &'a mut R,
    mode: XimalayaMode,
    offset: usize,
    header: [u8; SCRAMBLE_HEADER_LEN],
}

impl<'a, R> XimalayaReader<'a, R>
where
    R: Read,
{
    pub fn new(crypto: XimalayaCrypto, mode: XimalayaMode, prev_reader: &'a mut R) -> Self {
        Self {
            crypto,
            reader: prev_reader,
            mode,
            offset: 0,
            header: [0u8; SCRAMBLE_HEADER_LEN],
        }
    }

    pub fn new_encrypt(crypto: XimalayaCrypto, prev_reader: &'a mut R) -> Self {
        Self::new(crypto, XimalayaMode::Encrypt, prev_reader)
    }

    pub fn new_decrypt(crypto: XimalayaCrypto, prev_reader: &'a mut R) -> Self {
        Self::new(crypto, XimalayaMode::Decrypt, prev_reader)
    }
}

impl<R> Read for XimalayaReader<'_, R>
where
    R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut processed_len = 0usize;
        if self.offset == 0 {
            self.reader.read_exact(&mut self.header)?;
            self.header = match self.mode {
                XimalayaMode::Encrypt => self.crypto.encrypt(&self.header),
                XimalayaMode::Decrypt => self.crypto.decrypt(&self.header),
            }
        }

        let mut buf = buf;
        if self.offset < SCRAMBLE_HEADER_LEN {
            let decrypt_len = std::cmp::min(SCRAMBLE_HEADER_LEN - self.offset, buf.len());
            let (decrypted_header, next_buff) = buf.split_at_mut(decrypt_len);
            decrypted_header.copy_from_slice(&self.header[self.offset..self.offset + decrypt_len]);
            buf = next_buff;
            self.offset += decrypt_len;
            processed_len += decrypt_len;
        }

        let read_len = self.reader.read(buf)?;
        self.offset += read_len;
        processed_len += read_len;

        Ok(processed_len)
    }
}
