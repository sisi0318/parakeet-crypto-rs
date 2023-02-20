use std::io::{Read, Seek, Write};

use crate::interfaces::{DecryptorError, StreamDecryptor};

const SCRAMBLE_HEADER_LEN: usize = 1024;

#[derive(Debug, Clone, Copy)]
pub struct XimalayaCrypto {
    offset: usize,
    content_key: [u8; 32],
    scramble_table: [usize; SCRAMBLE_HEADER_LEN],
    header_buffer: [u8; SCRAMBLE_HEADER_LEN],
}

pub fn process_ximalaya_file<F, R, W>(
    from: &mut R,
    to: &mut W,
    handler: F,
) -> Result<(), std::io::Error>
where
    F: FnOnce(&[u8; 1024]) -> [u8; 1024],
    R: Read + Seek,
    W: Write,
{
    let mut header = [0u8; 1024];

    from.rewind()?;
    from.read_exact(&mut header)?;

    let header = handler(&header);
    to.write_all(&header)?;

    std::io::copy(from, to)?;
    Ok(())
}

impl XimalayaCrypto {
    pub fn new(content_key: &[u8; 32], scramble_table: &[usize; SCRAMBLE_HEADER_LEN]) -> Self {
        Self {
            offset: 0,
            content_key: *content_key,
            scramble_table: *scramble_table,
            header_buffer: [0u8; SCRAMBLE_HEADER_LEN],
        }
    }

    pub fn decrypt_header(
        &self,
        encrypted: &[u8; SCRAMBLE_HEADER_LEN],
    ) -> [u8; SCRAMBLE_HEADER_LEN] {
        let mut decrypted = *encrypted;

        for (di, &ei) in self.scramble_table.iter().enumerate() {
            let key = self.content_key[di % self.content_key.len()];
            decrypted[di] = encrypted[ei] ^ key
        }

        decrypted
    }

    pub fn encrypt_header(
        &self,
        decrypted: &[u8; SCRAMBLE_HEADER_LEN],
    ) -> [u8; SCRAMBLE_HEADER_LEN] {
        let mut encrypted = *decrypted;
        let reverse_scramble_table = self.scramble_table;

        for (di, &ei) in reverse_scramble_table.iter().enumerate() {
            let key = self.content_key[di % self.content_key.len()];
            encrypted[ei] = decrypted[di] ^ key
        }

        encrypted
    }

    pub fn encrypt<R, W>(&self, from: &mut R, to: &mut W) -> Result<(), DecryptorError>
    where
        R: Read + Seek,
        W: Write,
    {
        process_ximalaya_file(from, to, |header| self.encrypt_header(header))?;
        Ok(())
    }
}

impl StreamDecryptor for XimalayaCrypto {
    fn decrypt_block(&mut self, dst: &mut [u8], src: &[u8]) -> Result<usize, DecryptorError> {
        let mut produce_len = 0usize;

        let input_len = src.len();
        let mut src = src;
        let mut dst = dst;

        let mut offset = self.offset;
        if offset < self.header_buffer.len() {
            // Copy data from source
            let copy_len = std::cmp::min(SCRAMBLE_HEADER_LEN - offset, input_len);
            self.header_buffer[offset..offset + copy_len].copy_from_slice(&src[..copy_len]);

            src = &src[copy_len..];
            offset += copy_len;
        }

        if offset == SCRAMBLE_HEADER_LEN {
            if dst.len() < SCRAMBLE_HEADER_LEN {
                return Err(DecryptorError::OutputBufferTooSmallWithHint(
                    produce_len + src.len(),
                ));
            }

            let header_buffer = self.header_buffer;
            dst[..SCRAMBLE_HEADER_LEN].copy_from_slice(&self.decrypt_header(&header_buffer));
            dst = &mut dst[SCRAMBLE_HEADER_LEN..];
            produce_len += SCRAMBLE_HEADER_LEN;
        }

        if dst.len() < src.len() {
            return Err(DecryptorError::OutputBufferTooSmallWithHint(
                produce_len + src.len(),
            ));
        }

        dst[..src.len()].copy_from_slice(src);
        produce_len += src.len();

        self.offset += input_len;
        Ok(produce_len)
    }
}
