use std::io::{ErrorKind, Read, Write};

use crate::{interfaces::DecryptorError, utils::xor_helper};

const CIPHER_PAGE_SIZE: usize = 0x7fff;
const INDEX_OFFSET: usize = 80923 % 256;

#[derive(Debug)]
pub struct QMC1Static {
    offset: usize,
    key: [u8; 128],
}

impl QMC1Static {
    pub fn new(key: &[u8; 128]) -> Self {
        Self {
            offset: 0,
            key: *key,
        }
    }

    pub fn new_key256(long_key: &[u8; 256]) -> Self {
        let mut key128 = [0u8; 128];

        for (i, key) in key128.iter_mut().enumerate() {
            *key = long_key[(i * i + INDEX_OFFSET) % long_key.len()];
        }

        Self::new(&key128)
    }

    pub fn transform(&mut self, dst: &mut [u8], src: &[u8]) -> Result<usize, DecryptorError> {
        let offset = self.offset;
        xor_helper::xor_block_from_offset(dst, src, CIPHER_PAGE_SIZE, &self.key, offset)?;

        // Off-by-1 fix at the first page.
        if CIPHER_PAGE_SIZE >= offset && CIPHER_PAGE_SIZE - offset < src.len() {
            let boundary_index = CIPHER_PAGE_SIZE - offset;
            dst[boundary_index] = src[boundary_index] ^ self.key[CIPHER_PAGE_SIZE % self.key.len()];
        }

        self.offset += src.len();
        Ok(src.len())
    }
}

pub struct QMC1StaticReader<'a, R>
where
    R: Read,
{
    crypto: QMC1Static,
    reader: &'a mut R,
}

impl<'a, R> QMC1StaticReader<'a, R>
where
    R: Read,
{
    pub fn new(crypto: QMC1Static, prev_reader: &'a mut R) -> Self {
        Self {
            crypto,
            reader: prev_reader,
        }
    }
}

impl<R> Read for QMC1StaticReader<'_, R>
where
    R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut src = vec![0xffu8; buf.len()];
        let read_amount = self.reader.read(&mut src)?;

        self.crypto
            .transform(buf, &src[..read_amount])
            .map_err(|err| std::io::Error::new(ErrorKind::Other, err))
    }
}

pub struct QMC1StaticWriter<'a, W>
where
    W: Write,
{
    crypto: QMC1Static,
    writer: &'a mut W,
}

impl<'a, W> QMC1StaticWriter<'a, W>
where
    W: Write,
{
    pub fn new(crypto: QMC1Static, next_writer: &'a mut W) -> Self {
        Self {
            crypto,
            writer: next_writer,
        }
    }
}

impl<W> Write for QMC1StaticWriter<'_, W>
where
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut dst = vec![0xffu8; buf.len()];
        self.crypto
            .transform(&mut dst[..], buf)
            .map_err(|err| std::io::Error::new(ErrorKind::Other, err))?;
        self.writer.write(&dst)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
