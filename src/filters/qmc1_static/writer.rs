use std::io::{ErrorKind, Write};

use super::QMC1Static;

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
            .transform(&mut dst[..])
            .map_err(|err| std::io::Error::new(ErrorKind::Other, err))?;
        self.writer.write(&dst)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
