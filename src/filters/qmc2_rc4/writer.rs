use std::io::{ErrorKind, Write};

use super::QMC2RC4;

pub struct QMC2RC4Writer<'a, W>
where
    W: Write,
{
    crypto: QMC2RC4,
    writer: &'a mut W,
}

impl<'a, W> QMC2RC4Writer<'a, W>
where
    W: Write,
{
    pub fn new(crypto: QMC2RC4, next_writer: &'a mut W) -> Self {
        Self {
            crypto,
            writer: next_writer,
        }
    }
}

impl<W> Write for QMC2RC4Writer<'_, W>
where
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut dst = buf.to_vec();
        self.crypto
            .transform(&mut dst)
            .map_err(|err| std::io::Error::new(ErrorKind::Other, err))?;
        self.writer.write(&dst)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
