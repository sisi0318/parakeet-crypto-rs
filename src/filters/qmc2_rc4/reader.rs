use std::io::{ErrorKind, Read};

use super::QMC2RC4;

pub struct QMC2RC4Reader<'a, R>
where
    R: Read,
{
    crypto: QMC2RC4,
    reader: &'a mut R,
}

impl<'a, R> QMC2RC4Reader<'a, R>
where
    R: Read,
{
    pub fn new(crypto: QMC2RC4, prev_reader: &'a mut R) -> Self {
        Self {
            crypto,
            reader: prev_reader,
        }
    }
}

impl<R> Read for QMC2RC4Reader<'_, R>
where
    R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read_amount = self.reader.read(buf)?;

        self.crypto
            .transform(&mut buf[..read_amount])
            .map_err(|err| std::io::Error::new(ErrorKind::Other, err))
    }
}
