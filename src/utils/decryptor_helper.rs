use crate::interfaces::{Decryptor, DecryptorError, StreamDecryptor};
use std::io::{Read, Seek, SeekFrom, Write};

pub fn decrypt_full_stream<D, R, W>(
    decryptor: &mut D,
    from: &mut R,
    to: &mut W,
    opt_reserve_len: Option<usize>,
) -> Result<(), DecryptorError>
where
    D: StreamDecryptor + ?Sized,
    R: Read + Seek,
    W: Write,
{
    let mut buf_dst = [0u8; 4096 * 2];
    let mut buf_src = [0u8; 4096];

    let file_len = from.seek(SeekFrom::End(0))? as usize - opt_reserve_len.unwrap_or(0);
    let leftover_len = file_len % buf_src.len();
    let whole_block_len = file_len - leftover_len;

    // Move back to the beginning of the stream.
    from.rewind()?;

    for _ in (0..whole_block_len).step_by(buf_src.len()) {
        from.read_exact(&mut buf_src)?;
        let decrypted_len = decryptor.decrypt_block(&mut buf_dst, &buf_src)?;
        to.write_all(&buf_dst[..decrypted_len])?;
    }

    if leftover_len > 0 {
        from.read_exact(&mut buf_src[..leftover_len])?;
        let decrypted_len = decryptor.decrypt_block(&mut buf_dst, &buf_src[..leftover_len])?;
        to.write_all(&buf_dst[..decrypted_len])?;
    }

    Ok(())
}

impl<T: StreamDecryptor> Decryptor for T {
    fn check<R>(&self, _from: &mut R) -> Result<(), DecryptorError>
    where
        R: Read + Seek,
    {
        Ok(()) // no check
    }

    fn decrypt<R, W>(&mut self, from: &mut R, to: &mut W) -> Result<(), DecryptorError>
    where
        R: Read + Seek,
        W: Write,
    {
        decrypt_full_stream(self, from, to, None)
    }
}
