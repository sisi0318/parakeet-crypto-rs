use std::io::{Read, Seek, Write};

use super::DecryptorError;

pub trait Decryptor {
    fn check<R>(&self, from: &mut R) -> Result<(), DecryptorError>
    where
        R: Read + Seek;

    fn decrypt<R, W>(&mut self, from: &mut R, to: &mut W) -> Result<(), DecryptorError>
    where
        R: Read + Seek,
        W: Write;
}

pub trait StreamDecryptor {
    fn decrypt_block(&mut self, dst: &mut [u8], src: &[u8]) -> Result<usize, DecryptorError>;
}
