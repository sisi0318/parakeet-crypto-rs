use crate::interfaces::DecryptorError;

pub trait QMC2Crypto {
    fn set_file_key(&mut self, key: &[u8]) -> Result<(), DecryptorError>;
    fn get_offset(&self) -> usize;
    fn transform(&mut self, dst: &mut [u8]) -> Result<usize, DecryptorError>;
}
