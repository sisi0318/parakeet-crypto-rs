use crate::crypto::byte_offset_cipher::{ByteOffsetDecipher, ByteOffsetEncipher};

#[derive(Debug, Eq, PartialEq, Copy, Clone, Default)]
pub struct QMCv1;

const QMC1_TABLE: &[u8; 128] = include_bytes!("./qmc1.bin");

impl ByteOffsetDecipher for QMCv1 {
    fn decipher_byte(&self, offset: usize, datum: u8) -> u8 {
        datum ^ super::map_l(QMC1_TABLE, offset)
    }
}

impl ByteOffsetEncipher for QMCv1 {
    fn encipher_byte(&self, offset: usize, datum: u8) -> u8 {
        self.decipher_byte(offset, datum)
    }
}

pub fn decrypt_qmc1<T: AsMut<[u8]>>(offset: usize, buffer: &mut T) {
    QMCv1.decipher_buffer(offset, buffer);
}

pub fn encrypt_qmc1<T: AsMut<[u8]>>(offset: usize, buffer: &mut T) {
    QMCv1.encipher_buffer(offset, buffer);
}
