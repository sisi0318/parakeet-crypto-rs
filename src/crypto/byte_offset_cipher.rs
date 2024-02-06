pub trait ByteOffsetCipher {
    fn encrypt_byte(&self, offset: usize, datum: u8) -> u8;

    fn encrypt<T: AsMut<[u8]>>(&self, offset: usize, buffer: &mut T) {
        let mut offset = offset;
        for datum in buffer.as_mut() {
            *datum = self.encrypt_byte(offset, *datum);
            offset += 1;
        }
    }
}

pub trait ByteOffsetDecipher {
    fn decrypt_byte(&self, offset: usize, datum: u8) -> u8;

    fn decrypt<T: AsMut<[u8]>>(&self, offset: usize, buffer: &mut T) {
        let mut offset = offset;
        for datum in buffer.as_mut() {
            *datum = self.decrypt_byte(offset, *datum);
            offset += 1;
        }
    }
}
