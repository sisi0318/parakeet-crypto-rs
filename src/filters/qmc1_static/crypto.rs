use crate::{
    filters::qmc2::QMC2Crypto,
    interfaces::DecryptorError,
    utils::loop_iterator::{LoopCounter, LoopIter},
};

const CIPHER_PAGE_SIZE: usize = 0x7fff;
const INDEX_OFFSET: usize = 80923 % 256;

#[derive(Debug)]
pub struct QMC1Static {
    offset: usize,
    page_counter: LoopCounter,
    key: [u8; 128],
}

impl QMC1Static {
    pub fn new(key: &[u8; 128]) -> Self {
        Self {
            offset: 0,
            page_counter: LoopCounter::new(0, CIPHER_PAGE_SIZE),
            key: *key,
        }
    }

    pub fn new_key256(key256: &[u8; 256]) -> Self {
        let mut key128 = [0u8; 128];
        for (i, key) in key128.iter_mut().enumerate() {
            *key = key256[(i * i + INDEX_OFFSET) % key256.len()];
        }

        Self::new(&key128)
    }

    pub fn transform(&mut self, dst: &mut [u8]) -> Result<usize, DecryptorError> {
        let mut key_iter = LoopIter::new(&self.key, self.offset % CIPHER_PAGE_SIZE);

        for value in dst.iter_mut() {
            *value ^= key_iter.get_and_move();

            if self.page_counter.next() {
                key_iter.reset();
            }
        }

        // Off-by-1 fix at the first page.
        if CIPHER_PAGE_SIZE >= self.offset && CIPHER_PAGE_SIZE - self.offset < dst.len() {
            let boundary_index = CIPHER_PAGE_SIZE - self.offset;
            dst[boundary_index] ^= self.key[0] ^ self.key[1];
        }

        self.offset += dst.len();

        Ok(dst.len())
    }
}

impl QMC2Crypto for QMC1Static {
    fn get_offset(&self) -> usize {
        self.offset
    }

    fn set_file_key(&mut self, key: &[u8]) -> Result<(), DecryptorError> {
        if key.len() != self.key.len() {
            return Err(DecryptorError::QMCv1InitFailed);
        }

        self.key.copy_from_slice(key);
        Ok(())
    }

    fn transform(&mut self, dst: &mut [u8]) -> Result<usize, DecryptorError> {
        self.transform(dst)
    }
}
