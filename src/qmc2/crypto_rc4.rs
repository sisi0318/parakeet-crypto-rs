use crate::interfaces::{DecryptorError, StreamDecryptor};

use super::{
    key_utils::{calculate_key_hash, get_segment_key},
    utils_rc4::RC4,
};

const FIRST_SEGMENT_SIZE: usize = 0x0080;
const OTHER_SEGMENT_SIZE: usize = 0x1400;

/// QMC2's RC4 decryption implementation.
/// The file is split into segments:
///   - The first segment (0x80 bytes)
///   - The second segment (0x1400-0x80 bytes, segment_id = 0),
///     where the first 0x80 bytes were discarded.
///   - Rest of the segments (each 0x1400 bytes, segment_id = 1, 2, 3, ...)
pub struct CryptoRC4 {
    key: Box<[u8]>,
    key_hash: u64,
    offset: usize,
}

impl CryptoRC4 {
    pub fn new<T: AsRef<[u8]>>(key: T) -> Self {
        let key = key.as_ref();

        Self {
            key: Box::from(key),
            key_hash: calculate_key_hash(key) as u64,
            offset: 0,
        }
    }

    fn decrypt_first_segment(&self, dst: &mut [u8], src: &[u8], offset: usize) {
        let key_size = self.key.len();
        for ((i, dst_item), src_item) in dst.iter_mut().enumerate().zip(src.iter()) {
            let i = i + offset;
            let seed = self.key[i % key_size];
            let key_index = get_segment_key(self.key_hash, i as u64, seed as u64);
            *dst_item = *src_item ^ self.key[key_index % key_size];
        }
    }

    fn decrypt_other_segment(&self, id: usize, block: &mut [u8], offset: usize) {
        let seed = self.key[id & 0x1FF] as u64;
        let discards = get_segment_key(self.key_hash, id as u64, seed) & 0x1FF;

        let mut rc4 = RC4::new(&self.key);
        rc4.discard(discards + (offset % OTHER_SEGMENT_SIZE));
        rc4.derive(block);
    }
}

impl StreamDecryptor for CryptoRC4 {
    fn decrypt_block(&mut self, dst: &mut [u8], src: &[u8]) -> Result<usize, DecryptorError> {
        let mut total_process_len = 0usize;
        let mut dst = dst;
        let mut src = src;

        if self.offset < FIRST_SEGMENT_SIZE {
            let process_len = std::cmp::min(FIRST_SEGMENT_SIZE - self.offset, src.len());
            let (prev_src, next_src) = src.split_at(process_len);
            let (prev_dst, next_dst) = dst.split_at_mut(process_len);

            self.decrypt_first_segment(prev_dst, prev_src, self.offset);

            (dst, src) = (next_dst, next_src);
            self.offset += process_len;
            total_process_len += process_len;
        }

        while !src.is_empty() {
            let segment_id = self.offset / OTHER_SEGMENT_SIZE;
            let segment_offset = self.offset % OTHER_SEGMENT_SIZE;

            let process_len = std::cmp::min(OTHER_SEGMENT_SIZE - segment_offset, src.len());
            let (prev_src, next_src) = src.split_at(process_len);
            let (prev_dst, next_dst) = dst.split_at_mut(process_len);

            prev_dst.copy_from_slice(prev_src);
            self.decrypt_other_segment(segment_id, prev_dst, segment_offset);

            (dst, src) = (next_dst, next_src);
            self.offset += process_len;
            total_process_len += process_len;
        }

        Ok(total_process_len)
    }
}
