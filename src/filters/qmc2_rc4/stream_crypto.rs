use crate::{filters::qmc2::QMC2Crypto, interfaces::DecryptorError};

use super::{rc4::RC4, segment_key::SegmentKey};

const FIRST_SEGMENT_SIZE: usize = 0x0080;
const OTHER_SEGMENT_SIZE: usize = 0x1400;
const RC4_STREAM_CACHE_SIZE: usize = OTHER_SEGMENT_SIZE + 512;

#[derive(Debug, Clone)]
pub struct QMC2RC4 {
    offset: usize,
    segment_key: SegmentKey,
    rc4_stream: [u8; RC4_STREAM_CACHE_SIZE],
    key: Vec<u8>,
}

impl QMC2RC4 {
    pub fn new(key: &[u8]) -> Self {
        let mut rc4 = RC4::new(key);
        let mut rc4_stream = [0u8; RC4_STREAM_CACHE_SIZE];
        rc4.derive(&mut rc4_stream);

        Self {
            offset: 0,
            rc4_stream,
            key: key.to_vec(),
            segment_key: SegmentKey::new(key),
        }
    }

    pub fn new_blank() -> Self {
        Self {
            offset: 0,
            rc4_stream: [0u8; RC4_STREAM_CACHE_SIZE],
            key: vec![],
            segment_key: SegmentKey::new(&[]),
        }
    }

    fn process_first_segment(&mut self, dst: &mut [u8]) {
        for value in dst.iter_mut() {
            let seed = self.key[self.offset % self.key.len()];
            let key_idx = self.segment_key.get_key(self.offset as u64, seed);
            let xor_key = self.key[(key_idx as usize) % self.key.len()];

            *value ^= xor_key;

            self.offset += 1;
        }
    }

    pub fn transform(&mut self, dst: &mut [u8]) -> Result<usize, DecryptorError> {
        let final_process_len = dst.len();

        let mut dst = dst;
        if self.offset < FIRST_SEGMENT_SIZE {
            let process_len = std::cmp::min(FIRST_SEGMENT_SIZE - self.offset, dst.len());
            let (curr_dst, next_dst) = dst.split_at_mut(process_len);

            self.process_first_segment(curr_dst);

            dst = next_dst;
        }

        while !dst.is_empty() {
            let segment_id = self.offset / OTHER_SEGMENT_SIZE;
            let segment_offset = self.offset % OTHER_SEGMENT_SIZE;
            let process_len = std::cmp::min(dst.len(), OTHER_SEGMENT_SIZE - segment_offset);

            let seed = self.key[segment_id % 512];
            let segment_discard = self.segment_key.get_key(segment_id as u64, seed) % 512;
            let start_index = segment_offset + (segment_discard as usize);

            let xor_stream = &self.rc4_stream[start_index..start_index + process_len];
            let (curr_dst, next_dst) = dst.split_at_mut(process_len);
            for (i, v) in curr_dst.iter_mut().enumerate() {
                *v ^= xor_stream[i];
            }

            self.offset += process_len;
            dst = next_dst;
        }

        Ok(final_process_len)
    }
}

impl QMC2Crypto for QMC2RC4 {
    fn transform(&mut self, dst: &mut [u8]) -> Result<usize, DecryptorError> {
        self.transform(dst)
    }

    fn set_file_key(&mut self, key: &[u8]) -> Result<(), crate::interfaces::DecryptorError> {
        let mut rc4 = RC4::new(key);

        rc4.derive(&mut self.rc4_stream);
        self.segment_key = SegmentKey::new(key);
        self.key = key.to_vec();

        Ok(())
    }

    fn get_offset(&self) -> usize {
        self.offset
    }
}
