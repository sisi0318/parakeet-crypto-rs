use std::cmp::min;

use crate::crypto::byte_offset_cipher::{ByteOffsetDecipher, ByteOffsetEncipher};

use super::rc4::RC4;

const INITIAL_SEGMENT_SIZE: usize = 0x80;
const OTHER_SEGMENT_SIZE: usize = 0x1400;
const KEY_STREAM_LEN: usize = 0x1FF + OTHER_SEGMENT_SIZE;

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct QMCv2RC4 {
    key: Box<[u8]>,
    key_stream: Box<[u8; KEY_STREAM_LEN]>,
    key_hash: u32,
}

fn calc_key_hash(key: &[u8]) -> u32 {
    let mut hash = 1u32;
    for &v in key.iter().filter(|&&v| v != 0) {
        let next = hash.wrapping_mul(v.into());
        if next <= hash {
            break;
        }

        hash = next;
    }

    hash
}

impl QMCv2RC4 {
    pub fn new(key: &[u8]) -> Self {
        Self {
            key: key.into(),
            key_hash: calc_key_hash(key),
            key_stream: Box::from(RC4::new(key).get_key_stream()),
        }
    }

    #[inline]
    fn get_segment_key(&self, id: usize, seed: u8) -> usize {
        // Rust will panic on division by zero.
        if seed == 0 {
            0usize
        } else {
            let seed = seed as u32;
            let id = id as u32;
            let key = f64::from(self.key_hash) / f64::from(seed * (id + 1)) * 100.0;
            key as usize
        }
    }

    fn encode_first_segment(&self, offset: usize, buffer: &mut [u8]) {
        let mut i = offset;
        let key_len = self.key.len();

        for item in buffer.iter_mut() {
            *item ^= self.key[self.get_segment_key(i, self.key[i % key_len]) % key_len];
            i += 1;
        }
    }

    fn encode_other_segment(&self, offset: usize, buffer: &mut [u8]) {
        let key_len = self.key.len();

        let segment_idx = offset / OTHER_SEGMENT_SIZE;
        let segment_offset = offset % OTHER_SEGMENT_SIZE;

        let segment_key = self.get_segment_key(segment_idx, self.key[segment_idx % key_len]);
        let skip_len = segment_key & 0x1FF;

        let len = min(buffer.len(), OTHER_SEGMENT_SIZE - segment_offset);
        let buffer = &mut buffer[..len];
        let key_stream = &self.key_stream[skip_len + segment_offset..];

        for (item, &key) in buffer.iter_mut().zip(key_stream.iter()) {
            *item ^= key;
        }
    }
}

impl ByteOffsetDecipher for QMCv2RC4 {
    fn decipher_byte(&self, offset: usize, datum: u8) -> u8 {
        let mut buffer = [datum; 1];
        self.decipher_buffer(offset, &mut buffer);
        buffer[0]
    }

    fn decipher_buffer<T: AsMut<[u8]> + ?Sized>(&self, offset: usize, buffer: &mut T) {
        let mut offset = offset;
        let mut buffer = buffer.as_mut();

        if offset < INITIAL_SEGMENT_SIZE {
            let len = min(buffer.len(), INITIAL_SEGMENT_SIZE - offset);
            let (segment, rest) = buffer.split_at_mut(len);
            self.encode_first_segment(offset, segment);
            offset += len;
            buffer = rest;
        }

        if (offset % OTHER_SEGMENT_SIZE) != 0 {
            let len = OTHER_SEGMENT_SIZE - (offset % OTHER_SEGMENT_SIZE);
            let len = min(buffer.len(), len);
            let (segment, rest) = buffer.split_at_mut(len);
            self.encode_other_segment(offset, segment);
            offset += len;
            buffer = rest;
        }

        for segment in buffer.chunks_mut(OTHER_SEGMENT_SIZE) {
            let len = segment.len();
            self.encode_other_segment(offset, segment);
            offset += len;
        }
    }
}

impl ByteOffsetEncipher for QMCv2RC4 {
    fn encipher_byte(&self, offset: usize, datum: u8) -> u8 {
        self.decipher_byte(offset, datum)
    }

    fn encipher_buffer<T: AsMut<[u8]> + ?Sized>(&self, offset: usize, buffer: &mut T) {
        self.decipher_buffer(offset, buffer)
    }
}
