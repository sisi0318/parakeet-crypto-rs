use std::cmp::min;

use super::rc4::RC4;

const INITIAL_SEGMENT_SIZE: usize = 0x80;
const OTHER_SEGMENT_SIZE: usize = 0x1400;
const KEY_STREAM_LEN: usize = 0x1FF + OTHER_SEGMENT_SIZE;

struct Version2RC4 {
    key: Box<[u8]>,
    key_stream: [u8; KEY_STREAM_LEN],
    key_hash: u32,
}

fn calc_key_hash(key: &[u8]) -> u32 {
    let mut hash = 1u32;
    for &v in key.iter().filter(|v| v != 0) {
        let next = hash.wrapping_mul(v.into());
        if next <= hash {
            break;
        }

        hash = next;
    }

    hash
}

enum SegmentType {
    First,
    Other,
}

impl Version2RC4 {
    pub fn new(key: &[u8]) -> Self {
        Self {
            key: key.clone().into(),
            key_hash: calc_key_hash(key),
            key_stream: RC4::get_key_stream::<KEY_STREAM_LEN>(key),
        }
    }

    #[inline]
    fn get_segment_key(&self, id: usize, seed: u8) -> usize {
        // Rust will panic on division by zero.
        if seed == 0 {
            0usize
        } else {
            f64::from(self.key_hash) / f64::from((id + 1) * seed) * 100.0
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
        let mut offset = offset;

        let segment_index = offset / OTHER_SEGMENT_SIZE;
        let discard_len = offset % OTHER_SEGMENT_SIZE;
        let discard_len = discard_len
            + self.get_segment_key(segment_index, self.key[segment_index % key_len])
            & 0x1FF;

        let process_len = min(
            buffer.len(),
            OTHER_SEGMENT_SIZE - (offset % OTHER_SEGMENT_SIZE),
        );
        let mut buffer = &mut buffer[..process_len];
        let key_stream = &self.key_stream[discard_len..];

        for (item, &key) in buffer.iter_mut().zip(key_stream.iter()) {
            *item ^= key;
        }
    }

    pub fn decrypt(&self, offset: usize, buffer: &mut [u8]) {
        let mut offset = offset;
        let mut buffer = buffer;

        let process = #[inline(always)]
            |is_first_segment: SegmentType, len: usize| {
            let len = min(buffer.len(), len);
            let (segment, rest) = buffer.split_at_mut(len);
            if is_first_segment {
                self.encode_first_segment(offset, segment);
            } else {
                self.encode_other_segment(offset, segment);
            }
            offset += len;
            buffer = rest;
        };

        if offset < INITIAL_SEGMENT_SIZE {
            process(SegmentType::First, INITIAL_SEGMENT_SIZE - offset);
        }

        if (offset % OTHER_SEGMENT_SIZE) != 0 {
            let len = OTHER_SEGMENT_SIZE - (offset % OTHER_SEGMENT_SIZE);
            process(SegmentType::Other, len);
        }

        for segment in buffer.chunks_mut(OTHER_SEGMENT_SIZE) {
            let len = min(buffer.len(), OTHER_SEGMENT_SIZE);
            self.encode_other_segment(offset, segment);
            offset += len;
        }
    }
}
