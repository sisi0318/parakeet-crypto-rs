fn calculate_key_hash(key: &[u8]) -> u32 {
    let mut hash = 1u32;
    for &v in key.iter() {
        if v == 0 {
            continue;
        }

        let next_hash = hash.wrapping_mul(v as u32);
        if next_hash == 0 || next_hash <= hash {
            break;
        }

        hash = next_hash;
    }

    hash
}

#[derive(Debug, Clone, Copy)]
pub struct SegmentKey {
    hash: f64,
}

impl SegmentKey {
    pub fn new(key: &[u8]) -> Self {
        let key_hash = calculate_key_hash(key) as f64;
        Self { hash: key_hash }
    }

    pub fn get_hash(&self) -> f64 {
        self.hash
    }

    pub fn get_key(&self, segment_id: u64, seed: u8) -> u32 {
        if seed == 0 {
            0
        } else {
            let mut result = self.get_hash();
            result /= (segment_id + 1).wrapping_mul(seed.into()) as f64;
            result *= 100.0;
            result as u32
        }
    }
}
