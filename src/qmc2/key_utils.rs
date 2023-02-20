use std::ops::{Div, Mul};

pub fn calculate_key_hash(key: &[u8]) -> u32 {
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

pub fn get_segment_key(key_hash: u64, id: u64, seed: u64) -> u64 {
    if seed == 0 {
        0
    } else {
        (key_hash as f64)
            .div(seed.wrapping_mul(id + 1) as f64)
            .mul(100.0) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::get_segment_key;

    #[test]
    fn test_exploit_overflow() {
        assert_eq!(
            get_segment_key(516402887, 51, 35),
            28373784,
            "segment key should equal",
        );
    }
}
