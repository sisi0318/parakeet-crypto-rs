pub struct QMC2Map;

const INDEX_OFFSET: usize = 71214 % 256;

impl QMC2Map {
    pub fn to_qmc1_static_key128(key_blob: &[u8]) -> [u8; 128] {
        let mut key128 = [0u8; 128];

        if !key_blob.is_empty() {
            let mut long_key = vec![0u8; key_blob.len()];

            let mut shift_counter = 4u32;
            for (i, key) in long_key.iter_mut().enumerate() {
                let value = key_blob[i];
                *key = value.wrapping_shl(shift_counter) | value.wrapping_shr(shift_counter);
                shift_counter = shift_counter.wrapping_add(1) & 0b0111;
            }

            for (i, key) in key128.iter_mut().enumerate() {
                *key = long_key[(i * i + INDEX_OFFSET) % long_key.len()];
            }
        }

        key128
    }
}

#[cfg(test)]
mod tests {
    use super::QMC2Map;

    #[test]
    fn test_key_transformation() {
        todo!("test for qmc2 map key conversion")
    }
}
