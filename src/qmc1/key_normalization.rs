use super::key_expansion;

const QMC_V1_INDEX_OFFSET_STATIC_CIPHER: usize = 80923;
const QMC_V1_INDEX_OFFSET_MAP_CIPHER: usize = 71214;

pub fn normalize_static_key128(key: &[u8; 128]) -> [u8; 128] {
    *key
}

pub fn normalize_static_key256(key: &[u8; 256]) -> [u8; 128] {
    let mut long_key = *key;
    let mid_index = QMC_V1_INDEX_OFFSET_STATIC_CIPHER % long_key.len();
    long_key.rotate_left(mid_index);

    key_expansion::reduce_key256_to_key128(&long_key)
}

pub fn normalize_map_key128(key: &[u8; 128]) -> [u8; 128] {
    let mut key = *key;

    let mid_index = QMC_V1_INDEX_OFFSET_MAP_CIPHER % key.len();
    key.rotate_left(mid_index);

    key
}

pub fn normalize_map_key256(key: &[u8]) -> [u8; 128] {
    let mut long_key = [0u8; 256];
    let input_key = &key[..std::cmp::min(long_key.len(), key.len())];

    let mut shift_counter = 4u8;
    for (i, value) in input_key.iter().enumerate() {
        let shift_value = u32::from(shift_counter) & 0b0111;
        long_key[i] = value.wrapping_shl(shift_value) | value.wrapping_shr(shift_value);

        shift_counter = shift_counter.wrapping_add(1);
    }

    let mid_index = QMC_V1_INDEX_OFFSET_MAP_CIPHER % long_key.len();
    long_key.rotate_left(mid_index);

    key_expansion::reduce_key256_to_key128(&long_key)
}
