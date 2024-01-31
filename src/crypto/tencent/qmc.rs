lazy_static! {
    static ref QMC1_MAP_KEY: [u8; 128] = include_bytes!("./qmc1_map.bin").clone();
}

pub fn decrypt_qmc1(offset: usize, buffer: &mut [u8]) {
    let mut i = offset;
    for item in buffer {
        *item ^= super::map_l(&QMC1_MAP_KEY, i);
        i += 1;
    }
}
