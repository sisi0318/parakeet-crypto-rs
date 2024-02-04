pub fn decrypt_qmc1(offset: usize, buffer: &mut [u8]) {
    let qmc1_map = include_bytes!("./qmc1.bin");

    let mut i = offset;
    for item in buffer {
        *item ^= super::map_l(qmc1_map, i);
        i += 1;
    }
}

pub fn encrypt_qmc1(offset: usize, buffer: &mut [u8]) {
    decrypt_qmc1(offset, buffer)
}
