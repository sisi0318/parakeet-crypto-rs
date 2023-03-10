pub fn xor_u32_bytes(offset: u32) -> u8 {
    offset.to_le_bytes().iter().fold(0, |acc, x| acc ^ x)
}
