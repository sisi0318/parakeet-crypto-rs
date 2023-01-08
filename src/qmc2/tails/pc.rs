pub fn parse_tail_pc(buffer: &[u8]) -> Option<(usize, Vec<u8>)> {
    let buf_len = buffer.len();
    if buf_len < 4 {
        return None;
    }

    let mut key_len = [0u8; 4];
    key_len.copy_from_slice(&buffer[buf_len - 4..]);
    let key_len = u32::from_le_bytes(key_len) as usize;

    let full_payload_len = key_len + 4;
    if full_payload_len > buf_len {
        return None;
    }

    let key_start_index = buf_len - full_payload_len;
    let mut key = vec![0u8; key_len];
    key.copy_from_slice(&buffer[key_start_index..key_start_index + key_len]);

    Some((full_payload_len, key))
}
