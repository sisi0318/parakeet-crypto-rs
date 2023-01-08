pub fn parse_tail_qtag(buffer: &[u8]) -> Option<(usize, Vec<u8>)> {
    let buf_len = buffer.len();
    if buf_len < 8 {
        return None;
    }

    if &buffer[buf_len - 4..] != b"QTag" {
        return None;
    }

    let meta_len: &[u8; 4] = &buffer[buf_len - 8..buf_len - 4].try_into().unwrap();
    let meta_len = u32::from_be_bytes(*meta_len) as usize;
    let full_payload_len = meta_len + 8;

    if full_payload_len > buf_len {
        return None;
    }

    let meta_start = buf_len - full_payload_len;
    let embed_key_size = buffer[meta_start..].iter().position(|&v| v == b',')?;
    let embed_key = buffer[meta_start..meta_start + embed_key_size].to_vec();

    Some((full_payload_len, embed_key))
}
