use crate::interfaces::DecryptorError;

pub fn xor_from_offset(
    dst: &mut [u8],
    src: &[u8],
    key: &[u8],
    offset: usize,
) -> Result<(), DecryptorError> {
    if src.len() != dst.len() {
        return Err(DecryptorError::InputOutputBufferLenMismatch);
    }

    let key_len = key.len();
    let offset = offset;
    let mut dst = dst;
    let mut src = src;

    assert!(key_len > 1, "key.len() too small");

    // Align things
    let prev_key_offset = offset % key_len;
    if prev_key_offset != 0 {
        let process_len = std::cmp::min(src.len(), key_len - prev_key_offset);
        let key = &key[prev_key_offset..prev_key_offset + process_len];

        let (prev_dst, rest_dst) = dst.split_at_mut(process_len);
        let (prev_src, rest_src) = src.split_at(process_len);

        for (i, key) in key.iter().enumerate() {
            prev_dst[i] = prev_src[i] ^ key;
        }
        (dst, src) = (rest_dst, rest_src);
    }

    let leftover_len = dst.len() % key_len;
    let last_block_index = dst.len() - leftover_len;

    // Hopefully the compiler can optimise this to simd instructions.
    for i in (0..last_block_index).step_by(key_len) {
        for (j, key) in key.iter().enumerate() {
            dst[i + j] = src[i + j] ^ key;
        }
    }

    if leftover_len > 0 {
        for (i, key) in key[..leftover_len].iter().enumerate() {
            dst[last_block_index + i] = src[last_block_index + i] ^ key;
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub fn xor_block_from_offset(
    dst: &mut [u8],
    src: &[u8],
    block_len: usize,
    key: &[u8],
    offset: usize,
) -> Result<(), DecryptorError> {
    assert!(block_len > 1, "block_len too small");

    let mut dst = dst;
    let mut src = src;

    let prev_block_offset = offset % block_len;
    if prev_block_offset != 0 {
        let process_len = std::cmp::min(src.len(), block_len - prev_block_offset);

        let (prev_dst, rest_dst) = dst.split_at_mut(process_len);
        let (prev_src, rest_src) = src.split_at(process_len);
        xor_from_offset(prev_dst, prev_src, key, prev_block_offset)?;
        (dst, src) = (rest_dst, rest_src);
    }

    let leftover_len = dst.len() % block_len;
    let last_block_index = dst.len() - leftover_len;

    // Hopefully the compiler can optimise this to simd instructions.
    for _ in (0..last_block_index / block_len).step_by(block_len) {
        let (prev_dst, rest_dst) = dst.split_at_mut(block_len);
        let (prev_src, rest_src) = src.split_at(block_len);
        xor_from_offset(prev_dst, prev_src, key, 0)?;
        (dst, src) = (rest_dst, rest_src);
    }

    if leftover_len > 0 {
        xor_from_offset(dst, src, key, 0)?;
    }

    Ok(())
}
