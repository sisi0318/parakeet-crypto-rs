use crate::crypto::ximalaya_android::keys::{ContentKey, ScrambleTable, SCRAMBLED_HEADER_LEN};

pub fn decrypt_header(
    header: &[u8; SCRAMBLED_HEADER_LEN],
    content_key: &ContentKey,
    scramble_table: &ScrambleTable,
) -> [u8; SCRAMBLED_HEADER_LEN] {
    let mut plain = *header;

    let key_stream = content_key.iter().cycle();
    for (i, (&scramble_idx, &key)) in scramble_table.iter().zip(key_stream).enumerate() {
        plain[i] = header[scramble_idx] ^ key;
    }

    plain
}

pub fn encrypt_header(
    header: [u8; SCRAMBLED_HEADER_LEN],
    content_key: &ContentKey,
    scramble_table: &ScrambleTable,
) -> [u8; SCRAMBLED_HEADER_LEN] {
    let mut encrypted = header;

    let key_stream = content_key.iter().cycle();
    for (i, (&scramble_idx, &key)) in scramble_table.iter().zip(key_stream).enumerate() {
        encrypted[scramble_idx] = header[i] ^ key;
    }

    encrypted
}
