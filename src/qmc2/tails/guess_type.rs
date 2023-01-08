pub enum ClientType {
    /**
     * Legacy format, contains decryption key.
     */
    AndroidQTag,
    AndroidSTag,
    PC,
}

pub fn guess_type(tail: &[u8; 4]) -> Option<ClientType> {
    match tail {
        b"QTag" => Some(ClientType::AndroidQTag),
        b"STag" => Some(ClientType::AndroidSTag),
        _ => {
            let assume_pc_len = u32::from_le_bytes(*tail);
            if assume_pc_len <= 0x400 {
                Some(ClientType::PC)
            } else {
                None
            }
        }
    }
}
