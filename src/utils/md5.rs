use md5::{Digest, Md5};

pub fn md5<T: AsRef<[u8]>>(buffer: T) -> [u8; 16] {
    let mut hash = Md5::new();
    hash.update(buffer);
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5() {
        let data = b"hello";
        let result = md5(data);
        let expected = *b"\x5D\x41\x40\x2A\xBC\x4B\x2A\x76\xB9\x71\x9D\x91\x10\x17\xC5\x92";
        assert_eq!(result, expected);
    }
}
