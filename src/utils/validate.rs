#[inline(always)]
pub fn is_base64_chr(chr: u8) -> bool {
    chr.is_ascii_alphanumeric() || (chr == b'+') || (chr == b'/') || (chr == b'=')
}

#[inline(always)]
pub fn is_base64_str<T: AsRef<[u8]>>(s: T) -> bool {
    s.as_ref().iter().all(|&value| is_base64_chr(value))
}
