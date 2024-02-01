#[inline(always)]
pub fn is_base64_chr(chr: u8) -> bool {
    chr.is_ascii_alphanumeric() || (chr == b'+') || (chr == b'/') || (chr == b'=')
}

#[inline(always)]
pub fn is_base64_str<T: AsRef<[u8]>>(s: T) -> bool {
    s.as_ref().iter().all(|&value| is_base64_chr(value))
}

#[inline(always)]
pub fn is_digits_str<T: AsRef<[u8]>>(s: T) -> bool {
    s.as_ref().iter().all(|&value| value.is_ascii_digit())
}

pub trait ValidatorTrait {
    fn is_base64(&self) -> bool;
    fn is_digits(&self) -> bool;
}

impl<T: AsRef<[u8]>> ValidatorTrait for T {
    fn is_base64(&self) -> bool {
        is_base64_str(self.as_ref())
    }

    fn is_digits(&self) -> bool {
        is_digits_str(self.as_ref())
    }
}
