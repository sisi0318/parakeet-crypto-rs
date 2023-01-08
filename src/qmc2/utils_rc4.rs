use std::ops::Rem;

#[derive(Clone)]
pub struct RC4 {
    state: Vec<u8>,
    i: usize,
    j: usize,
}

impl RC4 {
    fn init_key(state: &mut [u8], key: &[u8]) {
        for (i, v) in state.iter_mut().enumerate() {
            *v = i as u8;
        }

        let mut j = 0usize;
        for i in 0..state.len() {
            j = j
                .wrapping_add(state[i].into())
                .wrapping_add(key[i % key.len()].into())
                .rem(key.len());

            state.swap(i, j);
        }
    }

    pub fn new<K: AsRef<[u8]>>(key: K) -> Self {
        let key = key.as_ref();
        let n = key.len();
        let mut state = vec![0u8; n];
        Self::init_key(&mut state, key);

        Self { state, i: 0, j: 0 }
    }

    fn next_byte(&mut self) {
        let n = self.state.len();
        self.i = self.i.wrapping_add(1).rem(n);
        self.j = self.j.wrapping_add(self.state[self.i].into()).rem(n);
        self.state.swap(self.i, self.j);
    }

    pub fn discard(&mut self, n: usize) {
        for _ in 0..n {
            self.next_byte();
        }
    }

    pub fn derive(&mut self, buffer: &mut [u8]) {
        for p in buffer.iter_mut() {
            self.next_byte();

            let final_index = usize::from(self.state[self.i])
                .wrapping_add(usize::from(self.state[self.j]))
                .rem(self.state.len());
            *p ^= self.state[final_index];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RC4;

    #[test]
    fn test_rc4() {
        let mut rc4 = RC4::new(b"this is a test key");

        #[allow(clippy::redundant_clone)]
        let rc4_copy = rc4.clone();

        let mut data = *b"hello world";
        rc4.derive(&mut data[..]);

        assert_ne!(rc4.state, rc4_copy.state);
        assert_eq!(&data, b"\x68\x75\x6b\x64\x64\x24\x7f\x60\x7c\x7d\x60")
    }
}
