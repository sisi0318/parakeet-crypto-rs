#[derive(Debug, Clone)]
pub struct RC4 {
    state: Vec<u8>,
    i: usize,
    j: usize,
}

fn init_state(key: &[u8]) -> Vec<u8> {
    let n = key.len();
    let mut state = vec![0u8; n];
    for (i, v) in state.iter_mut().enumerate() {
        *v = i as u8;
    }

    let mut j = 0usize;
    for i in 0..state.len() {
        j = (j + state[i] + key[i % n]) % n;
        state.swap(i, j);
    }

    state
}

impl RC4 {
    pub fn new<K: AsRef<[u8]>>(key: K) -> Self {
        Self {
            state: init_state(key.as_ref()),
            i: 0,
            j: 0,
        }
    }

    fn next(&mut self) -> u8 {
        let n = self.state.len();

        self.i = (self.i + 1) % n;
        self.j = (self.j + self.state[self.i]) % n;

        let (i, j) = (self.i, self.j);
        let final_idx = (i + j) % n;
        self.state.swap(i, j);

        self.state[final_idx]
    }

    pub fn process(&mut self, buffer: &mut [u8]) {
        for p in buffer.iter_mut() {
            *p ^= self.next();
        }
    }

    pub fn get_key_stream<const N: usize>(key: &[u8]) -> [u8; N] {
        let mut rc4 = Self::new(key);

        let mut buffer = [0u8; N];
        for item in buffer.iter_mut() {
            *item = rc4.next();
        }

        buffer
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
