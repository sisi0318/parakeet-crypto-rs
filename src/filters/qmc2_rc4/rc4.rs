use std::ops::Rem;

#[derive(Debug, Clone)]
pub struct RC4 {
    state: Vec<u8>,
    i: usize,
    j: usize,
}

impl RC4 {
    fn create_state_from_key(key: &[u8]) -> Vec<u8> {
        let mut state = vec![0xffu8; key.len()];
        for (i, v) in state.iter_mut().enumerate() {
            *v = i as u8;
        }

        let mut j = 0usize;
        for i in 0..state.len() {
            j += usize::from(state[i]);
            j += usize::from(key[i % key.len()]);
            j %= key.len();

            state.swap(i, j);
        }

        state
    }

    pub fn new<K: AsRef<[u8]>>(key: K) -> Self {
        Self {
            state: Self::create_state_from_key(key.as_ref()),
            i: 0,
            j: 0,
        }
    }

    fn move_state_forward(&mut self) {
        let n = self.state.len();
        self.i = self.i.wrapping_add(1).rem(n);
        self.j = self.j.wrapping_add(self.state[self.i].into()).rem(n);
        self.state.swap(self.i, self.j);
    }

    pub fn derive(&mut self, buffer: &mut [u8]) {
        for p in buffer.iter_mut() {
            self.move_state_forward();

            let i = usize::from(self.state[self.i]);
            let j = usize::from(self.state[self.j]);
            let index = (i + j) % self.state.len();
            *p ^= self.state[index];
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
