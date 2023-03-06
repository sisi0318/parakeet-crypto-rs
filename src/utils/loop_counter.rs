#[derive(Debug)]
pub struct LoopCounter {
    current: usize,
    len: usize,
}

impl LoopCounter {
    pub fn new(current: usize, len: usize) -> Self {
        Self {
            current: current % len,
            len,
        }
    }

    pub fn next(&mut self) -> bool {
        self.current += 1;

        if self.current == self.len {
            self.current = 0;
            true
        } else {
            false
        }
    }

    pub fn get(&self) -> usize {
        self.current
    }
}
