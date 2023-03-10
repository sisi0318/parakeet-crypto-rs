use std::{iter::Peekable, slice::Iter};

#[derive(Debug)]
pub struct PeekIter<'a, T>
where
    T: Copy,
{
    items: &'a [T],
    iter: Peekable<Iter<'a, T>>,
}

impl<'a, T> PeekIter<'a, T>
where
    T: Copy,
{
    pub fn new(items: &'a [T], index: usize) -> Self {
        let index = index % items.len();
        Self {
            items,
            iter: items[index..].iter().peekable(),
        }
    }

    pub fn get(&mut self) -> T {
        if let Some(&&value) = self.iter.peek() {
            value
        } else {
            panic!("can't peek current value")
        }
    }

    pub fn next(&mut self) -> bool {
        if self.iter.next().is_none() {
            self.reset();
            true
        } else {
            false
        }
    }

    pub fn reset(&mut self) {
        self.iter = self.items.iter().peekable();
    }
}
