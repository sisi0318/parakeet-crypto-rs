use std::slice::Iter;

#[derive(Debug)]
pub struct LoopIter<'a, T>
where
    T: Copy,
{
    items: &'a [T],
    iter: Iter<'a, T>,
}

impl<'a, T> LoopIter<'a, T>
where
    T: Copy,
{
    pub fn new(items: &'a [T], index: usize) -> Self {
        let index = index % items.len();
        Self {
            items,
            iter: items[index..].iter(),
        }
    }

    pub fn get_and_move(&mut self) -> T {
        if let Some(value) = self.iter.next() {
            *value
        } else {
            self.reset();
            self.get_and_move()
        }
    }

    pub fn reset(&mut self) {
        self.iter = self.items.iter();
    }
}
