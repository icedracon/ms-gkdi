//! Bounds-checked forward reader. Length fields on the wire are attacker-controlled, so
//! nothing is sliced without being checked against what is left.

use crate::{GkdiError, Result};

pub struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Cursor { b, pos: 0 }
    }

    pub fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8]> {
        let s = self
            .b
            .get(self.pos..self.pos.checked_add(n).ok_or(GkdiError::Truncated(what))?)
            .ok_or(GkdiError::Truncated(what))?;
        self.pos += n;
        Ok(s)
    }

    pub fn skip(&mut self, n: usize, what: &'static str) -> Result<()> {
        self.take(n, what).map(|_| ())
    }

    pub fn u32le(&mut self, what: &'static str) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4, what)?.try_into().unwrap()))
    }

    pub fn i32le(&mut self, what: &'static str) -> Result<i32> {
        Ok(i32::from_le_bytes(self.take(4, what)?.try_into().unwrap()))
    }
}
