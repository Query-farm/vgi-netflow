//! A panic-free big-endian byte cursor.
//!
//! Untrusted-binary-input discipline: every read is bounds-checked and returns
//! `None` on underrun rather than panicking, and any declared length is
//! validated against the remaining buffer before it is used to slice or
//! allocate (a hostile "length = 4 GB" never allocates). The decoders thread a
//! `Cursor` and turn an underrun into a `truncated` diagnostic.

/// A read cursor over a byte slice. All reads advance the position and never
/// panic.
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Borrow the next `n` bytes and advance, or `None` if fewer remain.
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.remaining() {
            return None;
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }

    /// Peek the next `n` bytes without advancing.
    pub fn peek(&self, n: usize) -> Option<&'a [u8]> {
        if n > self.remaining() {
            return None;
        }
        Some(&self.data[self.pos..self.pos + n])
    }

    pub fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    pub fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|b| u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    /// Skip `n` bytes; `false` if fewer remain.
    pub fn skip(&mut self, n: usize) -> bool {
        self.take(n).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_bounds() {
        let mut c = Cursor::new(&[0x00, 0x09, 0xff, 0xff]);
        assert_eq!(c.u16(), Some(9));
        assert_eq!(c.u16(), Some(0xffff));
        assert_eq!(c.u16(), None);
        assert!(c.is_empty());
    }

    #[test]
    fn oversized_take_never_panics() {
        let mut c = Cursor::new(&[1, 2, 3]);
        assert_eq!(c.take(4_000_000_000), None);
        assert_eq!(c.remaining(), 3);
    }
}
