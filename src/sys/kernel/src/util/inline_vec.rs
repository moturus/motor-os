//! A vector with fixed inline capacity that spills to the heap (S13).
//!
//! The wait/wake hot path deals in tiny collections (1-3 wait handles,
//! 1-2 wakers); the inline capacity makes those cycles allocation-free.
//! Storage is contiguous in either mode: elements live inline until the
//! first spill, after which all of them (including the former inline
//! ones) live in the spill Vec, so `as_slice()` is always a single
//! contiguous slice.

use alloc::vec::Vec;

pub struct InlineVec<T: Copy, const N: usize> {
    // Total length; the inline array holds the elements iff spill is empty.
    len: usize,
    inline: [T; N],
    spill: Vec<T>,
}

impl<T: Copy, const N: usize> InlineVec<T, N> {
    pub const fn new(fill: T) -> Self {
        Self {
            len: 0,
            inline: [fill; N],
            spill: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn push(&mut self, val: T) {
        if self.spill.is_empty() && self.len < N {
            self.inline[self.len] = val;
        } else {
            if self.spill.is_empty() {
                self.spill.reserve(2 * N);
                self.spill.extend_from_slice(&self.inline[..self.len]);
            }
            self.spill.push(val);
        }
        self.len += 1;
    }

    pub fn as_slice(&self) -> &[T] {
        if self.spill.is_empty() {
            &self.inline[..self.len]
        } else {
            &self.spill
        }
    }
}

impl<T: Copy + Ord, const N: usize> InlineVec<T, N> {
    pub fn sort_dedup(&mut self) {
        if self.len <= 1 {
            return;
        }
        if self.spill.is_empty() {
            self.inline[..self.len].sort_unstable();
            let mut w = 1_usize;
            for r in 1..self.len {
                if self.inline[r] != self.inline[w - 1] {
                    self.inline[w] = self.inline[r];
                    w += 1;
                }
            }
            self.len = w;
        } else {
            self.spill.sort_unstable();
            self.spill.dedup();
            self.len = self.spill.len();
        }
    }
}
