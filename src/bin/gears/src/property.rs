//! Small deterministic adversarial-input generator for unit tests.

pub struct ByteCases {
    state: u64,
    index: usize,
    count: usize,
    max_len: usize,
}

pub fn byte_cases(seed: u64, count: usize, max_len: usize) -> ByteCases {
    ByteCases {
        state: seed.max(1),
        index: 0,
        count,
        max_len,
    }
}

impl ByteCases {
    fn next_u64(&mut self) -> u64 {
        let mut value = self.state;
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        self.state = value;
        value.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, limit: usize) -> usize {
        if limit == 0 {
            return 0;
        }
        (self.next_u64() % limit as u64) as usize
    }
}

impl Iterator for ByteCases {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        if self.index == self.count {
            return None;
        }
        let bytes = match self.index {
            0 => Vec::new(),
            1 => vec![0],
            2 => vec![0; self.max_len],
            3 => vec![u8::MAX; self.max_len],
            _ => {
                let length = self.below(self.max_len.saturating_add(1));
                (0..length).map(|_| self.next_u64() as u8).collect()
            }
        };
        self.index += 1;
        Some(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_cases_are_reproducible_bounded_and_include_edges() {
        let first: Vec<_> = byte_cases(7, 32, 64).collect();
        assert_eq!(first, byte_cases(7, 32, 64).collect::<Vec<_>>());
        assert_ne!(first, byte_cases(8, 32, 64).collect::<Vec<_>>());
        assert_eq!(first.len(), 32);
        assert!(first[0].is_empty());
        assert_eq!(first[1], vec![0_u8]);
        assert_eq!(first[2], vec![0; 64]);
        assert_eq!(first[3], vec![u8::MAX; 64]);
        assert!(first.iter().all(|bytes| bytes.len() <= 64));
    }
}
