use super::*;

impl<L: PageLinks> Pool<'_, L> {
    fn scan(
        &self,
        map: &[AtomicU64],
        descending: bool,
        mut take: impl FnMut(usize) -> Result<Option<u64>, Corruption>,
    ) -> Result<Option<u64>, Corruption> {
        for offset in 0..map.len() {
            let word = if descending {
                map.len() - 1 - offset
            } else {
                offset
            };
            let mut bits = map[word].load(Ordering::Acquire);
            while bits != 0 {
                let bit = if descending {
                    63 - bits.leading_zeros()
                } else {
                    bits.trailing_zeros()
                };
                bits &= !(1 << bit);
                let index = word * 64 + bit as usize;
                if index < self.block_count {
                    if let Some(addr) = take(index)? {
                        return Ok(Some(addr));
                    }
                }
            }
        }
        Ok(None)
    }

    // None is the bootstrap path: it never consults CPU identity or claims.
    // P1b supplies a cursor only after the all-CPU publication is acquired.
    pub(super) fn allocate(
        &self,
        count: u16,
        cursor: Option<&AtomicUsize>,
    ) -> Result<Option<u64>, Corruption> {
        if count == 0 || count > PAGES {
            return Ok(None);
        }
        let previous = cursor.map_or(NO_CURSOR, |slot| slot.load(Ordering::Relaxed));
        if previous != NO_CURSOR {
            if let Some(addr) = self.take_small(previous, count, SmallSource::Split, true)? {
                return Ok(Some(addr));
            }
            let block = self.block(previous)?;
            let _guard = block.inner.lock(line!());
            block.flags.fetch_and(!CLAIMED, Ordering::Relaxed);
            cursor.unwrap().store(NO_CURSOR, Ordering::Relaxed);
        }
        loop {
            let take = |index, source| {
                let addr = self.take_small(index, count, source, cursor.is_some())?;
                if addr.is_some() {
                    if let Some(slot) = cursor {
                        slot.store(index, Ordering::Relaxed);
                    }
                }
                Ok(addr)
            };
            if count == 1 && cursor.is_some() {
                if let Some(addr) = self.scan(self.free, false, |index| {
                    take(index, SmallSource::Unclaimed)
                })? {
                    return Ok(Some(addr));
                }
            }
            if let Some(addr) =
                self.scan(self.free, false, |index| take(index, SmallSource::Split))?
            {
                return Ok(Some(addr));
            }
            if let Some(addr) =
                self.scan(self.whole, false, |index| take(index, SmallSource::Whole))?
            {
                return Ok(Some(addr));
            }
            // Fragmented free pages cannot guarantee a run. For one page,
            // acquiring a free's released charge also observes its index bit.
            if count != 1 || self.counters.used.load(Ordering::Acquire) == self.counters.total {
                return Ok(None);
            }
        }
    }

    pub(super) fn allocate_huge(&self) -> Result<Option<u64>, Corruption> {
        self.scan(self.whole, true, |index| self.take_huge(index))
    }
}
