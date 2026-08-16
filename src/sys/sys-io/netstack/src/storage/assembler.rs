use core::fmt;

use crate::config::ASSEMBLER_MAX_SEGMENT_COUNT;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooManyHolesError;

impl fmt::Display for TooManyHolesError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "too many holes")
    }
}

impl std::error::Error for TooManyHolesError {}

/// A contiguous chunk of absent data, followed by a contiguous chunk of present data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Contig {
    hole_size: usize,
    data_size: usize,
}

impl fmt::Display for Contig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.has_hole() {
            write!(f, "({})", self.hole_size)?;
        }
        if self.has_hole() && self.has_data() {
            write!(f, " ")?;
        }
        if self.has_data() {
            write!(f, "{}", self.data_size)?;
        }
        Ok(())
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Contig {
    fn format(&self, fmt: defmt::Formatter) {
        if self.has_hole() {
            defmt::write!(fmt, "({})", self.hole_size);
        }
        if self.has_hole() && self.has_data() {
            defmt::write!(fmt, " ");
        }
        if self.has_data() {
            defmt::write!(fmt, "{}", self.data_size);
        }
    }
}

impl Contig {
    const fn empty() -> Contig {
        Contig {
            hole_size: 0,
            data_size: 0,
        }
    }

    fn hole_and_data(hole_size: usize, data_size: usize) -> Contig {
        Contig {
            hole_size,
            data_size,
        }
    }

    fn has_hole(&self) -> bool {
        self.hole_size != 0
    }

    fn has_data(&self) -> bool {
        self.data_size != 0
    }

    fn total_size(&self) -> usize {
        self.hole_size + self.data_size
    }

    fn shrink_hole_by(&mut self, size: usize) {
        self.hole_size -= size;
    }

    fn shrink_hole_to(&mut self, size: usize) {
        debug_assert!(self.hole_size >= size);

        let total_size = self.total_size();
        self.hole_size = size;
        self.data_size = total_size - size;
    }
}

/// A buffer (re)assembler.
///
/// A growable interval list: an idle assembler holds no storage at all, and
/// a lossy window may record up to `bound` runs -- the floor is
/// `ASSEMBLER_MAX_SEGMENT_COUNT`, and the owner raises the bound with the
/// receive ring (see `Assembler::set_bound`). Segments past the bound are
/// dropped for the peer to retransmit, exactly as the fixed array dropped
/// them.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Assembler {
    contigs: Vec<Contig>,
    bound: usize,
}

impl fmt::Display for Assembler {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[ ")?;
        for contig in self.contigs.iter() {
            write!(f, "{contig} ")?;
        }
        write!(f, "]")?;
        Ok(())
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Assembler {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "[ ");
        for contig in self.contigs.iter() {
            defmt::write!(fmt, "{} ", contig);
        }
        defmt::write!(fmt, "]");
    }
}

// Invariant on Assembler::contigs:
// - Every element holds data (data_size != 0).
// - Every element but the first has a hole in front (hole_size != 0).

impl Assembler {
    /// Create a new buffer assembler.
    pub const fn new() -> Assembler {
        Assembler {
            contigs: Vec::new(),
            bound: ASSEMBLER_MAX_SEGMENT_COUNT,
        }
    }

    /// Raise the ceiling on recorded runs. Sized by the owner to its receive
    /// ring; never below `ASSEMBLER_MAX_SEGMENT_COUNT`, so no configuration
    /// shrinks the capacity the deployed floor promises.
    pub fn set_bound(&mut self, bound: usize) {
        self.bound = bound.max(ASSEMBLER_MAX_SEGMENT_COUNT);
    }

    pub fn clear(&mut self) {
        self.contigs.clear();
    }

    fn front(&self) -> Contig {
        self.contigs.first().copied().unwrap_or(Contig::empty())
    }

    /// Return length of the front contiguous range without removing it from the assembler
    pub fn peek_front(&self) -> usize {
        let front = self.front();
        if front.has_hole() { 0 } else { front.data_size }
    }

    /// Return whether the assembler contains no data.
    pub fn is_empty(&self) -> bool {
        self.contigs.is_empty()
    }

    /// Remove a contig at the given index.
    fn remove_contig_at(&mut self, at: usize) {
        debug_assert!(self.contigs[at].has_data());
        self.contigs.remove(at);
    }

    /// Add a contig at the given index, and return a pointer to it.
    fn add_contig_at(&mut self, at: usize) -> Result<&mut Contig, TooManyHolesError> {
        if self.contigs.len() >= self.bound {
            return Err(TooManyHolesError);
        }
        self.contigs.insert(at, Contig::empty());
        Ok(&mut self.contigs[at])
    }

    /// Add a new contiguous range to the assembler,
    /// or return `Err(TooManyHolesError)` if too many discontinuities are already recorded.
    pub fn add(&mut self, mut offset: usize, size: usize) -> Result<(), TooManyHolesError> {
        if size == 0 {
            return Ok(());
        }

        let mut i = 0;

        // Find index of the contig containing the start of the range.
        loop {
            if i == self.contigs.len() {
                // The new range is after all the previous ranges. Add it.
                if self.contigs.len() >= self.bound {
                    return Err(TooManyHolesError);
                }
                self.contigs.push(Contig::hole_and_data(offset, size));
                return Ok(());
            }
            let contig = &mut self.contigs[i];
            if offset <= contig.total_size() {
                break;
            }
            offset -= contig.total_size();
            i += 1;
        }

        let contig = &mut self.contigs[i];
        if offset < contig.hole_size {
            // Range starts within the hole.

            if offset + size < contig.hole_size {
                // Range also ends within the hole.
                let new_contig = self.add_contig_at(i)?;
                new_contig.hole_size = offset;
                new_contig.data_size = size;

                // Previous contigs[index] got moved to contigs[index+1]
                self.contigs[i + 1].shrink_hole_by(offset + size);
                return Ok(());
            }

            // The range being added covers both a part of the hole and a part of the data
            // in this contig, shrink the hole in this contig.
            contig.shrink_hole_to(offset);
        }

        // coalesce contigs to the right.
        let mut j = i + 1;
        while j < self.contigs.len()
            && offset + size >= self.contigs[i].total_size() + self.contigs[j].hole_size
        {
            self.contigs[i].data_size += self.contigs[j].total_size();
            j += 1;
        }
        self.contigs.drain(i + 1..j);

        if offset + size > self.contigs[i].total_size() {
            // The added range still extends beyond the current contig. Increase data size.
            let left = offset + size - self.contigs[i].total_size();
            self.contigs[i].data_size += left;

            // Decrease hole size of the next, if any.
            if i + 1 < self.contigs.len() {
                self.contigs[i + 1].hole_size -= left;
            }
        }

        Ok(())
    }

    /// Remove a contiguous range from the front of the assembler.
    /// If no such range, return 0.
    pub fn remove_front(&mut self) -> usize {
        let front = self.front();
        if front.has_hole() || !front.has_data() {
            0
        } else {
            self.remove_contig_at(0);
            debug_assert!(front.data_size > 0);
            front.data_size
        }
    }

    /// Add a segment, then remove_front.
    ///
    /// This is equivalent to calling `add` then `remove_front` individually,
    /// except it's guaranteed to not fail when offset = 0.
    /// This is required for TCP: we must never drop the next expected segment, or
    /// the protocol might get stuck.
    pub fn add_then_remove_front(
        &mut self,
        offset: usize,
        size: usize,
    ) -> Result<usize, TooManyHolesError> {
        // This is the only case where a segment at offset=0 would cause the
        // total amount of contigs to rise (and therefore can potentially cause
        // a TooManyHolesError). Handle it in a way that is guaranteed to succeed.
        if offset == 0
            && let Some(front) = self.contigs.first_mut()
            && size < front.hole_size
        {
            front.hole_size -= size;
            return Ok(size);
        }

        self.add(offset, size)?;
        Ok(self.remove_front())
    }

    /// Iterate over all of the contiguous data ranges.
    ///
    /// Returns `(offset, size)` tuples for each contiguous data range, where
    /// offset is relative to the start of the assembler.
    ///
    ///    Data        Hole        Data
    /// |--- 100 ---|--- 200 ---|--- 100 ---|
    ///
    /// Would return the ranges: ``(0, 100), (300, 400)``
    pub fn iter_data(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
        let mut offset = 0;
        self.contigs.iter().filter_map(move |contig| {
            offset += contig.hole_size;
            let left = offset;
            offset += contig.data_size;
            let right = offset;
            if left < right {
                Some((left, right))
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::vec::Vec;

    impl From<Vec<(usize, usize)>> for Assembler {
        fn from(vec: Vec<(usize, usize)>) -> Assembler {
            let contigs = vec
                .into_iter()
                .filter(|&(_, data_size)| data_size != 0)
                .map(|(hole_size, data_size)| Contig {
                    hole_size,
                    data_size,
                })
                .collect();
            Assembler {
                contigs,
                bound: ASSEMBLER_MAX_SEGMENT_COUNT,
            }
        }
    }

    macro_rules! contigs {
        [$( $x:expr ),*] => ({
            Assembler::from(vec![$( $x ),*])
        })
    }

    #[test]
    fn test_new() {
        let assr = Assembler::new();
        assert_eq!(assr, contigs![]);
    }

    #[test]
    fn test_empty_add_full() {
        let mut assr = Assembler::new();
        assert_eq!(assr.add(0, 16), Ok(()));
        assert_eq!(assr, contigs![(0, 16)]);
    }

    #[test]
    fn test_empty_add_front() {
        let mut assr = Assembler::new();
        assert_eq!(assr.add(0, 4), Ok(()));
        assert_eq!(assr, contigs![(0, 4)]);
    }

    #[test]
    fn test_empty_add_back() {
        let mut assr = Assembler::new();
        assert_eq!(assr.add(12, 4), Ok(()));
        assert_eq!(assr, contigs![(12, 4)]);
    }

    #[test]
    fn test_empty_add_mid() {
        let mut assr = Assembler::new();
        assert_eq!(assr.add(4, 8), Ok(()));
        assert_eq!(assr, contigs![(4, 8)]);
    }

    #[test]
    fn test_partial_add_front() {
        let mut assr = contigs![(4, 8)];
        assert_eq!(assr.add(0, 4), Ok(()));
        assert_eq!(assr, contigs![(0, 12)]);
    }

    #[test]
    fn test_partial_add_back() {
        let mut assr = contigs![(4, 8)];
        assert_eq!(assr.add(12, 4), Ok(()));
        assert_eq!(assr, contigs![(4, 12)]);
    }

    #[test]
    fn test_partial_add_front_overlap() {
        let mut assr = contigs![(4, 8)];
        assert_eq!(assr.add(0, 8), Ok(()));
        assert_eq!(assr, contigs![(0, 12)]);
    }

    #[test]
    fn test_partial_add_front_overlap_split() {
        let mut assr = contigs![(4, 8)];
        assert_eq!(assr.add(2, 6), Ok(()));
        assert_eq!(assr, contigs![(2, 10)]);
    }

    #[test]
    fn test_partial_add_back_overlap() {
        let mut assr = contigs![(4, 8)];
        assert_eq!(assr.add(8, 8), Ok(()));
        assert_eq!(assr, contigs![(4, 12)]);
    }

    #[test]
    fn test_partial_add_back_overlap_split() {
        let mut assr = contigs![(4, 8)];
        assert_eq!(assr.add(10, 4), Ok(()));
        assert_eq!(assr, contigs![(4, 10)]);
    }

    #[test]
    fn test_partial_add_both_overlap() {
        let mut assr = contigs![(4, 8)];
        assert_eq!(assr.add(0, 16), Ok(()));
        assert_eq!(assr, contigs![(0, 16)]);
    }

    #[test]
    fn test_partial_add_both_overlap_split() {
        let mut assr = contigs![(4, 8)];
        assert_eq!(assr.add(2, 12), Ok(()));
        assert_eq!(assr, contigs![(2, 12)]);
    }

    #[test]
    fn test_rejected_add_keeps_state() {
        let mut assr = Assembler::new();
        for c in 1..=ASSEMBLER_MAX_SEGMENT_COUNT {
            assert_eq!(assr.add(c * 10, 3), Ok(()));
        }
        // Maximum of allowed holes is reached
        let assr_before = assr.clone();
        assert_eq!(assr.add(1, 3), Err(TooManyHolesError));
        assert_eq!(assr_before, assr);
    }

    /// The bound is the ceiling `set_bound` raises and the deployed
    /// constant floors: a raised assembler holds more runs, and no request
    /// can shrink it below the floor.
    #[test]
    fn the_bound_grows_and_floors() {
        let mut assr = Assembler::new();
        assr.set_bound(2 * ASSEMBLER_MAX_SEGMENT_COUNT);
        for c in 1..=2 * ASSEMBLER_MAX_SEGMENT_COUNT {
            assert_eq!(assr.add(c * 10, 3), Ok(()));
        }
        assert_eq!(assr.add(1, 3), Err(TooManyHolesError));

        // Lowering below the floor clamps to the floor.
        assr.clear();
        assr.set_bound(1);
        for c in 1..=ASSEMBLER_MAX_SEGMENT_COUNT {
            assert_eq!(assr.add(c * 10, 3), Ok(()));
        }
        assert_eq!(assr.add(1, 3), Err(TooManyHolesError));
    }

    #[test]
    fn test_empty_remove_front() {
        let mut assr = contigs![];
        assert_eq!(assr.remove_front(), 0);
    }

    #[test]
    fn test_trailing_hole_remove_front() {
        let mut assr = contigs![(0, 4)];
        assert_eq!(assr.remove_front(), 4);
        assert_eq!(assr, contigs![]);
    }

    #[test]
    fn test_trailing_data_remove_front() {
        let mut assr = contigs![(0, 4), (4, 4)];
        assert_eq!(assr.remove_front(), 4);
        assert_eq!(assr, contigs![(4, 4)]);
    }

    #[test]
    fn test_boundary_case_remove_front() {
        let mut vec = vec![(1, 1); ASSEMBLER_MAX_SEGMENT_COUNT];
        vec[0] = (0, 2);
        let mut assr = Assembler::from(vec);
        assert_eq!(assr.remove_front(), 2);
        let mut vec = vec![(1, 1); ASSEMBLER_MAX_SEGMENT_COUNT];
        vec[ASSEMBLER_MAX_SEGMENT_COUNT - 1] = (0, 0);
        let exp_assr = Assembler::from(vec);
        assert_eq!(assr, exp_assr);
    }

    #[test]
    fn test_shrink_next_hole() {
        let mut assr = Assembler::new();
        assert_eq!(assr.add(100, 10), Ok(()));
        assert_eq!(assr.add(50, 10), Ok(()));
        assert_eq!(assr.add(40, 30), Ok(()));
        assert_eq!(assr, contigs![(40, 30), (30, 10)]);
    }

    #[test]
    fn test_join_two() {
        let mut assr = Assembler::new();
        assert_eq!(assr.add(10, 10), Ok(()));
        assert_eq!(assr.add(50, 10), Ok(()));
        assert_eq!(assr.add(15, 40), Ok(()));
        assert_eq!(assr, contigs![(10, 50)]);
    }

    #[test]
    fn test_join_two_reversed() {
        let mut assr = Assembler::new();
        assert_eq!(assr.add(50, 10), Ok(()));
        assert_eq!(assr.add(10, 10), Ok(()));
        assert_eq!(assr.add(15, 40), Ok(()));
        assert_eq!(assr, contigs![(10, 50)]);
    }

    #[test]
    fn test_join_two_overlong() {
        let mut assr = Assembler::new();
        assert_eq!(assr.add(50, 10), Ok(()));
        assert_eq!(assr.add(10, 10), Ok(()));
        assert_eq!(assr.add(15, 60), Ok(()));
        assert_eq!(assr, contigs![(10, 65)]);
    }

    #[test]
    fn test_iter_empty() {
        let assr = Assembler::new();
        let segments: Vec<_> = assr.iter_data().collect();
        assert_eq!(segments, vec![]);
    }

    #[test]
    fn test_iter_full() {
        let mut assr = Assembler::new();
        assert_eq!(assr.add(0, 16), Ok(()));
        let segments: Vec<_> = assr.iter_data().collect();
        assert_eq!(segments, vec![(0, 16)]);
    }

    #[test]
    fn test_iter_one_front() {
        let mut assr = Assembler::new();
        assert_eq!(assr.add(0, 4), Ok(()));
        let segments: Vec<_> = assr.iter_data().collect();
        assert_eq!(segments, vec![(0, 4)]);
    }

    #[test]
    fn test_iter_one_back() {
        let mut assr = Assembler::new();
        assert_eq!(assr.add(12, 4), Ok(()));
        let segments: Vec<_> = assr.iter_data().collect();
        assert_eq!(segments, vec![(12, 16)]);
    }

    #[test]
    fn test_iter_one_mid() {
        let mut assr = Assembler::new();
        assert_eq!(assr.add(4, 8), Ok(()));
        let segments: Vec<_> = assr.iter_data().collect();
        assert_eq!(segments, vec![(4, 12)]);
    }

    #[test]
    fn test_iter_one_trailing_gap() {
        let assr = contigs![(4, 8)];
        let segments: Vec<_> = assr.iter_data().collect();
        assert_eq!(segments, vec![(4, 12)]);
    }

    #[test]
    fn test_iter_two_split() {
        let assr = contigs![(2, 6), (4, 1)];
        let segments: Vec<_> = assr.iter_data().collect();
        assert_eq!(segments, vec![(2, 8), (12, 13)]);
    }

    #[test]
    fn test_iter_three_split() {
        let assr = contigs![(2, 6), (2, 1), (2, 2)];
        let segments: Vec<_> = assr.iter_data().collect();
        assert_eq!(segments, vec![(2, 8), (10, 11), (13, 15)]);
    }

    #[test]
    fn test_issue_694() {
        let mut assr = Assembler::new();
        assert_eq!(assr.add(0, 1), Ok(()));
        assert_eq!(assr.add(2, 1), Ok(()));
        assert_eq!(assr.add(1, 1), Ok(()));
    }

    #[test]
    fn test_add_then_remove_front() {
        let mut assr = Assembler::new();
        assert_eq!(assr.add(50, 10), Ok(()));
        assert_eq!(assr.add_then_remove_front(10, 10), Ok(0));
        assert_eq!(assr, contigs![(10, 10), (30, 10)]);
    }

    #[test]
    fn test_add_then_remove_front_at_front() {
        let mut assr = Assembler::new();
        assert_eq!(assr.add(50, 10), Ok(()));
        assert_eq!(assr.add_then_remove_front(0, 10), Ok(10));
        assert_eq!(assr, contigs![(40, 10)]);
    }

    #[test]
    fn test_add_then_remove_front_at_front_touch() {
        let mut assr = Assembler::new();
        assert_eq!(assr.add(50, 10), Ok(()));
        assert_eq!(assr.add_then_remove_front(0, 50), Ok(60));
        assert_eq!(assr, contigs![]);
    }

    #[test]
    fn test_add_then_remove_front_at_front_full() {
        let mut assr = Assembler::new();
        for c in 1..=ASSEMBLER_MAX_SEGMENT_COUNT {
            assert_eq!(assr.add(c * 10, 3), Ok(()));
        }
        // Maximum of allowed holes is reached
        let assr_before = assr.clone();
        assert_eq!(assr.add_then_remove_front(1, 3), Err(TooManyHolesError));
        assert_eq!(assr_before, assr);
    }

    #[test]
    fn test_add_then_remove_front_at_front_full_offset_0() {
        let mut assr = Assembler::new();
        for c in 1..=ASSEMBLER_MAX_SEGMENT_COUNT {
            assert_eq!(assr.add(c * 10, 3), Ok(()));
        }
        assert_eq!(assr.add_then_remove_front(0, 3), Ok(3));
    }

    // Test against an obviously-correct but inefficient bitmap impl.
    #[test]
    fn test_random() {
        use rand::Rng;

        const MAX_INDEX: usize = 256;

        for max_size in [2, 5, 10, 100] {
            for _ in 0..300 {
                //println!("===");
                let mut assr = Assembler::new();
                let mut map = [false; MAX_INDEX];

                for _ in 0..60 {
                    let offset = rand::thread_rng().gen_range(0..MAX_INDEX - max_size - 1);
                    let size = rand::thread_rng().gen_range(1..=max_size);

                    //println!("add {}..{} {}", offset, offset + size, size);
                    // Real impl
                    let res = assr.add(offset, size);

                    // Bitmap impl
                    let mut map2 = map;
                    map2[offset..][..size].fill(true);

                    let mut contigs = vec![];
                    let mut hole: usize = 0;
                    let mut data: usize = 0;
                    for b in map2 {
                        if b {
                            data += 1;
                        } else {
                            if data != 0 {
                                contigs.push((hole, data));
                                hole = 0;
                                data = 0;
                            }
                            hole += 1;
                        }
                    }

                    // Compare.
                    let wanted_res = if contigs.len() > ASSEMBLER_MAX_SEGMENT_COUNT {
                        Err(TooManyHolesError)
                    } else {
                        Ok(())
                    };
                    assert_eq!(res, wanted_res);
                    if res.is_ok() {
                        map = map2;
                        assert_eq!(assr, Assembler::from(contigs));
                    }
                }
            }
        }
    }
}
