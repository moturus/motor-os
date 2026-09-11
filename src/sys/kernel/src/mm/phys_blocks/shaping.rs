use super::{Inner, ABSENT, PAGES, SPLIT, WHOLE};
use core::ops::Range;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ShapeError {
    Bounds,
    Overlap,
    Initrd,
}

pub(super) struct Shape {
    pub inner: Inner,
    pub state: u8,
    pub managed: u16,
    pub reserved: u16,
    pub discarded: u16,
}

fn validate(ranges: &[Range<u16>]) -> Result<(), ShapeError> {
    let mut end = 0;
    for range in ranges {
        if range.start >= range.end || range.end > PAGES {
            return Err(ShapeError::Bounds);
        }
        if range.start < end {
            return Err(ShapeError::Overlap);
        }
        end = range.end;
    }
    Ok(())
}

fn overlap(a: &Range<u16>, b: &Range<u16>) -> u16 {
    a.end.min(b.end).saturating_sub(a.start.max(b.start))
}

// Inputs are block-local page intervals. The caller normalizes byte ranges,
// excludes kernel/fixed-mid RAM, and separately derives RAM/SMALL_ONLY flags.
// This helper touches no page data and allocates no temporary storage.
impl Shape {
    pub(super) fn new(
        managed: &[Range<u16>],
        reservations: &[Range<u16>],
        initrd: Range<u16>,
    ) -> Result<Self, ShapeError> {
        validate(managed)?;
        validate(reservations)?;
        if initrd.start > initrd.end
            || initrd.end > PAGES
            || (initrd.is_empty() && initrd.start != 0)
        {
            return Err(ShapeError::Bounds);
        }
        let initrd_pages = initrd.end - initrd.start;
        if managed.iter().map(|run| overlap(run, &initrd)).sum::<u16>() != initrd_pages
            || reservations.iter().any(|run| overlap(run, &initrd) != 0)
        {
            return Err(ShapeError::Initrd);
        }

        let mut retained = 0..0;
        let mut free = 0;
        let mut consider = |lo: u16, hi: u16| {
            if lo >= hi {
                return;
            }
            free += hi - lo;
            let adjacent = initrd_pages == 0 || hi == initrd.start || lo == initrd.end;
            // Ascending traversal makes a strict length comparison choose the
            // lowest-address run on ties, including either side of the initrd.
            if adjacent && hi - lo > retained.end - retained.start {
                retained = lo..hi;
            }
        };
        let mut gap = |lo: u16, hi: u16| {
            if initrd_pages == 0 {
                consider(lo, hi);
            } else {
                consider(lo, hi.min(initrd.start));
                consider(lo.max(initrd.end), hi);
            }
        };
        let mut runs = managed.iter().cloned().peekable();
        while let Some(mut run) = runs.next() {
            // Adjacent input ranges form one RAM interval before reservations
            // are removed; an initrd may span their original boundary.
            while runs.peek().is_some_and(|next| next.start == run.end) {
                run.end = runs.next().unwrap().end;
            }
            let mut lo = run.start;
            for reserved in reservations {
                if reserved.end <= lo {
                    continue;
                }
                if reserved.start >= run.end {
                    break;
                }
                gap(lo, reserved.start.min(run.end));
                lo = reserved.end.min(run.end);
            }
            gap(lo, run.end);
        }
        let managed = managed.iter().map(|run| run.end - run.start).sum::<u16>();
        let retained_pages = retained.end - retained.start;
        let alloc = if initrd_pages == 0 {
            retained.clone()
        } else if retained_pages == 0 {
            initrd
        } else {
            retained.start.min(initrd.start)..retained.end.max(initrd.end)
        };
        let state = if managed == 0 {
            ABSENT
        } else if retained_pages == PAGES {
            WHOLE
        } else {
            SPLIT
        };
        Ok(Self {
            inner: Inner {
                head: 0,
                used: PAGES - retained_pages,
                unused_lo: if state == WHOLE { 0 } else { retained.start },
                unused_hi: if state == WHOLE { 0 } else { retained.end },
                alloc_lo: alloc.start,
                alloc_hi: alloc.end,
            },
            state,
            managed,
            reserved: managed - initrd_pages - retained_pages,
            discarded: free - retained_pages,
        })
    }
}

impl Shape {
    // Take the first `pages` of the retained free run as permanent, allocated
    // table storage. The backing block starts split with its bounds intact.
    pub(super) fn carve(&mut self, pages: u16) -> Result<(), ShapeError> {
        let run = match self.state {
            WHOLE => 0..PAGES,
            SPLIT => self.inner.unused_lo..self.inner.unused_hi,
            _ => return Err(ShapeError::Bounds),
        };
        if pages == 0 || pages > run.end - run.start {
            return Err(ShapeError::Bounds);
        }
        self.inner.unused_lo = run.start + pages;
        self.inner.unused_hi = run.end;
        self.inner.used += pages;
        self.state = SPLIT;
        Ok(())
    }
}

#[cfg(debug_assertions)]
#[path = "shaping_tests.rs"]
mod tests;

#[cfg(debug_assertions)]
pub(super) fn test() {
    tests::run();
}
