//! Boot input normalization: byte ranges become validated page spans.

use super::shaping::{Shape, ShapeError};
use super::{BlockLine, BLOCK_SHIFT, MAX_BLOCKS, PAGES, PAGE_SHIFT, RAM, SMALL_ONLY, SPLIT, WHOLE};
use crate::mm::phys::FIXED_MID_SEGMENT;
use crate::mm::MemorySegment;
use alloc::vec::Vec;
use core::ops::Range;
use core::sync::atomic::AtomicU64;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum LayoutError {
    Arithmetic,
    Order,
    Span,
    FixedMid,
    Raw,
    Initrd,
    Heap { needed: u64, remaining: u64 },
}

// Permanent boot-heap storage for one span: descriptor lines, the F and W
// bitmaps with their alignment padding, and the list-state table's base
// pointer. The table itself is carved from managed RAM.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Budget {
    pub lines: usize,
    pub words: usize,
    pub table_pages: u16,
    pub heap_bytes: u64,
}

impl Budget {
    pub(super) fn preflight(blocks: usize, heap_remaining: u64) -> Result<Self, LayoutError> {
        if blocks > MAX_BLOCKS {
            return Err(LayoutError::Span);
        }
        let lines = blocks.div_ceil(4);
        let words = blocks.div_ceil(64);
        let line = size_of::<BlockLine>() as u64;
        let word = size_of::<AtomicU64>() as u64;
        let heap_bytes = (lines as u64 + 1) * line + 2 * (words as u64 + 1) * word + 8;
        if heap_bytes > heap_remaining {
            return Err(LayoutError::Heap {
                needed: heap_bytes,
                remaining: heap_remaining,
            });
        }
        Ok(Self {
            lines,
            words,
            table_pages: words as u16,
            heap_bytes,
        })
    }
}

// Sorted, disjoint page-number intervals. `managed` is coalesced and excludes
// the fixed mid segment; the caller already removed the kernel and boot heap.
// `ram` lists block indexes touching raw RAM, before any page trimming.
pub(super) struct Layout {
    pub managed: Vec<Range<u64>>,
    pub reserved: Vec<Range<u64>>,
    pub initrd: Range<u64>,
    pub ram: Vec<Range<usize>>,
    pub blocks: usize,
    // Block-local scratch for shaping, reused across blocks.
    managed_local: Vec<Range<u16>>,
    reserved_local: Vec<Range<u16>>,
}

pub(super) struct Shaped {
    pub shape: Shape,
    pub flags: u8,
}

const PAGE: u64 = 1 << PAGE_SHIFT;
const BLOCK: u64 = 1 << BLOCK_SHIFT;
const BLOCK_PAGES: u64 = BLOCK / PAGE;
// Blocks below 128 MiB never supply huge pages.
const DUAL_PURPOSE_BLOCK: usize = (128 << 20) >> BLOCK_SHIFT;

fn bytes(segment: &MemorySegment) -> Result<Range<u64>, LayoutError> {
    let end = segment
        .start
        .checked_add(segment.size)
        .ok_or(LayoutError::Arithmetic)?;
    Ok(segment.start..end)
}

fn inward(range: &Range<u64>, unit: u64) -> Range<u64> {
    let start = range.start.div_ceil(unit);
    start..(range.end / unit).max(start)
}

fn outward(range: &Range<u64>, unit: u64) -> Range<u64> {
    (range.start / unit)..range.end.div_ceil(unit)
}

// Byte segments must be sorted and disjoint; empty ones carry nothing. The
// rounded results are coalesced when adjacent or, after outward rounding,
// overlapping.
fn convert(
    segments: &[MemorySegment],
    round: impl Fn(&Range<u64>) -> Range<u64>,
) -> Result<Vec<Range<u64>>, LayoutError> {
    let mut out: Vec<Range<u64>> = Vec::with_capacity(segments.len());
    let mut end = 0;
    for segment in segments.iter().filter(|segment| segment.size != 0) {
        let range = bytes(segment)?;
        if range.start < end {
            return Err(LayoutError::Order);
        }
        end = range.end;
        let rounded = round(&range);
        if rounded.is_empty() {
            continue;
        }
        match out.last_mut() {
            Some(last) if rounded.start <= last.end => last.end = last.end.max(rounded.end),
            _ => out.push(rounded),
        }
    }
    Ok(out)
}

fn contains(outer: &Range<u64>, inner: &Range<u64>) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}

// Both lists are sorted and disjoint.
fn covered(inner: &[Range<u64>], outer: &[Range<u64>]) -> bool {
    let mut outer = outer.iter();
    let mut cover = 0..0;
    inner.iter().all(|range| {
        while cover.end < range.end {
            match outer.next() {
                Some(next) => cover = next.clone(),
                None => return false,
            }
        }
        contains(&cover, range)
    })
}

fn exclude(ranges: &[Range<u64>], hole: &Range<u64>) -> Vec<Range<u64>> {
    let mut out = Vec::with_capacity(ranges.len() + 1);
    for range in ranges {
        for part in [
            range.start..range.end.min(hole.start),
            range.start.max(hole.end)..range.end,
        ] {
            if !part.is_empty() {
                out.push(part);
            }
        }
    }
    out
}

impl Layout {
    pub(super) fn new(
        available: &[MemorySegment],
        reserved: &[MemorySegment],
        initrd: MemorySegment,
        raw: &[MemorySegment],
    ) -> Result<Self, LayoutError> {
        let ram = convert(raw, |range| outward(range, BLOCK))?;
        let blocks = ram.last().map_or(0, |range| range.end);
        if blocks > MAX_BLOCKS as u64 {
            return Err(LayoutError::Span);
        }
        let ram = ram
            .iter()
            .map(|range| range.start as usize..range.end as usize)
            .collect();

        let managed = convert(available, |range| inward(range, PAGE))?;
        if !covered(&managed, &convert(raw, |range| inward(range, PAGE))?) {
            return Err(LayoutError::Raw);
        }
        let mid = inward(&bytes(&FIXED_MID_SEGMENT)?, PAGE);
        if !managed.iter().any(|range| contains(range, &mid)) {
            return Err(LayoutError::FixedMid);
        }
        let managed = exclude(&managed, &mid);

        let reserved = convert(reserved, |range| outward(range, PAGE))?;
        let initrd = match initrd.size {
            0 => 0..0,
            _ => outward(&bytes(&initrd)?, PAGE),
        };
        if !initrd.is_empty()
            && (!managed.iter().any(|range| contains(range, &initrd))
                || reserved
                    .iter()
                    .any(|range| range.start < initrd.end && initrd.start < range.end))
        {
            return Err(LayoutError::Initrd);
        }

        Ok(Self {
            managed,
            reserved,
            initrd,
            ram,
            blocks: blocks as usize,
            managed_local: Vec::new(),
            reserved_local: Vec::new(),
        })
    }

    // Shape one block of the span from the normalized page intervals.
    pub(super) fn block(&mut self, index: usize) -> Result<Shaped, ShapeError> {
        assert!(index < self.blocks);
        clip(&self.managed, index, &mut self.managed_local);
        clip(&self.reserved, index, &mut self.reserved_local);
        let initrd = clip_one(&self.initrd, index).unwrap_or(0..0);
        let shape = Shape::new(&self.managed_local, &self.reserved_local, initrd)?;
        let mut flags = 0;
        if self.ram.iter().any(|range| range.contains(&index)) {
            flags |= RAM;
        }
        if index < DUAL_PURPOSE_BLOCK {
            flags |= SMALL_ONLY;
        }
        Ok(Shaped { shape, flags })
    }

    // The lowest block whose retained free run holds `pages`, and the run's
    // first page: the list-state table's permanent backing.
    pub(super) fn carve_table(&mut self, pages: u16) -> Result<Option<(usize, u16)>, ShapeError> {
        for index in 0..self.blocks {
            let shaped = self.block(index)?;
            let inner = shaped.shape.inner;
            let run = match shaped.shape.state {
                WHOLE => 0..PAGES,
                SPLIT => inner.unused_lo..inner.unused_hi,
                _ => continue,
            };
            if pages != 0 && run.end - run.start >= pages {
                return Ok(Some((index, run.start)));
            }
        }
        Ok(None)
    }
}

// A page interval intersected with block `index`, as block-local pages.
fn clip_one(range: &Range<u64>, index: usize) -> Option<Range<u16>> {
    let base = index as u64 * BLOCK_PAGES;
    let lo = range.start.max(base);
    let hi = range.end.min(base + BLOCK_PAGES);
    (lo < hi).then(|| (lo - base) as u16..(hi - base) as u16)
}

fn clip(ranges: &[Range<u64>], index: usize, out: &mut Vec<Range<u16>>) {
    out.clear();
    for range in ranges {
        if range.start >= (index as u64 + 1) * BLOCK_PAGES {
            break;
        }
        out.extend(clip_one(range, index));
    }
}

#[cfg(debug_assertions)]
#[path = "layout_tests.rs"]
mod tests;

#[cfg(debug_assertions)]
pub(super) fn test() {
    tests::run();
}
