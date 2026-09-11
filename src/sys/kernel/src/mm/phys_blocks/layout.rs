//! Boot input normalization: byte ranges become validated page spans.

use super::{BLOCK_SHIFT, MAX_BLOCKS, PAGE_SHIFT};
use crate::mm::phys::FIXED_MID_SEGMENT;
use crate::mm::MemorySegment;
use alloc::vec::Vec;
use core::ops::Range;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum LayoutError {
    Arithmetic,
    Order,
    Span,
    FixedMid,
    Raw,
    Initrd,
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
}

const PAGE: u64 = 1 << PAGE_SHIFT;
const BLOCK: u64 = 1 << BLOCK_SHIFT;

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
        })
    }
}

#[cfg(debug_assertions)]
#[path = "layout_tests.rs"]
mod tests;

#[cfg(debug_assertions)]
pub(super) fn test() {
    tests::run();
}
