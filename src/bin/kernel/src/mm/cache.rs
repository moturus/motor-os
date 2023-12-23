// Memory segment caching.
use crate::{mm::PAGE_SIZE_SMALL_LOG2, util::SpinLock};
use core::sync::atomic::*;
use moto_sys::ErrorCode;

use super::{MemorySegment, PAGE_SIZE_SMALL};

const CACHED_SEGMENTS_PER_PAGE: usize = (PAGE_SIZE_SMALL as usize - 32) / 16;

// A cache of memory segments of the same size. Forms an intrusive list.
#[repr(C)]
struct CacheLine {
    count: u64, // Total cached, here and "below".
    prev_block: u64,
    next_block: u64,
    _padding: u64,
    cache: [MemorySegment; CACHED_SEGMENTS_PER_PAGE],
}

const _: () = assert!(PAGE_SIZE_SMALL as usize == core::mem::size_of::<CacheLine>());

impl CacheLine {
    fn push(&mut self, segment: MemorySegment) -> Result<(), ErrorCode> {
        if self.count as usize == CACHED_SEGMENTS_PER_PAGE {
            return Err(ErrorCode::NotReady);
        }

        self.cache[self.count as usize] = segment;
        self.count += 1;
        Ok(())
    }

    fn pop(&mut self) -> Option<MemorySegment> {
        if self.count == 0 {
            return None;
        }

        self.count -= 1;
        if (self.count as usize) < CACHED_SEGMENTS_PER_PAGE {
            debug_assert_eq!(0, self.prev_block);
            debug_assert_eq!(0, self.next_block);
            return Some(self.cache[self.count as usize]);
        }

        None
        // todo!("pop from prev")
    }

    fn new() -> Result<*mut Self, ErrorCode> {
        // Allocate a page. Note that we don't need to map the frame/page here,
        // as all phys mem has been mapped at PAGING_DIRECT_MAP_OFFSET.
        let phys_addr = super::phys::phys_allocate_frameless(super::PageType::SmallPage)?;
        let virt_addr = phys_addr + super::PAGING_DIRECT_MAP_OFFSET;

        let result = virt_addr as usize as *mut Self;
        unsafe {
            let cache_line = result.as_mut().unwrap_unchecked();
            cache_line.count = 0;
            cache_line.prev_block = 0;
            cache_line.next_block = 0;
        }

        Ok(result)
    }

    fn drop(self_ptr: *mut Self) {
        unsafe {
            let cache_line = self_ptr.as_mut().unwrap();
            assert_eq!(0, cache_line.count);
            debug_assert_eq!(0, cache_line.prev_block);
            debug_assert_eq!(0, cache_line.next_block);
        }
        super::phys::phys_deallocate_frameless(
            (self_ptr as usize as u64) - super::PAGING_DIRECT_MAP_OFFSET,
            super::PageType::SmallPage,
        );
    }
}

const CACHE_LINES: usize = 30;

pub(super) struct SegmentCache {
    caches: [SpinLock<*mut CacheLine>; CACHE_LINES],
    counts: [AtomicU64; CACHE_LINES],
}

impl Drop for SegmentCache {
    fn drop(&mut self) {
        for idx in 0..CACHE_LINES {
            assert_eq!(0, self.counts[idx].load(Ordering::Relaxed));
            let mut lock = self.caches[idx].lock(line!());
            if lock.is_null() {
                return;
            }

            CacheLine::drop(*lock);
            *lock = core::ptr::null_mut();
        }
    }
}

impl SegmentCache {
    pub(super) const fn new() -> Self {
        const VAL0: SpinLock<*mut CacheLine> = SpinLock::new(core::ptr::null_mut());
        const VAL1: AtomicU64 = AtomicU64::new(0);
        Self {
            caches: [VAL0; CACHE_LINES],
            counts: [VAL1; CACHE_LINES],
        }
    }

    pub(super) fn _count(&self, num_pages: usize) -> u64 {
        debug_assert!(num_pages.is_power_of_two());
        let idx = num_pages.ilog2() as usize;
        debug_assert!(idx < CACHE_LINES);

        self.counts[idx].load(Ordering::Relaxed)
    }

    pub(super) fn push(&self, segment: MemorySegment, num_pages: usize) -> Result<(), ErrorCode> {
        debug_assert!(num_pages.is_power_of_two());
        debug_assert_eq!(segment.size, (num_pages as u64) << PAGE_SIZE_SMALL_LOG2);
        let idx = num_pages.ilog2() as usize;
        debug_assert!(idx < CACHE_LINES);

        self.push_at_line(idx, segment)
    }

    pub(super) fn pop(&self, num_pages: usize) -> Option<MemorySegment> {
        debug_assert!(num_pages.is_power_of_two());
        let idx = num_pages.ilog2() as usize;
        debug_assert!(idx < CACHE_LINES);

        self.pop_from_line(idx)
    }

    pub(super) fn pop_any_final(&self) -> Option<MemorySegment> {
        // Not very efficient, but used only during process drop, so ok.
        for idx in 0..CACHE_LINES {
            if self.counts[idx].load(Ordering::Relaxed) == 0 {
                continue;
            }

            // We do unwrap() below to check that our counts are correct.
            let segment = self.pop_from_line(idx).unwrap();
            return Some(segment);
        }

        None
    }

    fn push_at_line(&self, idx: usize, segment: MemorySegment) -> Result<(), ErrorCode> {
        debug_assert!(idx < CACHE_LINES);

        let mut lock = self.caches[idx].lock(line!());
        if lock.is_null() {
            *lock = CacheLine::new()?;
        }

        let line = unsafe { (*lock).as_mut().unwrap() };
        line.push(segment)?;

        self.counts[idx].fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn pop_from_line(&self, idx: usize) -> Option<MemorySegment> {
        debug_assert!(idx < CACHE_LINES);

        let lock = self.caches[idx].lock(line!());
        if lock.is_null() {
            return None;
        }

        let line = unsafe { (*lock).as_mut().unwrap() };
        match line.pop() {
            Some(seg) => {
                self.counts[idx].fetch_sub(1, Ordering::Relaxed);
                Some(seg)
            }
            None => None,
        }
    }
}
