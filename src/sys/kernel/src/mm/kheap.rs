use core::{alloc::Layout, sync::atomic::*};

use super::PAGE_SIZE_SMALL;
use super::PAGE_SIZE_SMALL_LOG2;

// The fallback allocator.
pub(super) struct RawAllocator {
    raw_area_start: AtomicU64,
    raw_area_size: AtomicU64,
    raw_area_used: AtomicU64,
    allocated: AtomicU64,
}

unsafe impl core::alloc::GlobalAlloc for RawAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        assert!(layout.align() as u64 <= PAGE_SIZE_SMALL);

        if !super::memory_initialized() {
            let prev_offset = self
                .raw_area_used
                .fetch_add(layout.size() as u64, Ordering::AcqRel);
            assert!(
                prev_offset + layout.size() as u64 <= self.raw_area_size.load(Ordering::Relaxed)
            );

            #[cfg(debug_assertions)]
            {
                let total = prev_offset + layout.size() as u64;
                crate::raw_log!(
                    "startup alloc: {:?} total: 0x{:x} ({})",
                    layout,
                    total,
                    total
                );
            }

            return (self.raw_area_start.load(Ordering::Relaxed) + prev_offset) as usize as *mut u8;
        }

        let size = super::align_up(layout.size() as u64, PAGE_SIZE_SMALL);
        if let Ok(segment) = super::virt::vmem_allocate_pages(
            super::virt::VmemKind::KernelHeap,
            size >> PAGE_SIZE_SMALL_LOG2,
        ) {
            self.allocated.fetch_add(size, Ordering::Relaxed);
            segment.start as usize as *mut u8
        } else {
            core::ptr::null_mut()
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        let addr = ptr as usize as u64;
        if addr >= self.raw_area_start.load(Ordering::Relaxed)
            && addr
                < self.raw_area_start.load(Ordering::Relaxed)
                    + self.raw_area_size.load(Ordering::Relaxed)
        {
            #[cfg(debug_assertions)]
            crate::raw_log!("dealloc in raw area: {:?}", _layout);
            return;
        }
        let sz = super::virt::vmem_free(ptr as usize as u64, super::virt::VmemKind::KernelHeap);
        self.allocated.fetch_sub(sz, Ordering::Relaxed);
    }
}

// #[global_allocator]
pub(super) static RAW_ALLOCATOR: RawAllocator = RawAllocator {
    raw_area_start: AtomicU64::new(0),
    raw_area_size: AtomicU64::new(0),
    raw_area_used: AtomicU64::new(0),
    allocated: AtomicU64::new(0),
};

#[global_allocator]
static KHEAP: frusa::Frusa4K = frusa::Frusa4K::new(&RAW_ALLOCATOR);

pub fn init(segment: super::MemorySegment) {
    assert_eq!(
        0,
        RAW_ALLOCATOR
            .raw_area_start
            .swap(segment.start, Ordering::Release)
    );
    assert_eq!(
        0,
        RAW_ALLOCATOR
            .raw_area_size
            .swap(segment.size, Ordering::Release)
    );

    RAW_ALLOCATOR
        .allocated
        .fetch_add(segment.size, Ordering::Relaxed);
}

#[derive(Debug)]
pub struct HeapStats {
    pub total_in_heap: usize,
}

pub fn heap_stats() -> HeapStats {
    HeapStats {
        total_in_heap: RAW_ALLOCATOR.allocated.load(Ordering::Relaxed) as usize,
    }
}

pub fn reclaim() {
    KHEAP.reclaim();
}
