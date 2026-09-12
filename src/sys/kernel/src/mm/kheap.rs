use core::{alloc::Layout, cell::Cell, sync::atomic::*};

use super::PAGE_SIZE_SMALL;
use super::PAGE_SIZE_SMALL_LOG2;

// The fallback allocator.
pub(super) struct RawAllocator {
    raw_area_start: AtomicU64,
    raw_area_size: AtomicU64,
    raw_area_used: AtomicU64,
    allocated: AtomicU64,
}

fn aligned_bump_offsets(base: u64, used: u64, capacity: u64, layout: Layout) -> Option<(u64, u64)> {
    let mask = layout.align() as u64 - 1;
    let start = base.checked_add(used)?.checked_add(mask)? & !mask;
    let end = start.checked_add(layout.size() as u64)?.checked_sub(base)?;
    (end <= capacity).then_some((start - base, end))
}

impl RawAllocator {
    fn reserve_startup(&self, layout: Layout) -> Option<(u64, u64)> {
        let base = self.raw_area_start.load(Ordering::Relaxed);
        let capacity = self.raw_area_size.load(Ordering::Relaxed);
        let mut used = self.raw_area_used.load(Ordering::Relaxed);
        loop {
            let (offset, end) = aligned_bump_offsets(base, used, capacity, layout)?;
            match self.raw_area_used.compare_exchange_weak(
                used,
                end,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some((base + offset, end)),
                Err(observed) => used = observed,
            }
        }
    }
}

unsafe impl core::alloc::GlobalAlloc for RawAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        assert!(layout.align() as u64 <= PAGE_SIZE_SMALL);

        if !super::memory_initialized() {
            let (addr, _end) = self.reserve_startup(layout).unwrap_or_else(|| {
                panic!(
                    "startup heap allocation failed: {:?}, {} bytes remaining",
                    layout,
                    startup_remaining()
                )
            });
            assert_eq!(addr & (layout.align() as u64 - 1), 0);

            #[cfg(debug_assertions)]
            {
                crate::raw_log!("startup alloc: {:?} total: 0x{:x} ({})", layout, _end, _end);
            }

            return addr as usize as *mut u8;
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

static FRUSA: frusa_v2::Frusa4K = frusa_v2::Frusa4K::new(&RAW_ALLOCATOR);

/// Size classes of `Frusa4K`: 16 bytes to 4 KiB.
const CLASSES: usize = 9;

/// One CPU's stage in front of `FRUSA` (docs/plans/frusa.md, section 8):
/// the allocator's private blocks and, per class, a LIFO of freed slots
/// linked through their first word. Kernel code is never preempted and
/// interrupt handlers do not allocate, so an allocation runs to completion
/// before another can begin on the same CPU: plain loads and stores are
/// enough, and the CPU is the guard shard.
#[repr(align(64))]
struct CpuHeap {
    cache: frusa_v2::Cache4K,
    heads: [Cell<*mut u8>; CLASSES],
    lens: [Cell<u32>; CLASSES],
}

struct CpuHeaps([CpuHeap; crate::config::MAX_CPUS as usize]);

// Each CPU touches only its own entry, and only from one context at a time.
unsafe impl Sync for CpuHeaps {}

static CPU_HEAPS: CpuHeaps = CpuHeaps(
    [const {
        CpuHeap {
            cache: frusa_v2::Cache4K::new(),
            heads: [const { Cell::new(core::ptr::null_mut()) }; CLASSES],
            lens: [const { Cell::new(0) }; CLASSES],
        }
    }; crate::config::MAX_CPUS as usize],
);

/// This CPU's stage, once CPU identity is valid; before that the shared
/// path serves.
fn cpu_heap() -> Option<(&'static CpuHeap, u32)> {
    super::cpu_initialized().then(|| {
        let cpu = crate::arch::current_cpu();
        (&CPU_HEAPS.0[cpu as usize], cpu as u32)
    })
}

/// The allocator's class of `layout`, or `None` above 4 KiB.
fn class_of(layout: &Layout) -> Option<usize> {
    let size = layout
        .size()
        .next_power_of_two()
        .max(layout.align())
        .max(16);
    (size <= 4096).then(|| size.ilog2() as usize - 4)
}

/// Slots a CPU keeps per class: at most 64, and at most 16 KiB.
fn magazine_limit(class: usize) -> u32 {
    ((16 * 1024) >> (class + 4)).min(64)
}

struct KernelHeap;

#[global_allocator]
static KHEAP: KernelHeap = KernelHeap;

unsafe impl core::alloc::GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let Some((heap, cpu)) = cpu_heap() else {
            return FRUSA.alloc(layout);
        };
        if let Some(class) = class_of(&layout) {
            let slot = heap.heads[class].get();
            if !slot.is_null() {
                heap.heads[class].set(*(slot as *const *mut u8));
                heap.lens[class].set(heap.lens[class].get() - 1);
                return slot;
            }
        }
        heap.cache.set_shard(cpu);
        FRUSA.alloc_cached(&heap.cache, layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let Some((heap, cpu)) = cpu_heap() else {
            return FRUSA.dealloc(ptr, layout);
        };
        if let Some(class) = class_of(&layout) {
            let len = heap.lens[class].get();
            if len < magazine_limit(class) {
                *(ptr as *mut *mut u8) = heap.heads[class].get();
                heap.heads[class].set(ptr);
                heap.lens[class].set(len + 1);
                return;
            }
        }
        heap.cache.set_shard(cpu);
        FRUSA.dealloc_cached(&heap.cache, ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
        let class = class_of(&layout);
        if class.is_some() && class == class_of(&new_layout) {
            return ptr; // Same class: the slot already fits.
        }
        let new_ptr = self.alloc(new_layout);
        if !new_ptr.is_null() {
            core::ptr::copy_nonoverlapping(ptr, new_ptr, layout.size().min(new_size));
            self.dealloc(ptr, layout);
        }
        new_ptr
    }
}

pub fn init(segment: super::MemorySegment) {
    #[cfg(debug_assertions)]
    test_startup_reservations();

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

// Bytes still available to permanent allocations before memory initialization.
pub(super) fn startup_remaining() -> u64 {
    RAW_ALLOCATOR.raw_area_size.load(Ordering::Relaxed)
        - RAW_ALLOCATOR.raw_area_used.load(Ordering::Relaxed)
}

#[cfg(debug_assertions)]
fn test_startup_reservations() {
    for shift in 0..=12 {
        let alignment = 1 << shift;
        let layout = Layout::from_size_align(13, alignment).unwrap();
        for (base, used) in [
            (0, 0),
            (0x1003, 0),
            (0x1003, 1),
            (0x1000, 3),
            (0x1003, 4095),
        ] {
            let (start, end) = aligned_bump_offsets(base, used, 0x4000, layout).unwrap();
            assert!(start >= used);
            assert!(start - used < alignment as u64);
            assert_eq!((base + start) & (alignment as u64 - 1), 0);
            assert_eq!(end, start + 13);
            assert_eq!(
                aligned_bump_offsets(base, used, end, layout),
                Some((start, end))
            );
            assert_eq!(aligned_bump_offsets(base, used, end - 1, layout), None);
        }
    }

    let byte = Layout::from_size_align(1, 1).unwrap();
    let aligned = Layout::from_size_align(4, 16).unwrap();
    assert_eq!(aligned_bump_offsets(u64::MAX, 0, 1, byte), None);
    assert_eq!(aligned_bump_offsets(u64::MAX - 7, 8, 16, byte), None);
    assert_eq!(aligned_bump_offsets(u64::MAX - 7, 0, 16, aligned), None);
    assert_eq!(aligned_bump_offsets(0, u64::MAX, u64::MAX, byte), None);
    assert_eq!(aligned_bump_offsets(0, 9, 8, byte), None);

    // Reserve only numeric addresses: no heap storage or pointer dereferences.
    let allocator = RawAllocator {
        raw_area_start: AtomicU64::new(0x1003),
        raw_area_size: AtomicU64::new(16),
        raw_area_used: AtomicU64::new(0),
        allocated: AtomicU64::new(0),
    };
    let layout = Layout::from_size_align(3, 8).unwrap();
    assert_eq!(allocator.reserve_startup(layout), Some((0x1008, 8)));
    assert_eq!(allocator.raw_area_used.load(Ordering::Relaxed), 8);
    assert_eq!(allocator.reserve_startup(aligned), None);
    assert_eq!(allocator.raw_area_used.load(Ordering::Relaxed), 8);
    assert_eq!(allocator.reserve_startup(layout), Some((0x1010, 16)));
    assert_eq!(allocator.reserve_startup(byte), None);
    assert_eq!(allocator.raw_area_used.load(Ordering::Relaxed), 16);

    allocator
        .raw_area_start
        .store(u64::MAX - 7, Ordering::Relaxed);
    allocator.raw_area_used.store(0, Ordering::Relaxed);
    assert_eq!(allocator.reserve_startup(aligned), None);
    assert_eq!(allocator.raw_area_used.load(Ordering::Relaxed), 0);
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

/// Returns every batch whose blocks are all free. Slots the CPUs keep
/// count as in use, so what they hold stays.
pub fn reclaim() {
    FRUSA.reclaim();
}
