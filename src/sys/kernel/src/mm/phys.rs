use super::phys_blocks::{BlockPool, BootInputs};
use super::slab::*;
use super::*;
use core::marker::PhantomData;
use core::sync::atomic::*;
use moto_sys::ErrorCode;

pub fn init(available: &[MemorySegment], initrd: MemorySegment, raw_ram: Vec<MemorySegment>) {
    PhysicalMemory::init(available, initrd, raw_ram);
}

pub(super) fn validate_mmio(phys_addr: u64, num_pages: u64) -> Result<(), ErrorCode> {
    let invalid = moto_rt::E_INVALID_ARGUMENT;
    if num_pages == 0 || phys_addr & (PAGE_SIZE_SMALL - 1) != 0 {
        return Err(invalid);
    }
    let size = num_pages.checked_mul(PAGE_SIZE_SMALL).ok_or(invalid)?;
    let end = phys_addr.checked_add(size).ok_or(invalid)?;
    // Bits above the x86 PTE's 52-bit address field are not address bits.
    if end > (1 << 52) {
        return Err(invalid);
    }
    // Blocks past the managed span hold no RAM.
    let blocks = &PhysicalMemory::inst().blocks;
    let first = (phys_addr >> PAGE_SIZE_MID_LOG2) as usize;
    let last = ((end - 1) >> PAGE_SIZE_MID_LOG2) as usize;
    if (first..=last.min(blocks.block_count().saturating_sub(1))).any(|block| blocks.is_ram(block))
    {
        return Err(invalid);
    }
    Ok(())
}

// Physical frame.
pub struct Frame {
    start: u64,
    kind: PageType,
    mmio: bool,
}

const _FRAME_SZ: () = assert!(core::mem::size_of::<Frame>() == 16);

impl Frame {
    pub fn start(&self) -> u64 {
        self.start
    }
    pub fn kind(&self) -> PageType {
        self.kind
    }
    pub fn is_mmio(&self) -> bool {
        self.mmio
    }
}

// A slab entry costs the struct plus its 4-byte refcount. Admission budgets
// mm::admission::METADATA_BYTES_PER_PAGE for all per-page metadata; a Frame
// entry is the second-largest consumer of it, after struct Page.
const _FRAME_SLAB_ENTRY_SZ: () =
    assert!(core::mem::size_of::<Frame>() + 4 <= super::admission::METADATA_BYTES_PER_PAGE / 4);

impl Slabbable for Frame {
    fn inplace_init(&mut self) {
        self.start = 0;
        self.kind = PageType::Unknown;
        self.mmio = false;
    }

    fn drop_slabbable(&mut self) {
        if !self.mmio {
            PhysicalMemory::inst().deallocate_frame(self)
        }
    }
}

pub fn available_small_pages() -> u64 {
    PhysicalMemory::inst().blocks.free_pages()
}

pub fn total_small_pages() -> u64 {
    PhysicalMemory::inst().blocks.total_pages()
}

/// The lowest free small-page count the allocator ever reached -- unlike the
/// admission-check low water, this includes allocations made outside any
/// admission window, so it measures the overlapping kernel work the floors
/// must absorb.
pub fn min_free_small_pages() -> u64 {
    let blocks = &PhysicalMemory::inst().blocks;
    blocks.total_pages() - blocks.high_water_pages()
}

pub fn allocate_frame(kind: PageType) -> Result<SlabArc<Frame>, ErrorCode> {
    let res = PhysicalMemory::inst().allocate_frame(kind);
    if res.is_err() {
        log::debug!("OOM");
        panic!("OOM")
    }
    res
}

/// A frame for a page the allocator already holds as used: boot-time
/// reservations such as the initrd. Dropping it frees the page, so the
/// owner must be something that lives as long as the reservation.
pub fn adopt_frame(phys_addr: u64) -> Result<SlabArc<Frame>, ErrorCode> {
    debug_assert_eq!(0, phys_addr & (PAGE_SIZE_SMALL - 1));
    let frame = PhysicalMemory::inst().slab.alloc_arc()?;
    frame.get_mut().unwrap().start = phys_addr;
    frame.get_mut().unwrap().kind = PageType::SmallPage;
    Ok(frame)
}

// Allocate a physical page without allocating struct Frame.
// Used internally in mm for page table and slab allocations.
pub fn phys_allocate_frameless(kind: PageType) -> Result<u64, ErrorCode> {
    #[cfg(debug_assertions)]
    {
        let res = PhysicalMemory::inst().allocate_frameless(kind);
        if res.is_err() {
            log::warn!("OOM!");
            dump_serial();
        }
        res
    }
    #[cfg(not(debug_assertions))]
    PhysicalMemory::inst().allocate_frameless(kind)
}

pub fn phys_deallocate_frameless(phys_addr: u64, kind: PageType) {
    PhysicalMemory::inst().deallocate_frameless(phys_addr, kind);
}

// The caller has validated the whole MMIO range. Only the descriptor is owned.
pub(super) fn mmio_frame(phys_addr: u64) -> Result<SlabArc<Frame>, ErrorCode> {
    let frame = PhysicalMemory::inst().slab.alloc_arc()?;
    let inner = frame.get_mut().unwrap();
    inner.start = phys_addr;
    inner.kind = PageType::SmallPage;
    inner.mmio = true;
    Ok(frame)
}

pub fn phys_allocate_contiguous_frames(
    kind: PageType,
    num_frames: u64,
) -> Result<Vec<SlabArc<Frame>>, ErrorCode> {
    PhysicalMemory::inst().allocate_contiguous_frames(kind, num_frames)
}

// Stage 2: the RAM below the kernel that the bootloader used becomes
// allocatable, except page zero and the two kloader page tables still in use.
pub fn release_low_memory() {
    let inst = PhysicalMemory::inst();
    inst.blocks.release_low(
        &inst.boot,
        [
            crate::arch::paging::kpt_phys_addr(),
            crate::arch::paging::l3_direct_phys_table_phys_addr(),
        ],
    );
}

#[cfg(debug_assertions)]
pub fn dump_serial() {
    PhysicalMemory::inst().dump_serial();
}

// Block allocator gauges and events for the kernel metrics; collected under
// no common lock, so they need not agree with each other instantaneously.
pub struct BlockMetrics {
    pub total: u64,
    pub whole: u64,
    pub split: u64,
    pub taken: u64,
    pub whole_low: u64,
    pub pages_reserved: u64,
    pub pages_free_low: u64,
    pub splits: u64,
    pub recombined: u64,
}

pub fn block_metrics() -> BlockMetrics {
    let blocks = &PhysicalMemory::inst().blocks;
    let (whole_low, pages_free_low) = blocks.low_memory();
    BlockMetrics {
        total: blocks.block_count() as u64,
        whole: blocks.whole_count(),
        split: blocks.split_count(),
        taken: blocks.taken_count(),
        whole_low,
        pages_reserved: blocks.reserved_pages(),
        pages_free_low,
        splits: blocks.split_events(),
        recombined: blocks.recombine_events(),
    }
}

// sys-io's fixed mid-page segment: [2 MiB, 10 MiB), outside small-page management.
pub(super) const FIXED_MID_SEGMENT: MemorySegment = MemorySegment {
    start: super::ONE_MB * 2,
    size: (PhysicalMemory::MID_PAGES << PAGE_SIZE_MID_LOG2) as u64,
};

// The fixed mid-page segment: a bitmap of at most 64 pages.
struct DesignatedSegment<S: PageSize> {
    segment: MemorySegment,
    used_bitmap: AtomicU64,
    num_pages: u8,
    _unused: PhantomData<S>,
}

impl<S: PageSize> DesignatedSegment<S> {
    fn new(segment: &MemorySegment) -> Self {
        DesignatedSegment {
            segment: *segment,
            used_bitmap: AtomicU64::new(0),
            num_pages: (segment.size >> S::SIZE_LOG2) as u8,
            _unused: PhantomData {},
        }
    }

    fn allocate_frame(&self) -> Result<u64, ErrorCode> {
        let mut iters = 0_u64;
        loop {
            iters += 1;
            if iters > 10000 {
                panic!("allocate_frame looping");
            }
            let prev = self.used_bitmap.load(Ordering::Relaxed);
            if prev == u64::MAX {
                return Err(moto_rt::E_OUT_OF_MEMORY);
            }

            let ones = prev.trailing_ones() as u8;
            if ones == self.num_pages {
                return Err(moto_rt::E_OUT_OF_MEMORY);
            }
            debug_assert!(ones < self.num_pages);

            let bit = 1u64 << ones;
            assert_eq!(0, prev & bit);
            if self
                .used_bitmap
                .compare_exchange_weak(prev, prev | bit, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                let start = ((ones as u64) << S::SIZE_LOG2) + self.segment.start;
                return Ok(start);
            }
        }
    }
}

// Contains everything. Has a single instantiation.
struct PhysicalMemory {
    total_size: u64, // does not change once initialized

    slab: MMSlab<Frame>,

    blocks: BlockPool,
    boot: BootInputs,

    mid_pages: DesignatedSegment<PageSizeMid>,
}

// A pointer to the one and only instance of struct PhysicalMemory.
static mut PHYS_MEM: usize = 0;

impl PhysicalMemory {
    // The number of MID pages we reserve. At the moment only the kernel
    // and, maybe, sys-io are allowed to use MID pages, so the number is small.
    const MID_PAGES: usize = 4;

    fn inst() -> &'static Self {
        let addr = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(PHYS_MEM)) };
        assert_ne!(addr, 0);
        unsafe { (addr as *const Self).as_ref().unwrap_unchecked() }
    }

    fn allocate_frame(&'static self, kind: PageType) -> Result<SlabArc<Frame>, ErrorCode> {
        let frame_start = self.allocate_frameless(kind)?;

        let frame_result = self.slab.alloc_arc();

        if let Ok(frame) = frame_result {
            frame.get_mut().unwrap().start = frame_start;
            frame.get_mut().unwrap().kind = kind;
            Ok(frame)
        } else {
            self.deallocate_frameless(frame_start, kind);
            frame_result
        }
    }

    fn allocate_frameless(&'static self, kind: PageType) -> Result<u64, ErrorCode> {
        match kind {
            PageType::SmallPage => self.blocks.alloc_small(1).ok_or_else(|| {
                log::error!(
                    "OOM: failed to allocate a small frame. Total pages: {}; used pages: {}.",
                    self.blocks.total_pages(),
                    self.blocks.used_pages()
                );
                moto_rt::E_OUT_OF_MEMORY
            }),
            PageType::MidPage => self.mid_pages.allocate_frame(),
            _ => panic!(),
        }
    }

    fn deallocate_frameless(&'static self, phys_addr: u64, kind: PageType) {
        match kind {
            PageType::SmallPage => self.free_small(phys_addr),
            _ => panic!(),
        };
    }

    // Frees happen outside admission windows (teardown, unmap), so this is
    // where the pressure flag learns memory came back.
    fn free_small(&self, phys_addr: u64) {
        self.blocks.free_small(phys_addr);
        crate::mm::admission::note_pages_freed();
    }

    fn deallocate_frame(&self, frame: &Frame) {
        match frame.kind {
            PageType::SmallPage => self.free_small(frame.start),
            _ => panic!(),
        };

        // Note that the frame is deallocated from its slab automatically.
    }

    fn allocate_contiguous_frames(
        &self,
        kind: PageType,
        num_frames: u64,
    ) -> Result<Vec<SlabArc<Frame>>, ErrorCode> {
        // The syscall caps contiguous requests at 64 small pages.
        assert!(num_frames <= 64);
        assert_eq!(kind, PageType::SmallPage);

        let start = self
            .blocks
            .alloc_small(num_frames as u16)
            .ok_or(moto_rt::E_OUT_OF_MEMORY)?;
        let mut result = Vec::with_capacity(num_frames as usize);
        for idx in 0..num_frames {
            let frame_start = start + (idx << PAGE_SIZE_SMALL_LOG2);
            match self.slab.alloc_arc() {
                Ok(frame) => {
                    frame.get_mut().unwrap().start = frame_start;
                    frame.get_mut().unwrap().kind = kind;
                    result.push(frame);
                }
                Err(err) => {
                    // Frames in `result` free their prefix on drop; the
                    // suffix, including this page, is freed here exactly once.
                    for page in idx..num_frames {
                        self.free_small(start + (page << PAGE_SIZE_SMALL_LOG2));
                    }
                    return Err(err);
                }
            }
        }
        Ok(result)
    }

    fn init(available: &[MemorySegment], initrd: MemorySegment, raw_ram: Vec<MemorySegment>) {
        assert_eq!(0, unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(PHYS_MEM))
        });

        let boot = BootInputs {
            available: available.to_vec(),
            initrd,
            raw: raw_ram,
        };
        let blocks = BlockPool::build(&boot);
        let total_size = (blocks.total_pages() << PAGE_SIZE_SMALL_LOG2) + FIXED_MID_SEGMENT.size;

        use alloc::boxed::Box;
        let self_ = Box::leak(Box::new(PhysicalMemory {
            total_size,
            slab: MMSlab::<Frame>::new(true),
            blocks,
            boot,
            mid_pages: DesignatedSegment::new(&FIXED_MID_SEGMENT),
        }));

        let ptr = self_ as *mut PhysicalMemory;
        let ptr = ptr as usize;
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(PHYS_MEM), ptr);
        }
    }

    #[cfg(debug_assertions)]
    fn dump_serial(&self) {
        crate::raw_log!("Physical Memory: {:?}", PhysStats::get());
    }
}

#[allow(unused)]
#[derive(Debug)]
pub struct PhysStats {
    pub total_size: u64,

    pub small_pages: u64,
    pub mid_pages: u64,

    pub small_pages_used: u64,
    pub mid_pages_used: u64,

    pub pages_reserved: u64,
    pub pages_discarded: u64,
    pub blocks_total: u64,
    pub blocks_whole: u64,
    pub blocks_split: u64,
    pub block_splits: u64,
    pub block_recombined: u64,
}

impl PhysStats {
    pub fn get() -> Self {
        let inst = PhysicalMemory::inst();
        Self {
            total_size: inst.total_size,

            small_pages: inst.blocks.total_pages(),
            mid_pages: inst.mid_pages.num_pages as u64,

            small_pages_used: inst.blocks.used_pages(),
            mid_pages_used: inst
                .mid_pages
                .used_bitmap
                .load(Ordering::Relaxed)
                .count_ones() as u64,

            pages_reserved: inst.blocks.reserved_pages(),
            pages_discarded: inst.blocks.discarded_pages(),
            blocks_total: inst.blocks.block_count() as u64,
            blocks_whole: inst.blocks.whole_count(),
            blocks_split: inst.blocks.split_count(),
            block_splits: inst.blocks.split_events(),
            block_recombined: inst.blocks.recombine_events(),
        }
    }

    pub fn used(&self) -> u64 {
        (self.small_pages_used << PAGE_SIZE_SMALL_LOG2)
            // Note: we don't count MID pages as available.
            + (self.mid_pages << PAGE_SIZE_MID_LOG2)
    }

    pub fn available(&self) -> u64 {
        self.total_size - self.used()
    }
}

#[cfg(debug_assertions)]
pub fn dump_stats() {
    log::debug!("phys mem stats:\n{:#?}", PhysStats::get());
}
