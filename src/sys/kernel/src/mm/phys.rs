use super::phys_blocks::{BlockPool, BootInputs};
use super::slab::*;
use super::*;
use super::{AllocationClass, AllocationFailure};

pub fn init(available: &[MemorySegment], initrd: MemorySegment, raw_ram: Vec<MemorySegment>) {
    PhysicalMemory::init(available, initrd, raw_ram);
}

pub(crate) fn validate_mmio(phys_addr: u64, num_pages: u64) -> Result<(), moto_sys::ErrorCode> {
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

/// The lowest free small-page count the physical allocator ever reached.
pub fn min_free_small_pages() -> u64 {
    let blocks = &PhysicalMemory::inst().blocks;
    blocks.total_pages() - blocks.high_water_pages()
}

/// Mirror the live free-page count into `target`; see `virt::init`.
pub fn publish_free_pages(target: &'static core::sync::atomic::AtomicU64) {
    PhysicalMemory::inst().blocks.publish_free_pages(target);
}

/// Whether free physical memory is below the shared low-memory limit.
pub fn low_memory() -> bool {
    available_small_pages() < moto_sys::LOW_MEMORY_PAGES
}

/// Request reclamation after rollback, only if the current count still needs
/// it. None means unarmed or recovered. Joining Latched does not restart it.
pub fn request_oom() -> Option<u64> {
    PhysicalMemory::inst().blocks.request_oom()
}

pub(crate) fn oom_snapshot() -> (super::phys_blocks::StateSnapshot, u64) {
    let blocks = &PhysicalMemory::inst().blocks;
    let state = blocks.state_snapshot();
    (state, state.free_pages(blocks.total_pages()))
}
pub(crate) fn take_oom_attention() -> bool {
    PhysicalMemory::inst().blocks.take_oom_attention()
}
pub(crate) fn request_oom_attention() {
    PhysicalMemory::inst().blocks.request_oom_attention();
}
pub(crate) fn still_killing(generation: u64) -> bool {
    PhysicalMemory::inst().blocks.still_killing(generation)
}
pub(crate) fn latch_oom(generation: u64) -> bool {
    PhysicalMemory::inst().blocks.latch_oom(generation)
}
pub(crate) fn oom_runs() -> u64 {
    PhysicalMemory::inst().blocks.oom_runs()
}

// The shared count equals the allocator's at quiescent boot checkpoints.
#[cfg(debug_assertions)]
fn assert_published_free_pages() {
    assert_eq!(
        super::virt::get_kernel_static_page_mut()
            .free_pages
            .load(core::sync::atomic::Ordering::Relaxed),
        available_small_pages()
    );
}

/// A frame for this recipient. Data and any new frame-descriptor slab pages
/// use the same class; failure releases the data allocation.
pub(crate) fn allocate_frame(
    kind: PageType,
    class: AllocationClass,
) -> Result<SlabArc<Frame>, AllocationFailure> {
    PhysicalMemory::inst().allocate_frame(kind, class)
}

/// A huge frame owning one whole dual-purpose block. Callers may fall back
/// to small pages on physical shortage, retaining a floor-refusal receipt;
/// a closed gate must be propagated instead of being treated as fragmentation.
pub(crate) fn allocate_huge_frame(
    class: AllocationClass,
) -> Result<SlabArc<Frame>, AllocationFailure> {
    let inst = PhysicalMemory::inst();
    let start = inst.blocks.alloc_huge(class)?;
    match inst.slab.alloc_arc(class) {
        Ok(frame) => {
            frame.get_mut().unwrap().start = start;
            frame.get_mut().unwrap().kind = PageType::MidPage;
            Ok(frame)
        }
        Err(err) => {
            inst.free_huge(start);
            Err(err)
        }
    }
}

/// A frame for a page the allocator already holds as used: boot-time
/// reservations such as the initrd. Dropping it frees the page, so the
/// owner must be something that lives as long as the reservation.
pub(crate) fn adopt_frame(phys_addr: u64) -> Result<SlabArc<Frame>, AllocationFailure> {
    let class = AllocationClass::Kernel;
    debug_assert_eq!(0, phys_addr & (PAGE_SIZE_SMALL - 1));
    let frame = PhysicalMemory::inst().slab.alloc_arc(class)?;
    frame.get_mut().unwrap().start = phys_addr;
    frame.get_mut().unwrap().kind = PageType::SmallPage;
    Ok(frame)
}

// Allocate a physical page without allocating struct Frame.
// Used internally in mm for page table and slab allocations.
pub(crate) fn phys_allocate_frameless(
    kind: PageType,
    class: AllocationClass,
) -> Result<u64, AllocationFailure> {
    PhysicalMemory::inst().allocate_frameless(kind, class)
}

pub fn phys_deallocate_frameless(phys_addr: u64, kind: PageType) {
    PhysicalMemory::inst().deallocate_frameless(phys_addr, kind);
}

// A run of `pages` small pages without frames, for the boot self-tests;
// `phys_deallocate_frameless` frees it page by page.
#[cfg(debug_assertions)]
pub(crate) fn phys_allocate_frameless_run(
    pages: u16,
    class: AllocationClass,
) -> Result<u64, AllocationFailure> {
    PhysicalMemory::inst().allocate_frameless_run(pages, class)
}

// The pages one frame-descriptor slab takes, for the boot self-tests.
#[cfg(debug_assertions)]
pub fn frame_slab_pages() -> u64 {
    MMSlab::<Frame>::backing_pages(true)
}

// The caller has validated the whole MMIO range. Only the descriptor is owned.
pub(super) fn mmio_frame(
    phys_addr: u64,
    class: AllocationClass,
) -> Result<SlabArc<Frame>, AllocationFailure> {
    let frame = PhysicalMemory::inst().slab.alloc_arc(class)?;
    let inner = frame.get_mut().unwrap();
    inner.start = phys_addr;
    inner.kind = PageType::SmallPage;
    inner.mmio = true;
    Ok(frame)
}

pub(crate) fn phys_allocate_contiguous_frames(
    kind: PageType,
    num_frames: u64,
    class: AllocationClass,
) -> Result<Vec<SlabArc<Frame>>, AllocationFailure> {
    PhysicalMemory::inst().allocate_contiguous_frames(kind, num_frames, class)
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

// Contains everything. Has a single instantiation.
struct PhysicalMemory {
    total_size: u64, // does not change once initialized

    slab: MMSlab<Frame>,

    blocks: BlockPool,
    boot: BootInputs,
}

// A pointer to the one and only instance of struct PhysicalMemory.
static mut PHYS_MEM: usize = 0;

impl PhysicalMemory {
    fn inst() -> &'static Self {
        let addr = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(PHYS_MEM)) };
        assert_ne!(addr, 0);
        unsafe { (addr as *const Self).as_ref().unwrap_unchecked() }
    }

    fn allocate_frame(
        &'static self,
        kind: PageType,
        class: AllocationClass,
    ) -> Result<SlabArc<Frame>, AllocationFailure> {
        let frame_start = self.allocate_frameless(kind, class)?;

        let frame_result = self.slab.alloc_arc(class);

        if let Ok(frame) = frame_result {
            frame.get_mut().unwrap().start = frame_start;
            frame.get_mut().unwrap().kind = kind;
            Ok(frame)
        } else {
            self.deallocate_frameless(frame_start, kind);
            frame_result
        }
    }

    // Exhaustion is the caller's to handle, not an event to log: a process
    // can provoke it at will.
    fn allocate_frameless(
        &'static self,
        kind: PageType,
        class: AllocationClass,
    ) -> Result<u64, AllocationFailure> {
        match kind {
            PageType::SmallPage => self.blocks.alloc_small(1, class),
            _ => panic!(),
        }
    }

    // A run of `pages` small pages from one block's unused range; freed
    // page by page like any small page.
    fn allocate_frameless_run(
        &self,
        pages: u16,
        class: AllocationClass,
    ) -> Result<u64, AllocationFailure> {
        self.blocks.alloc_small(pages, class)
    }

    fn deallocate_frameless(&'static self, phys_addr: u64, kind: PageType) {
        match kind {
            PageType::SmallPage => self.free_small(phys_addr),
            _ => panic!(),
        };
    }

    fn free_small(&self, phys_addr: u64) {
        self.blocks.free_small(phys_addr);
    }

    // Huge frames come only from the dual-purpose pool.
    fn free_huge(&self, phys_addr: u64) {
        self.blocks.free_huge(phys_addr);
    }

    fn deallocate_frame(&self, frame: &Frame) {
        match frame.kind {
            PageType::SmallPage => self.free_small(frame.start),
            PageType::MidPage => self.free_huge(frame.start),
            _ => panic!(),
        };

        // Note that the frame is deallocated from its slab automatically.
    }

    fn allocate_contiguous_frames(
        &self,
        kind: PageType,
        num_frames: u64,
        class: AllocationClass,
    ) -> Result<Vec<SlabArc<Frame>>, AllocationFailure> {
        // The syscall caps contiguous requests at 64 small pages.
        assert!(num_frames <= 64);
        assert_eq!(kind, PageType::SmallPage);

        let start = self.allocate_frameless_run(num_frames as u16, class)?;
        let mut result = Vec::with_capacity(num_frames as usize);
        for idx in 0..num_frames {
            let frame_start = start + (idx << PAGE_SIZE_SMALL_LOG2);
            match self.slab.alloc_arc(class) {
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
        let total_size = blocks.total_pages() << PAGE_SIZE_SMALL_LOG2;

        use alloc::boxed::Box;
        let self_ = Box::leak(Box::new(PhysicalMemory {
            total_size,
            slab: MMSlab::<Frame>::new(true),
            blocks,
            boot,
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
    pub small_pages_used: u64,

    pub pages_reserved: u64,
    pub pages_discarded: u64,
    pub blocks_total: u64,
    pub blocks_whole: u64,
    pub blocks_split: u64,
    pub blocks_taken: u64,
    pub block_splits: u64,
    pub block_recombined: u64,
}

impl PhysStats {
    pub fn get() -> Self {
        let inst = PhysicalMemory::inst();
        Self {
            total_size: inst.total_size,

            small_pages: inst.blocks.total_pages(),
            small_pages_used: inst.blocks.used_pages(),

            pages_reserved: inst.blocks.reserved_pages(),
            pages_discarded: inst.blocks.discarded_pages(),
            blocks_total: inst.blocks.block_count() as u64,
            blocks_whole: inst.blocks.whole_count(),
            blocks_split: inst.blocks.split_count(),
            blocks_taken: inst.blocks.taken_count(),
            block_splits: inst.blocks.split_events(),
            block_recombined: inst.blocks.recombine_events(),
        }
    }

    pub fn used(&self) -> u64 {
        self.small_pages_used << PAGE_SIZE_SMALL_LOG2
    }

    pub fn available(&self) -> u64 {
        self.total_size - self.used()
    }
}

#[cfg(debug_assertions)]
pub fn dump_stats() {
    log::debug!("phys mem stats:\n{:#?}", PhysStats::get());
}

// Take and return one huge frame from the live pool while the BSP is alone:
// block accounting, alignment, and shared free-page publication.
#[cfg(debug_assertions)]
pub fn huge_frame_self_test() {
    assert_published_free_pages();
    let small = phys_allocate_frameless(PageType::SmallPage, AllocationClass::Kernel).unwrap();
    assert_published_free_pages();
    phys_deallocate_frameless(small, PageType::SmallPage);
    assert_published_free_pages();
    let contiguous =
        phys_allocate_contiguous_frames(PageType::SmallPage, 32, AllocationClass::Kernel).unwrap();
    assert_published_free_pages();
    drop(contiguous);
    assert_published_free_pages();
    let inst = PhysicalMemory::inst();
    let before = block_metrics();
    let free_before = inst.blocks.free_pages();
    let frame = match allocate_huge_frame(AllocationClass::Kernel) {
        Ok(frame) => frame,
        Err(err) => {
            // Guests of 128 MiB or less have no dual-purpose block.
            assert_eq!(moto_sys::ErrorCode::from(err), moto_rt::E_OUT_OF_MEMORY);
            assert!(
                before.total <= 64,
                "huge frame refused with {} blocks",
                before.total
            );
            crate::raw_log!("phys huge frame tests SKIPPED: no dual-purpose block");
            return;
        }
    };
    let (start, kind) = (frame.get().unwrap().start(), frame.get().unwrap().kind());
    assert_eq!(kind, PageType::MidPage);
    assert_eq!(start & (PAGE_SIZE_MID - 1), 0);
    assert!(start >= 128 * super::ONE_MB);
    let held = block_metrics();
    assert_eq!(held.taken, before.taken + 1);
    assert_eq!(held.whole, before.whole - 1);
    assert_eq!(inst.blocks.free_pages(), free_before - 512);
    assert_published_free_pages();
    drop(frame);
    let after = block_metrics();
    assert_eq!((after.taken, after.whole), (before.taken, before.whole));
    assert_eq!(inst.blocks.free_pages(), free_before);
    assert_published_free_pages();
    crate::raw_log!("phys huge frame tests PASS");
}
