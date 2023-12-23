// Memory Management.
// Note: only kheap and virt_intrusive provide memory allocation facilities,
//       other than some corner cases that do frameless allocations.

mod cache;
pub mod kheap;
pub mod mmio;
pub mod phys;
mod slab;
pub mod user;
pub mod virt;
mod virt_intrusive;

use core::sync::atomic::Ordering;

pub use crate::arch::paging::*;

use alloc::vec::Vec;
use bitflags::bitflags;

pub const ONE_GB: u64 = 1 << 30;
pub const ONE_MB: u64 = 1 << 20;

// The full physical memory is mapped to [DIRECT_MAP_OFFSET, *)
pub const PAGING_DIRECT_MAP_OFFSET: u64 = 1_u64 << 46;

// We load the kernel at 34MB phys and PAGING_DIRECT_MAP_OFFSET + 34MB virt.
pub const KERNEL_PHYS_START: u64 = ONE_MB * 34;

// Note that we don't do kaslr, as it is mostly pointless:
// https://grsecurity.net/kaslr_an_exercise_in_cargo_cult_security
pub const fn kernel_offset_virt() -> u64 {
    PAGING_DIRECT_MAP_OFFSET + KERNEL_PHYS_START
}

// Slabs are currently only used for phys memory, and are thus never deallocated.
pub(super) unsafe fn raw_alloc_for_slab<T: Sized>() -> *mut T {
    let result: *mut T = if !memory_initialized() {
        // Bootup: use the bootup heap.
        use core::alloc::GlobalAlloc;
        let layout = core::alloc::Layout::from_size_align(
            core::mem::size_of::<T>(),
            core::mem::align_of::<T>(),
        )
        .expect("Invalid layout");

        core::mem::transmute(kheap::RAW_ALLOCATOR.alloc(layout))
    } else {
        // Runtime: "manually" map pages for slabs (they will never get unmapped).
        let num_pages =
            align_up(core::mem::size_of::<T>() as u64, PAGE_SIZE_SMALL) >> PAGE_SIZE_SMALL_LOG2;
        let vaddr = virt::reserve_pages_for_slabs(num_pages);
        let mut page_vaddr = vaddr;
        let mapping_options = MappingOptions::READABLE | MappingOptions::WRITABLE;

        for _ in 0..num_pages {
            let page_phys_addr = phys::phys_allocate_frameless(PageType::SmallPage)
                .expect("OOM: no more phys frames available");
            virt::map_page(
                page_phys_addr,
                page_vaddr,
                PageType::SmallPage,
                mapping_options,
            );

            page_vaddr += PAGE_SIZE_SMALL;
        }

        core::mem::transmute(vaddr as usize as *mut u8)
    };
    result
}

#[cfg(debug_assertions)]
pub fn dump_stats() {
    phys::dump_serial();
}

pub fn zero_page(virt_addr: u64, kind: PageType) {
    assert_eq!(0, virt_addr & (kind.page_size() - 1));
    unsafe {
        let mut pos = virt_addr as usize;
        let end = (virt_addr + kind.page_size()) as usize;
        while pos < end {
            let ptr = pos as *mut u64;
            *ptr = 0;
            pos += 8;
        }
    }
}

pub trait PageSize: Copy + Eq + PartialOrd + Ord {
    const SIZE: u64;
    const SIZE_LOG2: u8;

    fn page_type() -> PageType;

    fn as_str() -> &'static str;
}

pub const fn align_up(addr: u64, align: u64) -> u64 {
    (addr + align - 1) & !(align - 1)
}

pub const fn align_down(addr: u64, align: u64) -> u64 {
    addr & !(align - 1)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PageSizeSmall {}

impl PageSize for PageSizeSmall {
    const SIZE: u64 = PAGE_SIZE_SMALL;
    const SIZE_LOG2: u8 = PAGE_SIZE_SMALL_LOG2;

    fn page_type() -> PageType {
        PageType::SmallPage
    }

    fn as_str() -> &'static str {
        assert_eq!(Self::SIZE, 1_u64 << 12);
        "4K"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PageSizeMid {}

impl PageSize for PageSizeMid {
    const SIZE: u64 = PAGE_SIZE_MID;
    const SIZE_LOG2: u8 = PAGE_SIZE_MID_LOG2;

    fn page_type() -> PageType {
        PageType::MidPage
    }

    fn as_str() -> &'static str {
        assert_eq!(Self::SIZE, 1_u64 << 21);
        "2M"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PageSizeLarge {}

impl PageSize for PageSizeLarge {
    const SIZE: u64 = PAGE_SIZE_LARGE;
    const SIZE_LOG2: u8 = PAGE_SIZE_LARGE_LOG2;

    fn page_type() -> PageType {
        PageType::LargePage
    }

    fn as_str() -> &'static str {
        assert_eq!(Self::SIZE, 1_u64 << 30);
        "1G"
    }
}

// TODO: MemorySegment is, basically, a u64 slice. Do we need it?
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct MemorySegment {
    pub start: u64,
    pub size: u64,
}

impl MemorySegment {
    pub fn end(&self) -> u64 {
        self.start + self.size
    }

    pub fn contains(&self, addr: u64) -> bool {
        (self.start <= addr) && (self.end() > addr)
    }

    pub fn contains_segment(&self, segment: &Self) -> bool {
        (self.start <= segment.start) && (self.end() >= segment.end())
    }

    pub unsafe fn as_slice(&self) -> &[u8] {
        core::slice::from_raw_parts(self.start as usize as *const u8, self.size as usize)
    }

    pub unsafe fn as_slice_mut(&self) -> &mut [u8] {
        core::slice::from_raw_parts_mut(self.start as usize as *mut u8, self.size as usize)
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub const fn empty_segment() -> Self {
        Self { start: 0, size: 0 }
    }

    pub fn take(&mut self) -> Self {
        let result = *self;
        *self = Self::empty_segment();
        result
    }

    pub fn intersect(&self, other: &MemorySegment) -> Self {
        let start = self.start.max(other.start);
        let end = self.end().min(other.end());

        if start > end {
            Self { start: 0, size: 0 }
        } else {
            Self {
                start,
                size: end - start,
            }
        }
    }

    pub fn minus(&self, other: &MemorySegment) -> (Self, Self) {
        if self.intersect(other).is_empty() {
            return (*self, Self::empty_segment());
        }

        let left_start = self.start;
        let left_end = if other.start > self.start {
            other.start
        } else {
            self.start
        };

        let right_end = self.end();
        let right_start = if other.end() < self.end() {
            other.end()
        } else {
            self.end()
        };

        (
            Self {
                start: left_start,
                size: left_end - left_start,
            },
            Self {
                start: right_start,
                size: right_end - right_start,
            },
        )
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum PageType {
    Unknown = 0,
    SmallPage,
    MidPage,
    LargePage,
}

impl Default for PageType {
    fn default() -> Self {
        Self::Unknown
    }
}

impl PageType {
    pub fn page_size(&self) -> u64 {
        match self {
            PageType::SmallPage => PAGE_SIZE_SMALL,
            PageType::MidPage => PAGE_SIZE_MID,
            PageType::LargePage => PAGE_SIZE_LARGE,
            PageType::Unknown => panic!(),
        }
    }

    pub fn page_size_log2(&self) -> u8 {
        match self {
            PageType::SmallPage => PAGE_SIZE_SMALL_LOG2,
            PageType::MidPage => PAGE_SIZE_MID_LOG2,
            PageType::LargePage => PAGE_SIZE_LARGE_LOG2,
            PageType::Unknown => panic!(),
        }
    }
}

bitflags! {
    pub struct MappingOptions: u8 {
        const READABLE        = 1;
        const WRITABLE        = 2;
        const USER_ACCESSIBLE = 4;
        const MMIO            = 8;
        const DONT_ZERO       = 16;
        const LAZY            = 32;
        const GUARD           = 64;
        const PRIVATE         = 128;  // Used by vmem_pages.
    }
}

impl Default for MappingOptions {
    fn default() -> Self {
        Self {
            bits: Default::default(),
        }
    }
}

const INIT_STATUS_NONE: u32 = 0;
const INIT_STATUS_MEMORY: u32 = 1;
const INIT_STATUS_CPU: u32 = u32::MAX;

static INIT_STATUS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(INIT_STATUS_NONE);

pub(super) fn memory_initialized() -> bool {
    INIT_STATUS.load(Ordering::Relaxed) > 0
}

fn inc_cpu_initialized() {
    INIT_STATUS.fetch_add(1, Ordering::Relaxed);
}

#[allow(unused)]
fn cpu_initialized() -> bool {
    INIT_STATUS.load(Ordering::Relaxed) == INIT_STATUS_CPU
}

// Returns the new stack.
pub fn init_mm_bsp_stage1(boot_info: &crate::init::KernelBootupInfo) -> u64 {
    // [0..34M) - potentially used by the bootloader
    // [34M..max_ram_offset) - the kernel binary
    // initrd may be either below the kernel (if we loaded it) or above (if CHV)

    // Step 1. Give 2M+ to the kernel heap, permanently.
    let heap_start_phys = align_up(boot_info.kernel_bytes_phys().end(), PAGE_SIZE_SMALL);
    let heap_size = align_up(heap_start_phys + PAGE_SIZE_MID, PAGE_SIZE_MID) - heap_start_phys;
    assert!(heap_size >= PAGE_SIZE_MID);
    assert!(heap_size < PAGE_SIZE_MID * 2);

    #[cfg(debug_assertions)]
    crate::raw_log!(
        "Bootup KHEAP at [0x{:x}..0x{:x}): {} pages",
        heap_start_phys,
        heap_start_phys + heap_size,
        heap_size >> PAGE_SIZE_SMALL_LOG2
    );

    let bootup_heap_phys = MemorySegment {
        start: heap_start_phys,
        size: heap_size,
    };
    assert!(boot_info.is_available(&bootup_heap_phys));
    let bootup_heap_virt = MemorySegment {
        start: bootup_heap_phys.start + PAGING_DIRECT_MAP_OFFSET,
        size: bootup_heap_phys.size,
    };
    kheap::init(bootup_heap_virt);

    // Step 2. Init physical memory.
    let exclusion = MemorySegment {
        start: KERNEL_PHYS_START as u64,
        size: bootup_heap_phys.end() - (KERNEL_PHYS_START as u64),
    };
    let pvh_mem_map = boot_info.pvh().mem_map();
    let mut available_memory: Vec<MemorySegment> = Vec::with_capacity(pvh_mem_map.len() + 2);
    for entry in pvh_mem_map {
        if !entry.available() {
            continue;
        }
        let pvh_seg = entry.to_segment();
        // Exclude the kernel + bootup heap permanently.
        let (left, right) = pvh_seg.minus(&exclusion);
        if !left.is_empty() {
            available_memory.push(left);
        }
        if !right.is_empty() {
            available_memory.push(right);
        }
    }

    let mut in_use: Vec<MemorySegment> = Vec::with_capacity(2);

    in_use.push(MemorySegment {
        start: 0,
        size: KERNEL_PHYS_START as u64,
    });

    let initrd_seg = boot_info.initrd_bytes_phys();
    if initrd_seg.start > bootup_heap_phys.end() {
        in_use.push(initrd_seg);
    } else {
        assert!(initrd_seg.end() < KERNEL_PHYS_START as u64);
    }

    phys::init(&available_memory[0..], &in_use[0..]);
    virt::init();

    // Do the INIT_STATUS dance so that we can initialize CPUs (allocates pages for per-cpu GS)
    // and initialize PERCPU_ALLOC_STATUS (depends on CPUs and needed for alloc debugging).
    INIT_STATUS.store(INIT_STATUS_MEMORY, Ordering::Release);

    crate::arch::init_cpu_postboot();

    allocate_kernel_stack()
}

pub fn init_mm_bsp_stage2() {
    #[cfg(debug_assertions)]
    log::warn!("TODO: there is some stranded (wasted) memory in the bootup KHEAP.");

    crate::arch::paging::init_paging_bsp(); // Unmaps the lower 1G.
    phys::mark_unused(&MemorySegment {
        start: 0,
        size: KERNEL_PHYS_START,
    });

    inc_cpu_initialized();

    while INIT_STATUS.load(Ordering::Relaxed) < (crate::config::num_cpus() + 1) as u32 {
        core::hint::spin_loop();
    }

    INIT_STATUS.store(INIT_STATUS_CPU, Ordering::Release);
}

// Returns the new stack.
pub fn init_mm_ap_stage1() -> u64 {
    while !memory_initialized() {
        core::hint::spin_loop();
    }

    crate::arch::init_cpu_postboot();

    allocate_kernel_stack()
}

pub fn init_mm_ap_stage2() {
    inc_cpu_initialized();
}

fn allocate_kernel_stack() -> u64 {
    let stack = virt::vmem_allocate_pages(
        virt::VmemKind::KernelStack,
        crate::config::KERNEL_STACK_PAGES + 2,
    )
    .expect("OOM during kernel bootup.");

    stack.end() - PAGE_SIZE_SMALL
}
