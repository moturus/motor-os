// Virtual memory management.

/*
    x64 Note: all kernel memory (excluding the full physical map) is mapped such that it
              is covered by a single L3 page table, so that the single L4 PTE can be
              installed into the UPT (user page table) to cover the kernel.

              This way all UPTs also have access to kernel memory when in ring 0, so that
              TLB invalidation/flushes are needed only on context switches between user
              processes, but not in normal syscalls, interrupts, and context switches
              between threads of the same process.

              TODO: actually make this happen; ATM we do PT flushes on all kernel/user
              context switches.

              TBD: do we also keep the full physical memory map in UPTs?
*/

use super::phys::Frame;
use super::slab::*;
use super::virt_intrusive::SegmentMap;
use super::virt_intrusive::VmemSegment;
use super::*;
use crate::util::SpinLock;
use crate::util::StaticRef;
use crate::util::UnsafeRef;
use crate::xray::stats::MemStats;

use core::marker::PhantomPinned;
use core::sync::atomic::AtomicU64;

use crate::arch::paging::PAGING_DIRECT_MAP_OFFSET;

use alloc::sync::Arc;
use moto_sys::ErrorCode;

const ONE_GB: u64 = 1u64 << 30;

// Most (all?) of the regions below are too large for our small kernel.
// But we have reserved 515GB for the kernel to keep it in a single L3 PT,
// so let's have these regions large enough to not think about it too much.

pub const VMEM_KERNEL_CODE_START: u64 = super::PAGING_DIRECT_MAP_OFFSET + super::KERNEL_PHYS_START;
const _: () = assert!(VMEM_KERNEL_CODE_START == 0x400002200000);
pub const VMEM_KERNEL_DATA_START: u64 = super::PAGING_DIRECT_MAP_OFFSET - (512 * super::ONE_GB);

// NOTE: all of kernel offsets below are relative to VMEM_KERNEL_DYNAMIC_START.
const VMEM_KSTATIC_START: u64 = VMEM_KERNEL_DATA_START + 4 * ONE_GB;
const VMEM_KSTATIC_END: u64 = VMEM_KSTATIC_START + 4 * ONE_GB; // 8 GB

const VMEM_KSTACKS_START: u64 = VMEM_KSTATIC_END;
const VMEM_KSTACKS_END: u64 = VMEM_KSTACKS_START + 8 * ONE_GB; // 16 GB

const VMEM_KHEAP_START: u64 = VMEM_KSTACKS_END;
const _: () = assert!(VMEM_KHEAP_START == 0x3F8400000000);
const VMEM_KHEAP_END: u64 = VMEM_KHEAP_START + 8 * ONE_GB; // 24 GB

const VMEM_K_MMIO_START: u64 = VMEM_KHEAP_END;
const VMEM_K_MMIO_END: u64 = VMEM_K_MMIO_START + ONE_GB; // 25 GB

const VMEM_K_SLABS_START: u64 = VMEM_K_MMIO_END; // 25GB
const VMEM_K_SLABS_END: u64 = VMEM_K_SLABS_START + 7 * ONE_GB; // 32 GB

// Init copies sys-io bytes from initrd here, as initrd memory may get reused.
pub const VMEM_K_SYS_IO_START: u64 = VMEM_K_SLABS_END; // 32 GB

// User virtual addresses start at zero and can go up to VMEM_USER_END.
const VMEM_USER_END: u64 = PAGING_DIRECT_MAP_OFFSET >> 1; // 1 << 45 on x64.

// Note: the address below must NOT be in the L4 region that is used by
//       the kernel, as we will either have to give the userspace access
//       to it, or will get #PF.
const KERNEL_STATIC_SHARED_PAGE_USER_VADDR: u64 = VMEM_KERNEL_DATA_START - PAGE_SIZE_MID;
const PROCESS_STATIC_SHARED_PAGE_USER_VADDR: u64 =
    KERNEL_STATIC_SHARED_PAGE_USER_VADDR - PAGE_SIZE_MID;
pub(super) const STATIC_SYS_IO_MID_PAGE: u64 =
    KERNEL_STATIC_SHARED_PAGE_USER_VADDR - 2 * PAGE_SIZE_MID;

const _: () = assert!(moto_sys::KernelStaticPage::PAGE_SIZE == PAGE_SIZE_SMALL);
const _: () = assert!(moto_sys::KernelStaticPage::VADDR == KERNEL_STATIC_SHARED_PAGE_USER_VADDR);

pub const fn kernel_vmem_offset() -> u64 {
    VMEM_KERNEL_DATA_START
}

pub fn kernel_mem_stats() -> Arc<MemStats> {
    KERNEL_ADDRESS_SPACE.mem_stats()
}

pub fn is_kernel_addr(vmem_addr: u64) -> bool {
    vmem_addr >= kernel_vmem_offset() // VMEM_USER_END
}

pub fn is_kernel_ip(vmem_addr: u64) -> bool {
    vmem_addr >= VMEM_KERNEL_CODE_START
}

pub fn is_user(vmem_addr: u64) -> bool {
    vmem_addr <= VMEM_USER_END
        || (moto_sys::CUSTOM_USERSPACE_REGION_START..moto_sys::CUSTOM_USERSPACE_REGION_END)
            .contains(&vmem_addr)
}

pub fn init() {
    KERNEL_ADDRESS_SPACE.set(KernelAddressSpace::new());
}

/// # Safety
///
/// Assumes addresses are properly initialized.
pub unsafe fn map_page(phys_addr: u64, virt_addr: u64, kind: PageType, options: MappingOptions) {
    KERNEL_ADDRESS_SPACE
        .base
        .page_table
        .map_page(phys_addr, virt_addr, kind, options);
}

pub fn get_kernel_static_page_mut() -> &'static mut moto_sys::KernelStaticPage {
    KERNEL_ADDRESS_SPACE.get_static_shared_page_mut()
}

pub(super) fn reserve_pages_for_slabs(num_pages: u64) -> u64 {
    let sz = num_pages << PAGE_SIZE_SMALL_LOG2;
    let result = KERNEL_ADDRESS_SPACE
        .next_slabs_addr
        .fetch_add(sz, Ordering::Relaxed);
    assert!(result + sz <= VMEM_K_SLABS_END);
    result
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum VmemKind {
    Unassigned = 0,
    KernelBoot, // Allocated at boot time. Not managed later.
    KernelMM,   // A special frame-less and page-less "raw" memory region to manage MM slabs.
    KernelMMIO,
    KernelHeap,
    KernelStack,
    KernelStatic, // For things like entry pages, GS, etc.
    User,
    UserMMIO,
    UserStack,
    Unmapped,
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum VaddrMapStatus {
    Unallocated,
    Unmapped,
    ZeroPageMapped,
    Private(u64),
    Shared(u64),
}

impl VaddrMapStatus {
    pub fn is_private(&self) -> bool {
        matches!(*self, Self::Private(_))
    }

    pub fn is_shared(&self) -> bool {
        matches!(*self, Self::Shared(_))
    }
}

pub fn vmem_allocate_pages(kind: VmemKind, num_pages: u64) -> Result<MemorySegment, ErrorCode> {
    KERNEL_ADDRESS_SPACE.vmem_allocate_pages(kind, num_pages)
}

pub fn vmem_free(addr: u64, kind: VmemKind) -> u64 {
    KERNEL_ADDRESS_SPACE.free(addr, kind)
}

pub fn vaddr_map_status(vmem_addr: u64) -> VaddrMapStatus {
    KERNEL_ADDRESS_SPACE.vaddr_map_status(vmem_addr)
}

pub(super) struct VmemRegion {
    segment: MemorySegment, // never changes, once set
    bytes_used: AtomicU64,
    // pub(super) used_segments: spin::Mutex<BTreeMap<u64, VmemSegment>>,
    pub(super) used_segments: SpinLock<SegmentMap>,
    pub(super) address_space: UnsafeRef<AddressSpaceBase>,
}

#[cfg(debug_assertions)]
impl Drop for VmemRegion {
    fn drop(&mut self) {
        assert_eq!(self.bytes_used.load(Ordering::Relaxed), 0);
        assert!(self.used_segments.lock(line!()).is_empty());
    }
}

impl VmemRegion {
    fn new(segment: MemorySegment) -> Self {
        VmemRegion {
            segment,
            bytes_used: AtomicU64::new(0),
            used_segments: SpinLock::new(SegmentMap::default()),
            address_space: UnsafeRef::const_default(),
        }
    }

    fn vaddr_map_status(&self, vmem_addr: u64) -> VaddrMapStatus {
        if !self.segment.contains(vmem_addr) {
            return VaddrMapStatus::Unallocated;
        }

        let segments = self.used_segments.lock(line!());
        if let Some(segment) = segments.find(vmem_addr) {
            debug_assert!(segment.segment().contains(vmem_addr));
            return segment.vaddr_map_status(vmem_addr);
        }
        // match segments.range(vmem_addr..).next() {
        //     Some((_, seg)) => {
        //         if seg.segment().contains(vmem_addr) {
        //             return seg.vaddr_map_status(vmem_addr);
        //         }
        //     }
        //     None => {}
        // }

        // match segments.range(..vmem_addr).next_back() {
        //     Some((_, seg)) => {
        //         if seg.segment().contains(vmem_addr) {
        //             return seg.vaddr_map_status(vmem_addr);
        //         }
        //     }
        //     None => {}
        // }

        VaddrMapStatus::Unallocated
    }

    #[allow(unused)]
    pub(super) fn free(&self, addr: u64) -> Result<u64, ErrorCode> {
        if !self.segment.contains(addr) {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let mut segments = self.used_segments.lock(line!());

        if let Some(deleted) = segments.remove(addr) {
            let sz = VmemSegment::unmap(deleted); // Consumes deleted.

            self.bytes_used.fetch_sub(sz, Ordering::Relaxed);
            {
                unsafe { self.address_space.get() }
                    .mem_stats
                    .sub(sz >> PAGE_SIZE_SMALL_LOG2);
            }

            Ok(sz)
        } else {
            Err(moto_rt::E_INVALID_ARGUMENT)
        }
    }

    fn clear(&self) {
        let mut segments = self.used_segments.lock(line!());

        while let Some(deleted) = segments.pop_first() {
            let sz = VmemSegment::unmap(deleted); // Consumes deleted.

            self.bytes_used.fetch_sub(sz, Ordering::Relaxed);
            {
                unsafe { self.address_space.get() }
                    .mem_stats
                    .sub(sz >> PAGE_SIZE_SMALL_LOG2);
            }
        }

        segments.clear();
    }

    pub(super) fn allocate_pages(
        &self,
        num_pages: u64,
        mapping_options: MappingOptions,
    ) -> Result<MemorySegment, ErrorCode> {
        debug_assert!(!self.address_space.is_null());
        debug_assert_ne!(num_pages, 0);
        let size = num_pages << PAGE_SIZE_SMALL_LOG2;
        let mut start = self.segment.start;

        if start == 0 {
            start = PAGE_SIZE_SMALL
        }

        let mut found_gap = false;
        let mut segments = self.used_segments.lock(line!());

        if segments.is_empty() {
            // If nothing has been allocated, we are good.
            if size > self.segment.size {
                log::warn!(
                    "VmemRegion::allocate_pages: bad size: 0x{:x} vs 0x{:x} available.",
                    size,
                    self.segment.size
                );
                return Err(moto_rt::E_OUT_OF_MEMORY);
            }
            found_gap = true;
        } else if let Some(last_seg) = segments.last_segment() {
            // Otherwise, try to add to the end, as this is the fastest.
            let end = last_seg.segment().end();
            if (end + size) <= self.segment.end() {
                start = end;
                found_gap = true;
            }
        }

        if !found_gap {
            // The worst case: find a gap in the middle.
            // This is a linear search, but regions should be large
            // enough to make this a rare/exceptional case.
            for seg in segments.iter() {
                if seg.vmem_segment().segment().start >= (start + size) {
                    found_gap = true;
                    break;
                }
                start = seg.vmem_segment().segment().end();
            }
        }

        if !found_gap {
            log::error!(
                "vmem_allocate: have 0x{:x}, in use 0x{:x}, need 0x{:x}: no gap: OOM",
                self.segment.size,
                self.bytes_used.load(Ordering::Relaxed),
                size
            );
            return Err(moto_rt::E_OUT_OF_MEMORY);
        }

        let mut seg = VmemSegment::new(MemorySegment { start, size }, self, mapping_options);
        seg.allocate_pages()?;
        self.bytes_used.fetch_add(size, Ordering::Relaxed);

        segments.insert(seg);

        unsafe { self.address_space.get() }.mem_stats.add(num_pages);

        Ok(MemorySegment { start, size })
    }

    fn allocate_contiguous_pages(
        &self,
        num_pages: u64,
        mapping_options: MappingOptions,
    ) -> Result<MemorySegment, ErrorCode> {
        let mut frames: alloc::vec::Vec<SlabArc<Frame>> =
            super::phys::phys_allocate_contiguous_frames(PageType::SmallPage, num_pages)?;

        #[cfg(debug_assertions)]
        {
            assert!(!frames.is_empty());

            let mut prev_kind = None;
            let mut prev_start = None;

            for frame in &frames {
                let kind = frame.get().unwrap().kind();
                let start = frame.get().unwrap().start();

                if let Some(prev) = prev_kind {
                    assert_eq!(prev, kind);
                }
                if let Some(prev) = prev_start {
                    assert_eq!(prev + kind.page_size(), start);
                }

                prev_kind = Some(kind);
                prev_start = Some(start);
            }
        }

        let memory_segment = self.allocate_pages(frames.len() as u64, MappingOptions::empty())?;

        let mut segments = self.used_segments.lock(line!());
        let vmem_segment = segments.get_mut(&memory_segment.start).unwrap();
        let mut virt_addr = vmem_segment.segment().start;
        for idx in 0..num_pages {
            let frame = frames[idx as usize].take();

            unsafe {
                self.address_space.get().page_table.map_page(
                    frame.get().unwrap().start(),
                    virt_addr,
                    PageType::SmallPage,
                    mapping_options,
                );
            }

            vmem_segment.set_frame(virt_addr, frame);
            virt_addr += PAGE_SIZE_SMALL;
        }

        Ok(memory_segment)
    }

    pub(super) fn mmio_map(
        &self,
        phys_addr: u64,
        virt_addr: u64,
        user: bool,
    ) -> Result<(), ErrorCode> {
        let segments = self.used_segments.lock(line!());
        let segment = segments.get(&virt_addr).unwrap();
        segment.mmio_map(phys_addr, user)
    }

    fn allocate_user_fixed(
        &self,
        vaddr_start: u64,
        num_pages: u64,
        mapping_options: MappingOptions,
    ) -> Result<MemorySegment, ErrorCode> {
        debug_assert_eq!(0, vaddr_start & (PAGE_SIZE_SMALL - 1));
        debug_assert!(!self.address_space.is_null());
        let size = num_pages << PAGE_SIZE_SMALL_LOG2;

        let memory_segment = MemorySegment {
            start: vaddr_start,
            size,
        };

        if (vaddr_start < self.segment.start) || ((vaddr_start + size) >= self.segment.end()) {
            log::debug!("allocate_user_fixed failed for addr 0x{:x}", vaddr_start);
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let mut segments = self.used_segments.lock(line!());

        // Validate that there is no overlap with existing segments.
        if segments.intersects(&memory_segment) {
            log::debug!("allocate_user_fixed failed for addr 0x{:x}", vaddr_start);
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let mut seg = VmemSegment::new(memory_segment, self, mapping_options);
        self.bytes_used.fetch_add(size, Ordering::Relaxed);

        seg.allocate_pages()?;
        segments.insert(seg);

        unsafe { self.address_space.get() }.mem_stats.add(num_pages);

        Ok(memory_segment)
    }

    fn fix_pagefault(&self, pf_addr: u64, error_code: u64) -> Result<(), ErrorCode> {
        if !self.segment.contains(pf_addr) {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let mut segments = self.used_segments.lock(line!());
        if let Some(seg) = segments.find_mut(pf_addr) {
            debug_assert!(seg.segment().contains(pf_addr));
            return seg.fix_pagefault(pf_addr, error_code);
        }

        Err(moto_rt::E_INVALID_ARGUMENT)
    }
}

pub(super) struct AddressSpaceBase {
    pub(super) page_table: PageTable,
    pub(super) page_allocator: super::virt_intrusive::PageAllocator,

    mem_stats: Arc<crate::xray::stats::MemStats>,
}

impl AddressSpaceBase {
    pub fn page_table(&self) -> u64 {
        self.page_table.phys_addr()
    }

    fn new(kernel: bool) -> Result<Self, ErrorCode> {
        Ok(Self {
            page_table: if kernel {
                PageTable::new_kernel_page_table()
            } else {
                PageTable::new_user_page_table()?
            },
            page_allocator: super::virt_intrusive::PageAllocator::default(),

            mem_stats: Arc::new(if kernel {
                // let stats = super::phys::PhysStats::get();
                // // log::debug and similare are not yet available.
                // crate::arch_raw_log!(
                //     "New kernel address space: s: {} m: {}",
                //     stats.small_pages_used,
                //     stats.mid_pages_used,
                // );

                // MemStats::new_with_data(stats.small_pages_used)

                // Note: while there is some (excessive) memory usage
                //       here, during boot, captured in the commented
                //       section above; it will mostly be freed
                //       later; and this freeing will not be captured
                //       properly, so it is more accurate to start with
                //       zero usage than to have ~30M of extra RAM
                //       attributed to the kernel.

                MemStats::new_kernel()
            } else {
                MemStats::new_user()
            }),
        })
    }
}

pub struct KernelAddressSpace {
    base: AddressSpaceBase,

    kernel_static: VmemRegion,
    kernel_stacks: VmemRegion,
    kernel_heap: VmemRegion,
    kernel_mmio: VmemRegion,

    static_shared_page: UnsafeRef<moto_sys::KernelStaticPage>,
    next_slabs_addr: AtomicU64,

    _pin: PhantomPinned,
}

impl KernelAddressSpace {
    // Unsafe to indicate the caller(s) must deal with memory barriers properly.
    // Otherwise safe, if called after the bootup init.
    fn get_static_shared_page_mut(&self) -> &'static mut moto_sys::KernelStaticPage {
        unsafe { self.static_shared_page.get_mut() }
    }

    fn new() -> &'static mut Self {
        use alloc::boxed::Box;

        assert!(!KERNEL_ADDRESS_SPACE.is_set());

        let result = Box::leak(Box::new(KernelAddressSpace {
            kernel_static: VmemRegion::new(MemorySegment {
                start: VMEM_KSTATIC_START,
                size: VMEM_KSTATIC_END - VMEM_KSTATIC_START,
            }),
            kernel_stacks: VmemRegion::new(MemorySegment {
                start: VMEM_KSTACKS_START,
                size: VMEM_KSTACKS_END - VMEM_KSTACKS_START,
            }),
            kernel_heap: VmemRegion::new(MemorySegment {
                start: VMEM_KHEAP_START,
                size: VMEM_KHEAP_END - VMEM_KHEAP_START,
            }),
            kernel_mmio: VmemRegion::new(MemorySegment {
                start: VMEM_K_MMIO_START,
                size: VMEM_K_MMIO_END - VMEM_K_MMIO_START,
            }),
            base: AddressSpaceBase::new(true).unwrap(),

            static_shared_page: UnsafeRef::const_default(),
            next_slabs_addr: AtomicU64::new(VMEM_K_SLABS_START),

            _pin: PhantomPinned,
        }));

        let space = UnsafeRef::from(&result.base);

        result.kernel_heap.address_space.set_from(&space);
        result.kernel_mmio.address_space.set_from(&space);
        result.kernel_stacks.address_space.set_from(&space);
        result.kernel_static.address_space.set_from(&space);

        {
            let phys_addr = super::phys::phys_allocate_frameless(PageType::SmallPage).unwrap();
            let virt_addr = phys_addr + PAGING_DIRECT_MAP_OFFSET;
            result.static_shared_page =
                UnsafeRef::from_ptr(virt_addr as usize as *const moto_sys::KernelStaticPage);
            super::zero_page(virt_addr, PageType::SmallPage);

            result.base.mem_stats.add(1);
        }

        result
    }

    pub(super) fn static_shared_phys_addr(&self) -> u64 {
        // Safe because we carefully initialized self.static_ref.
        let virt_addr = unsafe { self.static_shared_page.get() } as *const _ as usize as u64;
        virt_addr - PAGING_DIRECT_MAP_OFFSET
    }

    pub fn mem_stats(&self) -> Arc<MemStats> {
        self.base.mem_stats.clone()
    }

    pub(super) fn vmem_allocate_pages(
        &self,
        kind: VmemKind,
        num_pages: u64,
    ) -> Result<MemorySegment, ErrorCode> {
        match kind {
            VmemKind::KernelMMIO => self
                .kernel_mmio
                .allocate_pages(num_pages, MappingOptions::empty()),
            VmemKind::KernelHeap => {
                // assert_eq!(page_type, PageType::MidPage);
                self.kernel_heap.allocate_pages(
                    num_pages,
                    MappingOptions::READABLE | MappingOptions::WRITABLE | MappingOptions::DONT_ZERO,
                )
            }
            VmemKind::KernelStack => self.kernel_stacks.allocate_pages(
                num_pages,
                MappingOptions::READABLE
                    | MappingOptions::WRITABLE
                    | MappingOptions::DONT_ZERO
                    | MappingOptions::GUARD,
            ),
            VmemKind::KernelStatic => self.kernel_static.allocate_pages(
                num_pages,
                MappingOptions::READABLE | MappingOptions::WRITABLE,
            ),
            _ => panic!(),
        }
    }

    #[allow(unused)]
    pub(super) fn free(&self, addr: u64, kind: VmemKind) -> u64 {
        match kind {
            VmemKind::KernelHeap => self.kernel_heap.free(addr).unwrap(),
            VmemKind::KernelStack => self.kernel_stacks.free(addr).unwrap(),
            _ => panic!(),
        }
    }

    // pub(super) fn ___free_segment(&self, addr: u64, size: u64) {
    //     self.kernel_heap.free_segment(addr, size);
    // }

    pub(super) fn vaddr_map_status(&self, vmem_addr: u64) -> VaddrMapStatus {
        let mut status = self.kernel_heap.vaddr_map_status(vmem_addr);
        if status == VaddrMapStatus::Unallocated {
            status = self.kernel_mmio.vaddr_map_status(vmem_addr);
        }
        if status == VaddrMapStatus::Unallocated {
            status = self.kernel_stacks.vaddr_map_status(vmem_addr);
        }

        status
    }

    pub(super) fn mmio_map(&self, phys_addr: u64, virt_addr: u64) -> Result<(), ErrorCode> {
        self.kernel_mmio.mmio_map(phys_addr, virt_addr, false)
    }
}

pub(super) static KERNEL_ADDRESS_SPACE: StaticRef<KernelAddressSpace> = StaticRef::default_const();

pub(super) struct UserAddressSpaceBase {
    base: AddressSpaceBase,
    pub(super) normal_memory: VmemRegion, // "Normal" memory, managed by the kernel.
    pub(super) custom_memory: VmemRegion, // "Custom" memory, managed by the userspace.

    // Each process has a small page that the kernel maps at a fixed address
    // to share some info. See moto_sys::shared_mem::ProcessStaticPage.
    process_static_page_phys_addr: AtomicU64,
}

impl Drop for UserAddressSpaceBase {
    fn drop(&mut self) {
        self.normal_memory.clear();
        self.custom_memory.clear();

        self.base.page_allocator.clear();

        // Need to manually unmap manually mapped pages.
        self.base.page_table.unmap_page(
            KERNEL_ADDRESS_SPACE.static_shared_phys_addr(),
            KERNEL_STATIC_SHARED_PAGE_USER_VADDR,
            PageType::SmallPage,
        );

        let phys_addr = self
            .process_static_page_phys_addr
            .swap(0, Ordering::Relaxed);
        self.base.page_table.unmap_page(
            phys_addr,
            PROCESS_STATIC_SHARED_PAGE_USER_VADDR,
            PageType::SmallPage,
        );
        super::phys::phys_deallocate_frameless(phys_addr, PageType::SmallPage);

        self.base.page_table.unmap_kernel_from_user();

        #[cfg(debug_assertions)]
        log::debug!("UserAddressSpaceBase::drop()");
    }
}

impl UserAddressSpaceBase {
    pub fn page_table(&self) -> u64 {
        self.base.page_table()
    }

    pub(super) fn page_table_ref(&self) -> &PageTable {
        &self.base.page_table
    }

    pub(super) fn new() -> Result<Self, ErrorCode> {
        #[cfg(debug_assertions)]
        log::debug!("UserAddressSpaceBase::new()");

        Ok(UserAddressSpaceBase {
            normal_memory: VmemRegion::new(MemorySegment {
                start: 0,
                size: VMEM_USER_END,
            }),
            custom_memory: VmemRegion::new(MemorySegment {
                start: moto_sys::CUSTOM_USERSPACE_REGION_START,
                size: moto_sys::CUSTOM_USERSPACE_REGION_END
                    - moto_sys::CUSTOM_USERSPACE_REGION_START,
            }),

            base: AddressSpaceBase::new(false)?,
            process_static_page_phys_addr: AtomicU64::new(0),
        })
    }

    pub(super) fn init(&mut self) {
        let space = UnsafeRef::from(&self.base);

        let region = &mut self.normal_memory;
        region.address_space.set_from(&space);
        let region = &mut self.custom_memory;
        region.address_space.set_from(&space);

        // We map kernel to user (with user accessible bit not set) for simplicity.
        // We may need to harden this against speculative execution attacks.
        self.base
            .page_table
            .map_kernel_to_user(&KERNEL_ADDRESS_SPACE.base.page_table);

        const _: () = assert!(moto_sys::KernelStaticPage::PAGE_SIZE == PAGE_SIZE_SMALL);

        self.base.page_table.map_page(
            KERNEL_ADDRESS_SPACE.static_shared_phys_addr(),
            KERNEL_STATIC_SHARED_PAGE_USER_VADDR,
            PageType::SmallPage,
            MappingOptions::READABLE | MappingOptions::USER_ACCESSIBLE | MappingOptions::DONT_ZERO,
        );

        let phys_addr = super::phys::phys_allocate_frameless(PageType::SmallPage).unwrap();
        self.base.page_table.map_page(
            phys_addr,
            PROCESS_STATIC_SHARED_PAGE_USER_VADDR,
            PageType::SmallPage,
            MappingOptions::READABLE | MappingOptions::USER_ACCESSIBLE,
        );
        self.process_static_page_phys_addr
            .store(phys_addr, Ordering::Relaxed);
    }

    pub fn process_static_page_mut(&self) -> &'static mut moto_sys::ProcessStaticPage {
        let vaddr =
            self.process_static_page_phys_addr.load(Ordering::Relaxed) + PAGING_DIRECT_MAP_OFFSET;
        unsafe {
            (vaddr as usize as *mut moto_sys::ProcessStaticPage)
                .as_mut()
                .unwrap_unchecked()
        }
    }

    pub(super) fn mem_stats(&self) -> &Arc<MemStats> {
        &self.base.mem_stats
    }

    pub(super) fn vmem_allocate_pages(
        &self,
        kind: VmemKind,
        num_pages: u64,
        mapping_options: Option<MappingOptions>,
    ) -> Result<MemorySegment, ErrorCode> {
        debug_assert_ne!(num_pages, 0);

        if let Some(m_o) = mapping_options {
            return self.normal_memory.allocate_pages(num_pages, m_o);
        };

        match kind {
            VmemKind::User => self.normal_memory.allocate_pages(
                num_pages,
                MappingOptions::READABLE
                    | MappingOptions::WRITABLE
                    | MappingOptions::USER_ACCESSIBLE,
            ),
            VmemKind::UserStack => self.normal_memory.allocate_pages(
                num_pages,
                MappingOptions::READABLE
                    | MappingOptions::WRITABLE
                    | MappingOptions::USER_ACCESSIBLE
                    | MappingOptions::LAZY
                    | MappingOptions::GUARD,
            ),
            VmemKind::UserMMIO | VmemKind::Unmapped => self
                .normal_memory
                .allocate_pages(num_pages, MappingOptions::empty()),
            _ => panic!("Unexpected VmemKind for userspace memory."),
        }
    }

    pub(super) fn vmem_allocate_contiguous_pages(
        &self,
        kind: VmemKind,
        num_pages: u64,
    ) -> Result<MemorySegment, ErrorCode> {
        debug_assert_ne!(num_pages, 0);
        debug_assert_eq!(kind, VmemKind::User);
        self.normal_memory.allocate_contiguous_pages(
            num_pages,
            MappingOptions::READABLE | MappingOptions::WRITABLE | MappingOptions::USER_ACCESSIBLE,
        )
    }

    pub(super) fn vmem_allocate_user_fixed(
        &self,
        vaddr_start: u64,
        num_pages: u64,
        mapping_options: MappingOptions,
    ) -> Result<MemorySegment, ErrorCode> {
        match vaddr_start {
            0..=VMEM_USER_END => {
                self.normal_memory
                    .allocate_user_fixed(vaddr_start, num_pages, mapping_options)
            }
            moto_sys::CUSTOM_USERSPACE_REGION_START..=moto_sys::CUSTOM_USERSPACE_REGION_END => self
                .custom_memory
                .allocate_user_fixed(vaddr_start, num_pages, mapping_options),
            _ => Err(moto_rt::E_INVALID_ARGUMENT),
        }
    }

    pub(super) fn vaddr_map_status(&self, vmem_addr: u64) -> VaddrMapStatus {
        match vmem_addr {
            0..=VMEM_USER_END => self.normal_memory.vaddr_map_status(vmem_addr),
            moto_sys::CUSTOM_USERSPACE_REGION_START..=moto_sys::CUSTOM_USERSPACE_REGION_END => {
                self.custom_memory.vaddr_map_status(vmem_addr)
            }
            _ => VaddrMapStatus::Unallocated,
        }
    }

    pub(super) fn mmio_map(&self, phys_addr: u64, virt_addr: u64) -> Result<(), ErrorCode> {
        self.normal_memory.mmio_map(phys_addr, virt_addr, true)
    }

    pub(super) fn share_with(
        &self,
        addr_here: u64,
        other: &Self,
        addr_there: u64,
        mapping_options: MappingOptions,
    ) -> Result<(), ErrorCode> {
        log::trace!(
            "share_with: here: 0x{:x} there: 0x{:x}",
            addr_here,
            addr_there
        );
        let ptr_here = self as *const _ as usize;
        let ptr_there = other as *const _ as usize;
        if ptr_here == ptr_there {
            // TODO: here we duplicate the mapping code below, as
            // we have only one mutex guard, not two. Can this be
            // easily refactored to avoid duplicate code?
            let lock_both = if self.normal_memory.segment.contains(addr_here) {
                self.normal_memory.used_segments.lock(line!())
            } else {
                self.custom_memory.used_segments.lock(line!())
            };
            let map_here_segment = lock_both.get(&addr_here);
            let map_there_segment = lock_both.get(&addr_there);

            if map_there_segment.is_none() || map_here_segment.is_none() {
                log::debug!("map_shared: can't find the segments to map");
                return Err(moto_rt::E_INVALID_ARGUMENT);
            }

            let map_there_segment = map_there_segment.unwrap();
            let map_here_segment = map_here_segment.unwrap();

            if map_there_segment.segment().size != map_here_segment.segment().size {
                log::debug!(
                    "map_shared: segment sizes don't match: to: {} from: {}",
                    map_there_segment.segment().size,
                    map_here_segment.segment().size,
                );
                return Err(moto_rt::E_INVALID_ARGUMENT);
            }

            // Rust does not allow concurrent mutable access to elements of
            // a collection, so we need to remove const "unsafely". This is
            // actually safe, as everything is protected by lock_both.
            let there_mut = unsafe {
                (map_there_segment as *const _ as usize as *mut VmemSegment)
                    .as_mut()
                    .unwrap_unchecked()
            };

            return map_here_segment.share_with(
                there_mut,
                mapping_options | MappingOptions::USER_ACCESSIBLE | MappingOptions::DONT_ZERO,
            );
        }

        // Always lock in the same order to avoid deadlocks.
        let (mut lock_here, mut lock_there) = {
            if ptr_here < ptr_there {
                let lock_there = if other.normal_memory.segment.contains(addr_there) {
                    other.normal_memory.used_segments.lock(line!())
                } else {
                    other.custom_memory.used_segments.lock(line!())
                };
                let lock_here = if self.normal_memory.segment.contains(addr_here) {
                    self.normal_memory.used_segments.lock(line!())
                } else {
                    self.custom_memory.used_segments.lock(line!())
                };

                (lock_here, lock_there)
            } else {
                let lock_here = if self.normal_memory.segment.contains(addr_here) {
                    self.normal_memory.used_segments.lock(line!())
                } else {
                    self.custom_memory.used_segments.lock(line!())
                };
                let lock_there = if other.normal_memory.segment.contains(addr_there) {
                    other.normal_memory.used_segments.lock(line!())
                } else {
                    other.custom_memory.used_segments.lock(line!())
                };

                (lock_here, lock_there)
            }
        };

        // TODO: we here only map if both address spaces have allocated
        // the segments to map exactly as they are being considered here.
        // We should allow mapping any allocated region to any allocated
        // region, regardless of the history of allocations.
        let map_here_segment = lock_here.get_mut(&addr_here);
        let map_there_segment = lock_there.get_mut(&addr_there);

        if map_there_segment.is_none() || map_here_segment.is_none() {
            log::debug!("map_shared: can't find the segments to map");
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let map_there_segment = map_there_segment.unwrap();
        let map_here_segment = map_here_segment.unwrap();

        if map_there_segment.segment().size != map_here_segment.segment().size {
            log::debug!(
                "map_shared: segment sizes don't match: to: {} from: {}",
                map_there_segment.segment().size,
                map_here_segment.segment().size,
            );
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        map_here_segment.share_with(
            map_there_segment,
            mapping_options | MappingOptions::USER_ACCESSIBLE | MappingOptions::DONT_ZERO,
        )
    }

    pub(super) fn fix_pagefault(&self, pf_addr: u64, error_code: u64) -> Result<(), ErrorCode> {
        self.normal_memory.fix_pagefault(pf_addr, error_code)
    }
}
