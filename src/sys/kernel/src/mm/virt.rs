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
        .map_page(phys_addr, virt_addr, kind, options)
        .expect("invalid kernel mapping options");
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
    UserStack,
    Unmapped,
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum VaddrMapStatus {
    Unallocated,
    Unmapped,
    ZeroPageMapped,
    Mmio,
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

/// Read-only kernel-static mapping of reserved physical pages (see
/// `VmemRegion::map_reserved_pages`).
pub fn vmem_map_reserved_pages(
    phys_start: u64,
    num_pages: u64,
) -> Result<MemorySegment, ErrorCode> {
    KERNEL_ADDRESS_SPACE.kernel_static.map_reserved_pages(
        phys_start,
        num_pages,
        MappingOptions::READABLE,
    )
}

pub fn vmem_free(addr: u64, kind: VmemKind) -> u64 {
    KERNEL_ADDRESS_SPACE.free(addr, kind)
}

pub fn vaddr_map_status(vmem_addr: u64) -> VaddrMapStatus {
    KERNEL_ADDRESS_SPACE.vaddr_map_status(vmem_addr)
}

// Huge-mapping events, cumulative and including later undone maps: a
// successful huge PTE installation, and a candidate served small (also the
// candidates skipped after the first refusal). Produced once huge pages map.
pub(crate) static HUGE_PAGES_MAPPED: AtomicU64 = AtomicU64::new(0);
pub(crate) static HUGE_FALLBACKS: AtomicU64 = AtomicU64::new(0);

// The first `align`-aligned start of `size` bytes inside [gap_start,
// gap_end), with checked arithmetic and an exact end bound.
fn aligned_start(gap_start: u64, gap_end: u64, size: u64, align: u64) -> Option<u64> {
    debug_assert!(align.is_power_of_two());
    let start = gap_start.checked_add(align - 1)? & !(align - 1);
    let end = start.checked_add(size)?;
    (end <= gap_end).then_some(start)
}

#[cfg(debug_assertions)]
pub(crate) fn self_test() {
    let (small, mid) = (PAGE_SIZE_SMALL, PAGE_SIZE_MID);
    // Empty region, append and gap placement all reduce to this: an exact
    // fit, an aligned fit, a gap one byte short, and an aligned gap that is
    // too narrow once its start is rounded up.
    assert_eq!(aligned_start(0, 2 * small, small, small), Some(0));
    assert_eq!(aligned_start(small, 2 * small, small, small), Some(small));
    assert_eq!(aligned_start(small, 2 * small, 2 * small, small), None);
    assert_eq!(aligned_start(small, 2 * small - 1, small, small), None);
    assert_eq!(aligned_start(small, 4 * mid, small, mid), Some(mid));
    assert_eq!(aligned_start(mid + 1, 6 * mid, 2 * mid, mid), Some(2 * mid));
    assert_eq!(aligned_start(mid + 1, 4 * mid - 1, 2 * mid, mid), None);
    assert_eq!(aligned_start(mid, 3 * mid, 2 * mid, mid), Some(mid));
    assert_eq!(aligned_start(u64::MAX - 100, u64::MAX, small, small), None);
    assert_eq!(
        aligned_start(u64::MAX - small + 1, u64::MAX, 1, small),
        Some(u64::MAX - small + 1)
    );
    assert_eq!(
        aligned_start(u64::MAX - small + 1, u64::MAX, small, small),
        None
    );

    // The creation policy never reaches a page; guard handling is unchanged.
    use super::virt_intrusive::page_mapping_options;
    let rw = MappingOptions::READABLE | MappingOptions::WRITABLE;
    let eligible = rw | MappingOptions::HUGE_ELIGIBLE;
    assert_eq!(page_mapping_options(eligible, 0, 4), rw);
    assert_eq!(page_mapping_options(eligible, 3, 4), rw);
    let guarded = eligible | MappingOptions::GUARD | MappingOptions::LAZY;
    assert_eq!(page_mapping_options(guarded, 0, 4), MappingOptions::empty());
    assert_eq!(page_mapping_options(guarded, 3, 4), MappingOptions::empty());
    assert_eq!(page_mapping_options(guarded, 1, 4), rw);
    assert_eq!(
        page_mapping_options(rw | MappingOptions::LAZY, 2, 4),
        rw | MappingOptions::LAZY
    );
    crate::raw_log!("virt placement tests PASS");
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

    fn pin_user_page(&self, addr: u64) -> Option<(SlabArc<Frame>, u64)> {
        let segments = self.used_segments.lock(line!());
        segments.find(addr)?.pin_user_page(addr)
    }

    #[allow(unused)]
    pub(super) fn free(&self, addr: u64) -> Result<u64, ErrorCode> {
        if !self.segment.contains(addr) {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let mut segments = self.used_segments.lock(line!());
        self.free_locked(&mut segments, addr)
    }

    fn free_locked(&self, segments: &mut SegmentMap, addr: u64) -> Result<u64, ErrorCode> {
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
        let mut segments = self.used_segments.lock(line!());
        self.allocate_pages_locked(&mut segments, num_pages, mapping_options)
    }

    fn allocate_pages_locked(
        &self,
        segments: &mut SegmentMap,
        num_pages: u64,
        mapping_options: MappingOptions,
    ) -> Result<MemorySegment, ErrorCode> {
        debug_assert!(!self.address_space.is_null());
        debug_assert_ne!(num_pages, 0);
        let size = num_pages << PAGE_SIZE_SMALL_LOG2;
        // Huge-eligible segments start on a 2 MiB boundary, whether or not
        // any candidate ends up huge.
        let align = if mapping_options.contains(MappingOptions::HUGE_ELIGIBLE) {
            PAGE_SIZE_MID
        } else {
            PAGE_SIZE_SMALL
        };
        let region_start = self.segment.start.max(PAGE_SIZE_SMALL);
        let region_end = self.segment.end();

        let mut start = None;
        if segments.is_empty() {
            start = aligned_start(region_start, region_end, size, align);
        } else if let Some(last_seg) = segments.last_segment() {
            // Appending is the fastest.
            start = aligned_start(last_seg.segment().end(), region_end, size, align);
        }
        if start.is_none() {
            // The worst case: find a gap in the middle. This is a linear
            // search, but regions should be large enough to make this rare.
            let mut gap_start = region_start;
            for seg in segments.iter() {
                let next = seg.vmem_segment().segment();
                start = aligned_start(gap_start, next.start, size, align);
                if start.is_some() {
                    break;
                }
                gap_start = next.end();
            }
        }

        let Some(start) = start else {
            log::error!(
                "vmem_allocate: have 0x{:x}, in use 0x{:x}, need 0x{:x}: no gap: OOM",
                self.segment.size,
                self.bytes_used.load(Ordering::Relaxed),
                size
            );
            return Err(moto_rt::E_OUT_OF_MEMORY);
        };

        let mut seg = VmemSegment::new(MemorySegment { start, size }, self, mapping_options);
        seg.allocate_pages()?;
        self.bytes_used.fetch_add(size, Ordering::Relaxed);

        segments.insert(seg);

        unsafe { self.address_space.get() }.mem_stats.add(num_pages);

        Ok(MemorySegment { start, size })
    }

    // Maps `num_pages` physical pages at `phys_start`, already reserved in
    // the physical allocator, into a new segment that adopts them as its
    // frames. Boot-time only: a failure leaves the segment half built.
    pub(super) fn map_reserved_pages(
        &self,
        phys_start: u64,
        num_pages: u64,
        mapping_options: MappingOptions,
    ) -> Result<MemorySegment, ErrorCode> {
        debug_assert_eq!(0, phys_start & (PAGE_SIZE_SMALL - 1));
        let mut segments = self.used_segments.lock(line!());
        let memory_segment =
            self.allocate_pages_locked(&mut segments, num_pages, MappingOptions::empty())?;
        let vmem_segment = segments.get_mut(&memory_segment.start).unwrap();
        let mut virt_addr = memory_segment.start;
        let mut phys_addr = phys_start;
        for _ in 0..num_pages {
            let frame = super::phys::adopt_frame(phys_addr)?;
            unsafe {
                self.address_space.get().page_table.map_page(
                    phys_addr,
                    virt_addr,
                    PageType::SmallPage,
                    mapping_options | MappingOptions::DONT_ZERO,
                )?;
            }
            vmem_segment.set_frame(virt_addr, frame);
            virt_addr += PAGE_SIZE_SMALL;
            phys_addr += PAGE_SIZE_SMALL;
        }

        Ok(memory_segment)
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

        // Do not expose a reservation that unmap can remove before mapping completes.
        let mut segments = self.used_segments.lock(line!());
        let memory_segment =
            self.allocate_pages_locked(&mut segments, num_pages, MappingOptions::empty())?;
        let vmem_segment = segments.get_mut(&memory_segment.start).unwrap();
        let mut virt_addr = vmem_segment.segment().start;
        for idx in 0..num_pages {
            let frame = frames[idx as usize].take();

            let result = unsafe {
                self.address_space.get().page_table.map_page(
                    frame.get().unwrap().start(),
                    virt_addr,
                    PageType::SmallPage,
                    mapping_options,
                )
            };
            if let Err(err) = result {
                // Unmap the successful prefix before its frames can be freed.
                self.free_locked(&mut segments, memory_segment.start)
                    .unwrap();
                return Err(err);
            }

            vmem_segment.set_frame(virt_addr, frame);
            virt_addr += PAGE_SIZE_SMALL;
        }

        Ok(memory_segment)
    }

    pub(super) fn mmio_map(
        &self,
        phys_addr: u64,
        num_pages: u64,
        user: bool,
    ) -> Result<MemorySegment, ErrorCode> {
        // Reservation, mapping and rollback share the same lock as unmap.
        let mut segments = self.used_segments.lock(line!());
        let memory_segment =
            self.allocate_pages_locked(&mut segments, num_pages, MappingOptions::empty())?;
        let virt_addr = memory_segment.start;
        let segment = segments.get_mut(&virt_addr).unwrap();
        let size = segment.segment().size;
        let result = segment.mmio_map(phys_addr, user);
        if result.is_err() {
            // Tear down the mapped prefix before releasing the reservation lock.
            assert_eq!(self.free_locked(&mut segments, virt_addr).unwrap(), size);
            #[cfg(debug_assertions)]
            {
                assert!(segments.find(virt_addr).is_none());
                let pt = &unsafe { self.address_space.get() }.page_table;
                for offset in (0..size).step_by(PAGE_SIZE_SMALL as usize) {
                    assert!(pt.virt_to_phys(virt_addr + offset).is_none());
                }
            }
        }
        result.map(|()| memory_segment)
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
            log::debug!("allocate_user_fixed failed for addr 0x{vaddr_start:x}");
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let mut segments = self.used_segments.lock(line!());

        // Validate that there is no overlap with existing segments.
        if segments.intersects(&memory_segment) {
            log::debug!("allocate_user_fixed failed for addr 0x{vaddr_start:x}");
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let mut seg = VmemSegment::new(memory_segment, self, mapping_options);
        seg.allocate_pages()?;
        self.bytes_used.fetch_add(size, Ordering::Relaxed);
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
            VmemKind::KernelMMIO => self.kernel_mmio.free(addr).unwrap(),
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

    pub(super) fn mmio_map(
        &self,
        phys_addr: u64,
        num_pages: u64,
    ) -> Result<MemorySegment, ErrorCode> {
        self.kernel_mmio.mmio_map(phys_addr, num_pages, false)
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

        self.base
            .page_table
            .map_page(
                KERNEL_ADDRESS_SPACE.static_shared_phys_addr(),
                KERNEL_STATIC_SHARED_PAGE_USER_VADDR,
                PageType::SmallPage,
                MappingOptions::READABLE
                    | MappingOptions::USER_ACCESSIBLE
                    | MappingOptions::DONT_ZERO,
            )
            .expect("invalid kernel-static-page mapping options");

        let phys_addr = super::phys::phys_allocate_frameless(PageType::SmallPage).unwrap();
        self.base
            .page_table
            .map_page(
                phys_addr,
                PROCESS_STATIC_SHARED_PAGE_USER_VADDR,
                PageType::SmallPage,
                MappingOptions::READABLE | MappingOptions::USER_ACCESSIBLE,
            )
            .expect("invalid process-static-page mapping options");
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
            VmemKind::Unmapped => self
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

    pub(super) fn pin_user_page(&self, addr: u64) -> Option<(SlabArc<Frame>, u64)> {
        match addr {
            0..=VMEM_USER_END => self.normal_memory.pin_user_page(addr),
            moto_sys::CUSTOM_USERSPACE_REGION_START..=moto_sys::CUSTOM_USERSPACE_REGION_END => {
                self.custom_memory.pin_user_page(addr)
            }
            _ => None,
        }
    }

    pub(super) fn mmio_map(
        &self,
        phys_addr: u64,
        num_pages: u64,
    ) -> Result<MemorySegment, ErrorCode> {
        self.normal_memory.mmio_map(phys_addr, num_pages, true)
    }

    pub(super) fn share_with(
        &self,
        addr_here: u64,
        other: &Self,
        addr_there: u64,
        mapping_options: MappingOptions,
    ) -> Result<(), ErrorCode> {
        log::trace!("share_with: here: 0x{addr_here:x} there: 0x{addr_there:x}");
        let ptr_here = self as *const _ as usize;
        let ptr_there = other as *const _ as usize;
        if ptr_here == ptr_there {
            if addr_here == addr_there {
                log::debug!("map_shared: source and destination are identical");
                return Err(moto_rt::E_INVALID_ARGUMENT);
            }

            // TODO: here we duplicate the mapping code below, as
            // we have only one mutex guard, not two. Can this be
            // easily refactored to avoid duplicate code?
            let here_in_normal = self.normal_memory.segment.contains(addr_here);
            let there_in_normal = self.normal_memory.segment.contains(addr_there);

            if here_in_normal == there_in_normal {
                let lock = if here_in_normal {
                    self.normal_memory.used_segments.lock(line!())
                } else {
                    self.custom_memory.used_segments.lock(line!())
                };
                let Some(map_here_segment) = lock.get(&addr_here) else {
                    log::debug!("map_shared: can't find the source segment");
                    return Err(moto_rt::E_INVALID_ARGUMENT);
                };
                let Some(map_there_segment) = lock.get(&addr_there) else {
                    log::debug!("map_shared: can't find the destination segment");
                    return Err(moto_rt::E_INVALID_ARGUMENT);
                };

                if map_there_segment.segment().size != map_here_segment.segment().size {
                    log::debug!(
                        "map_shared: segment sizes don't match: to: {} from: {}",
                        map_there_segment.segment().size,
                        map_here_segment.segment().size,
                    );
                    return Err(moto_rt::E_INVALID_ARGUMENT);
                }

                // TODO: add a SegmentMap helper for borrowing two distinct
                // entries mutably, then remove this same-region cast.
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

            // Cross-region sharing has two independent collections, so the
            // destination can be borrowed mutably without a cast. Keep the
            // lock order fixed: normal, then custom.
            let mut normal = self.normal_memory.used_segments.lock(line!());
            let mut custom = self.custom_memory.used_segments.lock(line!());
            let (map_here_segment, map_there_segment) = if here_in_normal {
                (normal.get(&addr_here), custom.get_mut(&addr_there))
            } else {
                (custom.get(&addr_here), normal.get_mut(&addr_there))
            };

            let Some(map_here_segment) = map_here_segment else {
                log::debug!("map_shared: can't find the source segment");
                return Err(moto_rt::E_INVALID_ARGUMENT);
            };
            let Some(map_there_segment) = map_there_segment else {
                log::debug!("map_shared: can't find the destination segment");
                return Err(moto_rt::E_INVALID_ARGUMENT);
            };

            if map_there_segment.segment().size != map_here_segment.segment().size {
                log::debug!(
                    "map_shared: segment sizes don't match: to: {} from: {}",
                    map_there_segment.segment().size,
                    map_here_segment.segment().size,
                );
                return Err(moto_rt::E_INVALID_ARGUMENT);
            }

            return map_here_segment.share_with(
                map_there_segment,
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

    /// Maps the kernel-static pages starting at `kernel_vaddr` into the
    /// reservation at `vaddr` (both page-aligned; the reservation's size
    /// says how many), sharing the frames. This is how sys-io's read-only
    /// segments are mapped from the kernel's copy of its ELF bytes.
    pub(super) fn share_kernel_static(
        &self,
        kernel_vaddr: u64,
        vaddr: u64,
        mapping_options: MappingOptions,
    ) -> Result<(), ErrorCode> {
        let kernel_segments = KERNEL_ADDRESS_SPACE
            .kernel_static
            .used_segments
            .lock(line!());
        let Some(source) = kernel_segments.find(kernel_vaddr) else {
            log::debug!("share_kernel_static: 0x{kernel_vaddr:x} is not kernel-static");
            return Err(moto_rt::E_INVALID_ARGUMENT);
        };
        let first_page = (kernel_vaddr - source.segment().start) >> PAGE_SIZE_SMALL_LOG2;

        let mut user_segments = if self.normal_memory.segment.contains(vaddr) {
            self.normal_memory.used_segments.lock(line!())
        } else {
            self.custom_memory.used_segments.lock(line!())
        };
        let Some(dest) = user_segments.get_mut(&vaddr) else {
            log::debug!("share_kernel_static: no reservation at 0x{vaddr:x}");
            return Err(moto_rt::E_INVALID_ARGUMENT);
        };

        source.share_range_with(
            first_page,
            dest,
            mapping_options | MappingOptions::USER_ACCESSIBLE | MappingOptions::DONT_ZERO,
        )
    }
}
