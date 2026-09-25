use core::sync::atomic::*;

use alloc::sync::Arc;

use super::{virt::*, PAGE_SIZE_SMALL, PAGE_SIZE_SMALL_LOG2};
use crate::mm::{MappingOptions, PAGE_SIZE_MID};
use crate::xray::stats::MemStats;
use moto_sys::ErrorCode;

// A direct-map address is usable only while its backing frame is owned.
pub struct PinnedUserPage {
    frame: super::slab::SlabArc<super::phys::Frame>,
    offset: u64,
}

impl PinnedUserPage {
    pub fn kernel_addr(&self) -> u64 {
        self.frame.get().unwrap().start()
            + self.offset
            + crate::arch::paging::PAGING_DIRECT_MAP_OFFSET
    }
}

#[derive(Debug)]
pub struct UserStack {
    segment: super::MemorySegment, // Includes guard pages.
}

impl UserStack {
    pub fn stack_top(&self) -> u64 {
        self.segment.end() - PAGE_SIZE_SMALL
    }

    pub fn is_overflow(&self, addr: u64) -> bool {
        (self.segment.start <= addr) && ((self.segment.start + PAGE_SIZE_SMALL) > addr)
    }

    pub fn is_underflow(&self, addr: u64) -> bool {
        (self.stack_top() <= addr) && (self.segment.end() > addr)
    }
}

pub struct UserAddressSpace {
    inner: UserAddressSpaceBase,

    // The maximum amount of memory (phys, including the binary)
    // that the owner process is allowed to use.
    max_memory: AtomicU64,
    total_usage: AtomicU64,

    // System and I/O-manager address spaces use the lower admission floor.
    // Set from CAP_SYS | CAP_IO_MANAGER when the process is created.
    privileged: AtomicBool,

    // User mem stats are tracked via @inner.
    // Kernel mem stats (kernel stacks) are tracked here.
    kernel_mem_stats: Arc<MemStats>,

    kernel_stacks: super::cache::SegmentCache,
    // user_stacks: super::cache::SegmentCache,
}

unsafe impl Send for UserAddressSpace {}
unsafe impl Sync for UserAddressSpace {}

impl Drop for UserAddressSpace {
    fn drop(&mut self) {
        // W6b: CPUs no longer leave a process's page table on syscall/
        // preempt, so this CPU (running the teardown) and idle remote CPUs
        // may still have it as CR3. Teardown mutates the table — including
        // removing its *kernel* L4 entries (unmap_kernel_from_user), which
        // triple-faults any CPU still standing on it as soon as a kernel
        // address misses the (global) TLB. Move everyone off first.
        crate::arch::tlb::evict_user_page_table(self.inner.page_table_ref().phys_addr());

        self.inner.page_table_ref().mark_dead();

        // We manually clear caches instead of relying on drops
        // to make sure self.inner is still available, and to
        // validate usage stats.
        // while let Some(segment) = self.user_stacks.pop_any_final() {
        //     self.do_drop_user_stack(segment);
        // }
        while let Some(segment) = self.kernel_stacks.pop_any_final() {
            self.do_drop_kernel_stack(segment);
        }

        log::debug!("UserAddressSpace::drop()");
        // We don't check that total_usage is zero here, because
        // memory could still be mapped in self.inner.
    }
}

impl UserAddressSpace {
    pub fn new() -> Result<Arc<Self>, ErrorCode> {
        log::debug!("UserAddressSpace::new()");

        let self_ = Arc::new(Self {
            inner: UserAddressSpaceBase::new()?,
            max_memory: AtomicU64::new(
                crate::config::get()
                    .default_max_user_memory
                    .load(Ordering::Relaxed),
            ),
            total_usage: AtomicU64::new(0),
            privileged: AtomicBool::new(false),
            kernel_mem_stats: Arc::new(MemStats::new_kernel()),

            kernel_stacks: super::cache::SegmentCache::new(),
            //
            // NOTE: commit c090f671a26b193dd6b1c4d36ab5669539d88d7a
            // added several fields to userspace TCB, and httpd started
            // to panic via __stack_chk_fail() after spawning ~ 50 threads.
            // The panic was consistently triggered in some "C" curve encryption
            // code in ring crate.
            //
            // Before this change the error was not there - httpd ran for
            // several days without any issues.
            //
            // Tweaks here and there made it so that the error became less
            // frequent, but the only change that restored reliability
            // is this one, the removal of user stack caching.
            // Increasing stack size to 4M didn't help.
            //
            // Why user stack caching change is relevant?
            // - option 1: it is buggy and the same stack is occasionally
            //   shared between threads;
            // - option 2: the ring code is buggy and on-stack variables
            //   must be implicitly initialized to zero: without stack caching
            //   user stacks are zero-initialized; with stack caching
            //   reused stacks contain old data (from the same process).
            //
            // TODO: re-enable user stack caching.
            // user_stacks: super::cache::SegmentCache::new(),
        });

        // Safe because we are the only users.
        unsafe {
            let self_ref = &*self_;
            let self_mut = self_ref as *const _ as usize as *mut Self;
            (*self_mut).inner.init();
        }

        Ok(self_)
    }

    pub fn process_static_page_mut(&self) -> &'static mut moto_sys::ProcessStaticPage {
        self.inner.process_static_page_mut()
    }

    pub fn user_mem_stats(&self) -> &Arc<MemStats> {
        self.inner.mem_stats()
    }

    pub fn mark_privileged(&self) {
        self.privileged.store(true, Ordering::Relaxed);
    }

    /// The admission class of this address space. Operations on it are charged
    /// against this class even when a remote process (e.g. a loader) makes
    /// them, so loading an ordinary process never widens its guard band.
    pub fn mem_class(&self) -> super::admission::MemClass {
        if self.privileged.load(Ordering::Relaxed) {
            super::admission::MemClass::Privileged
        } else {
            super::admission::MemClass::User
        }
    }

    pub fn kernel_mem_stats(&self) -> &Arc<MemStats> {
        &self.kernel_mem_stats
    }

    fn stats_user_add(&self, bytes: u64) -> Result<(), ErrorCode> {
        let new_total = bytes + self.total_usage.fetch_add(bytes, Ordering::AcqRel);
        if new_total > self.max_memory.load(Ordering::Relaxed) {
            #[cfg(debug_assertions)]
            {
                log::error!("user OOM: user usage {new_total} when allocating {bytes}",);
                crate::arch::log_backtrace("user OOM");
            }
            self.total_usage.fetch_sub(bytes, Ordering::Relaxed);
            Err(moto_rt::E_OUT_OF_MEMORY)
        } else {
            Ok(())
        }
    }

    fn stats_user_sub(&self, bytes: u64) {
        self.total_usage.fetch_sub(bytes, Ordering::Relaxed);
    }

    fn stats_kernel_add(&self, num_pages: u64) -> Result<(), ErrorCode> {
        // TODO: replace the magic constant below with something more intelligent.
        if num_pages >= 65536 {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        let bytes = num_pages << PAGE_SIZE_SMALL_LOG2;
        let new_total = bytes + self.total_usage.fetch_add(bytes, Ordering::AcqRel);
        if new_total > self.max_memory.load(Ordering::Relaxed) {
            #[cfg(debug_assertions)]
            log::info!("user OOM: user usage {new_total} when allocating {bytes}");
            self.total_usage.fetch_sub(bytes, Ordering::Relaxed);
            Err(moto_rt::E_OUT_OF_MEMORY)
        } else {
            self.kernel_mem_stats.add(num_pages);
            Ok(())
        }
    }

    fn stats_kernel_sub(&self, num_pages: u64) {
        let bytes = num_pages << PAGE_SIZE_SMALL_LOG2;
        self.total_usage.fetch_sub(bytes, Ordering::Relaxed);
        self.kernel_mem_stats.sub(num_pages);
    }

    pub fn allocate_user_fixed(
        &self,
        vaddr: u64,
        num_pages: u64,
        mapping_options: super::MappingOptions,
    ) -> Result<(), ErrorCode> {
        self.inner
            .vmem_allocate_user_fixed(vaddr, num_pages, mapping_options)?;
        Ok(())
    }

    pub fn map_shared(
        map_to: &Self,
        map_to_addr: u64,
        map_from: &Self,
        map_from_addr: u64,
        mapping_options: super::MappingOptions,
    ) -> Result<(), ErrorCode> {
        map_from
            .inner
            .share_with(map_from_addr, &map_to.inner, map_to_addr, mapping_options)
    }

    pub fn alloc_user_shared(
        &self,
        vaddr: u64,
        num_pages: u64,
        mapping_options: super::MappingOptions,
        other: &UserAddressSpace,
    ) -> Result<(u64, u64), ErrorCode> {
        log::trace!("alloc_user_shared: 0x{vaddr:x}");
        self.stats_user_add(num_pages << PAGE_SIZE_SMALL_LOG2)?;

        if other
            .stats_user_add(num_pages << PAGE_SIZE_SMALL_LOG2)
            .is_err()
        {
            log::debug!("other OOM.");
            self.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
            return Err(moto_rt::E_OUT_OF_MEMORY);
        }

        // Allocate in self.
        let self_segment = {
            if vaddr != u64::MAX {
                match self
                    .inner
                    .vmem_allocate_user_fixed(vaddr, num_pages, mapping_options)
                {
                    Err(err) => {
                        self.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
                        other.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
                        return Err(err);
                    }
                    Ok(seg) => seg,
                }
            } else {
                match self.inner.vmem_allocate_pages(
                    VmemKind::Unmapped, /* not used */
                    num_pages,
                    Some(mapping_options),
                ) {
                    Err(err) => {
                        self.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
                        other.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
                        return Err(err);
                    }
                    Ok(seg) => seg,
                }
            }
        };

        // Allocate in other.
        let other_segment =
            match other
                .inner
                .vmem_allocate_pages(VmemKind::Unmapped, num_pages, None)
            {
                Err(err) => {
                    self.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
                    other.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
                    return Err(err);
                }
                Ok(seg) => seg,
            };

        let addr_here = self_segment.start;
        let addr_there = other_segment.start;

        self.inner
            .share_with(
                addr_here,
                &other.inner,
                addr_there,
                super::MappingOptions::USER_ACCESSIBLE
                    | super::MappingOptions::READABLE
                    | super::MappingOptions::WRITABLE
                    | super::MappingOptions::DONT_ZERO,
            )
            .unwrap();

        log::trace!("alloc_user_shared ok: 0x{addr_here:x} 0x{addr_there:x}");
        Ok((addr_here, addr_there))
    }

    pub fn user_page_table(&self) -> u64 {
        self.inner.page_table()
    }

    pub fn alloc_user_stack(&self, num_pages: u64) -> Result<UserStack, ErrorCode> {
        let num_pages = (num_pages + 2).next_power_of_two();

        // if let Some(segment) = self.user_stacks.pop(num_pages as usize) {
        //     return Ok(UserStack { segment });
        // }

        // When dropping, we count the full segment, with guard pages, so when adding,
        // we need to do the same.
        self.stats_user_add(num_pages << PAGE_SIZE_SMALL_LOG2)?;
        let segment = self
            .inner
            .vmem_allocate_pages(VmemKind::UserStack, num_pages, None);

        if let Err(err) = segment {
            self.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
            return Err(err);
        }

        let segment = segment.unwrap();

        // Map the top stack page: the kernel uses some of it for user TCB.
        if let Err(err) = self.fix_pagefault(
            segment.end() - PAGE_SIZE_SMALL - 4, // Adjust for the guard page.
            6,                                   /* #PF error code: user + write */
        ) {
            self.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
            return Err(err);
        }

        Ok(UserStack { segment })
    }

    pub fn alloc_kernel_stack(&self, num_pages: u64) -> Result<super::MemorySegment, ErrorCode> {
        let num_pages = (num_pages + 2).next_power_of_two();

        if let Some(segment) = self.kernel_stacks.pop(num_pages as usize) {
            return Ok(segment);
        }

        // When dropping, we count the full segment, with guard pages, so when adding,
        // we need to do the same.
        self.stats_kernel_add(num_pages)?;
        super::virt::vmem_allocate_pages(super::virt::VmemKind::KernelStack, num_pages).inspect_err(
            |_| {
                self.stats_kernel_sub(num_pages);
            },
        )
    }

    fn do_drop_user_stack(&self, user_stack: super::MemorySegment) {
        self.unmap(user_stack.start).unwrap(); // Stats are updated in unmap().
    }

    fn do_drop_kernel_stack(&self, kernel_stack: super::MemorySegment) {
        self.stats_kernel_sub(kernel_stack.size >> PAGE_SIZE_SMALL_LOG2);

        super::virt::KERNEL_ADDRESS_SPACE
            .free(kernel_stack.start, super::virt::VmemKind::KernelStack);
    }

    pub fn drop_stacks(&self, user_stack: &UserStack, kernel_stack: &Option<super::MemorySegment>) {
        let user_segment = user_stack.segment;
        // if self
        //     .user_stacks
        //     .push(
        //         user_segment,
        //         (user_segment.size as usize) >> PAGE_SIZE_SMALL_LOG2,
        //     )
        //     .is_err()
        // {
        self.do_drop_user_stack(user_segment);
        // }

        if let Some(kernel_stack) = kernel_stack {
            let kernel_segment = *kernel_stack;
            if self
                .kernel_stacks
                .push(
                    kernel_segment,
                    (kernel_stack.size as usize) >> PAGE_SIZE_SMALL_LOG2,
                )
                .is_err()
            {
                self.do_drop_kernel_stack(*kernel_stack);
            }
        }
    }

    pub fn alloc_user_heap(&self, num_pages: u64) -> Result<super::MemorySegment, ErrorCode> {
        // Ordinary eager private heap above 1 MiB may map huge pages; the
        // policy is the segment's, not inferred from anything else. Its
        // mapping never covers less than requested; the rounded size is
        // what the caller, the statistics and admission all see.
        let sizing = HeapSizing::new(num_pages);
        let mapped = sizing.mapped_pages;
        self.stats_user_add(mapped << PAGE_SIZE_SMALL_LOG2)?;
        let options = sizing.eligible.then_some(
            MappingOptions::READABLE
                | MappingOptions::WRITABLE
                | MappingOptions::USER_ACCESSIBLE
                | MappingOptions::HUGE_ELIGIBLE,
        );
        self.inner
            .vmem_allocate_pages(VmemKind::User, mapped, options)
            .inspect_err(|_| {
                log::error!("failed to allocate {mapped} pages");
                self.stats_user_sub(mapped << PAGE_SIZE_SMALL_LOG2);
            })
    }

    /// Reserves `num_pages` at `vaddr` (no frames) and lets `fill` map
    /// shared frames into the reservation, undoing it if that fails.
    fn fill_fixed<F>(&self, vaddr: u64, num_pages: u64, fill: F) -> Result<(), ErrorCode>
    where
        F: FnOnce(&UserAddressSpaceBase) -> Result<(), ErrorCode>,
    {
        self.stats_user_add(num_pages << PAGE_SIZE_SMALL_LOG2)?;
        if let Err(err) =
            self.inner
                .vmem_allocate_user_fixed(vaddr, num_pages, super::MappingOptions::empty())
        {
            self.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
            return Err(err);
        }
        fill(&self.inner).inspect_err(|_| {
            let _ = self.unmap(vaddr); // Gives the stats back too.
        })
    }

    /// Maps `source`'s segment at `source_addr` into this address space at
    /// `vaddr`, sharing its frames. The segments must be the same size, and
    /// nothing may be mapped at `vaddr` yet.
    pub fn share_from(
        &self,
        source: &UserAddressSpace,
        source_addr: u64,
        vaddr: u64,
        num_pages: u64,
        mapping_options: super::MappingOptions,
    ) -> Result<(), ErrorCode> {
        self.fill_fixed(vaddr, num_pages, |inner| {
            source
                .inner
                .share_with(source_addr, inner, vaddr, mapping_options)
        })
    }

    /// Maps `num_pages` of kernel-static memory at `kernel_vaddr` into this
    /// address space at `vaddr`, sharing the frames (read-only or
    /// read+execute: the ELF loader's in-place text and rodata).
    pub fn map_kernel_static(
        &self,
        vaddr: u64,
        kernel_vaddr: u64,
        num_pages: u64,
        mapping_options: super::MappingOptions,
    ) -> Result<(), ErrorCode> {
        debug_assert!(!mapping_options.contains(super::MappingOptions::WRITABLE));
        self.fill_fixed(vaddr, num_pages, |inner| {
            inner.share_kernel_static(kernel_vaddr, vaddr, mapping_options)
        })
    }

    pub fn alloc_user_lazy(&self, num_pages: u64) -> Result<super::MemorySegment, ErrorCode> {
        self.stats_user_add(num_pages << PAGE_SIZE_SMALL_LOG2)?;

        self.inner
            .vmem_allocate_pages(
                VmemKind::User,
                num_pages,
                Some(
                    MappingOptions::READABLE
                        | MappingOptions::WRITABLE
                        | MappingOptions::USER_ACCESSIBLE
                        | MappingOptions::LAZY,
                ),
            )
            .inspect_err(|_| {
                self.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
            })
    }

    pub fn alloc_user_unmapped(&self, num_pages: u64) -> Result<super::MemorySegment, ErrorCode> {
        // Stats have to be increased, otherwise:
        // - process A gets unmapped, no stats change
        // - process B gets mapped, accounted
        // - process B shares the memory with process A
        // - process B unmaps
        // - we end up with process A having memory it does not have stats for.
        self.stats_user_add(num_pages << PAGE_SIZE_SMALL_LOG2)?;

        self.inner
            .vmem_allocate_pages(VmemKind::Unmapped, num_pages, None)
            .inspect_err(|_| {
                self.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
            })
    }

    pub fn alloc_contiguous_pages(
        &self,
        num_pages: u64,
    ) -> Result<super::MemorySegment, ErrorCode> {
        self.stats_user_add(num_pages << PAGE_SIZE_SMALL_LOG2)?;
        self.inner
            .vmem_allocate_contiguous_pages(VmemKind::User, num_pages)
            .inspect_err(|_| {
                self.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
            })
    }

    pub fn unmap(&self, addr: u64) -> Result<(), ErrorCode> {
        self.inner.normal_memory.free(addr).map_or_else(
            |_| {
                self.inner.custom_memory.free(addr).map(|sz| {
                    self.stats_user_sub(sz);
                })
            },
            |sz| {
                self.stats_user_sub(sz);
                Ok(())
            },
        )
    }

    pub fn mmio_map(&self, phys_addr: u64, num_pages: u64) -> Result<u64, ErrorCode> {
        super::phys::validate_mmio(phys_addr, num_pages)?;

        self.stats_user_add(num_pages << PAGE_SIZE_SMALL_LOG2)?;

        self.inner
            .mmio_map(phys_addr, num_pages)
            .map(|segment| segment.start)
            .inspect_err(|_| {
                self.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
            })
    }

    pub fn fix_pagefault(&self, pf_addr: u64, error_code: u64) -> Result<(), ErrorCode> {
        // A refused fault cannot be reported to the faulting instruction, so
        // the faulting thread is killed. Deliberate: there is no OOM killer,
        // and the victim is whoever faults below the floor.
        let _admission =
            super::admission::admit(self.mem_class(), super::admission::lazy_fault_charge())?;
        self.inner.fix_pagefault(pf_addr, error_code)
    }

    pub fn copy_to_user(&self, bytes: &[u8], user_vaddr_start: u64) -> Result<(), ErrorCode> {
        let stats = crate::xray::stats::kernel_stats_ref();
        stats.adjust_metric(crate::xray::stats::MetricType::UserCopyWrite, 1);
        stats.adjust_metric(
            crate::xray::stats::MetricType::UserCopyWriteBytes,
            bytes.len() as i64,
        );

        user_vaddr_start
            .checked_add(bytes.len() as u64)
            .ok_or(moto_rt::E_INVALID_ARGUMENT)?;
        let mut source = bytes;
        let mut dst_start = user_vaddr_start;
        while !source.is_empty() {
            // Pin under the region lock and retain ownership through the copy.
            // Frame-less zero/CoW pages and device mappings remain refused.
            let page = self.pin_user_page(dst_start)?;
            let bytes_to_copy = source
                .len()
                .min((PAGE_SIZE_SMALL - (dst_start & (PAGE_SIZE_SMALL - 1))) as usize);
            unsafe {
                core::intrinsics::copy_nonoverlapping(
                    source.as_ptr(),
                    page.kernel_addr() as *mut u8,
                    bytes_to_copy,
                );
            }
            dst_start += bytes_to_copy as u64;
            source = &source[bytes_to_copy..];
        }

        Ok(())
    }

    fn pin_user_page(&self, addr: u64) -> Result<PinnedUserPage, ErrorCode> {
        let (frame, offset) = self
            .inner
            .pin_user_page(addr)
            .ok_or(moto_rt::E_INVALID_ARGUMENT)?;
        Ok(PinnedUserPage { frame, offset })
    }

    pub fn get_user_page_as_kernel(
        &self,
        user_page_addr: u64,
    ) -> Result<PinnedUserPage, ErrorCode> {
        if user_page_addr & (PAGE_SIZE_SMALL - 1) != 0 {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        self.pin_user_page(user_page_addr)
    }

    pub fn read_from_user(
        &self,
        vaddr_start: u64,
        count: u64,
    ) -> Result<alloc::vec::Vec<u8>, ErrorCode> {
        let mut result = alloc::vec![0; count as usize];
        self.read_from_user_into(vaddr_start, result.as_mut_slice())?;
        Ok(result)
    }

    pub fn read_from_user_into(&self, vaddr_start: u64, buf: &mut [u8]) -> Result<(), ErrorCode> {
        let stats = crate::xray::stats::kernel_stats_ref();
        stats.adjust_metric(crate::xray::stats::MetricType::UserCopyRead, 1);
        stats.adjust_metric(
            crate::xray::stats::MetricType::UserCopyReadBytes,
            buf.len() as i64,
        );

        self.inner.page_table_ref().copy_from_user(vaddr_start, buf)
    }

    pub fn virt_to_phys(&self, virt_addr: u64) -> Option<u64> {
        self.inner.page_table_ref().virt_to_phys(virt_addr)
    }

    pub fn get_backtrace(&self, rip: u64, rbp: u64) -> alloc::vec::Vec<u64> {
        let mut backtrace = alloc::vec::Vec::with_capacity(32);

        backtrace.push(rip);
        let mut rbp = rbp;

        for _ in 1..256 {
            if rbp == 0 {
                break;
            }
            let mut val_u64: u64 = 0;
            let buf: &mut [u8] =
                unsafe { core::slice::from_raw_parts_mut(&mut val_u64 as *mut _ as *mut u8, 8) };
            if self.read_from_user_into(rbp + 8, buf).is_err() {
                break;
            }
            backtrace.push(val_u64);
            if self.read_from_user_into(rbp, buf).is_err() {
                break;
            }
            rbp = val_u64;
        }

        backtrace
    }
}

/// The huge-eligible sizing rule for an ordinary heap request of `pages`
/// small pages: whole 2 MiB units are huge candidates, a tail above 1 MiB
/// rounds up to one more, and a smaller tail stays small. Small-only
/// requests (1 MiB and below) map exactly what they ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeapSizing {
    pub eligible: bool,
    pub huge: u64,
    pub small: u64,
    pub mapped_pages: u64,
}

impl HeapSizing {
    pub fn new(pages: u64) -> Self {
        const HUGE_PAGES: u64 = PAGE_SIZE_MID >> PAGE_SIZE_SMALL_LOG2;
        if pages <= HUGE_PAGES / 2 {
            return Self {
                eligible: false,
                huge: 0,
                small: pages,
                mapped_pages: pages,
            };
        }
        let tail = pages % HUGE_PAGES;
        let round_up = tail > HUGE_PAGES / 2;
        let huge = pages / HUGE_PAGES + u64::from(round_up);
        let small = if round_up { 0 } else { tail };
        Self {
            eligible: true,
            huge,
            small,
            mapped_pages: huge.saturating_mul(HUGE_PAGES).saturating_add(small),
        }
    }
}

// Controlled huge mapping tests on private address spaces whose CR3 is never
// installed, on the live pool while the BSP is alone. With every whole
// dual-purpose block held, an eligible request falls back to small pages
// with the policy retained; with exactly one such block free, a dirtied
// frame maps as a 2 MiB leaf and comes back zeroed; sharing is refused at
// either eligible endpoint whatever the backing; teardown returns the block.
#[cfg(debug_assertions)]
pub fn huge_mapping_self_test() {
    use super::phys::{allocate_huge_frame, block_metrics};
    use super::virt::{HUGE_FALLBACKS, HUGE_PAGES_MAPPED};
    use super::PageType;
    use super::PAGING_DIRECT_MAP_OFFSET;

    const HUGE_PAGES: u64 = PAGE_SIZE_MID >> PAGE_SIZE_SMALL_LOG2;
    let space = UserAddressSpace::new().unwrap();
    let peer = UserAddressSpace::new().unwrap();
    let taken_before = block_metrics().taken;
    let (mapped_before, fallbacks_before) = (
        HUGE_PAGES_MAPPED.load(Ordering::Relaxed),
        HUGE_FALLBACKS.load(Ordering::Relaxed),
    );
    let options =
        MappingOptions::READABLE | MappingOptions::WRITABLE | MappingOptions::USER_ACCESSIBLE;
    let refused: Result<(), ErrorCode> = Err(moto_rt::E_INVALID_ARGUMENT);

    // Hold every whole dual-purpose block: the pool has no huge page to give
    // until one is released.
    let mut held = alloc::vec::Vec::new();
    while let Ok(frame) = allocate_huge_frame() {
        held.push(frame);
    }
    if held.is_empty() {
        crate::raw_log!("huge mapping tests SKIPPED: no dual-purpose block");
        return;
    }
    let taken_held = taken_before + held.len() as u64;
    assert_eq!(block_metrics().taken, taken_held);
    let table = space.inner.page_table_ref();

    // A refused candidate is served small: 512 small leaves, one fallback,
    // the policy retained for the segment.
    let fallback = space.alloc_user_heap(HUGE_PAGES).unwrap();
    assert_eq!(fallback.size, PAGE_SIZE_MID);
    assert_eq!(fallback.start & (PAGE_SIZE_MID - 1), 0);
    for page in [0, 1, HUGE_PAGES - 1] {
        assert_eq!(
            table.leaf_kind(fallback.start + page * PAGE_SIZE_SMALL),
            Some(PageType::SmallPage)
        );
    }
    assert_eq!(HUGE_FALLBACKS.load(Ordering::Relaxed), fallbacks_before + 1);
    assert_eq!(block_metrics().taken, taken_held);

    // The peer's small-only 2 MiB segments: a populated lazy one as a
    // source, an unmapped reservation as a destination. Sharing with the
    // small-backed eligible segment is refused at either end, and the
    // existing destination keeps its bytes.
    let lazy = peer.alloc_user_lazy(HUGE_PAGES).unwrap();
    for page in 0..HUGE_PAGES {
        // A user write fault on a not-present page.
        peer.fix_pagefault(lazy.start + page * PAGE_SIZE_SMALL, 6)
            .unwrap();
    }
    peer.copy_to_user(b"lazy", lazy.start).unwrap();
    let peer_dest = peer.alloc_user_unmapped(HUGE_PAGES).unwrap();
    space.copy_to_user(b"intact", fallback.start).unwrap();
    assert_eq!(
        UserAddressSpace::map_shared(&peer, peer_dest.start, &space, fallback.start, options),
        refused
    );
    assert_eq!(
        UserAddressSpace::map_shared(&space, fallback.start, &peer, lazy.start, options),
        refused
    );
    assert_eq!(space.read_from_user(fallback.start, 6).unwrap(), b"intact");
    space.unmap(fallback.start).unwrap();
    assert_eq!(block_metrics().taken, taken_held);

    // Exactly one whole block free, dirtied first: the eligible request
    // must map that block as a 2 MiB leaf and zero it before publishing.
    let frame = held.pop().unwrap();
    let phys = frame.get().unwrap().start();
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            (phys + PAGING_DIRECT_MAP_OFFSET) as *mut u8,
            PAGE_SIZE_MID as usize,
        )
    };
    bytes.fill(0xa5);
    drop(frame);
    let huge = space.alloc_user_heap(HUGE_PAGES).unwrap();
    assert_eq!(huge.size, PAGE_SIZE_MID);
    assert_eq!(huge.start & (PAGE_SIZE_MID - 1), 0);
    assert_eq!(table.leaf_kind(huge.start), Some(PageType::MidPage));
    assert_eq!(table.virt_to_phys(huge.start + 12345), Some(phys + 12345));
    assert!(
        bytes.iter().all(|byte| *byte == 0),
        "a dirtied huge page was not zeroed"
    );
    let (pinned, offset) = space
        .inner
        .pin_user_page(huge.start + PAGE_SIZE_MID - 1)
        .unwrap();
    assert_eq!(pinned.get().unwrap().kind(), PageType::MidPage);
    assert_eq!(
        pinned.get().unwrap().start() + offset,
        phys + PAGE_SIZE_MID - 1
    );
    drop(pinned);
    assert_eq!(HUGE_PAGES_MAPPED.load(Ordering::Relaxed), mapped_before + 1);
    assert_eq!(block_metrics().taken, taken_held);

    // Sharing is refused with the huge-backed eligible segment at either
    // end too.
    space.copy_to_user(b"intact", huge.start).unwrap();
    assert_eq!(
        UserAddressSpace::map_shared(&peer, peer_dest.start, &space, huge.start, options),
        refused
    );
    assert_eq!(
        UserAddressSpace::map_shared(&space, huge.start, &peer, lazy.start, options),
        refused
    );
    assert_eq!(space.read_from_user(huge.start, 6).unwrap(), b"intact");

    // Teardown returns the block; the frame count observes it.
    space.unmap(huge.start).unwrap();
    assert_eq!(block_metrics().taken, taken_held - 1);
    assert_eq!(table.leaf_kind(huge.start), None);
    drop(held);
    assert_eq!(block_metrics().taken, taken_before);

    // Small-only sharing still works, the populated 2 MiB lazy segment and
    // a 1 MiB eager one, into unmapped reservations.
    let dest = space.alloc_user_unmapped(HUGE_PAGES).unwrap();
    UserAddressSpace::map_shared(&space, dest.start, &peer, lazy.start, options).unwrap();
    assert_eq!(space.read_from_user(dest.start, 4).unwrap(), b"lazy");
    let small = peer.alloc_user_heap(HUGE_PAGES / 2).unwrap();
    peer.copy_to_user(b"small", small.start).unwrap();
    let dest = space.alloc_user_unmapped(HUGE_PAGES / 2).unwrap();
    UserAddressSpace::map_shared(&space, dest.start, &peer, small.start, options).unwrap();
    assert_eq!(space.read_from_user(dest.start, 5).unwrap(), b"small");

    // The sizing rule and a mixed segment: a request one page over 1 MiB
    // maps a whole huge page, and 3 MiB maps one huge page followed by 256
    // small ones. Copies and lookups cross the huge/small boundary, and the
    // statistics charge exactly the mapped size.
    for (pages, expected) in [
        (16, (false, 0, 16, 16)),
        (256, (false, 0, 256, 256)),
        (257, (true, 1, 0, 512)),
        (384, (true, 1, 0, 512)),
        (512, (true, 1, 0, 512)),
        (768, (true, 1, 256, 768)),
        (769, (true, 2, 0, 1024)),
        (1408, (true, 3, 0, 1536)),
    ] {
        let sizing = HeapSizing::new(pages);
        assert_eq!(
            (
                sizing.eligible,
                sizing.huge,
                sizing.small,
                sizing.mapped_pages
            ),
            expected,
            "{pages} pages"
        );
    }
    assert_eq!(HeapSizing::new(u64::MAX).mapped_pages, u64::MAX);
    let usage_before = space.user_mem_stats().total();
    let mixed = space.alloc_user_heap(HUGE_PAGES + 256).unwrap();
    assert_eq!(mixed.size, PAGE_SIZE_MID + 256 * PAGE_SIZE_SMALL);
    assert_eq!(space.user_mem_stats().total() - usage_before, mixed.size);
    let boundary = mixed.start + PAGE_SIZE_MID;
    assert_eq!(table.leaf_kind(mixed.start), Some(PageType::MidPage));
    assert_eq!(
        table.leaf_kind(boundary - PAGE_SIZE_SMALL),
        Some(PageType::MidPage)
    );
    assert_eq!(table.leaf_kind(boundary), Some(PageType::SmallPage));
    space.copy_to_user(b"across", boundary - 3).unwrap();
    assert_eq!(space.read_from_user(boundary - 3, 6).unwrap(), b"across");
    let (pinned, offset) = space.inner.pin_user_page(boundary + 5).unwrap();
    assert_eq!(pinned.get().unwrap().kind(), PageType::SmallPage);
    assert_eq!(offset, 5);
    drop(pinned);
    let rounded = space.alloc_user_heap(HUGE_PAGES / 2 + 1).unwrap();
    assert_eq!(rounded.size, PAGE_SIZE_MID);
    assert_eq!(rounded.start & (PAGE_SIZE_MID - 1), 0);
    space.unmap(rounded.start).unwrap();
    space.unmap(mixed.start).unwrap();
    assert_eq!(space.user_mem_stats().total(), usage_before);
    assert_eq!(block_metrics().taken, taken_before);
    crate::raw_log!("huge mapping tests PASS");
}
