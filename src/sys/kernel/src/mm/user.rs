use core::sync::atomic::*;

use alloc::sync::Arc;

use super::user_copy::UserCopyError;
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
    pub(crate) pager: crate::util::SpinLock<crate::uspace::pager::MappingState>,

    // The maximum amount of memory (phys, including the binary)
    // that the owner process is allowed to use.
    max_memory: AtomicU64,
    total_usage: AtomicU64,

    // User mem stats are tracked via @inner.
    // Kernel mem stats (kernel stacks) are tracked here.
    kernel_mem_stats: Arc<MemStats>,

    kernel_stacks: super::cache::SegmentCache,
    // user_stacks: super::cache::SegmentCache,
    /// Set once a process is built on this space; see claim_for_process().
    hosts_process: AtomicBool,
}

unsafe impl Send for UserAddressSpace {}
unsafe impl Sync for UserAddressSpace {}

impl Drop for UserAddressSpace {
    fn drop(&mut self) {
        // Both are no-ops if a process exited from this space.
        crate::uspace::pager::retire_space(self);
        self.release_user_memory();
        log::debug!("UserAddressSpace::drop()");
    }
}

impl UserAddressSpace {
    /// Releases the process's memory: every user segment with its private
    /// frames, the page descriptors, the process static page and the cached
    /// kernel stacks with their cache pages; shared frames live on in their
    /// other mappings. The regions are closed, so a handle that outlives the
    /// process cannot map into the space again. The page-table root and its
    /// kernel entries stay until the space is dropped. The caller retires
    /// the pager mappings first. Process exit calls this once its threads
    /// are gone and their stacks unmapped; drop calls it again, as a no-op
    /// or for a space no process exited from.
    pub fn release_user_memory(&self) {
        let page_table = self.inner.page_table_ref();
        if !page_table.is_dead() {
            // W6b: CPUs no longer leave a process's page table on syscall/
            // preempt, so this CPU and idle remote CPUs may still have it as
            // CR3, and the process has no thread left that would install it
            // again. Teardown mutates the table -- drop even removes its
            // kernel L4 entries, which triple-faults a CPU still standing on
            // it as soon as a kernel address misses the TLB. Move everyone
            // off first; the unmaps of a dead table then skip their
            // shootdowns.
            crate::arch::tlb::evict_user_page_table(page_table.phys_addr());
            page_table.mark_dead();
        }

        // Drained by hand rather than by drop, so that self.inner is still
        // available and the usage statistics are validated.
        while let Some(segment) = self.kernel_stacks.pop_any_final() {
            self.do_drop_kernel_stack(segment);
        }
        self.kernel_stacks.release_storage();
        self.inner.release_user_memory();
    }

    /// Binds the space to the process about to be built on it. A space
    /// hosts one process in its lifetime: the process's exit releases the
    /// space (see Process::on_thread_exited), so a second process on it
    /// would run on freed memory.
    pub fn claim_for_process(&self) -> Result<(), ErrorCode> {
        self.hosts_process
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| moto_rt::E_ALREADY_IN_USE)
    }

    /// Undoes claim_for_process() for a process that could not be built.
    pub fn release_claim(&self) {
        self.hosts_process.store(false, Ordering::Release);
    }

    pub fn new() -> Result<Arc<Self>, ErrorCode> {
        log::debug!("UserAddressSpace::new()");

        let self_ = Arc::new(Self {
            inner: UserAddressSpaceBase::new()?,
            pager: crate::util::SpinLock::default(),
            max_memory: AtomicU64::new(
                crate::config::get()
                    .default_max_user_memory
                    .load(Ordering::Relaxed),
            ),
            total_usage: AtomicU64::new(0),
            kernel_mem_stats: Arc::new(MemStats::new_kernel()),

            kernel_stacks: super::cache::SegmentCache::new(),
            hosts_process: AtomicBool::new(false),
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
        let bytes = num_pages << PAGE_SIZE_SMALL_LOG2;
        self.stats_user_add(bytes)?;
        if other.stats_user_add(bytes).is_err() {
            log::debug!("other OOM.");
            self.stats_user_sub(bytes);
            return Err(moto_rt::E_OUT_OF_MEMORY);
        }
        // Both reservations, the share and any rollback happen under the
        // region locks; each side's charge stays until its own unmap.
        self.inner
            .alloc_shared(vaddr, num_pages, mapping_options, &other.inner)
            .inspect_err(|_| {
                self.stats_user_sub(bytes);
                other.stats_user_sub(bytes);
            })
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
        let bytes = num_pages << PAGE_SIZE_SMALL_LOG2;
        self.stats_user_add(bytes)?;
        let segment = self
            .inner
            .vmem_allocate_pages(VmemKind::UserStack, num_pages, None)
            .inspect_err(|_| self.stats_user_sub(bytes))?;

        // Map the top stack page: the kernel uses some of it for user TCB.
        if let Err(err) = self.fix_pagefault(
            segment.end() - PAGE_SIZE_SMALL - 4, // Adjust for the guard page.
            6,                                   /* #PF error code: user + write */
        ) {
            // The unmap takes the statistics back.
            self.unmap(segment.start).unwrap();
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
        super::virt::vmem_allocate_pages(super::virt::VmemKind::KernelStack, num_pages)
            .inspect(|_| self.kernel_mem_stats.add_resident(num_pages - 2))
            .inspect_err(|_| {
                self.stats_kernel_sub(num_pages);
            })
    }

    fn do_drop_user_stack(&self, user_stack: super::MemorySegment) {
        self.unmap(user_stack.start).unwrap(); // Stats are updated in unmap().
    }

    fn do_drop_kernel_stack(&self, kernel_stack: super::MemorySegment) {
        self.stats_kernel_sub(kernel_stack.size >> PAGE_SIZE_SMALL_LOG2);

        super::virt::KERNEL_ADDRESS_SPACE
            .free(kernel_stack.start, super::virt::VmemKind::KernelStack);
        self.kernel_mem_stats
            .sub_resident((kernel_stack.size >> PAGE_SIZE_SMALL_LOG2) - 2);
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
        // what the caller and statistics see.
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
                log::debug!("failed to allocate {mapped} pages");
                self.stats_user_sub(mapped << PAGE_SIZE_SMALL_LOG2);
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
        let bytes = num_pages << PAGE_SIZE_SMALL_LOG2;
        self.stats_user_add(bytes)?;
        self.inner
            .share_into_fixed(
                vaddr,
                num_pages,
                &source.inner,
                source_addr,
                mapping_options,
            )
            .inspect_err(|_| self.stats_user_sub(bytes))
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
        let bytes = num_pages << PAGE_SIZE_SMALL_LOG2;
        self.stats_user_add(bytes)?;
        self.inner
            .fill_kernel_static(vaddr, kernel_vaddr, num_pages, mapping_options)
            .inspect_err(|_| self.stats_user_sub(bytes))
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

    /// `num_pages` small pages between two guard pages that are never
    /// mapped, eager or lazy. The segment is `num_pages + 2` pages, guards
    /// included and nothing rounded: that is what the caller sees, is
    /// charged for and unmaps.
    pub fn alloc_user_guarded(
        &self,
        num_pages: u64,
        lazy: bool,
    ) -> Result<super::MemorySegment, ErrorCode> {
        let num_pages = num_pages
            .checked_add(2)
            .ok_or(moto_rt::E_INVALID_ARGUMENT)?;
        let mut options = MappingOptions::READABLE
            | MappingOptions::WRITABLE
            | MappingOptions::USER_ACCESSIBLE
            | MappingOptions::GUARD;
        if lazy {
            options |= MappingOptions::LAZY;
        }
        let bytes = num_pages << PAGE_SIZE_SMALL_LOG2;
        self.stats_user_add(bytes)?;
        self.inner
            .vmem_allocate_pages(VmemKind::User, num_pages, Some(options))
            .inspect_err(|_| self.stats_user_sub(bytes))
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
        crate::uspace::pager::unmap(self, addr, || {
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
        })
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

    /// Reserves a sparse segment whose pages the executable pager installs
    /// on demand. The whole segment is accounted now, like an eager one.
    /// The caller holds `pager` through reservation and publication.
    pub(crate) fn reserve_file(
        &self,
        start: u64,
        num_pages: u64,
        writable: bool,
        executable: bool,
    ) -> Result<(), ErrorCode> {
        if writable && executable {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        let mut options =
            MappingOptions::READABLE | MappingOptions::USER_ACCESSIBLE | MappingOptions::FILE_PAGED;
        if writable {
            options |= MappingOptions::WRITABLE;
        }
        if executable {
            options |= MappingOptions::EXECUTABLE;
        }
        self.stats_user_add(num_pages << PAGE_SIZE_SMALL_LOG2)?;
        self.inner
            .vmem_allocate_user_fixed(start, num_pages, options)
            .map(|_| ())
            .inspect_err(|_| self.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2))
    }

    /// Copies each source page into a fresh frame and installs the copies
    /// from `start` on, keeping pages that are already present. Returns the
    /// number of pages installed even if a later page fails. The caller holds
    /// `pager` through validation and installation.
    pub(crate) fn fill_file(
        &self,
        start: u64,
        sources: &[PinnedUserPage],
    ) -> (u64, Result<(), ErrorCode>) {
        let mut installed = 0;
        let result = self.inner.with_file_segment(start, |segment| {
            let end = (sources.len() as u64)
                .checked_mul(PAGE_SIZE_SMALL)
                .and_then(|bytes| start.checked_add(bytes))
                .ok_or(moto_rt::E_INVALID_ARGUMENT)?;
            if !start.is_multiple_of(PAGE_SIZE_SMALL) || end > segment.segment().end() {
                return Err(moto_rt::E_INVALID_ARGUMENT);
            }
            for (idx, source) in sources.iter().enumerate() {
                let addr = start + ((idx as u64) << PAGE_SIZE_SMALL_LOG2);
                if segment.fill_file_page(addr, Some(source))? {
                    installed += 1;
                }
            }
            Ok(())
        });
        (installed, result)
    }

    /// Installs a zeroed page in a file-paged segment unless one is present.
    /// The caller holds `pager`, as for `fill_file`.
    pub(crate) fn fill_file_zero(&self, page: u64) -> Result<bool, ErrorCode> {
        self.inner
            .with_file_segment(page, |segment| segment.fill_file_page(page, None))
    }

    pub fn fix_pagefault(&self, pf_addr: u64, error_code: u64) -> Result<(), ErrorCode> {
        self.inner.fix_pagefault(pf_addr, error_code)
    }

    pub fn copy_to_user(&self, bytes: &[u8], user_vaddr_start: u64) -> Result<(), UserCopyError> {
        self.copy_to_user_impl(bytes, user_vaddr_start, MappingOptions::WRITABLE)
    }

    /// Initialize private ELF pages before the bootstrap process can run.
    ///
    /// # Safety
    /// The destination pages must be private, never exposed to userspace, and
    /// have no concurrent readers or writers. This bypasses user write protection.
    pub unsafe fn initialize_user_memory(
        &self,
        bytes: &[u8],
        user_vaddr_start: u64,
    ) -> Result<(), ErrorCode> {
        self.copy_to_user_impl(bytes, user_vaddr_start, MappingOptions::READABLE)
            .map_err(Into::into)
    }

    fn copy_to_user_impl(
        &self,
        bytes: &[u8],
        user_vaddr_start: u64,
        access: MappingOptions,
    ) -> Result<(), UserCopyError> {
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
            let page = self.pin_user_page(dst_start, access)?;
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

    fn pin_user_page(
        &self,
        addr: u64,
        access: MappingOptions,
    ) -> Result<PinnedUserPage, UserCopyError> {
        let (frame, offset) = self.inner.pin_user_page(addr, access)?;
        Ok(PinnedUserPage { frame, offset })
    }

    pub fn get_user_page_as_kernel(
        &self,
        user_page_addr: u64,
        access: MappingOptions,
    ) -> Result<PinnedUserPage, UserCopyError> {
        if user_page_addr & (PAGE_SIZE_SMALL - 1) != 0 {
            return Err(moto_rt::E_INVALID_ARGUMENT.into());
        }
        self.pin_user_page(user_page_addr, access)
    }

    pub fn read_from_user(
        &self,
        vaddr_start: u64,
        count: u64,
    ) -> Result<alloc::vec::Vec<u8>, UserCopyError> {
        let mut result = alloc::vec![0; count as usize];
        self.read_from_user_into(vaddr_start, result.as_mut_slice())?;
        Ok(result)
    }

    pub fn read_from_user_into(
        &self,
        vaddr_start: u64,
        buf: &mut [u8],
    ) -> Result<(), UserCopyError> {
        let stats = crate::xray::stats::kernel_stats_ref();
        stats.adjust_metric(crate::xray::stats::MetricType::UserCopyRead, 1);
        stats.adjust_metric(
            crate::xray::stats::MetricType::UserCopyReadBytes,
            buf.len() as i64,
        );

        self.inner.page_table_ref().copy_from_user(vaddr_start, buf)
    }

    pub(super) fn is_file_page(&self, addr: u64) -> bool {
        self.inner.with_file_segment(addr, |_| Ok(())).is_ok()
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
    assert_eq!(space.user_mem_stats().resident(), PAGE_SIZE_MID);
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
    assert_eq!(space.user_mem_stats().resident(), 0);
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
    assert_eq!(space.user_mem_stats().resident(), PAGE_SIZE_MID);
    assert_eq!(huge.start & (PAGE_SIZE_MID - 1), 0);
    assert_eq!(table.leaf_kind(huge.start), Some(PageType::MidPage));
    assert_eq!(table.virt_to_phys(huge.start + 12345), Some(phys + 12345));
    assert!(
        bytes.iter().all(|byte| *byte == 0),
        "a dirtied huge page was not zeroed"
    );
    let (pinned, offset) = space
        .inner
        .pin_user_page(huge.start + PAGE_SIZE_MID - 1, MappingOptions::READABLE)
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
    assert_eq!(space.user_mem_stats().resident(), 0);
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
    let resident_before = space.user_mem_stats().resident();
    let mixed = space.alloc_user_heap(HUGE_PAGES + 256).unwrap();
    assert_eq!(mixed.size, PAGE_SIZE_MID + 256 * PAGE_SIZE_SMALL);
    assert_eq!(space.user_mem_stats().total() - usage_before, mixed.size);
    assert_eq!(
        space.user_mem_stats().resident() - resident_before,
        mixed.size
    );
    let boundary = mixed.start + PAGE_SIZE_MID;
    assert_eq!(table.leaf_kind(mixed.start), Some(PageType::MidPage));
    assert_eq!(
        table.leaf_kind(boundary - PAGE_SIZE_SMALL),
        Some(PageType::MidPage)
    );
    assert_eq!(table.leaf_kind(boundary), Some(PageType::SmallPage));
    space.copy_to_user(b"across", boundary - 3).unwrap();
    assert_eq!(space.read_from_user(boundary - 3, 6).unwrap(), b"across");
    let (pinned, offset) = space
        .inner
        .pin_user_page(boundary + 5, MappingOptions::READABLE)
        .unwrap();
    assert_eq!(pinned.get().unwrap().kind(), PageType::SmallPage);
    assert_eq!(offset, 5);
    drop(pinned);
    let rounded = space.alloc_user_heap(HUGE_PAGES / 2 + 1).unwrap();
    assert_eq!(rounded.size, PAGE_SIZE_MID);
    assert_eq!(rounded.start & (PAGE_SIZE_MID - 1), 0);
    space.unmap(rounded.start).unwrap();
    space.unmap(mixed.start).unwrap();
    assert_eq!(space.user_mem_stats().total(), usage_before);
    assert_eq!(space.user_mem_stats().resident(), resident_before);
    assert_eq!(block_metrics().taken, taken_before);
    crate::raw_log!("huge mapping tests PASS");
}

// A share is validated in full before the first destination PTE changes: a
// lazy source with an untouched page is refused and the destination keeps
// its bytes, the same source is accepted once every page is touched, and a
// lazy destination is refused whatever its state.
#[cfg(debug_assertions)]
pub fn share_validation_self_test() {
    const PAGES: u64 = 4;
    let source_space = UserAddressSpace::new().unwrap();
    let dest_space = UserAddressSpace::new().unwrap();
    let options =
        MappingOptions::READABLE | MappingOptions::WRITABLE | MappingOptions::USER_ACCESSIBLE;
    let refused: Result<(), ErrorCode> = Err(moto_rt::E_INVALID_ARGUMENT);
    let page = |segment: super::MemorySegment, idx: u64| segment.start + idx * PAGE_SIZE_SMALL;
    let share = |dest: super::MemorySegment, source: super::MemorySegment| {
        UserAddressSpace::map_shared(
            &dest_space,
            dest.start,
            &source_space,
            source.start,
            options,
        )
    };

    // The source: a lazy segment with its third page untouched.
    let lazy = source_space.alloc_user_lazy(PAGES).unwrap();
    for idx in [0, 1, 3] {
        source_space.fix_pagefault(page(lazy, idx), 6).unwrap();
    }
    source_space.copy_to_user(b"source", lazy.start).unwrap();

    // The destination: eager pages holding known bytes.
    let dest = dest_space.alloc_user_heap(PAGES).unwrap();
    dest_space.copy_to_user(b"intact", dest.start).unwrap();
    let dest_phys = |idx: u64| {
        dest_space
            .inner
            .page_table_ref()
            .virt_to_phys(page(dest, idx))
            .unwrap()
    };
    let source_phys = |idx: u64| {
        source_space
            .inner
            .page_table_ref()
            .virt_to_phys(page(lazy, idx))
            .unwrap()
    };
    let before: [u64; PAGES as usize] = core::array::from_fn(|idx| dest_phys(idx as u64));

    assert_eq!(share(dest, lazy), refused);
    assert_eq!(
        dest_space.user_mem_stats().resident(),
        PAGES * PAGE_SIZE_SMALL
    );
    assert_eq!(dest_space.read_from_user(dest.start, 6).unwrap(), b"intact");
    for (idx, phys_before) in before.iter().enumerate() {
        assert_eq!(dest_phys(idx as u64), *phys_before);
    }

    // Touched in full, the same source is accepted, and the destination
    // reads the source's bytes through the shared frames.
    source_space.fix_pagefault(page(lazy, 2), 6).unwrap();
    share(dest, lazy).unwrap();
    assert_eq!(
        dest_space.user_mem_stats().resident(),
        PAGES * PAGE_SIZE_SMALL
    );
    assert_eq!(dest_space.read_from_user(dest.start, 6).unwrap(), b"source");
    for idx in 0..PAGES {
        assert_eq!(dest_phys(idx), source_phys(idx));
    }

    // A lazy destination is refused, untouched or touched; an untouched
    // lazy source is refused too.
    let lazy_dest = dest_space.alloc_user_lazy(PAGES).unwrap();
    assert_eq!(share(lazy_dest, lazy), refused);
    for idx in 0..PAGES {
        dest_space.fix_pagefault(page(lazy_dest, idx), 6).unwrap();
    }
    assert_eq!(share(lazy_dest, lazy), refused);
    let untouched = source_space.alloc_user_lazy(PAGES).unwrap();
    assert_eq!(share(dest, untouched), refused);
    assert_eq!(dest_space.read_from_user(dest.start, 6).unwrap(), b"source");

    // A source whose last page is untouched runs out of pages before the
    // destination does.
    let short = source_space.alloc_user_lazy(PAGES).unwrap();
    for idx in 0..PAGES - 1 {
        source_space.fix_pagefault(page(short, idx), 6).unwrap();
    }
    assert_eq!(share(dest, short), refused);
    assert_eq!(dest_space.read_from_user(dest.start, 6).unwrap(), b"source");

    for (space, segment) in [
        (&dest_space, dest),
        (&dest_space, lazy_dest),
        (&source_space, lazy),
        (&source_space, untouched),
        (&source_space, short),
    ] {
        space.unmap(segment.start).unwrap();
    }
    crate::raw_log!("share validation tests PASS");
    assert_eq!(source_space.user_mem_stats().resident(), 0);
    assert_eq!(dest_space.user_mem_stats().resident(), 0);
}

// Sparse lazy segments: an untouched reservation holds no page descriptors
// at any size, the first touch creates one, repeated touches keep the data,
// guard pages and plain reservations still refuse faults, and unmapping
// gives the accounting and the descriptors back.
#[cfg(debug_assertions)]
pub fn sparse_lazy_self_test() {
    let space = UserAddressSpace::new().unwrap();
    let descriptors = || space.inner.page_descriptors();
    let accounted = || space.user_mem_stats().total();
    let resident = || space.user_mem_stats().resident();
    let table = space.inner.page_table_ref();
    let (descriptors_before, accounted_before) = (descriptors(), accounted());
    let refused: Result<(), ErrorCode> = Err(moto_rt::E_INVALID_ARGUMENT);

    // 4 GiB, untouched: nothing but the segment node.
    let lazy = space.alloc_user_lazy(1 << 20).unwrap();
    assert_eq!(lazy.size, 4 << 30);
    assert_eq!(descriptors(), descriptors_before);
    assert_eq!(accounted(), accounted_before + lazy.size);
    assert_eq!(resident(), 0);
    assert_eq!(table.virt_to_phys(lazy.start), None);
    assert!(space.read_from_user(lazy.start, 1).is_err());

    // The first touch creates the descriptor; a later fault on the same
    // page takes the concurrent-fault shortcut and keeps the data.
    let middle = lazy.start + lazy.size / 2;
    let last = lazy.end() - PAGE_SIZE_SMALL;
    space.fix_pagefault(lazy.start, 6).unwrap();
    assert_eq!(descriptors(), descriptors_before + 1);
    space.copy_to_user(b"first", lazy.start).unwrap();
    space.fix_pagefault(lazy.start + 100, 6).unwrap();
    assert_eq!(resident(), PAGE_SIZE_SMALL);
    assert_eq!(space.read_from_user(lazy.start, 5).unwrap(), b"first");
    space.fix_pagefault(middle, 6).unwrap();
    space.fix_pagefault(last, 4).unwrap();
    assert_eq!(descriptors(), descriptors_before + 3);
    assert_eq!(resident(), 3 * PAGE_SIZE_SMALL);
    assert_eq!(space.read_from_user(last, 1).unwrap(), [0]);
    assert_eq!(table.virt_to_phys(lazy.start + PAGE_SIZE_SMALL), None);

    // A user stack: its top page is mapped at creation, its guards refuse
    // faults, and an interior page is created on first touch.
    let stack = space.alloc_user_stack(14).unwrap();
    assert_eq!(stack.segment.size, 16 * PAGE_SIZE_SMALL);
    assert_eq!(descriptors(), descriptors_before + 4);
    assert_eq!(space.fix_pagefault(stack.segment.start, 6), refused);
    assert_eq!(space.fix_pagefault(stack.segment.end() - 1, 6), refused);
    assert_eq!(resident(), 4 * PAGE_SIZE_SMALL);
    space
        .fix_pagefault(stack.segment.start + PAGE_SIZE_SMALL, 6)
        .unwrap();
    assert_eq!(descriptors(), descriptors_before + 5);

    // A plain reservation is dense and still refuses faults.
    let plain = space.alloc_user_unmapped(2).unwrap();
    assert_eq!(descriptors(), descriptors_before + 7);
    assert_eq!(space.fix_pagefault(plain.start, 6), refused);
    assert_eq!(resident(), 5 * PAGE_SIZE_SMALL);

    // A quarter of the user region, in one segment.
    let quarter = space.alloc_user_lazy(1 << 31).unwrap();
    assert_eq!(quarter.size, 8 << 40);
    assert_eq!(descriptors(), descriptors_before + 7);
    space
        .fix_pagefault(quarter.end() - PAGE_SIZE_SMALL, 6)
        .unwrap();
    assert_eq!(descriptors(), descriptors_before + 8);

    space.unmap(quarter.start).unwrap();
    space.unmap(plain.start).unwrap();
    space.drop_stacks(&stack, &None);
    space.unmap(lazy.start).unwrap();
    assert_eq!(descriptors(), descriptors_before);
    assert_eq!(accounted(), accounted_before);
    assert_eq!(resident(), 0);
    crate::raw_log!("sparse lazy tests PASS");
}

// Guarded heaps: an eager one is dense, exactly `pages + 2` small pages with
// a frameless descriptor at each end, never rounded or huge; a lazy one is
// sparse. Both refuse faults on their guards, neither end of a share may be
// guarded, and unmapping gives everything back.
#[cfg(debug_assertions)]
pub fn guarded_heap_self_test() {
    use super::PageType;
    // A heap would round this to 512 pages.
    const PAGES: u64 = (PAGE_SIZE_MID >> PAGE_SIZE_SMALL_LOG2) / 2 + 1;
    let space = UserAddressSpace::new().unwrap();
    let peer = UserAddressSpace::new().unwrap();
    let descriptors = || space.inner.page_descriptors();
    let accounted = || space.user_mem_stats().total();
    let resident = || space.user_mem_stats().resident();
    let table = space.inner.page_table_ref();
    let (descriptors_before, accounted_before, resident_before) =
        (descriptors(), accounted(), resident());
    let refused: Result<(), ErrorCode> = Err(moto_rt::E_INVALID_ARGUMENT);
    let options =
        MappingOptions::READABLE | MappingOptions::WRITABLE | MappingOptions::USER_ACCESSIBLE;

    // The smallest allocation of either kind: one page between the guards.
    for lazy in [false, true] {
        let one = space.alloc_user_guarded(1, lazy).unwrap();
        let page = one.start + PAGE_SIZE_SMALL;
        assert_eq!(one.size, 3 * PAGE_SIZE_SMALL);
        assert_eq!(accounted(), accounted_before + one.size);
        assert_eq!(table.virt_to_phys(page).is_some(), !lazy);
        assert_eq!(space.fix_pagefault(one.start, 6), refused);
        assert_eq!(space.fix_pagefault(one.end() - 1, 4), refused);
        space.fix_pagefault(page, 6).unwrap();
        assert_eq!(resident(), resident_before + PAGE_SIZE_SMALL);
        space.copy_to_user(b"one", page).unwrap();
        assert_eq!(space.read_from_user(page, 3).unwrap(), b"one");
        space.unmap(one.start).unwrap();
        assert_eq!(descriptors(), descriptors_before);
        assert_eq!(accounted(), accounted_before);
        assert_eq!(resident(), resident_before);
    }

    // Eager: exactly PAGES + 2 pages, every interior page resident; the
    // guards have no frame and no translation, and refuse faults whatever
    // the access.
    let eager = space.alloc_user_guarded(PAGES, false).unwrap();
    assert_eq!(eager.size, (PAGES + 2) * PAGE_SIZE_SMALL);
    assert_eq!(descriptors(), descriptors_before + PAGES + 2);
    assert_eq!(accounted(), accounted_before + eager.size);
    assert_eq!(resident(), resident_before + PAGES * PAGE_SIZE_SMALL);
    let (lower, upper) = (eager.start, eager.end() - PAGE_SIZE_SMALL);
    assert_eq!(table.virt_to_phys(lower), None);
    assert_eq!(table.virt_to_phys(upper), None);
    assert_eq!(
        table.leaf_kind(lower + PAGE_SIZE_SMALL),
        Some(PageType::SmallPage)
    );
    assert_eq!(
        table.leaf_kind(upper - PAGE_SIZE_SMALL),
        Some(PageType::SmallPage)
    );
    assert_eq!(space.fix_pagefault(lower, 6), refused);
    assert_eq!(space.fix_pagefault(lower + PAGE_SIZE_SMALL - 1, 4), refused);
    assert_eq!(space.fix_pagefault(upper, 4), refused);
    assert_eq!(space.fix_pagefault(upper + PAGE_SIZE_SMALL - 1, 6), refused);
    space
        .copy_to_user(b"guarded", lower + PAGE_SIZE_SMALL)
        .unwrap();
    assert_eq!(
        space.read_from_user(lower + PAGE_SIZE_SMALL, 7).unwrap(),
        b"guarded"
    );
    assert!(space.copy_to_user(b"x", lower).is_err());
    assert!(space.read_from_user(upper, 1).is_err());
    assert_eq!(descriptors(), descriptors_before + PAGES + 2);

    // Lazy: nothing until touched; the guards refuse and never get a
    // descriptor, an interior page gets one on first touch.
    let lazy = space.alloc_user_guarded(PAGES, true).unwrap();
    assert_eq!(lazy.size, (PAGES + 2) * PAGE_SIZE_SMALL);
    assert_eq!(descriptors(), descriptors_before + PAGES + 2);
    assert_eq!(accounted(), accounted_before + eager.size + lazy.size);
    assert_eq!(space.fix_pagefault(lazy.start, 6), refused);
    assert_eq!(space.fix_pagefault(lazy.end() - 1, 4), refused);
    assert!(space.read_from_user(lazy.start, 1).is_err());
    assert_eq!(descriptors(), descriptors_before + PAGES + 2);
    space
        .fix_pagefault(lazy.start + PAGE_SIZE_SMALL, 6)
        .unwrap();
    space
        .fix_pagefault(lazy.end() - PAGE_SIZE_SMALL - 1, 4)
        .unwrap();
    assert_eq!(descriptors(), descriptors_before + PAGES + 4);
    assert_eq!(resident(), resident_before + (PAGES + 2) * PAGE_SIZE_SMALL);
    assert_eq!(table.virt_to_phys(lazy.start), None);

    // Neither can be a share source: a guard has no frame.
    let dest = peer.alloc_user_unmapped(PAGES + 2).unwrap();
    for source in [eager, lazy] {
        assert_eq!(
            UserAddressSpace::map_shared(&peer, dest.start, &space, source.start, options),
            refused
        );
    }
    peer.unmap(dest.start).unwrap();

    // Nor a share destination, which would put frames in the guards. The
    // refused destination keeps its guards, bytes, translation and accounting.
    let source = peer.alloc_user_heap(3).unwrap();
    peer.copy_to_user(b"src", source.start).unwrap();
    let guarded = space.alloc_user_guarded(1, false).unwrap();
    let page = guarded.start + PAGE_SIZE_SMALL;
    space.copy_to_user(b"dst", page).unwrap();
    let phys = table.virt_to_phys(page).unwrap();
    let full = (descriptors(), accounted(), resident());
    let peer_resident = peer.user_mem_stats().resident();
    assert_eq!(
        UserAddressSpace::map_shared(&space, guarded.start, &peer, source.start, options),
        refused
    );
    assert_eq!(table.virt_to_phys(guarded.start), None);
    assert_eq!(table.virt_to_phys(guarded.end() - PAGE_SIZE_SMALL), None);
    assert_eq!(table.virt_to_phys(page), Some(phys));
    assert_eq!(space.read_from_user(page, 3).unwrap(), b"dst");
    assert_eq!(space.fix_pagefault(guarded.start, 6), refused);
    assert_eq!((descriptors(), accounted(), resident()), full);
    assert_eq!(peer.user_mem_stats().resident(), peer_resident);
    space.unmap(guarded.start).unwrap();
    peer.unmap(source.start).unwrap();

    space.unmap(lazy.start).unwrap();
    space.unmap(eager.start).unwrap();
    assert_eq!(descriptors(), descriptors_before);
    assert_eq!(accounted(), accounted_before);
    assert_eq!(resident(), resident_before);
    crate::raw_log!("guarded heap tests PASS");
}

// alloc_user_shared cleans up after itself: when the peer cannot reserve
// the counterpart, the first mapping is unmapped and each charge is
// reversed exactly once.
#[cfg(debug_assertions)]
pub fn shared_alloc_cleanup_self_test() {
    let space = UserAddressSpace::new().unwrap();
    let peer = UserAddressSpace::new().unwrap();
    let options =
        MappingOptions::READABLE | MappingOptions::WRITABLE | MappingOptions::USER_ACCESSIBLE;
    let usage = |space: &UserAddressSpace| {
        (
            space.total_usage.load(Ordering::Relaxed),
            space.user_mem_stats().total(),
            space.user_mem_stats().resident(),
            space.inner.page_descriptors(),
        )
    };
    let (space_before, peer_before) = (usage(&space), usage(&peer));

    // Fill the peer's address space with lazy reservations, cheap now,
    // until a small one no longer fits.
    let mut held = alloc::vec::Vec::new();
    let mut pages = 1_u64 << 32;
    while pages >= 16 {
        match peer.alloc_user_lazy(pages) {
            Ok(segment) => held.push(segment.start),
            Err(_) => pages >>= 1,
        }
    }
    assert!(peer.alloc_user_unmapped(16).is_err());

    // The first refused call may grow kernel slabs that are never given
    // back; the second must leave the pool exactly where it found it.
    let peer_full = usage(&peer);
    let refused = Err(moto_rt::E_OUT_OF_MEMORY);
    assert_eq!(
        space.alloc_user_shared(u64::MAX, 16, options, &peer),
        refused
    );
    let free_before = super::phys::available_small_pages();
    assert_eq!(
        space.alloc_user_shared(u64::MAX, 16, options, &peer),
        refused
    );
    assert_eq!(usage(&space), space_before);
    assert_eq!(usage(&peer), peer_full);
    assert_eq!(super::phys::available_small_pages(), free_before);

    // With a fixed address, the first mapping is made and then undone, so
    // the address is free for the next caller.
    const FIXED: u64 = 1 << 40;
    assert_eq!(space.alloc_user_shared(FIXED, 16, options, &peer), refused);
    assert_eq!(usage(&space), space_before);
    let other = UserAddressSpace::new().unwrap();
    let (here, there) = space.alloc_user_shared(FIXED, 16, options, &other).unwrap();
    assert_eq!(here, FIXED);
    space.unmap(here).unwrap();
    other.unmap(there).unwrap();
    assert_eq!(usage(&space), space_before);

    // A refused share into a fixed address undoes its reservation the same
    // way; an untouched lazy source is refused.
    let untouched = other.alloc_user_lazy(16).unwrap();
    let readable = MappingOptions::READABLE | MappingOptions::USER_ACCESSIBLE;
    assert_eq!(
        space.share_from(&other, untouched.start, FIXED, 16, readable),
        Err(moto_rt::E_INVALID_ARGUMENT)
    );
    assert_eq!(usage(&space), space_before);
    for idx in 0..16 {
        other
            .fix_pagefault(untouched.start + idx * PAGE_SIZE_SMALL, 6)
            .unwrap();
    }
    space
        .share_from(&other, untouched.start, FIXED, 16, readable)
        .unwrap();
    space.unmap(FIXED).unwrap();
    other.unmap(untouched.start).unwrap();
    assert_eq!(usage(&space), space_before);

    for start in held {
        peer.unmap(start).unwrap();
    }
    assert_eq!(usage(&peer), peer_before);
    crate::raw_log!("shared alloc cleanup tests PASS");
}

// Releasing a space's memory the way process exit does: every segment and
// cached kernel stack goes back with the statistics at zero, a frame shared
// with a peer survives there, every kind of later reservation is refused,
// and a second release and the final drop are no-ops.
#[cfg(debug_assertions)]
pub fn exit_release_self_test() {
    const PAGES: u64 = 4;
    let space = UserAddressSpace::new().unwrap();
    let peer = UserAddressSpace::new().unwrap();
    let options =
        MappingOptions::READABLE | MappingOptions::WRITABLE | MappingOptions::USER_ACCESSIBLE;
    let refused: Result<(), ErrorCode> = Err(moto_rt::E_BAD_HANDLE);

    let heap = space.alloc_user_heap(PAGES).unwrap();
    space.copy_to_user(b"shared", heap.start).unwrap();
    let lazy = space.alloc_user_lazy(PAGES).unwrap();
    space.fix_pagefault(lazy.start, 6).unwrap();
    let user_stack = space.alloc_user_stack(16).unwrap();
    let kernel_stack = space.alloc_kernel_stack(4).unwrap();
    space.drop_stacks(&user_stack, &Some(kernel_stack));
    let dest = peer.alloc_user_unmapped(PAGES).unwrap();
    UserAddressSpace::map_shared(&peer, dest.start, &space, heap.start, options).unwrap();
    let peer_usage = peer.user_mem_stats().total();
    assert_ne!(space.user_mem_stats().total(), 0);
    assert_ne!(space.kernel_mem_stats().total(), 0);

    space.release_user_memory();
    assert_eq!(space.user_mem_stats().total(), 0);
    assert_eq!(space.user_mem_stats().resident(), 0);
    assert_eq!(space.kernel_mem_stats().total(), 0);
    assert_eq!(space.virt_to_phys(heap.start), None);
    assert_eq!(peer.read_from_user(dest.start, 6).unwrap(), b"shared");

    assert_eq!(space.alloc_user_heap(PAGES).map(|_| ()), refused);
    assert_eq!(space.alloc_user_lazy(PAGES).map(|_| ()), refused);
    assert_eq!(space.alloc_user_unmapped(PAGES).map(|_| ()), refused);
    assert_eq!(
        space.allocate_user_fixed(heap.start, PAGES, options),
        refused
    );
    assert_eq!(
        space.share_from(&peer, dest.start, heap.start, PAGES, options),
        refused
    );
    assert_eq!(
        space
            .alloc_user_shared(u64::MAX, PAGES, options, &peer)
            .map(|_| ()),
        refused
    );
    assert_eq!(
        peer.alloc_user_shared(u64::MAX, PAGES, options, &space)
            .map(|_| ()),
        refused
    );
    assert_eq!(
        space.fix_pagefault(lazy.start + PAGE_SIZE_SMALL, 6),
        Err(moto_rt::E_INVALID_ARGUMENT)
    );
    assert_eq!(space.user_mem_stats().total(), 0);
    assert_eq!(peer.user_mem_stats().total(), peer_usage);

    space.release_user_memory();
    assert_eq!(space.user_mem_stats().total(), 0);
    drop(space);
    assert_eq!(peer.read_from_user(dest.start, 6).unwrap(), b"shared");
    peer.unmap(dest.start).unwrap();
    assert_eq!(peer.user_mem_stats().total(), 0);
    crate::raw_log!("exit release tests PASS");
}

// Exhaustion is an error, not a panic. With the live pool drained on the BSP
// alone, every path that acquires pages for a process refuses with
// E_OUT_OF_MEMORY and leaves no trace, whether the frame, a descriptor slab
// or a page-table page was what ran out and however far it had got, and
// proceeds once exactly the pages it needs are back. The pool and the
// statistics come back exact.
#[cfg(debug_assertions)]
pub fn exhaustion_self_test() {
    use super::phys::Frame;
    use super::phys::{allocate_huge_frame, available_small_pages, block_metrics};
    use super::phys::{frame_slab_pages, mmio_frame, phys_allocate_frameless};
    use super::phys::{phys_allocate_frameless_run, phys_deallocate_frameless};
    use super::slab::SlabArc;
    use super::virt::{HUGE_FALLBACKS, KERNEL_ADDRESS_SPACE};
    use super::{align_up, PageType, PAGE_SIZE_LARGE_LOG2, PAGING_DIRECT_MAP_OFFSET};

    const HUGE_PAGES: u64 = PAGE_SIZE_MID >> PAGE_SIZE_SMALL_LOG2;
    const FILE_ADDR: u64 = 1 << 30;
    const SHARE_ADDR: u64 = 3 * (1 << 30) - PAGE_SIZE_SMALL;
    let oom = moto_rt::E_OUT_OF_MEMORY;
    let options =
        MappingOptions::READABLE | MappingOptions::WRITABLE | MappingOptions::USER_ACCESSIBLE;

    // The pool's free small pages, threaded through the pages themselves:
    // holding every page of the guest costs no memory.
    #[derive(Default)]
    struct Hoard {
        head: u64,
        count: u64,
    }
    impl Hoard {
        fn push(&mut self, phys: u64) {
            unsafe { *((phys + PAGING_DIRECT_MAP_OFFSET) as *mut u64) = self.head };
            self.head = phys;
            self.count += 1;
        }
        fn take(&mut self, pages: u64) {
            for _ in 0..pages {
                self.push(phys_allocate_frameless(PageType::SmallPage).unwrap());
            }
        }
        fn take_all(&mut self) {
            while let Ok(phys) = phys_allocate_frameless(PageType::SmallPage) {
                self.push(phys);
            }
            assert_eq!(available_small_pages(), 0);
        }
        fn give_back(&mut self, pages: u64) {
            for _ in 0..pages {
                let phys = self.head;
                self.head = unsafe { *((phys + PAGING_DIRECT_MAP_OFFSET) as *const u64) };
                phys_deallocate_frameless(phys, PageType::SmallPage);
                self.count -= 1;
            }
        }
    }

    // Whole blocks go first, so that every eligible request falls back to
    // small pages and the drain below stays short: dual-purpose blocks as
    // huge frames, the small-only region's as untouched runs. The drain
    // writes into each page it takes, and a first touch costs a host page
    // fault on VMMs that back the guest with 4 KiB pages.
    let taken_before = block_metrics().taken;
    let mut held = alloc::vec::Vec::with_capacity(block_metrics().total as usize);
    while let Ok(frame) = allocate_huge_frame() {
        held.push(frame);
    }
    let mut runs = alloc::vec::Vec::with_capacity(64);
    while available_small_pages() > 4 * HUGE_PAGES {
        match phys_allocate_frameless_run(HUGE_PAGES as u16) {
            Ok(start) => runs.push(start),
            Err(_) => break,
        }
    }
    let run_pages = runs.len() as u64 * HUGE_PAGES;
    let free_run = |start: u64| {
        for page in 0..HUGE_PAGES {
            phys_deallocate_frameless(start + (page << PAGE_SIZE_SMALL_LOG2), PageType::SmallPage);
        }
    };
    // The frames that fill the frame-descriptor slab below live in a run of
    // their own, 170 to a page: the pool has nothing to spare for them.
    struct Frames {
        base: *mut SlabArc<Frame>,
        len: usize,
    }
    const STORE_CAP: usize = PAGE_SIZE_MID as usize / size_of::<SlabArc<Frame>>();
    impl Frames {
        fn push(&mut self, frame: SlabArc<Frame>) {
            assert!(self.len < STORE_CAP);
            unsafe { self.base.add(self.len).write(frame) };
            self.len += 1;
        }
    }
    impl Drop for Frames {
        fn drop(&mut self) {
            for idx in 0..self.len {
                drop(unsafe { self.base.add(idx).read() });
            }
        }
    }
    let store = runs.pop().unwrap();
    let mut frames = Frames {
        base: (store + PAGING_DIRECT_MAP_OFFSET) as *mut SlabArc<Frame>,
        len: 0,
    };
    // Warm up what must not be allocated while the pool is empty: the heap
    // behind address-space objects, a 4 MiB mapping's frame descriptors and
    // the kernel-stack region's segment nodes.
    for _ in 0..2 {
        let space = UserAddressSpace::new().unwrap();
        let warm = space.alloc_user_heap(2 * HUGE_PAGES).unwrap();
        space.unmap(warm.start).unwrap();
        let stack = space.alloc_kernel_stack(4).unwrap();
        space.do_drop_kernel_stack(stack);
    }
    let free_held = available_small_pages();

    // The space under test, with the page and segment descriptors of a
    // 4 MiB small-page mapping already in its slabs, a lazy segment, a
    // three-page file-paged reservation at 1 GiB and a two-page plain
    // reservation across the 3 GiB boundary. A peer holds two touched pages
    // to share and copy into it. A kernel stack is measured and freed: six
    // frames and the page-table pages its slot needs.
    let space = UserAddressSpace::new().unwrap();
    let table = space.inner.page_table_ref();
    let warm = space.alloc_user_heap(2 * HUGE_PAGES).unwrap();
    assert_eq!(table.leaf_kind(warm.start), Some(PageType::SmallPage));
    space.unmap(warm.start).unwrap();
    let lazy = space.alloc_user_lazy(2).unwrap();
    space.reserve_file(FILE_ADDR, 3, false, false).unwrap();
    space
        .allocate_user_fixed(SHARE_ADDR, 2, MappingOptions::empty())
        .unwrap();
    let peer = UserAddressSpace::new().unwrap();
    let source = peer.alloc_user_lazy(2).unwrap();
    for page in [source.start, source.start + PAGE_SIZE_SMALL] {
        peer.fix_pagefault(page, 6).unwrap();
    }
    peer.copy_to_user(b"shared", source.start).unwrap();
    let pinned = || {
        peer.get_user_page_as_kernel(source.start, MappingOptions::READABLE)
            .unwrap()
    };
    let share = || UserAddressSpace::map_shared(&space, SHARE_ADDR, &peer, source.start, options);
    let before = available_small_pages();
    let probe = space.alloc_kernel_stack(4).unwrap();
    let kernel_stack_pages = before - available_small_pages();
    assert!(kernel_stack_pages >= 6);
    space.do_drop_kernel_stack(probe);
    assert_eq!(available_small_pages(), before);

    // The space as a failure must leave it: `descriptors` page descriptors
    // and `resident` resident pages, nothing reserved or charged since.
    let descriptors = space.inner.page_descriptors();
    let usage = space.user_mem_stats().total();
    let charged = space.total_usage.load(Ordering::Relaxed);
    let check = |descriptors: u64, resident: u64| {
        assert_eq!(space.inner.page_descriptors(), descriptors);
        assert_eq!(space.user_mem_stats().total(), usage);
        assert_eq!(
            space.user_mem_stats().resident(),
            resident << PAGE_SIZE_SMALL_LOG2
        );
        assert_eq!(space.total_usage.load(Ordering::Relaxed), charged);
        assert_eq!(space.kernel_mem_stats().total(), 0);
        assert_eq!(space.kernel_mem_stats().resident(), 0);
    };
    let mut hoard = Hoard::default();
    hoard.take_all();

    // Nothing to give: every path refuses and leaves no trace.
    assert_eq!(space.alloc_user_heap(1).map(|_| ()), Err(oom));
    assert_eq!(space.alloc_contiguous_pages(4).map(|_| ()), Err(oom));
    assert_eq!(space.fix_pagefault(lazy.start, 6), Err(oom));
    assert_eq!(space.fill_file_zero(FILE_ADDR), Err(oom));
    assert_eq!(space.fill_file(FILE_ADDR, &[pinned()]), (0, Err(oom)));
    assert_eq!(share(), Err(oom));
    assert_eq!(space.alloc_user_stack(4).map(|_| ()), Err(oom));
    assert_eq!(space.alloc_kernel_stack(4).map(|_| ()), Err(oom));
    assert_eq!(UserAddressSpace::new().map(|_| ()), Err(oom));
    check(descriptors, 0);
    assert_eq!(available_small_pages(), 0);

    // The frame-descriptor slab grows by `slab_pages` mapped pages once
    // every slab is full. MMIO frames own no page, so filling the slabs
    // with them costs the pool nothing and finds that boundary: the frame
    // that needs the growth is refused with the pool empty. The growth under
    // test straddles a page-table boundary: the region's cursor is moved to
    // `prefix` pages short of the next 2 MiB boundary, which is no 1 GiB
    // one; the addresses skipped stay unused, which costs the sparse region
    // nothing. Every growth short of a page gives all its pages back, the
    // cursor unmoved and nothing left mapped, the one with the slab's pages
    // but not the page-table page too, after mapping the prefix. One more
    // succeeds.
    let cursor = || *KERNEL_ADDRESS_SPACE.next_slab_addr.lock(line!());
    let slab_pages = frame_slab_pages();
    let prefix = slab_pages / 2;
    assert!(prefix >= 1);
    let boundary = align_up(cursor() + (prefix << PAGE_SIZE_SMALL_LOG2), PAGE_SIZE_MID);
    assert_eq!(
        cursor() >> PAGE_SIZE_LARGE_LOG2,
        boundary >> PAGE_SIZE_LARGE_LOG2
    );
    let slab_start = boundary - (prefix << PAGE_SIZE_SMALL_LOG2);
    *KERNEL_ADDRESS_SPACE.next_slab_addr.lock(line!()) = slab_start;
    let kernel_table = &KERNEL_ADDRESS_SPACE.base.page_table;
    let mapped = || {
        (0..slab_pages)
            .filter(|&page| {
                kernel_table
                    .virt_to_phys(slab_start + (page << PAGE_SIZE_SMALL_LOG2))
                    .is_some()
            })
            .count() as u64
    };
    assert_eq!(mapped(), 0);
    loop {
        match mmio_frame(0) {
            Ok(frame) => frames.push(frame),
            Err(err) => {
                assert_eq!(err, oom);
                break;
            }
        }
    }
    assert_eq!(available_small_pages(), 0);
    let mut grown = 0;
    loop {
        hoard.give_back(1);
        grown += 1;
        match mmio_frame(0) {
            Ok(frame) => {
                frames.push(frame);
                break;
            }
            Err(err) => {
                assert_eq!(err, oom);
                assert!(grown <= slab_pages, "{grown}");
                assert_eq!(available_small_pages(), grown);
                assert_eq!(cursor(), slab_start);
                assert_eq!(mapped(), 0);
            }
        }
    }
    assert_eq!(grown, slab_pages + 1);
    assert_eq!(available_small_pages(), 0);
    assert_eq!(cursor(), slab_start + (slab_pages << PAGE_SIZE_SMALL_LOG2));
    assert_eq!(mapped(), slab_pages);
    check(descriptors, 0);

    // A one-page heap at a fresh address takes four pages: the frame and
    // three page-table pages. One short, it fails and what it created is
    // unwound; complete, it maps, and the unmap returns all four.
    for short in 1..4 {
        hoard.give_back(1);
        assert_eq!(space.alloc_user_heap(1).map(|_| ()), Err(oom));
        assert_eq!(available_small_pages(), short);
        check(descriptors, 0);
    }
    hoard.give_back(1);
    let heap = space.alloc_user_heap(1).unwrap();
    assert_eq!(available_small_pages(), 0);
    space.unmap(heap.start).unwrap();
    assert_eq!(available_small_pages(), 4);
    hoard.take_all();

    // A fault on the untouched lazy segment: the same four pages, then one
    // per page once its tables exist. A refused fault leaves no descriptor.
    for short in 1..4 {
        hoard.give_back(1);
        assert_eq!(space.fix_pagefault(lazy.start, 6), Err(oom));
        assert_eq!(available_small_pages(), short);
        assert_eq!(table.virt_to_phys(lazy.start), None);
        check(descriptors, 0);
    }
    hoard.give_back(1);
    space.fix_pagefault(lazy.start, 6).unwrap();
    assert_eq!(available_small_pages(), 0);
    assert_eq!(
        space.fix_pagefault(lazy.start + PAGE_SIZE_SMALL, 6),
        Err(oom)
    );
    check(descriptors + 1, 1);
    hoard.give_back(1);
    space
        .fix_pagefault(lazy.start + PAGE_SIZE_SMALL, 6)
        .unwrap();
    assert_eq!(available_small_pages(), 0);
    check(descriptors + 2, 2);

    // A pager fill at 1 GiB: the frame and two page-table pages under the
    // L3 table the faults just created. Then a two-page fill with one page
    // in hand installs its first page and reports the failure of the
    // second; given that page, it installs the rest.
    for short in 1..3 {
        hoard.give_back(1);
        assert_eq!(space.fill_file_zero(FILE_ADDR), Err(oom));
        assert_eq!(available_small_pages(), short);
        assert_eq!(table.virt_to_phys(FILE_ADDR), None);
        check(descriptors + 2, 2);
    }
    hoard.give_back(1);
    assert_eq!(space.fill_file_zero(FILE_ADDR), Ok(true));
    assert_eq!(available_small_pages(), 0);
    check(descriptors + 3, 3);
    let rest = FILE_ADDR + PAGE_SIZE_SMALL;
    hoard.give_back(1);
    assert_eq!(space.fill_file(rest, &[pinned(), pinned()]), (1, Err(oom)));
    assert_eq!(available_small_pages(), 0);
    assert_eq!(table.virt_to_phys(rest + PAGE_SIZE_SMALL), None);
    check(descriptors + 4, 4);
    hoard.give_back(1);
    assert_eq!(space.fill_file(rest, &[pinned(), pinned()]), (1, Ok(())));
    assert_eq!(
        space.read_from_user(rest + PAGE_SIZE_SMALL, 6).unwrap(),
        b"shared"
    );
    check(descriptors + 5, 5);

    // A user stack goes after the reservations, in a fresh 2 MiB: its first
    // page needs the frame and two page-table pages. Short, the segment it
    // had reserved is unmapped again; whole, it maps, and dropping it
    // returns the three pages and the charge.
    for short in 1..3 {
        hoard.give_back(1);
        assert_eq!(space.alloc_user_stack(4).map(|_| ()), Err(oom));
        assert_eq!(available_small_pages(), short);
        check(descriptors + 5, 5);
    }
    hoard.give_back(1);
    let stack = space.alloc_user_stack(4).unwrap();
    assert_eq!(available_small_pages(), 0);
    assert_eq!(space.user_mem_stats().resident(), 6 << PAGE_SIZE_SMALL_LOG2);
    space.drop_stacks(&stack, &None);
    assert_eq!(available_small_pages(), 3);
    check(descriptors + 5, 5);
    hoard.take_all();

    // A contiguous run comes from a block's unused range, never from pages
    // freed one by one. With a whole block released and all but four of its
    // pages taken, a request of four finds its run and not the first page's
    // two page-table pages: the run goes back, to the block's list. With a
    // second block released it maps, from that block; the unmap and the
    // hoard then give both blocks back whole. Both are small-only blocks
    // from `runs`: a guest under 128 MiB has no dual-purpose block.
    assert!(runs.len() >= 2);
    free_run(runs.pop().unwrap());
    assert_eq!(available_small_pages(), HUGE_PAGES);
    hoard.take(HUGE_PAGES - 4);
    assert_eq!(space.alloc_contiguous_pages(4).map(|_| ()), Err(oom));
    assert_eq!(available_small_pages(), 4);
    check(descriptors + 5, 5);
    free_run(runs.pop().unwrap());
    let contiguous = space.alloc_contiguous_pages(4).unwrap();
    assert_eq!(available_small_pages(), HUGE_PAGES - 2);
    assert_eq!(space.inner.page_descriptors(), descriptors + 9);
    assert_eq!(space.user_mem_stats().resident(), 9 << PAGE_SIZE_SMALL_LOG2);
    space.unmap(contiguous.start).unwrap();
    assert_eq!(available_small_pages(), HUGE_PAGES + 4);
    check(descriptors + 5, 5);
    hoard.give_back(HUGE_PAGES - 4);
    for _ in 0..2 {
        runs.push(phys_allocate_frameless_run(HUGE_PAGES as u16).unwrap());
    }
    assert_eq!(available_small_pages(), 0);

    // Sharing the peer's pages into the reservation across the 3 GiB
    // boundary needs two page-table pages per page and no frame. Short of
    // any, the share fails and the page it had mapped, if any, is unmapped
    // again: the reservation is as it was. Whole, both pages read the
    // peer's frames.
    for short in 1..4 {
        hoard.give_back(1);
        assert_eq!(share(), Err(oom));
        assert_eq!(available_small_pages(), short);
        assert_eq!(table.virt_to_phys(SHARE_ADDR), None);
        assert_eq!(table.virt_to_phys(SHARE_ADDR + PAGE_SIZE_SMALL), None);
        check(descriptors + 5, 5);
    }
    hoard.give_back(1);
    share().unwrap();
    assert_eq!(available_small_pages(), 0);
    for idx in 0..2 {
        assert_eq!(
            table.virt_to_phys(SHARE_ADDR + idx * PAGE_SIZE_SMALL),
            peer.virt_to_phys(source.start + idx * PAGE_SIZE_SMALL)
        );
    }
    assert_eq!(space.read_from_user(SHARE_ADDR, 6).unwrap(), b"shared");
    check(descriptors + 5, 7);

    // A kernel stack takes its frames one by one, so short of any it is half
    // built and torn down again, in the kernel's page table. Whole, it shows
    // in the space's kernel statistics until it is freed.
    for short in 1..kernel_stack_pages {
        hoard.give_back(1);
        assert_eq!(space.alloc_kernel_stack(4).map(|_| ()), Err(oom));
        assert_eq!(available_small_pages(), short);
        check(descriptors + 5, 7);
    }
    hoard.give_back(1);
    let kernel_stack = space.alloc_kernel_stack(4).unwrap();
    assert_eq!(available_small_pages(), 0);
    assert_eq!(space.kernel_mem_stats().total(), 8 << PAGE_SIZE_SMALL_LOG2);
    assert_eq!(
        space.kernel_mem_stats().resident(),
        6 << PAGE_SIZE_SMALL_LOG2
    );
    space.do_drop_kernel_stack(kernel_stack);
    assert_eq!(available_small_pages(), kernel_stack_pages);
    check(descriptors + 5, 7);
    hoard.take_all();

    // An eligible 4 MiB heap with no whole block to take falls back to
    // small pages and, 600 pages in hand, runs out midway: every page it
    // mapped comes back.
    let fallbacks = HUGE_FALLBACKS.load(Ordering::Relaxed);
    hoard.give_back(600);
    assert_eq!(space.alloc_user_heap(2 * HUGE_PAGES).map(|_| ()), Err(oom));
    assert_eq!(available_small_pages(), 600);
    assert!(HUGE_FALLBACKS.load(Ordering::Relaxed) > fallbacks);
    check(descriptors + 5, 7);
    hoard.take_all();

    // A new address space takes six pages: its root, three page-table pages
    // for the kernel static page, one more for the process static page, and
    // that page. Short of any of them, construction fails and gives back
    // the rest.
    for short in 1..6 {
        hoard.give_back(1);
        assert_eq!(UserAddressSpace::new().map(|_| ()), Err(oom));
        assert_eq!(available_small_pages(), short);
    }
    hoard.give_back(1);
    let built = UserAddressSpace::new().unwrap();
    assert_eq!(available_small_pages(), 0);

    // The new space has no descriptor slabs. Its first one-page heap needs
    // a segment-node slab, the frame, a page-descriptor slab and the three
    // page-table pages, in that order. The slabs stay with the space once
    // allocated, so a failure past one leaves the pool a page lower than it
    // found it, and the heap then needs a page less.
    let built_charged = built.total_usage.load(Ordering::Relaxed);
    for (give, left) in [(0, 0), (1, 0), (1, 1), (1, 1), (1, 2), (1, 3)] {
        hoard.give_back(give);
        assert_eq!(built.alloc_user_heap(1).map(|_| ()), Err(oom));
        assert_eq!(available_small_pages(), left);
        assert_eq!(built.inner.page_descriptors(), 0);
        assert_eq!(built.user_mem_stats().total(), 0);
        assert_eq!(built.total_usage.load(Ordering::Relaxed), built_charged);
    }
    hoard.give_back(1);
    let heap = built.alloc_user_heap(1).unwrap();
    assert_eq!(available_small_pages(), 0);
    built.unmap(heap.start).unwrap();
    assert_eq!(available_small_pages(), 4);
    drop(built);
    assert_eq!(available_small_pages(), 12);
    hoard.take_all();

    // Teardown returns everything but the grown slab, the blocks included.
    drop(space);
    drop(peer);
    let count = hoard.count;
    hoard.give_back(count);
    assert_eq!(available_small_pages(), free_held - grown);
    drop(frames);
    free_run(store);
    for start in runs {
        free_run(start);
    }
    assert_eq!(available_small_pages(), free_held - grown + run_pages);
    drop(held);
    assert_eq!(block_metrics().taken, taken_before);
    crate::raw_log!("exhaustion tests PASS");
}
