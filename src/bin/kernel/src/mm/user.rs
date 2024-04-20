use core::sync::atomic::*;

use alloc::sync::Arc;

use super::{align_up, virt::*, PAGE_SIZE_SMALL, PAGE_SIZE_SMALL_LOG2};
use crate::mm::{MappingOptions, MemorySegment, PAGE_SIZE_MID, PAGING_DIRECT_MAP_OFFSET};
use crate::stats::MemStats;
use moto_sys::ErrorCode;

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

    // User mem stats are tracked via @inner.
    // Kernel mem stats (kernel stacks) are tracked here.
    kernel_mem_stats: Arc<MemStats>,

    kernel_stacks: super::cache::SegmentCache,
    user_stacks: super::cache::SegmentCache,
}

unsafe impl Send for UserAddressSpace {}
unsafe impl Sync for UserAddressSpace {}

impl Drop for UserAddressSpace {
    fn drop(&mut self) {
        self.inner.page_table_ref().mark_dead();

        // We manually clear caches instead of relying on drops
        // to make sure self.inner is still available, and to
        // validate usage stats.
        while let Some(segment) = self.user_stacks.pop_any_final() {
            self.do_drop_user_stack(segment);
        }
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
            kernel_mem_stats: Arc::new(MemStats::new_kernel()),

            kernel_stacks: super::cache::SegmentCache::new(),
            user_stacks: super::cache::SegmentCache::new(),
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
                log::debug!(
                    "user OOM: user usage {} when allocating {}",
                    new_total,
                    bytes
                );
                crate::arch::log_backtrace("user OOM");
            }
            self.total_usage.fetch_sub(bytes, Ordering::Relaxed);
            Err(ErrorCode::OutOfMemory)
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
            return Err(ErrorCode::InvalidArgument);
        }
        let bytes = num_pages << PAGE_SIZE_SMALL_LOG2;
        let new_total = bytes + self.total_usage.fetch_add(bytes, Ordering::AcqRel);
        if new_total > self.max_memory.load(Ordering::Relaxed) {
            #[cfg(debug_assertions)]
            log::info!(
                "user OOM: user usage {} when allocating {}",
                new_total,
                bytes
            );
            self.total_usage.fetch_sub(bytes, Ordering::Relaxed);
            Err(ErrorCode::OutOfMemory)
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

    // Used to map the binary.
    pub fn map_bytes(
        &self,
        addr: u64,
        bytes: super::MemorySegment,
        mapping_options: super::MappingOptions,
    ) -> Result<(), ErrorCode> {
        let vaddr_start = addr & !(PAGE_SIZE_SMALL - 1);
        let vaddr_end = align_up(addr + bytes.size, PAGE_SIZE_SMALL);
        let sz = vaddr_end - vaddr_start;
        let num_pages = sz >> super::PAGE_SIZE_SMALL_LOG2;

        self.stats_user_add(num_pages << PAGE_SIZE_SMALL_LOG2)?;

        let _ = self
            .inner
            .vmem_allocate_user_fixed(vaddr_start, num_pages, mapping_options)?;

        unsafe {
            self.copy_to_user(bytes.as_slice(), addr)?;
        }

        Ok(())
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
        log::trace!("alloc_user_shared: 0x{:x}", vaddr);
        self.stats_user_add(num_pages << PAGE_SIZE_SMALL_LOG2)?;

        if other
            .stats_user_add(num_pages << PAGE_SIZE_SMALL_LOG2)
            .is_err()
        {
            log::debug!("other OOM.");
            self.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
            return Err(ErrorCode::OutOfMemory);
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

        log::trace!("alloc_user_shared ok: 0x{:x} 0x{:x}", addr_here, addr_there);
        Ok((addr_here, addr_there))
    }

    pub fn user_page_table(&self) -> u64 {
        self.inner.page_table()
    }

    pub fn alloc_user_stack(&self, num_pages: u64) -> Result<UserStack, ErrorCode> {
        let num_pages = (num_pages + 2).next_power_of_two();

        if let Some(segment) = self.user_stacks.pop(num_pages as usize) {
            return Ok(UserStack { segment });
        }

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
        super::virt::vmem_allocate_pages(super::virt::VmemKind::KernelStack, num_pages).or_else(
            |err| {
                self.stats_kernel_sub(num_pages);
                Err(err)
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
        if self
            .user_stacks
            .push(
                user_segment,
                (user_segment.size as usize) >> PAGE_SIZE_SMALL_LOG2,
            )
            .is_err()
        {
            self.do_drop_user_stack(user_segment);
        }

        if let Some(kernel_stack) = kernel_stack {
            let kernel_segment = kernel_stack.clone();
            if self
                .kernel_stacks
                .push(
                    kernel_segment,
                    (kernel_stack.size as usize) >> PAGE_SIZE_SMALL_LOG2,
                )
                .is_err()
            {
                self.do_drop_kernel_stack(kernel_stack.clone());
            }
        }
    }

    pub fn alloc_user_heap(&self, num_pages: u64) -> Result<super::MemorySegment, ErrorCode> {
        self.stats_user_add(num_pages << PAGE_SIZE_SMALL_LOG2)?;

        self.inner
            .vmem_allocate_pages(VmemKind::User, num_pages, None)
            .or_else(|err| {
                self.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
                Err(err)
            })
    }

    pub fn alloc_user_mid_pages(&self, num_pages: u64) -> Result<super::MemorySegment, ErrorCode> {
        self.stats_user_add(num_pages << super::PAGE_SIZE_MID_LOG2)?;

        assert_eq!(num_pages, 1);
        let phys_addr = super::phys::phys_allocate_frameless(crate::mm::PageType::MidPage)?;
        assert_eq!(phys_addr, 2 * super::ONE_MB); // For now, a single MID page can be allocated globally.

        let virt_addr = super::virt::STATIC_SYS_IO_MID_PAGE;
        self.inner.page_table_ref().map_page(
            phys_addr,
            virt_addr,
            crate::mm::PageType::MidPage,
            MappingOptions::READABLE | MappingOptions::WRITABLE | MappingOptions::USER_ACCESSIBLE,
        );

        Ok(MemorySegment {
            start: virt_addr,
            size: PAGE_SIZE_MID,
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
            .or_else(|err| {
                self.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
                Err(err)
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
            .or_else(|err| {
                self.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
                Err(err)
            })
    }

    pub fn alloc_contiguous_pages(
        &self,
        num_pages: u64,
    ) -> Result<super::MemorySegment, ErrorCode> {
        self.stats_user_add(num_pages << PAGE_SIZE_SMALL_LOG2)?;
        self.inner
            .vmem_allocate_contiguous_pages(VmemKind::User, num_pages)
            .or_else(|err| {
                self.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
                Err(err)
            })
    }

    pub fn unmap(&self, addr: u64) -> Result<(), ErrorCode> {
        self.inner.normal_memory.free(addr).map_or_else(
            |_| {
                self.inner.custom_memory.free(addr).map(|sz| {
                    self.stats_user_sub(sz);
                    ()
                })
            },
            |sz| {
                self.stats_user_sub(sz);
                Ok(())
            },
        )
    }

    pub fn mmio_map(&self, phys_addr: u64, num_pages: u64) -> Result<u64, ErrorCode> {
        assert_eq!(0, phys_addr & (PAGE_SIZE_SMALL - 1));

        self.stats_user_add(num_pages << PAGE_SIZE_SMALL_LOG2)?;

        self.inner
            .vmem_allocate_pages(VmemKind::UserMMIO, num_pages, None)
            .map_or_else(
                |err| {
                    self.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
                    Err(err)
                },
                |segment| {
                    self.inner
                        .mmio_map(phys_addr, segment.start)
                        .map(|_| segment.start)
                        .or_else(|err| {
                            self.stats_user_sub(num_pages << PAGE_SIZE_SMALL_LOG2);
                            Err(err)
                        })
                },
            )
    }

    pub fn fix_pagefault(&self, pf_addr: u64, error_code: u64) -> Result<(), ErrorCode> {
        self.inner.fix_pagefault(pf_addr, error_code)
    }

    pub unsafe fn copy_to_user(
        &self,
        bytes: &[u8],
        user_vaddr_start: u64,
    ) -> Result<(), ErrorCode> {
        let mut source_start = 0_u64;
        let mut dst_start = user_vaddr_start;
        let mut bytes_left = bytes.len() as u64;

        while bytes_left > 0 {
            let bytes_to_copy = {
                let page_end = align_up(dst_start + 1, PAGE_SIZE_SMALL);
                if page_end - dst_start >= bytes_left {
                    bytes_left
                } else {
                    page_end - dst_start
                }
            };

            let mapping = self.inner.vaddr_map_status(dst_start);
            let phys_start = match mapping {
                VaddrMapStatus::Private(addr) => addr,
                VaddrMapStatus::Shared(addr) => addr,
                _ => {
                    log::error!("{}:{} - copy_to_user: bad mapping.", file!(), line!());
                    return Err(ErrorCode::InvalidArgument);
                }
            };

            let phys_start_2 = self.inner.page_table_ref().virt_to_phys(dst_start).unwrap();
            assert_eq!(phys_start, phys_start_2);

            core::intrinsics::copy_nonoverlapping(
                bytes.get_unchecked(source_start as usize) as *const u8,
                (phys_start + crate::arch::paging::PAGING_DIRECT_MAP_OFFSET) as usize as *mut u8,
                bytes_to_copy as usize,
            );

            source_start += bytes_to_copy;
            dst_start += bytes_to_copy;
            bytes_left -= bytes_to_copy;
        }

        Ok(())
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
        let mut source_start = vaddr_start;
        let mut remaining_bytes = buf.len() as u64;

        let mut dst_ptr = buf.as_mut_ptr();

        while remaining_bytes > 0 {
            let phys_start = self.inner.page_table_ref().virt_to_phys(source_start);
            if phys_start.is_none() {
                return Err(ErrorCode::InvalidArgument);
            }
            let phys_start = phys_start.unwrap();

            let source_end = align_up(source_start + 1, PAGE_SIZE_SMALL);
            let size_to_copy = core::cmp::min(source_end - source_start, remaining_bytes);
            unsafe {
                core::intrinsics::copy_nonoverlapping(
                    (phys_start + PAGING_DIRECT_MAP_OFFSET) as usize as *const u8,
                    dst_ptr,
                    (size_to_copy) as usize,
                );
                dst_ptr = dst_ptr.add(size_to_copy as usize);
            }
            source_start += size_to_copy;
            remaining_bytes -= size_to_copy;
        }

        Ok(())
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
