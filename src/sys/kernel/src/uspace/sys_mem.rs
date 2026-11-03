use moto_sys::*;
use syscalls::SyscallResult;

use super::oom::wait::Retry;
use crate::mm::user::UserAddressSpace;
use crate::mm::{AllocationFailure, MappingOptions};

use super::syscall::*;

fn sys_mmio_map(
    retry: &Retry,
    address_space: &UserAddressSpace,
    phys_addr: u64,
    virt_addr: u64,
    page_size: u64,
    num_pages: u64,
) -> Result<SyscallResult, AllocationFailure> {
    if virt_addr != u64::MAX {
        log::debug!("sys_mem_impl: bad virt_addr: 0x{virt_addr:x}");
        return Ok(ResultBuilder::invalid_argument());
    }

    if page_size != sys_mem::PAGE_SIZE_SMALL {
        log::debug!("sys_mem_impl: bad page_size: 0x{page_size:x}");
        return Ok(ResultBuilder::invalid_argument());
    }

    crate::mm::phys::validate_mmio(phys_addr, num_pages)?;
    retry.check_space(address_space, num_pages * page_size)?;
    match address_space.mmio_map(phys_addr, num_pages) {
        Ok(virt_addr) => Ok(ResultBuilder::ok_1(virt_addr)),
        Err(err) => {
            log::debug!("sys_mmio_map failed: {err:?}");
            Err(err)
        }
    }
}

fn sys_map(
    retry: &Retry,
    curr_thread: &super::process::Thread,
    address_space: &UserAddressSpace,
    args: &SyscallArgs,
) -> Result<SyscallResult, AllocationFailure> {
    let (flags, phys_addr, virt_addr, page_size, num_pages) = (
        args.flags,
        args.args[1],
        args.args[2],
        args.args[3],
        args.args[4],
    );
    // Protect against bad numbers. No mapping is empty: every path below
    // builds a segment, and a segment of zero size is a kernel assertion.
    // A size that overflows is malformed; one above a terabyte is refused
    // as unsatisfiable before any lookup. Everything else below answers
    // with the memory manager's own code.
    if num_pages == 0 {
        log::debug!("sys_mem_impl: zero pages");
        return Ok(ResultBuilder::invalid_argument());
    }
    let (new_bytes, overflow) = page_size.overflowing_mul(num_pages);
    if overflow {
        return Ok(ResultBuilder::invalid_argument());
    }
    if new_bytes > (1 << 40) {
        return Ok(ResultBuilder::result(moto_rt::E_OUT_OF_MEMORY));
    }

    let io_manager = curr_thread.owner().capabilities() & moto_sys::caps::CAP_IO_MANAGER != 0;

    if flags == (SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_MMIO) {
        // This is used for MMIO at specific addresses, e.g. PCI functions.
        if !io_manager {
            log::debug!("sys_map: MMIO w/o CAP_IO_MAN");
            return Ok(ResultBuilder::result(moto_rt::E_NOT_ALLOWED));
        }
        return sys_mmio_map(
            retry,
            address_space,
            phys_addr,
            virt_addr,
            page_size,
            num_pages,
        );
    }

    if page_size != sys_mem::PAGE_SIZE_SMALL {
        return Ok(ResultBuilder::invalid_argument());
    }

    if flags == (SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_CONTIGUOUS) {
        // This is used for MMIO at arbitrary addresses, e.g. to create VirtIO virtqueues.
        if !io_manager {
            log::debug!("sys_map: MMIO w/o CAP_IO_MAN");
            return Ok(ResultBuilder::result(moto_rt::E_NOT_ALLOWED));
        }
        if phys_addr != u64::MAX || virt_addr != u64::MAX {
            log::debug!("sys_mem_impl: bad map addresses");
            return Ok(ResultBuilder::invalid_argument());
        }

        if num_pages > 64 {
            log::debug!("sys_mem_impl: too many pages");
            return Ok(ResultBuilder::invalid_argument());
        }

        retry.check_space(address_space, new_bytes)?;
        return match address_space.alloc_contiguous_pages(num_pages) {
            Ok(segment) => Ok(ResultBuilder::ok_2(segment.start, segment.size)),
            Err(
                err @ AllocationFailure::Pressure {
                    kind: crate::mm::RefusalKind::Gate,
                    ..
                },
            ) => Err(err),
            Err(err) => Err(AllocationFailure::Code(err.into())),
        };
    }

    if flags & SysMem::F_CUSTOM_USER == SysMem::F_CUSTOM_USER {
        if !io_manager {
            log::debug!("sys_map: F_CUSTOM_USER w/o CAP_IO_MAN");
            return Ok(ResultBuilder::result(moto_rt::E_NOT_ALLOWED));
        }
        if phys_addr != u64::MAX || virt_addr == u64::MAX {
            log::debug!("sys_mem_impl: bad map addresses");
            return Ok(ResultBuilder::invalid_argument());
        }

        let mut flags = flags ^ SysMem::F_CUSTOM_USER;
        if flags == 0 {
            log::debug!("sys_mem_impl: bad flags");
            return Ok(ResultBuilder::invalid_argument());
        }

        let mut mapping_options = MappingOptions::USER_ACCESSIBLE;
        if flags & SysMem::F_READABLE != 0 {
            mapping_options |= MappingOptions::READABLE;
            flags ^= SysMem::F_READABLE;
        }
        if flags & SysMem::F_WRITABLE != 0 {
            mapping_options |= MappingOptions::WRITABLE;
            flags ^= SysMem::F_WRITABLE;
        }

        if flags != 0 {
            log::debug!("sys_mem_impl: bad flags");
            return Ok(ResultBuilder::invalid_argument());
        }
        if !mapping_options.contains(MappingOptions::READABLE) {
            log::debug!("sys_mem_impl: writable-only custom mapping");
            return Ok(ResultBuilder::invalid_argument());
        }

        if virt_addr < moto_sys::CUSTOM_USERSPACE_REGION_START
            || (virt_addr + (num_pages << sys_mem::PAGE_SIZE_SMALL_LOG2))
                >= CUSTOM_USERSPACE_REGION_END
        {
            return Ok(ResultBuilder::invalid_argument());
        }

        retry.check_space(address_space, 0)?;
        return match address_space.allocate_user_fixed(virt_addr, num_pages, mapping_options) {
            Ok(()) => Ok(ResultBuilder::ok_2(
                virt_addr,
                num_pages << sys_mem::PAGE_SIZE_SMALL_LOG2,
            )),
            Err(err) => Err(err),
        };
    }

    if flags == (SysMem::F_READABLE | SysMem::F_WRITABLE) {
        if phys_addr == u64::MAX && virt_addr == u64::MAX {
            // This is a normal user heap allocation.
            retry.check_space(
                address_space,
                crate::mm::user::heap_allocation_bytes(num_pages),
            )?;
            return match address_space.alloc_user_heap(num_pages) {
                Ok(segment) => Ok(ResultBuilder::ok_2(segment.start, segment.size)),
                Err(err) => Err(err),
            };
        }

        log::debug!("sys_mem_impl: bad map addresses");
        return Ok(ResultBuilder::invalid_argument());
    }

    if flags == (SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_LAZY) {
        // This is a normal user heap allocation.
        if phys_addr != u64::MAX || virt_addr != u64::MAX {
            log::debug!("sys_mem_impl: bad map addresses");
            return Ok(ResultBuilder::invalid_argument());
        }

        retry.check_space(address_space, new_bytes)?;
        return match address_space.alloc_user_lazy(num_pages) {
            Ok(segment) => Ok(ResultBuilder::ok_2(segment.start, segment.size)),
            Err(err) => Err(err),
        };
    }

    if flags == (SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_GUARDED)
        || flags == (SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_LAZY | SysMem::F_GUARDED)
    {
        // A heap allocation between two never-mapped guard pages: the caller
        // gets the whole segment, num_pages + 2 pages, guards included.
        if phys_addr != u64::MAX || virt_addr != u64::MAX {
            log::debug!("sys_mem_impl: bad map addresses");
            return Ok(ResultBuilder::invalid_argument());
        }

        let lazy = (flags & SysMem::F_LAZY) != 0;
        retry.check_space(address_space, new_bytes + 2 * page_size)?;
        return match address_space.alloc_user_guarded(num_pages, lazy) {
            Ok(segment) => Ok(ResultBuilder::ok_2(segment.start, segment.size)),
            Err(err) => Err(err),
        };
    }

    if flags == 0 {
        // This is used to reserve virt memory without physical mapping, for
        // shared memory operations.
        if phys_addr != u64::MAX || virt_addr != u64::MAX {
            log::debug!("sys_mem_impl: bad map addresses");
            return Ok(ResultBuilder::invalid_argument());
        }

        retry.check_space(address_space, new_bytes)?;
        return match address_space.alloc_user_unmapped(num_pages) {
            Ok(segment) => {
                debug_assert_eq!(page_size * num_pages, segment.size);
                Ok(ResultBuilder::ok_2(segment.start, segment.size))
            }
            Err(err) => Err(err),
        };
    }

    if (flags & SysMem::F_SHARE_SELF) != 0 {
        // Two shapes. With phys_addr unset: allocate in the target and alias
        // the frames into the caller R+W, which is how a loader writes a
        // binary into an address space. With phys_addr set: map the caller's
        // existing segment at that address into the target at virt_addr,
        // read-only or read+execute, for pages every process has identical
        // (the vdso's text and read-only data).
        let mut flags = flags & !SysMem::F_SHARE_SELF;
        let mut opts = MappingOptions::USER_ACCESSIBLE;
        if (flags & SysMem::F_READABLE) != 0 {
            opts |= MappingOptions::READABLE;
            flags &= !SysMem::F_READABLE;
        }
        if (flags & SysMem::F_WRITABLE) != 0 {
            opts |= MappingOptions::WRITABLE;
            flags &= !SysMem::F_WRITABLE;
        }
        // F_EXECUTABLE applies to the target side only (ELF text or JIT code);
        // the caller's side of the sharing is always mapped R+W, which is
        // how loaders write text into a mapping the target can't write.
        if (flags & SysMem::F_EXECUTABLE) != 0 {
            opts |= MappingOptions::EXECUTABLE;
            flags &= !SysMem::F_EXECUTABLE;
        }
        if flags != 0 {
            log::debug!("sys_mem_impl: bad map flags: 0x{flags:x}");
            return Ok(ResultBuilder::invalid_argument());
        }
        if !opts.contains(MappingOptions::READABLE) {
            log::debug!("sys_mem_impl: shared mapping is not readable");
            return Ok(ResultBuilder::invalid_argument());
        }
        // W^X is enforced per mapping. The writable loader alias can refer
        // to the same frame as an executable target mapping.
        if opts.contains(MappingOptions::EXECUTABLE) && opts.contains(MappingOptions::WRITABLE) {
            log::debug!("sys_mem_impl: W+X mapping rejected");
            return Ok(ResultBuilder::invalid_argument());
        }
        if phys_addr != u64::MAX {
            return sys_share_existing(
                retry,
                curr_thread,
                address_space,
                opts,
                phys_addr,
                virt_addr,
                num_pages,
            );
        }

        let owner = curr_thread.owner();
        let alias = owner.address_space();
        alias.check_allocation(new_bytes)?;
        let target_bytes = if core::ptr::eq(address_space, alias.as_ref()) {
            2 * new_bytes
        } else {
            new_bytes
        };
        retry.check_space(address_space, target_bytes)?;
        retry.check(alias.allocation_class())?;
        return match address_space.alloc_user_shared(virt_addr, num_pages, opts, alias) {
            Ok((addr1, addr2)) => Ok(ResultBuilder::ok_2(addr1, addr2)),
            Err(err) => Err(err),
        };
    }

    log::debug!("sys_mem_impl: bad map flags: 0x{flags:x}");
    Ok(ResultBuilder::invalid_argument())
}

/// Maps the caller's segment at `local_addr` into `address_space` at
/// `virt_addr`. Both addresses are fixed and the segments must be the same
/// size; the target mapping is never writable.
fn sys_share_existing(
    retry: &Retry,
    curr_thread: &super::process::Thread,
    address_space: &UserAddressSpace,
    opts: MappingOptions,
    local_addr: u64,
    virt_addr: u64,
    num_pages: u64,
) -> Result<SyscallResult, AllocationFailure> {
    let target_is_self = core::ptr::eq(address_space, curr_thread.owner().address_space().as_ref());
    let page_mask = sys_mem::PAGE_SIZE_SMALL - 1;
    if target_is_self
        || opts.contains(MappingOptions::WRITABLE)
        || virt_addr == u64::MAX
        || (local_addr | virt_addr) & page_mask != 0
    {
        log::debug!("sys_mem_impl: bad share arguments");
        return Ok(ResultBuilder::invalid_argument());
    }

    retry.check_space(address_space, num_pages << sys_mem::PAGE_SIZE_SMALL_LOG2)?;
    match address_space.share_from(
        curr_thread.owner().address_space(),
        local_addr,
        virt_addr,
        num_pages,
        opts,
    ) {
        Ok(()) => Ok(ResultBuilder::ok_2(
            virt_addr,
            num_pages << sys_mem::PAGE_SIZE_SMALL_LOG2,
        )),
        Err(err) => Err(err),
    }
}

fn sys_unmap(
    curr_thread: &super::process::Thread,
    address_space: &UserAddressSpace,
    flags: u32,
    phys_addr: u64,
    virt_addr: u64,
) -> SyscallResult {
    curr_thread
        .process_stats
        .adjust_metric(crate::xray::stats::MetricType::SysMemUnmaps, 1);

    if flags != 0 {
        log::debug!("sys_unmap: unrecognized flags 0x{flags:x}");
        return ResultBuilder::invalid_argument();
    }
    if phys_addr != u64::MAX {
        log::debug!("sys_mem_query: invalid phys_addr: 0x{phys_addr:x}");
        return ResultBuilder::invalid_argument();
    }

    match address_space.unmap(virt_addr) {
        Err(err) => {
            log::debug!("sys_unmap: 0x{virt_addr:x} failed: {err:?}");
            ResultBuilder::result(err)
        }
        Ok(()) => ResultBuilder::ok(),
    }
}

fn sys_mem_global_stats(
    thread: &super::process::Thread,
    flags: u32,
    user_ptr: u64,
) -> SyscallResult {
    match flags {
        SysMem::F_QUERY_STATS => {
            let phys_stats = crate::mm::phys::PhysStats::get();
            let heap_stats = crate::mm::kheap::heap_stats();

            let stats = moto_sys::stats::MemoryStats {
                available: phys_stats.total_size,
                used_pages: phys_stats.small_pages_used,
                heap_total: heap_stats.total_in_heap as u64,
            };
            copy_stats_to_user(thread, &stats, user_ptr)
        }
        _ => ResultBuilder::invalid_argument(),
    }
}

fn copy_stats_to_user<T>(
    thread: &super::process::Thread,
    stats: &T,
    user_ptr: u64,
) -> SyscallResult {
    unsafe {
        let src: &[u8] =
            core::slice::from_raw_parts(stats as *const _ as *const u8, core::mem::size_of::<T>());
        if let Err(err) = thread.owner().address_space().copy_to_user(src, user_ptr) {
            return err.into_syscall_result(thread.owner().address_space());
        }
    }

    ResultBuilder::ok()
}

fn sys_mem_query(
    _curr_thread: &super::process::Thread,
    address_space: &UserAddressSpace,
    flags: u32,
    phys_addr: u64,
    virt_addr: u64,
    page_size: u64,
    num_pages: u64,
) -> SyscallResult {
    if flags != 0 {
        log::trace!("sys_mem_query: unrecognized flags 0x{flags:x}");
        return ResultBuilder::invalid_argument();
    }

    if phys_addr != u64::MAX || page_size != 0 || num_pages != 0 {
        log::trace!("sys_mem_query: invalid args: 0x{phys_addr:x} 0x{page_size:x} 0x{num_pages:x}");
        return ResultBuilder::invalid_argument();
    }

    if let Some(phys_addr) = address_space.virt_to_phys(virt_addr) {
        ResultBuilder::ok_1(phys_addr)
    } else {
        log::trace!("sys_mem_query: virt_to_phys: not found: 0x{virt_addr:x}");
        ResultBuilder::invalid_argument()
    }
}

fn sys_reclaim() -> SyscallResult {
    log::warn!("SysMem::reclaim(): do CAPs check.");

    crate::mm::kheap::reclaim();
    ResultBuilder::ok()
}

pub fn sys_mem_impl(thread: &super::process::Thread, args: &SyscallArgs) -> SyscallResult {
    thread
        .process_stats
        .adjust_metric(crate::xray::stats::MetricType::SysMemCalls, 1);
    if args.version > 0 {
        return ResultBuilder::version_too_high();
    }
    if args.operation == SysMem::OP_PAGER {
        return super::pager::sys_pager(thread, args);
    }
    if args.operation == SysMem::OP_MAP {
        thread
            .process_stats
            .adjust_metric(crate::xray::stats::MetricType::SysMemMaps, 1);
    }
    let mut retry = Retry::default();
    loop {
        match try_sys_mem(thread, args, &retry) {
            Ok(result) => return result,
            Err(failure) => {
                if let Err(code) = retry.after_failure(thread, failure) {
                    return ResultBuilder::result(code);
                }
            }
        }
    }
}

// All owner/target Arcs and sharing temporaries die here, before the outer wait.
fn try_sys_mem(
    thread: &super::process::Thread,
    args: &SyscallArgs,
    retry: &Retry,
) -> Result<SyscallResult, AllocationFailure> {
    let address_space_handle = SysHandle::from_u64(args.args[0]);

    if address_space_handle == SysHandle::NONE {
        if args.operation != SysMem::OP_QUERY {
            log::debug!("sys_mem_impl: NONE handle and not OP_QUERY.");
            return Ok(ResultBuilder::invalid_argument());
        }

        return Ok(sys_mem_global_stats(thread, args.flags, args.args[1]));
    }

    if address_space_handle == SysHandle::KERNEL {
        if args.operation == SysMem::OP_RECLAIM {
            return Ok(sys_reclaim());
        }
        return Ok(ResultBuilder::invalid_argument());
    }

    let process = thread.owner();
    let address_space = match address_space_handle {
        SysHandle::SELF => process.address_space().clone(),
        _ => {
            match super::sysobject::object_from_handle::<UserAddressSpace>(
                &process,
                address_space_handle,
            ) {
                None => match super::sysobject::object_from_handle::<super::Process>(
                    &process,
                    address_space_handle,
                ) {
                    Some(p) => {
                        if args.operation == SysMem::OP_MAP && !p.status().is_alive() {
                            return Ok(ResultBuilder::invalid_argument());
                        }
                        p.address_space().clone()
                    }
                    None => {
                        log::debug!("sys_mem_impl: bad handle");
                        return Ok(ResultBuilder::invalid_argument());
                    }
                },
                Some(a) => a,
            }
        }
    };

    match args.operation {
        SysMem::OP_MAP => {
            if args.args[5] != 0 {
                return Ok(ResultBuilder::invalid_argument());
            }
            sys_map(retry, thread, &address_space, args)
        }
        SysMem::OP_UNMAP => {
            if args.args[3] != 0 || args.args[4] != 0 || args.args[5] != 0 {
                return Ok(ResultBuilder::invalid_argument());
            }
            Ok(sys_unmap(
                thread,
                &address_space,
                args.flags,
                args.args[1],
                args.args[2],
            ))
        }
        SysMem::OP_QUERY => {
            if args.args[5] != 0 {
                return Ok(ResultBuilder::invalid_argument());
            }
            Ok(sys_mem_query(
                thread,
                &address_space,
                args.flags,
                args.args[1],
                args.args[2],
                args.args[3],
                args.args[4],
            ))
        }
        _ => {
            log::debug!("sys_mem: bad op {}", args.operation);
            Ok(ResultBuilder::invalid_argument())
        }
    }
}
