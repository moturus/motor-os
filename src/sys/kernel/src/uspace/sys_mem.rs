use moto_sys::*;
use syscalls::SyscallResult;

use crate::mm::user::UserAddressSpace;
use crate::mm::MappingOptions;

use super::syscall::*;

fn sys_mmio_map(
    address_space: &UserAddressSpace,
    phys_addr: u64,
    virt_addr: u64,
    page_size: u64,
    num_pages: u64,
) -> SyscallResult {
    if virt_addr != u64::MAX {
        log::debug!("sys_mem_impl: bad virt_addr: 0x{:x}", virt_addr);
        return ResultBuilder::invalid_argument();
    }

    if page_size != sys_mem::PAGE_SIZE_SMALL {
        log::debug!("sys_mem_impl: bad page_size: 0x{:x}", page_size);
        return ResultBuilder::invalid_argument();
    }

    if let Ok(virt_addr) = address_space.mmio_map(phys_addr, num_pages) {
        ResultBuilder::ok_1(virt_addr)
    } else {
        log::debug!("sys_mmio_map failed");
        ResultBuilder::result(moto_rt::E_INVALID_ARGUMENT)
    }
}

fn sys_map(
    curr_thread: &super::process::Thread,
    address_space: &UserAddressSpace,
    flags: u32,
    phys_addr: u64,
    virt_addr: u64,
    page_size: u64,
    num_pages: u64,
) -> SyscallResult {
    // Protect against bad numbers.
    let (new_bytes, overflow) = page_size.overflowing_mul(num_pages);
    if overflow || new_bytes > (1 << 40) {
        return ResultBuilder::result(moto_rt::E_OUT_OF_MEMORY); // TODO: should we kill the process?
    }

    let io_manager = curr_thread.owner().capabilities() & moto_sys::caps::CAP_IO_MANAGER != 0;

    if !io_manager && crate::mm::oom_for_user(page_size * num_pages) {
        return ResultBuilder::result(moto_rt::E_OUT_OF_MEMORY);
    }

    if flags == (SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_MMIO) {
        // This is used for MMIO at specific addresses, e.g. PCI functions.
        if !io_manager {
            log::debug!("sys_map: MMIO w/o CAP_IO_MAN");
            return ResultBuilder::result(moto_rt::E_NOT_ALLOWED);
        }
        return sys_mmio_map(address_space, phys_addr, virt_addr, page_size, num_pages);
    }

    if page_size == sys_mem::PAGE_SIZE_MID {
        if !io_manager {
            return ResultBuilder::result(moto_rt::E_NOT_ALLOWED);
        }
        if flags != (SysMem::F_READABLE | SysMem::F_WRITABLE) || num_pages != 1 {
            log::debug!(
                "sys_map: bad flags: 0x{:x} or num_pages: {}",
                flags,
                num_pages
            );
            return ResultBuilder::result(moto_rt::E_INVALID_ARGUMENT);
        }
        if phys_addr != u64::MAX || virt_addr != u64::MAX {
            log::debug!("sys_mem_impl: bad map addresses");
            return ResultBuilder::invalid_argument();
        }

        return match address_space.alloc_user_mid_pages(num_pages) {
            Ok(segment) => ResultBuilder::ok_2(segment.start, segment.size),
            Err(_) => ResultBuilder::result(moto_rt::E_OUT_OF_MEMORY),
        };
    }

    if page_size != sys_mem::PAGE_SIZE_SMALL {
        return ResultBuilder::invalid_argument();
    }

    if flags == (SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_CONTIGUOUS) {
        // This is used for MMIO at arbitrary addresses, e.g. to create VirtIO virtqueues.
        if !io_manager {
            log::debug!("sys_map: MMIO w/o CAP_IO_MAN");
            return ResultBuilder::result(moto_rt::E_NOT_ALLOWED);
        }
        if phys_addr != u64::MAX || virt_addr != u64::MAX {
            log::debug!("sys_mem_impl: bad map addresses");
            return ResultBuilder::invalid_argument();
        }

        if num_pages > 64 {
            log::debug!("sys_mem_impl: too many pages");
            return ResultBuilder::invalid_argument();
        }

        return match address_space.alloc_contiguous_pages(num_pages) {
            Ok(segment) => ResultBuilder::ok_2(segment.start, segment.size),
            Err(_) => ResultBuilder::result(moto_rt::E_OUT_OF_MEMORY),
        };
    }

    if flags & SysMem::F_CUSTOM_USER == SysMem::F_CUSTOM_USER {
        if !io_manager {
            log::debug!("sys_map: F_CUSTOM_USER w/o CAP_IO_MAN");
            return ResultBuilder::result(moto_rt::E_NOT_ALLOWED);
        }
        if phys_addr != u64::MAX || virt_addr == u64::MAX {
            log::debug!("sys_mem_impl: bad map addresses");
            return ResultBuilder::invalid_argument();
        }

        let mut flags = flags ^ SysMem::F_CUSTOM_USER;
        if flags == 0 {
            log::debug!("sys_mem_impl: bad flags");
            return ResultBuilder::invalid_argument();
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
            return ResultBuilder::invalid_argument();
        }

        if virt_addr < moto_sys::CUSTOM_USERSPACE_REGION_START
            || (virt_addr + (num_pages << sys_mem::PAGE_SIZE_SMALL_LOG2))
                >= CUSTOM_USERSPACE_REGION_END
        {
            return ResultBuilder::invalid_argument();
        }

        return match address_space.allocate_user_fixed(virt_addr, num_pages, mapping_options) {
            Ok(()) => ResultBuilder::ok_2(virt_addr, num_pages << sys_mem::PAGE_SIZE_SMALL_LOG2),
            Err(_) => ResultBuilder::result(moto_rt::E_OUT_OF_MEMORY),
        };
    }

    if flags == (SysMem::F_READABLE | SysMem::F_WRITABLE) {
        if phys_addr == u64::MAX && virt_addr == u64::MAX {
            // This is a normal user heap allocation.
            return match address_space.alloc_user_heap(num_pages) {
                Ok(segment) => ResultBuilder::ok_2(segment.start, segment.size),
                Err(_) => ResultBuilder::result(moto_rt::E_OUT_OF_MEMORY),
            };
        }

        log::debug!("sys_mem_impl: bad map addresses");
        return ResultBuilder::invalid_argument();
    }

    if flags == (SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_LAZY) {
        // This is a normal user heap allocation.
        if phys_addr != u64::MAX || virt_addr != u64::MAX {
            log::debug!("sys_mem_impl: bad map addresses");
            return ResultBuilder::invalid_argument();
        }

        return match address_space.alloc_user_lazy(num_pages) {
            Ok(segment) => ResultBuilder::ok_2(segment.start, segment.size),
            Err(_) => ResultBuilder::result(moto_rt::E_OUT_OF_MEMORY),
        };
    }

    if flags == 0 {
        // This is used to reserve virt memory without physical mapping, for
        // shared memory operations.
        if phys_addr != u64::MAX || virt_addr != u64::MAX {
            log::debug!("sys_mem_impl: bad map addresses");
            return ResultBuilder::invalid_argument();
        }

        return match address_space.alloc_user_unmapped(num_pages) {
            Ok(segment) => {
                debug_assert_eq!(page_size * num_pages, segment.size);
                ResultBuilder::ok_2(segment.start, segment.size)
            }
            Err(_) => ResultBuilder::result(moto_rt::E_OUT_OF_MEMORY),
        };
    }

    if (flags & SysMem::F_SHARE_SELF) != 0 {
        // This is used to load a binary into an address space.
        if phys_addr != u64::MAX {
            log::debug!("sys_mem_impl: bad map addresses");
            return ResultBuilder::invalid_argument();
        }

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
        if flags != 0 {
            log::debug!("sys_mem_impl: bad map flags: 0x{:x}", flags);
            return ResultBuilder::invalid_argument();
        }

        return match address_space.alloc_user_shared(
            virt_addr,
            num_pages,
            opts,
            curr_thread.owner().address_space(),
        ) {
            Ok((addr1, addr2)) => ResultBuilder::ok_2(addr1, addr2),
            Err(_) => ResultBuilder::result(moto_rt::E_OUT_OF_MEMORY),
        };
    }

    log::debug!("sys_mem_impl: bad map flags: 0x{:x}", flags);
    return ResultBuilder::invalid_argument();
}

fn sys_unmap(
    _curr_thread: &super::process::Thread,
    address_space: &UserAddressSpace,
    flags: u32,
    phys_addr: u64,
    virt_addr: u64,
) -> SyscallResult {
    if flags != 0 {
        log::debug!("sys_unmap: unrecognized flags 0x{:x}", flags);
        return ResultBuilder::invalid_argument();
    }
    if phys_addr != u64::MAX {
        log::debug!("sys_mem_query: invalid phys_addr: 0x{:x}", phys_addr);
        return ResultBuilder::invalid_argument();
    }

    match address_space.unmap(virt_addr) {
        Err(err) => {
            log::debug!("sys_unmap: 0x{:x} failed: {:?}", virt_addr, err);
            ResultBuilder::invalid_argument()
        }
        Ok(()) => ResultBuilder::ok(),
    }
}

fn sys_mem_global_stats(
    thread: &super::process::Thread,
    flags: u32,
    user_ptr: u64,
) -> SyscallResult {
    if flags != SysMem::F_QUERY_STATS {
        return ResultBuilder::invalid_argument();
    }

    let phys_stats = crate::mm::phys::PhysStats::get();
    let heap_stats = crate::mm::kheap::heap_stats();

    let mut stats = moto_sys::stats::MemoryStats::default();
    stats.available = phys_stats.total_size;
    stats.used_pages = phys_stats.small_pages_used;
    stats.heap_total = heap_stats.total_in_heap as u64;

    unsafe {
        let src: &[u8] = core::slice::from_raw_parts(
            &stats as *const _ as *const u8,
            core::mem::size_of::<moto_sys::stats::MemoryStats>(),
        );
        if let Err(err) = thread.owner().address_space().copy_to_user(src, user_ptr) {
            return ResultBuilder::result(err);
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
        log::trace!("sys_mem_query: unrecognized flags 0x{:x}", flags);
        return ResultBuilder::invalid_argument();
    }

    if phys_addr != u64::MAX || page_size != 0 || num_pages != 0 {
        log::trace!(
            "sys_mem_query: invalid args: 0x{:x} 0x{:x} 0x{:x}",
            phys_addr,
            page_size,
            num_pages
        );
        return ResultBuilder::invalid_argument();
    }

    if let Some(phys_addr) = address_space.virt_to_phys(virt_addr) {
        ResultBuilder::ok_1(phys_addr)
    } else {
        log::trace!("sys_mem_query: virt_to_phys: not found: 0x{:x}", virt_addr);
        ResultBuilder::invalid_argument()
    }
}

fn sys_reclaim() -> SyscallResult {
    log::warn!("SysMem::reclaim(): do CAPs check.");

    crate::mm::kheap::reclaim();
    ResultBuilder::ok()
}

pub fn sys_mem_impl(thread: &super::process::Thread, args: &SyscallArgs) -> SyscallResult {
    let version = args.version;

    if version > 0 {
        return ResultBuilder::version_too_high();
    }

    let address_space_handle = SysHandle::from_u64(args.args[0]);

    if address_space_handle == SysHandle::NONE {
        if args.operation != SysMem::OP_QUERY {
            log::debug!("sys_mem_impl: NONE handle and not OP_QUERY.");
            return ResultBuilder::invalid_argument();
        }

        return sys_mem_global_stats(thread, args.flags, args.args[1]);
    }

    if address_space_handle == SysHandle::KERNEL {
        if args.operation == SysMem::OP_RECLAIM {
            return sys_reclaim();
        }
        return ResultBuilder::invalid_argument();
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
                    Some(p) => p.address_space().clone(),
                    None => {
                        log::debug!("sys_mem_impl: bad handle");
                        return ResultBuilder::invalid_argument();
                    }
                },
                Some(a) => a,
            }
        }
    };

    match args.operation {
        SysMem::OP_MAP => {
            if args.args[5] != 0 {
                return ResultBuilder::invalid_argument();
            }
            return sys_map(
                thread,
                &address_space,
                args.flags,
                args.args[1],
                args.args[2],
                args.args[3],
                args.args[4],
            );
        }
        SysMem::OP_UNMAP => {
            if args.args[3] != 0 || args.args[4] != 0 || args.args[5] != 0 {
                return ResultBuilder::invalid_argument();
            }
            return sys_unmap(
                thread,
                &address_space,
                args.flags,
                args.args[1],
                args.args[2],
            );
        }
        SysMem::OP_QUERY => {
            if args.args[5] != 0 {
                return ResultBuilder::invalid_argument();
            }
            return sys_mem_query(
                thread,
                &address_space,
                args.flags,
                args.args[1],
                args.args[2],
                args.args[3],
                args.args[4],
            );
        }
        _ => {
            log::debug!("sys_mem: bad op {}", args.operation);
            ResultBuilder::invalid_argument()
        }
    }
}
