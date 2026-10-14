//! SysMem syscall.

#[cfg(feature = "userspace")]
use crate::syscalls::*;
#[cfg(feature = "userspace")]
use crate::ErrorCode;

// Various constants.
pub const PAGE_SIZE_SMALL: u64 = 4096;
pub const PAGE_SIZE_MID: u64 = 4096 * 512;
pub const PAGE_SIZE_LARGE: u64 = 4096 * 512 * 512;

pub const PAGE_SIZE_SMALL_LOG2: u64 = 12;
pub const PAGE_SIZE_MID_LOG2: u64 = 21;
pub const PAGE_SIZE_LARGE_LOG2: u64 = 30;

pub const PAGE_TYPE_SMALL: u64 = 1;
pub const PAGE_TYPE_MID: u64 = 2;
pub const PAGE_TYPE_LARGE: u64 = 3;

pub const MAX_ADDRESS_SPACE_SIZE_LOG2: u64 = 46;

/// SysMem syscall: various memory-management-related operations.
pub struct SysMem;

impl SysMem {
    // Operations: just constants, not bit flags.
    pub const OP_MAP: u8 = 1;
    pub const OP_UNMAP: u8 = 2;
    pub const OP_QUERY: u8 = 3;
    pub const OP_RECLAIM: u8 = 4;
    /// sys-io's executable pager; see `pager_*` below.
    pub const OP_PAGER: u8 = 5;

    // OP_PAGER sub-operations, passed as flags.
    pub const F_PAGER_INIT: u32 = 0;
    pub const F_PAGER_RESERVE: u32 = 1;
    pub const F_PAGER_DEQUEUE: u32 = 2;
    pub const F_PAGER_FILL: u32 = 3;
    pub const F_PAGER_FAIL: u32 = 4;
    pub const F_PAGER_ZERO_FROM: u32 = 5;
    /// The page value of a dequeued event that retires its mapping.
    pub const PAGER_RETIRED: u64 = u64::MAX;
    /// Maximum events returned by one dequeue.
    pub const PAGER_MAX_EVENTS: usize = 64;

    // Bit flags for create/map operations.
    pub const F_READABLE: u32 = 1;
    pub const F_WRITABLE: u32 = 2;
    pub const F_MMIO: u32 = 4;
    pub const F_CONTIGUOUS: u32 = 8;
    pub const F_SHARE_SELF: u32 = 0x10;
    pub const F_LAZY: u32 = 0x20; // Just a hint.
    pub const F_CUSTOM_USER: u32 = 0x40;
    // Only valid with F_SHARE_SELF; applies to the target mapping, while the
    // caller gets an R+W alias to the same frames. W+X is rejected per mapping.
    // Targeting the caller's own address space requires CAP_IO_MANAGER.
    pub const F_EXECUTABLE: u32 = 0x80;

    // Bit flags for query.
    pub const F_QUERY_STATS: u32 = 1;
    pub const F_QUERY_ADMISSION_STATS: u32 = 2;

    #[cfg(feature = "userspace")]
    pub fn map(
        address_space: SysHandle,
        flags: u32,
        phys_addr: u64,
        virt_addr: u64,
        page_size: u64,
        num_pages: u64,
    ) -> Result<u64, ErrorCode> {
        debug_assert_ne!(num_pages, 0);
        let result = do_syscall(
            pack_nr_ver(SYS_MEM, Self::OP_MAP, flags, 0),
            address_space.as_u64(),
            phys_addr,
            virt_addr,
            page_size,
            num_pages,
            0,
        );
        if result.is_ok() {
            Ok(result.data[0])
        } else {
            Err(result.error_code())
        }
    }

    #[cfg(feature = "userspace")]
    pub fn map2(
        address_space: SysHandle,
        flags: u32,
        phys_addr: u64,
        virt_addr: u64,
        page_size: u64,
        num_pages: u64,
    ) -> Result<(u64, u64), ErrorCode> {
        debug_assert_ne!(num_pages, 0);
        let result = do_syscall(
            pack_nr_ver(SYS_MEM, Self::OP_MAP, flags, 0),
            address_space.as_u64(),
            phys_addr,
            virt_addr,
            page_size,
            num_pages,
            0,
        );
        if result.is_ok() {
            Ok((result.data[0], result.data[1]))
        } else {
            Err(result.error_code())
        }
    }
    #[cfg(feature = "userspace")]
    pub fn unmap(
        address_space: SysHandle,
        flags: u32,
        phys_addr: u64,
        virt_addr: u64,
    ) -> Result<(), ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_MEM, Self::OP_UNMAP, flags, 0),
            address_space.as_u64(),
            phys_addr,
            virt_addr,
            0,
            0,
            0,
        );

        if result.is_ok() {
            Ok(())
        } else {
            Err(result.error_code())
        }
    }

    #[cfg(feature = "userspace")]
    pub fn virt_to_phys(virt_addr: u64) -> Result<u64, ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_MEM, Self::OP_QUERY, 0, 0),
            SysHandle::SELF.as_u64(),
            u64::MAX,
            virt_addr,
            0,
            0,
            0,
        );

        if result.is_ok() {
            Ok(result.data[0])
        } else {
            Err(result.error_code())
        }
    }

    #[cfg(feature = "userspace")]
    pub fn alloc(page_size: u64, num_pages: u64) -> Result<u64, ErrorCode> {
        assert!(
            page_size == PAGE_SIZE_SMALL
                || page_size == PAGE_SIZE_MID
                || page_size == PAGE_SIZE_LARGE
        );
        assert_ne!(num_pages, 0);
        Self::map(
            SysHandle::SELF,
            Self::F_READABLE | Self::F_WRITABLE,
            u64::MAX,
            u64::MAX,
            page_size,
            num_pages,
        )
    }

    // Note: the calling process must have CAP_IO_MANAGER.
    #[cfg(feature = "userspace")]
    pub fn alloc_contiguous_pages(size: u64) -> Result<u64, ErrorCode> {
        assert_ne!(size, 0);
        if size > 20 * PAGE_SIZE_MID {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        let (page_size, page_size_log_2) = if size > (PAGE_SIZE_MID >> 1) {
            (PAGE_SIZE_MID, PAGE_SIZE_MID_LOG2)
        } else {
            (PAGE_SIZE_SMALL, PAGE_SIZE_SMALL_LOG2)
        };

        let size = super::align_up(size, page_size);
        Self::map(
            SysHandle::SELF,
            Self::F_READABLE | Self::F_WRITABLE | Self::F_CONTIGUOUS,
            u64::MAX,
            u64::MAX,
            page_size,
            size >> page_size_log_2,
        )
    }

    #[cfg(feature = "userspace")]
    pub fn free(virt_addr: u64) -> Result<(), ErrorCode> {
        Self::unmap(SysHandle::SELF, 0, u64::MAX, virt_addr)
    }

    #[cfg(feature = "userspace")]
    pub fn mmio_map(phys_addr: u64, size: u64) -> Result<u64, ErrorCode> {
        assert_eq!(0, size & (PAGE_SIZE_SMALL - 1));
        Self::map(
            SysHandle::SELF,
            Self::F_READABLE | Self::F_WRITABLE | Self::F_MMIO,
            phys_addr,
            u64::MAX,
            PAGE_SIZE_SMALL,
            size >> PAGE_SIZE_SMALL_LOG2,
        )
    }

    #[cfg(feature = "userspace")]
    pub fn query_stats() -> Result<super::stats::MemoryStats, ErrorCode> {
        use crate::stats::MemoryStats;

        let mut stats = MemoryStats::default();

        let res = do_syscall(
            pack_nr_ver(SYS_MEM, Self::OP_QUERY, Self::F_QUERY_STATS, 0),
            SysHandle::NONE.as_u64(),
            &mut stats as *mut _ as usize as u64,
            0,
            0,
            0,
            0,
        );

        if res.is_ok() {
            Ok(stats)
        } else {
            Err(res.error_code())
        }
    }

    #[cfg(feature = "userspace")]
    pub fn query_admission_stats() -> Result<super::stats::AdmissionStats, ErrorCode> {
        use crate::stats::AdmissionStats;

        let mut stats = AdmissionStats::default();

        let res = do_syscall(
            pack_nr_ver(SYS_MEM, Self::OP_QUERY, Self::F_QUERY_ADMISSION_STATS, 0),
            SysHandle::NONE.as_u64(),
            &mut stats as *mut _ as usize as u64,
            0,
            0,
            0,
            0,
        );

        if res.is_ok() {
            Ok(stats)
        } else {
            Err(res.error_code())
        }
    }

    #[cfg(feature = "userspace")]
    pub fn reclaim(handle: SysHandle) -> Result<(), ErrorCode> {
        let res = do_syscall(
            pack_nr_ver(SYS_MEM, Self::OP_RECLAIM, 0, 0),
            handle.as_u64(),
            0,
            0,
            0,
            0,
            0,
        );

        if res.is_ok() {
            Ok(())
        } else {
            Err(res.error_code())
        }
    }
}

/// The executable pager (sys-io only). sys-io reserves sparse file-paged
/// segments in a child's address space and fills pages on request.
#[cfg(feature = "userspace")]
impl SysMem {
    fn pager_op(flags: u32, args: [u64; 5]) -> Result<(u64, u64), ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_MEM, Self::OP_PAGER, flags, 0),
            args[0],
            args[1],
            args[2],
            args[3],
            args[4],
            0,
        );
        if result.is_ok() {
            Ok((result.data[0], result.data[1]))
        } else {
            Err(result.error_code())
        }
    }

    /// Creates the pager's notification object; signalled when requests or
    /// retirements are queued.
    pub fn pager_init() -> Result<SysHandle, ErrorCode> {
        Self::pager_op(Self::F_PAGER_INIT, [0; 5]).map(|(h, _)| SysHandle::from_u64(h))
    }

    /// Reserves a file-paged segment; returns the mapping id.
    pub fn pager_reserve(
        address_space: SysHandle,
        start: u64,
        num_pages: u64,
        writable: bool,
        executable: bool,
    ) -> Result<u64, ErrorCode> {
        let prot = u64::from(executable) | (u64::from(writable) << 1);
        Self::pager_op(
            Self::F_PAGER_RESERVE,
            [address_space.as_u64(), start, num_pages, prot, 0],
        )
        .map(|(id, _)| id)
    }

    /// Moves queued (mapping id, page) events into `events`; returns how many.
    pub fn pager_dequeue(events: &mut [(u64, u64)]) -> Result<usize, ErrorCode> {
        Self::pager_op(
            Self::F_PAGER_DEQUEUE,
            [
                0,
                events.as_mut_ptr() as usize as u64,
                events.len() as u64,
                0,
                0,
            ],
        )
        .map(|(n, _)| n as usize)
    }

    /// Installs copies of `count` pages at `source` (in the caller) at `dest`.
    pub fn pager_fill(id: u64, dest: u64, source: u64, count: u64) -> Result<u64, ErrorCode> {
        Self::pager_op(Self::F_PAGER_FILL, [0, id, dest, source, count]).map(|(n, _)| n)
    }

    /// Fails the threads waiting for `page`.
    pub fn pager_fail(id: u64, page: u64) -> Result<(), ErrorCode> {
        Self::pager_op(Self::F_PAGER_FAIL, [0, id, page, 0, 0]).map(|_| ())
    }

    /// Pages from `start` on are zero-filled by the kernel without requests.
    pub fn pager_zero_from(id: u64, start: u64) -> Result<(), ErrorCode> {
        Self::pager_op(Self::F_PAGER_ZERO_FROM, [0, id, start, 0, 0]).map(|_| ())
    }
}
