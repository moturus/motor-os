//! SysMem syscall.

use crate::syscalls::*;
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
    pub const OP_CREATE: u8 = 1;
    pub const OP_GET: u8 = 2;
    pub const OP_PUT: u8 = 3;
    pub const OP_MAP: u8 = 4;
    pub const OP_UNMAP: u8 = 5;
    pub const OP_REMAP: u8 = 6;
    pub const OP_QUERY: u8 = 7;
    pub const OP_DEBUG: u8 = 8;
    pub const OP_RECLAIM: u8 = 9;

    // Bit flags for create/map operations.
    pub const F_READABLE: u32 = 1;
    pub const F_WRITABLE: u32 = 2;
    pub const F_MMIO: u32 = 4;
    pub const F_CONTIGUOUS: u32 = 8;
    pub const F_SHARE_SELF: u32 = 0x10;

    // The kernel may or may not do actual mapping on
    // memory allocations; F_LAZY is a *hint* that the userspace
    // is OK with lazy mapping.
    pub const F_LAZY: u32 = 0x20;

    pub const F_LOG_UTF8: u32 = 1; // OP_DEBUG.

    // Bit flags for query.
    pub const F_QUERY_STATS: u32 = 1;

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
            return Err(ErrorCode::InvalidArgument);
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
    pub fn log(msg: &str) -> Result<(), ErrorCode> {
        let bytes = msg.as_bytes();
        if bytes.len() == 0 {
            return Err(ErrorCode::InvalidArgument);
        }

        let res = do_syscall(
            pack_nr_ver(SYS_MEM, Self::OP_DEBUG, Self::F_LOG_UTF8, 0),
            SysHandle::SELF.as_u64(),
            0,
            msg.as_bytes().as_ptr() as usize as u64,
            0,
            0,
            bytes.len() as u64,
        );

        if res.is_ok() {
            Ok(())
        } else {
            Err(res.error_code())
        }
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
