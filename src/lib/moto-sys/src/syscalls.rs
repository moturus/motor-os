/*
 * Three syscalls:
 * - SYS_CTL: object management/configuration
 * - SYS_MEM: memory management (memory allocation and sharing)
 * - SYS_CPU: CPU management (scheduling)
 */

// Syscall numbers.
pub const SYS_CTL: u8 = 1;
pub const SYS_MEM: u8 = 2;
pub const SYS_CPU: u8 = 3;

use crate::ErrorCode;

// SyscallResult is passed on registers; x64, arm64, and risc-v all have
// enough argument/scratch registers to pass data back this way.
#[derive(Debug)]
pub struct SyscallResult {
    pub result: u64,    // rax
    pub data: [u64; 6], // rdi, rsi, rdx, r10, r8, r9
}

impl SyscallResult {
    // Flags.
    pub const F_TIMED_OUT: u64 = 0x01_00_00;
    pub const F_HANDLE_ARRAY: u64 = 0x_02_00_00;

    pub fn is_ok(&self) -> bool {
        ((self.result & 0xFF_FF) as u16) == ErrorCode::Ok as u16
    }

    pub fn timed_out(&self) -> bool {
        (self.result & Self::F_TIMED_OUT) != 0
    }

    pub fn error_code(&self) -> ErrorCode {
        ErrorCode::from_u16((self.result & 0xFF_FF) as u16)
    }
}

/// SysHandle represents a kernel object to the userspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(C, align(8))]
pub struct SysHandle(u64);

const _: () = assert!(core::mem::size_of::<SysHandle>() == 8);

impl SysHandle {
    // Pre-defined object handles.
    pub const NONE: SysHandle = SysHandle(0);
    pub const KERNEL: SysHandle = SysHandle(1);
    pub const SELF: SysHandle = SysHandle(2); // This process.
    pub const CURR: SysHandle = SysHandle(3); // This thread.
    pub const PARENT: SysHandle = SysHandle(4); // The parent process.
    pub const IO_MAN: SysHandle = SysHandle(5); // IO Manager process (the parent by default).

    pub const fn from_u64(val: u64) -> Self {
        SysHandle(val)
    }
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
    pub const fn is_none(&self) -> bool {
        self.as_u64() == Self::NONE.as_u64()
    }

    #[cfg(feature = "userspace")]
    pub fn this_thread() -> Self {
        crate::shared_mem::UserThreadControlBlock::get()
            .self_handle
            .into()
    }
}

impl From<u64> for SysHandle {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<&u64> for SysHandle {
    fn from(value: &u64) -> Self {
        Self(*value)
    }
}

impl From<SysHandle> for u64 {
    fn from(value: SysHandle) -> u64 {
        value.0
    }
}

impl From<&SysHandle> for u64 {
    fn from(value: &SysHandle) -> u64 {
        value.0
    }
}

/// Same as SysHandle, but calls SysCtl::put on drop.
#[cfg(feature = "userspace")]
pub struct RaiiHandle(u64);

#[cfg(feature = "userspace")]
impl Drop for RaiiHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            SysCtl::put(self.syshandle()).unwrap()
        }
    }
}

#[cfg(feature = "userspace")]
impl RaiiHandle {
    pub const fn syshandle(&self) -> SysHandle {
        SysHandle(self.0)
    }

    pub const fn from(handle: SysHandle) -> Self {
        Self(handle.0)
    }

    pub fn take(mut self) -> SysHandle {
        let result = SysHandle(self.0);
        self.0 = 0;
        result
    }
}

pub struct SysCtl;

#[cfg(feature = "userspace")]
fn pack_nr_ver(syscall_number: u8, operation: u8, flags: u32, version: u16) -> u64 {
    ((syscall_number as u64) << 56)
        | ((operation as u64) << 48)
        | ((flags as u64) << 16)
        | (version as u64)
}

impl SysCtl {
    pub const OP_GET: u8 = 1;
    pub const OP_PUT: u8 = 2;
    pub const OP_CREATE: u8 = 3;
    pub const OP_QUERY_PROCESS: u8 = 4;
    pub const OP_SET_LOG_LEVEL: u8 = 5;

    pub const F_QUERY_STATUS: u32 = 1;
    pub const F_QUERY_LIST: u32 = 2;
    pub const F_QUERY_LIST_CHILDREN: u32 = 3;

    // When connecting to ("getting") a shared URL, wake the counterpart.
    pub const F_WAKE_PEER: u32 = 1;

    // URLS:
    //     - "address_space:$URL"
    //                  Creates a new address space that can be identified by the $URL;
    //     - "capabilities"
    //     - "irq_wait:$NUM"
    //     - "process:entry_point=$NUM;capabilities=$NUM"
    //     - "serial_console"
    //     - "shared:url=$URL;address=$addr;page_type=[small|mid];page_num=$num"
    //            - A "server" calls CREATE for a custom URL (can be duplicates). Then waits.
    //              may provide an unmapped page.
    //            - A "client" calls GET for the URL; page must be mapped; if there is a matching
    //              endpoint, the IPC channel is created and returned. Who then waits and who wakes
    //              is up to the userspace.
    //            - For now, only 1:1 connections are supported.
    //            - Later "multicast" connections will be added (server writes), multiple clients read.
    #[cfg(feature = "userspace")]
    pub fn create(parent: SysHandle, flags: u32, url: &str) -> Result<SysHandle, ErrorCode> {
        let bytes = url.as_bytes();

        let result = do_syscall(
            pack_nr_ver(SYS_CTL, Self::OP_CREATE, flags, 0),
            parent.as_u64(),
            bytes.as_ptr() as usize as u64,
            bytes.len() as u64,
            0,
            0,
            0,
        );
        if result.is_ok() {
            Ok(SysHandle(result.data[0]))
        } else {
            Err(result.error_code())
        }
    }

    // Create a pair of wait handles so that the userspace can wake/wait/swap on them.
    // Similar to shared, but while shared is more of a server/client setup,
    // the IPC pair is more of a direct connection (e.g. stdio).
    //
    // Returned handles are valid inside processes passed as parameters, not
    // the caller; the caller can pass SysHandle::SELF to have one (or both) of
    // the wait handles to belong to it.
    #[cfg(feature = "userspace")]
    pub fn create_ipc_pair(
        process1: SysHandle,
        process2: SysHandle,
        flags: u32,
    ) -> Result<(SysHandle, SysHandle), ErrorCode> {
        let bytes = "ipc_pair".as_bytes();
        let result = do_syscall(
            pack_nr_ver(SYS_CTL, Self::OP_CREATE, flags, 0),
            process1.as_u64(),
            bytes.as_ptr() as usize as u64,
            bytes.len() as u64,
            process2.as_u64(),
            0,
            0,
        );
        if result.is_ok() {
            Ok((SysHandle(result.data[0]), SysHandle(result.data[1])))
        } else {
            Err(result.error_code())
        }
    }

    #[cfg(feature = "userspace")]
    pub fn get(parent: SysHandle, flags: u32, url: &str) -> Result<SysHandle, ErrorCode> {
        let res = Self::get_res1(parent, flags, url)?;
        Ok(res.0)
    }

    #[cfg(feature = "userspace")]
    pub fn get_res1(
        parent: SysHandle,
        flags: u32,
        url: &str,
    ) -> Result<(SysHandle, u64), ErrorCode> {
        let bytes = url.as_bytes();

        let result = do_syscall(
            pack_nr_ver(SYS_CTL, Self::OP_GET, flags, 0),
            parent.as_u64(),
            bytes.as_ptr() as usize as u64,
            bytes.len() as u64,
            0,
            0,
            0,
        );
        if result.is_ok() {
            Ok((SysHandle(result.data[0]), result.data[1]))
        } else {
            Err(result.error_code())
        }
    }

    #[cfg(feature = "userspace")]
    pub fn put(handle: SysHandle) -> Result<(), ErrorCode> {
        Self::put_1(handle, 0)
    }

    #[cfg(feature = "userspace")]
    pub fn put_1(handle: SysHandle, arg: u64) -> Result<(), ErrorCode> {
        Self::put_remote_1(SysHandle::SELF, handle, arg)
    }

    #[cfg(feature = "userspace")]
    pub fn put_remote(owner_process: SysHandle, handle: SysHandle) -> Result<(), ErrorCode> {
        Self::put_remote_1(owner_process, handle, 0)
    }

    #[cfg(feature = "userspace")]
    pub fn put_remote_1(
        owner_process: SysHandle,
        handle: SysHandle,
        arg: u64,
    ) -> Result<(), ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_CTL, Self::OP_PUT, 0, 0),
            owner_process.as_u64(),
            handle.as_u64(),
            arg,
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

    // Level: log::LevelFilter; 3 => Info, 4 => Debug, etc.
    #[cfg(feature = "userspace")]
    pub fn set_log_level(level: u8) -> Result<u8, ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_CTL, Self::OP_SET_LOG_LEVEL, 0, 0),
            level as u64,
            0,
            0,
            0,
            0,
            0,
        );
        if result.is_ok() {
            Ok(result.data[0] as u8)
        } else {
            Err(result.error_code())
        }
    }

    #[cfg(feature = "userspace")]
    pub fn process_status(handle: SysHandle) -> Result<Option<u64>, ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_CTL, Self::OP_QUERY_PROCESS, Self::F_QUERY_STATUS, 0),
            handle.as_u64(),
            0,
            0,
            0,
            0,
            0,
        );

        if result.is_ok() {
            Ok(Some(result.data[0]))
        } else {
            if result.error_code() == ErrorCode::AlreadyInUse {
                Ok(None)
            } else {
                Err(ErrorCode::NotFound)
            }
        }
    }

    #[cfg(feature = "userspace")]
    pub fn list_processes_v1(
        pid: u64,
        flat_list: bool,
        buf: &mut [super::stats::ProcessStatsV1],
    ) -> Result<usize, ErrorCode> {
        if buf.len() < 1 {
            return Err(ErrorCode::InvalidArgument);
        }

        let flags = if flat_list {
            Self::F_QUERY_LIST
        } else {
            Self::F_QUERY_LIST_CHILDREN
        };
        let result = do_syscall(
            pack_nr_ver(SYS_CTL, Self::OP_QUERY_PROCESS, flags, 1),
            pid,
            buf.as_mut_ptr() as usize as u64,
            buf.len() as u64,
            0,
            0,
            0,
        );

        if result.is_ok() {
            Ok(result.data[0] as usize)
        } else {
            Err(result.error_code())
        }
    }
}

// standard arguments: rdi, rsi, rdx, rcx, r8, r9
// our syscall arguments: rdi, rsi, rdx, r10, r8, r9
#[cfg(feature = "userspace")]
pub fn do_syscall(
    nr_ver: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> SyscallResult {
    use core::arch::asm;

    let mut val0 = arg0;
    let mut val1 = arg1;
    let mut val2 = arg2;
    let mut val3 = arg3;
    let mut val4 = arg4;
    let mut val5 = arg5;
    let mut rax = nr_ver;

    unsafe {
        asm!(
            "syscall",
            inout("rax") rax,
            inout("rdi") val0,
            inout("rsi") val1,
            inout("rdx") val2,
            inout("r10") val3,
            inout("r8" ) val4,
            inout("r9" ) val5,
            lateout("rcx") _,
            lateout("r11") _,
        )
    };

    let mut data: [u64; 6] = [0; 6];
    data[0] = val0;
    data[1] = val1;
    data[2] = val2;
    data[3] = val3;
    data[4] = val4;
    data[5] = val5;

    SyscallResult { result: rax, data }
}

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
            page_size == Self::PAGE_SIZE_SMALL
                || page_size == Self::PAGE_SIZE_MID
                || page_size == Self::PAGE_SIZE_LARGE
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
        if size > 20 * Self::PAGE_SIZE_MID {
            return Err(ErrorCode::InvalidArgument);
        }
        let (page_size, page_size_log_2) = if size > (Self::PAGE_SIZE_MID >> 1) {
            (Self::PAGE_SIZE_MID, Self::PAGE_SIZE_MID_LOG2)
        } else {
            (Self::PAGE_SIZE_SMALL, Self::PAGE_SIZE_SMALL_LOG2)
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
        assert_eq!(0, size & (Self::PAGE_SIZE_SMALL - 1));
        Self::map(
            SysHandle::SELF,
            Self::F_READABLE | Self::F_WRITABLE | Self::F_MMIO,
            phys_addr,
            u64::MAX,
            Self::PAGE_SIZE_SMALL,
            size >> Self::PAGE_SIZE_SMALL_LOG2,
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

pub struct SysCpu;

impl SysCpu {
    pub const OP_EXIT: u8 = 1;
    pub const OP_WAIT: u8 = 2;
    pub const OP_WAKE: u8 = 3;
    pub const OP_KILL: u8 = 4;
    pub const OP_SPAWN: u8 = 5;
    pub const OP_USAGE: u8 = 6;
    pub const OP_AFFINE_CPU: u8 = 7;

    // Controls whether hanles to wait for are passed via registers or as an array in memory.
    pub const F_HANDLE_ARRAY: u32 = 1;
    pub const F_TIMEOUT: u32 = 2; // If present, args[0] contains Instant abs timeout.

    // If present, poll wakers and return, don't block. Can't be combined with F_TIMEOUT.
    pub const F_DONTBLOCK: u32 = 4;

    // If present, args[0] (if no timeout) or args[1] (if timeout) contains swap target.
    pub const F_SWAP_TARGET: u32 = 8;

    // If present, args[0] (if no timeout) or args[1] (if timeout) contains wake target.
    pub const F_WAKE_TARGET: u32 = 16;

    #[cfg(feature = "userspace")]
    pub fn exit(code: u64) -> ! {
        do_syscall(
            pack_nr_ver(SYS_CPU, Self::OP_EXIT, 0, 0),
            code,
            0,
            0,
            0,
            0,
            0,
        );
        unreachable!();
    }

    #[cfg(feature = "userspace")]
    pub fn kill(target: SysHandle) -> Result<(), ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_CPU, Self::OP_KILL, 0, 0),
            target.as_u64(),
            0,
            0,
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
    pub fn wake(target: SysHandle) -> Result<(), ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_CPU, Self::OP_WAKE, 0, 0),
            target.as_u64(),
            0,
            0,
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

    // Wake a specific thread in a (remote) process.
    #[cfg(feature = "userspace")]
    pub fn wake_thread(
        remote_target: SysHandle,
        remote_thread: SysHandle,
    ) -> Result<(), ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_CPU, Self::OP_WAKE, 0, 0),
            remote_target.as_u64(),
            remote_thread.as_u64(),
            0,
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

    // THE wait function:
    // - if timed out, will return Err(ErrorCode::TimedOut);
    // - if Instant is_nan(), then won't block (and won't return TimedOut);
    // - if Err(BadHandle), @handles will contain bad handles;
    // - if Ok(()), @handles will contain wakers;
    // - if [swap|wake]_target is not NONE, will swap into the target;
    // - the [swap|wake]_target, if present, will be woken even if one of the wait handles are bad;
    // - at the moment, specifying both the swap and the wake targets is not allowed.
    #[cfg(feature = "userspace")]
    pub fn wait(
        wait_handles: &mut [SysHandle],
        swap_target: SysHandle,
        wake_target: SysHandle,
        timeout: Option<crate::time::Instant>,
    ) -> Result<(), ErrorCode> {
        // Note: we consciously drop all wait objects on wakeup and
        // require a full list of wait objects on each new wait. While it
        // may seem that requiring a full list of wait objects on each wait
        // is wasteful and does not scale, this is done consciously so that
        // we avoid synchronous designs (where many wait objects are needed).
        let mut flags: u32 = 0;
        let mut next_arg: usize = 0;
        let mut args = [0_u64; 6];

        if let Some(timeout) = timeout {
            if timeout.is_nan() {
                flags |= Self::F_DONTBLOCK;
            } else {
                flags |= Self::F_TIMEOUT;
                args[next_arg] = timeout.as_u64();
                next_arg += 1;
            }
        }

        if swap_target != SysHandle::NONE {
            if wake_target != SysHandle::NONE {
                return Err(ErrorCode::InvalidArgument);
            }
            flags |= Self::F_SWAP_TARGET;
            args[next_arg] = swap_target.as_u64();
            next_arg += 1;
        } else if wake_target != SysHandle::NONE {
            flags |= Self::F_WAKE_TARGET;
            args[next_arg] = wake_target.as_u64();
            next_arg += 1;
        }

        if wait_handles.len() > (args.len() - next_arg) {
            flags |= Self::F_HANDLE_ARRAY;
            args[next_arg] = wait_handles.as_ptr() as usize as u64;
            args[next_arg + 1] = wait_handles.len() as u64;
        } else {
            for idx in 0..wait_handles.len() {
                args[next_arg] = wait_handles[idx].as_u64();
                next_arg += 1;
            }
        }

        let result = do_syscall(
            pack_nr_ver(SYS_CPU, Self::OP_WAIT, flags, 1),
            args[0],
            args[1],
            args[2],
            args[3],
            args[4],
            args[5],
        );

        Self::process_result(&result, wait_handles)
    }

    #[cfg(feature = "userspace")]
    fn process_result(result: &SyscallResult, handles: &mut [SysHandle]) -> Result<(), ErrorCode> {
        // If the condition below is false, the kernel has properly put data in @handles.
        if result.result & SyscallResult::F_HANDLE_ARRAY == 0 {
            for idx in 0..handles.len() {
                if idx < 6 {
                    handles[idx] = SysHandle::from_u64(result.data[idx]);
                } else {
                    handles[idx] = SysHandle::NONE;
                }
            }
        }

        if result.is_ok() {
            Ok(())
        } else {
            Err(result.error_code())
        }
    }

    #[cfg(feature = "userspace")]
    pub fn spawn(
        process: SysHandle,
        stack_start: u64,
        thread_fn: u64,
        thread_arg: u64,
    ) -> Result<SysHandle, ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_CPU, Self::OP_SPAWN, 0, 0),
            process.as_u64(),
            stack_start,
            thread_fn,
            thread_arg,
            0,
            0,
        );

        if result.is_ok() {
            Ok(SysHandle::from_u64(result.data[0]))
        } else {
            Err(result.error_code())
        }
    }

    #[cfg(feature = "userspace")]
    pub fn sched_yield() {
        // Self::wait_timeout(Self::__F_TIMEOUT_RELATIVE, 0, SysHandle::NONE).unwrap();
        Self::wait(
            &mut [],
            SysHandle::NONE,
            SysHandle::NONE,
            Some(crate::time::Instant::nan()),
        )
        .unwrap();
    }

    #[cfg(feature = "userspace")]
    pub fn query_stats(buf: &mut [f32]) -> Result<(), ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_CPU, Self::OP_USAGE, 0, 0),
            buf.as_ptr() as usize as u64,
            buf.len() as u64,
            0,
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

    /// Affine the current thread to the specified CPU (or remove the affinity).
    /// Only the IO_MANAGER can affine to CPU 0.
    #[cfg(feature = "userspace")]
    pub fn affine_to_cpu(cpu: Option<u32>) -> Result<(), ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_CPU, Self::OP_AFFINE_CPU, 0, 0),
            match cpu {
                Some(cpu) => cpu as u64,
                None => u64::MAX,
            },
            0,
            0,
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
}
