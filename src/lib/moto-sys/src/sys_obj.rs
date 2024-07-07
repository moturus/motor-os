//! SysObj syscall.

use crate::syscalls::*;
use crate::ErrorCode;

/// SysObj syscall: various object-management-related operations.
pub struct SysObj;

impl SysObj {
    pub const OP_GET: u8 = 1;
    pub const OP_PUT: u8 = 2;
    pub const OP_CREATE: u8 = 3;
    pub const OP_QUERY_PROCESS: u8 = 4;
    pub const OP_SET_LOG_LEVEL: u8 = 5;
    pub const OP_QUERY_HANDLE: u8 = 6;

    pub const OP_DBG: u8 = 7;

    pub const F_QUERY_STATUS: u32 = 1;
    pub const F_QUERY_LIST: u32 = 2;
    pub const F_QUERY_LIST_CHILDREN: u32 = 3;
    pub const F_QUERY_PID: u32 = 4;

    // When connecting to ("getting") a shared URL, wake the counterpart.
    pub const F_WAKE_PEER: u32 = 1;

    /// Attach to a running process.
    pub const F_DBG_ATTACH: u32 = 1;
    /// Stop all threads in the attached process.
    pub const F_DBG_STOP: u32 = 2;
    /// Resume a single thread or all threads in the attached process.
    pub const F_DBG_RESUME: u32 = 3;
    /// List threads in the attached process.
    pub const F_DBG_LIST_THREADS: u32 = 4;
    /// Get thread data.
    pub const F_DBG_GET_THREAD_DATA: u32 = 5;
    /// Get process memory.
    pub const F_DBG_GET_MEM: u32 = 6;

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
            pack_nr_ver(SYS_OBJ, Self::OP_CREATE, flags, 0),
            parent.as_u64(),
            bytes.as_ptr() as usize as u64,
            bytes.len() as u64,
            0,
            0,
            0,
        );
        if result.is_ok() {
            Ok(SysHandle::from(result.data[0]))
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
            pack_nr_ver(SYS_OBJ, Self::OP_CREATE, flags, 0),
            process1.as_u64(),
            bytes.as_ptr() as usize as u64,
            bytes.len() as u64,
            process2.as_u64(),
            0,
            0,
        );
        if result.is_ok() {
            Ok((
                SysHandle::from(result.data[0]),
                SysHandle::from(result.data[1]),
            ))
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
            pack_nr_ver(SYS_OBJ, Self::OP_GET, flags, 0),
            parent.as_u64(),
            bytes.as_ptr() as usize as u64,
            bytes.len() as u64,
            0,
            0,
            0,
        );
        if result.is_ok() {
            Ok((SysHandle::from(result.data[0]), result.data[1]))
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
            pack_nr_ver(SYS_OBJ, Self::OP_PUT, 0, 0),
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
            pack_nr_ver(SYS_OBJ, Self::OP_SET_LOG_LEVEL, 0, 0),
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
            pack_nr_ver(SYS_OBJ, Self::OP_QUERY_PROCESS, Self::F_QUERY_STATUS, 0),
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

    // Returns OK if the handle can be waited on.
    #[cfg(feature = "userspace")]
    pub fn handle_status(handle: SysHandle) -> Result<(), ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_OBJ, Self::OP_QUERY_HANDLE, 0, 0),
            handle.as_u64(),
            0,
            0,
            0,
            0,
            0,
        );

        if result.is_ok() {
            Ok(())
        } else {
            Err(result.error_code().into())
        }
    }

    /// Returns the PID of the handle owner.
    #[cfg(feature = "userspace")]
    pub fn get_pid(handle: SysHandle) -> Result<u64, ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_OBJ, Self::OP_QUERY_HANDLE, Self::F_QUERY_PID, 0),
            handle.as_u64(),
            0,
            0,
            0,
            0,
            0,
        );

        if result.is_ok() {
            Ok(result.data[0])
        } else {
            Err(result.error_code().into())
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
            pack_nr_ver(SYS_OBJ, Self::OP_QUERY_PROCESS, flags, 1),
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

    #[cfg(feature = "userspace")]
    pub fn dbg_attach(pid: u64) -> Result<SysHandle, ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_OBJ, Self::OP_DBG, Self::F_DBG_ATTACH, 1),
            pid,
            0,
            0,
            0,
            0,
            0,
        );

        if result.is_ok() {
            Ok(result.data[0].into())
        } else {
            Err(result.error_code())
        }
    }

    #[cfg(feature = "userspace")]
    pub fn dbg_stop(dbg_handle: SysHandle) -> Result<(), ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_OBJ, Self::OP_DBG, Self::F_DBG_STOP, 1),
            dbg_handle.into(),
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
    pub fn dbg_resume(dbg_handle: SysHandle) -> Result<(), ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_OBJ, Self::OP_DBG, Self::F_DBG_RESUME, 1),
            dbg_handle.into(),
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

    /// Fill buf with thread IDs starting with start_tid.
    /// The process indicated by dbg_handle must be stopped.
    /// Upon success, returns the number of TIDs populated into buf.
    #[cfg(feature = "userspace")]
    pub fn dbg_list_threads(
        dbg_handle: SysHandle,
        start_tid: u64,
        buf: &mut [u64],
    ) -> Result<usize, ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_OBJ, Self::OP_DBG, Self::F_DBG_LIST_THREADS, 1),
            dbg_handle.into(),
            start_tid,
            buf.as_ptr() as usize as u64,
            buf.len() as u64,
            0,
            0,
        );

        if result.is_ok() {
            Ok(result.data[0] as usize)
        } else {
            Err(result.error_code())
        }
    }

    #[cfg(feature = "userspace")]
    pub fn dbg_get_thread_data_v1(
        dbg_handle: SysHandle,
        tid: u64,
    ) -> Result<crate::stats::ThreadDataV1, ErrorCode> {
        let mut thread_data = crate::stats::ThreadDataV1::default();
        let result = do_syscall(
            pack_nr_ver(SYS_OBJ, Self::OP_DBG, Self::F_DBG_GET_THREAD_DATA, 1),
            dbg_handle.into(),
            tid,
            (&mut thread_data) as *mut _ as usize as u64,
            0,
            0,
            0,
        );

        if result.is_ok() {
            Ok(thread_data)
        } else {
            Err(result.error_code())
        }
    }

    /// Copy userspace memory of the debugged process into buf,
    /// starting at start_addr address. Returns the number of bytes copied.
    #[cfg(feature = "userspace")]
    pub fn dbg_get_mem(
        dbg_handle: SysHandle,
        start_addr: u64,
        buf: &mut [u8],
    ) -> Result<usize, ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_OBJ, Self::OP_DBG, Self::F_DBG_GET_MEM, 1),
            dbg_handle.into(),
            start_addr,
            buf.as_ptr() as usize as u64,
            buf.len() as u64,
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
