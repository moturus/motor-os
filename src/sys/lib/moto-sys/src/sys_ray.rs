//! SysRay syscall.

#[cfg(feature = "userspace")]
use crate::syscalls::*;
#[cfg(feature = "userspace")]
use crate::ErrorCode;

/// SysRay syscall: various statistics/debugging operations.
pub struct SysRay;

impl SysRay {
    pub const OP_QUERY_PROCESS: u8 = 1;
    pub const OP_DBG: u8 = 2;
    pub const OP_LOG: u8 = 3;

    pub const F_QUERY_STATUS: u32 = 1;
    pub const F_QUERY_LIST: u32 = 2;
    pub const F_QUERY_LIST_CHILDREN: u32 = 3;

    /// Attach to a running process.
    pub const F_DBG_ATTACH: u32 = 1;
    /// Mark the debuggee process as paused. All its threads will
    /// eventually pause.
    pub const F_DBG_PAUSE_PROCESS: u32 = 2;
    /// Mark a paused debuggee process as running. Paused threads
    /// will not resume automatically until explicitly resumed
    /// using F_DBG_RESUME_THREAD.
    pub const F_DBG_RESUME_PROCESS: u32 = 3;
    /// Resume a paused thread.
    pub const F_DBG_RESUME_THREAD: u32 = 4;
    /// List threads in the attached process.
    pub const F_DBG_LIST_THREADS: u32 = 5;
    /// Get thread data.
    pub const F_DBG_GET_THREAD_DATA: u32 = 6;
    /// Get process memory.
    pub const F_DBG_GET_MEM: u32 = 7;
    /// Detach the debugger. Note that just putting the handle is not enough.
    pub const F_DBG_DETACH: u32 = 8;

    #[cfg(feature = "userspace")]
    pub fn process_status(handle: SysHandle) -> Result<Option<u64>, ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_RAY, Self::OP_QUERY_PROCESS, Self::F_QUERY_STATUS, 0),
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
            pack_nr_ver(SYS_RAY, Self::OP_QUERY_PROCESS, flags, 1),
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
            pack_nr_ver(SYS_RAY, Self::OP_DBG, Self::F_DBG_ATTACH, 1),
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
    pub fn dbg_pause_process(dbg_handle: SysHandle) -> Result<(), ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_RAY, Self::OP_DBG, Self::F_DBG_PAUSE_PROCESS, 1),
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
    pub fn dbg_resume_process(dbg_handle: SysHandle) -> Result<(), ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_RAY, Self::OP_DBG, Self::F_DBG_RESUME_PROCESS, 1),
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
    pub fn dbg_resume_thread(dbg_handle: SysHandle, tid: u64) -> Result<(), ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_RAY, Self::OP_DBG, Self::F_DBG_RESUME_THREAD, 1),
            dbg_handle.into(),
            tid,
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
            pack_nr_ver(SYS_RAY, Self::OP_DBG, Self::F_DBG_LIST_THREADS, 1),
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
            pack_nr_ver(SYS_RAY, Self::OP_DBG, Self::F_DBG_GET_THREAD_DATA, 1),
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
            pack_nr_ver(SYS_RAY, Self::OP_DBG, Self::F_DBG_GET_MEM, 1),
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

    #[cfg(feature = "userspace")]
    pub fn dbg_detach(dbg_handle: SysHandle) -> Result<(), ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_RAY, Self::OP_DBG, Self::F_DBG_DETACH, 1),
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
    pub fn log(msg: &str) -> Result<(), ErrorCode> {
        let bytes = msg.as_bytes();
        if bytes.len() == 0 {
            return Err(ErrorCode::InvalidArgument);
        }

        let res = do_syscall(
            pack_nr_ver(SYS_RAY, Self::OP_LOG, 0, 0),
            msg.as_bytes().as_ptr() as usize as u64,
            bytes.len() as u64,
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
