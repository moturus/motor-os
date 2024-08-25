//! SysCpu syscall.

#[cfg(feature = "userspace")]
use crate::syscalls::*;
#[cfg(feature = "userspace")]
use crate::ErrorCode;

/// SysCpu syscall: various scheduling-related operations.
pub struct SysCpu;

impl SysCpu {
    pub const OP_EXIT: u8 = 1;
    pub const OP_WAIT: u8 = 2;
    pub const OP_WAKE: u8 = 3;
    pub const OP_KILL: u8 = 4;
    pub const OP_SPAWN: u8 = 5;
    pub const OP_USAGE: u8 = 6;
    pub const OP_AFFINE_CPU: u8 = 7;
    pub const OP_QUERY_PERCPU_STATS: u8 = 8;

    // Controls whether hanles to wait for are passed via registers or as an array in memory.
    pub const F_HANDLE_ARRAY: u32 = 1;
    pub const F_TIMEOUT: u32 = 2; // If present, args[0] contains Instant abs timeout.

    // If present, poll wakers and return, don't block. Can't be combined with F_TIMEOUT.
    pub const F_DONTBLOCK: u32 = 4;

    // If present, args[0] (if no timeout) or args[1] (if timeout) contains swap target.
    pub const F_SWAP_TARGET: u32 = 8;

    // If present, args[0] (if no timeout) or args[1] (if timeout) contains wake target.
    pub const F_WAKE_TARGET: u32 = 16;

    // If present, OP_KILL kills the peer of the share handle.
    pub const F_KILL_PEER: u32 = 1;

    // If present, OP_KILL's arg is the PID.
    pub const F_KILL_PID: u32 = 2;

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
    pub fn kill_remote(target: SysHandle) -> Result<(), ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_CPU, Self::OP_KILL, Self::F_KILL_PEER, 0),
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
    pub fn kill_pid(target: u64) -> Result<(), ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_CPU, Self::OP_KILL, Self::F_KILL_PID, 0),
            target,
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

    #[cfg(feature = "userspace")]
    pub fn get_percpu_stats_v1(page_addr: u64) -> Result<u32, ErrorCode> {
        let res = do_syscall(
            pack_nr_ver(SYS_CPU, Self::OP_QUERY_PERCPU_STATS, 0, 0),
            page_addr,
            0,
            0,
            0,
            0,
            0,
        );

        if res.is_ok() {
            Ok(res.data[0] as u32)
        } else {
            Err(res.error_code())
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
