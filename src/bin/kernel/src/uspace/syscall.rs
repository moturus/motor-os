use moto_sys::syscalls;
use moto_sys::{syscalls::SyscallResult, ErrorCode};

pub const RES_EXIT: u64 = 0xff_ff_ff_ff; // Kill the thread. Never returns to uspace.

#[derive(Debug, Default)]
pub struct SyscallArgs {
    pub syscall_nr: u8,
    pub operation: u8,
    pub flags: u32,
    pub version: u16,
    pub args: [u64; 6],
}

impl SyscallArgs {
    #[inline]
    pub fn new(
        nr_ver: u64,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
    ) -> Self {
        SyscallArgs {
            syscall_nr: (nr_ver >> 56) as u8,
            operation: ((nr_ver & 0x00ff0000_00000000) >> 48) as u8,
            flags: ((nr_ver & 0x0000ffff_ffff0000) >> 16) as u32,
            version: (nr_ver & 0xffff) as u16,
            args: [arg0, arg1, arg2, arg3, arg4, arg5],
        }
    }
}

pub struct ResultBuilder;

impl ResultBuilder {
    #[allow(dead_code)]
    #[inline(always)]
    pub fn ok() -> SyscallResult {
        Self::result(ErrorCode::Ok)
    }

    #[inline(always)]
    pub fn ok_1(val0: u64) -> SyscallResult {
        let mut data = [0_u64; 6];
        data[0] = val0;
        SyscallResult { result: 0, data }
    }

    #[inline(always)]
    pub fn ok_2(val0: u64, val1: u64) -> SyscallResult {
        let mut data = [0_u64; 6];
        data[0] = val0;
        data[1] = val1;
        SyscallResult { result: 0, data }
    }

    #[inline(always)]
    pub fn result(result: ErrorCode) -> SyscallResult {
        SyscallResult {
            result: result as u64,
            data: [0; 6],
        }
    }

    #[inline(always)]
    pub fn bad_handle(handle: moto_sys::SysHandle) -> SyscallResult {
        let mut data = [0_u64; 6];
        data[0] = handle.as_u64();
        SyscallResult {
            result: ErrorCode::BadHandle as u64,
            data,
        }
    }

    pub fn invalid_argument() -> SyscallResult {
        Self::result(ErrorCode::InvalidArgument)
    }

    pub fn not_implemented() -> SyscallResult {
        Self::result(ErrorCode::NotImplemented)
    }

    pub fn version_too_high() -> SyscallResult {
        Self::result(ErrorCode::VersionTooHigh)
    }

    pub fn version_too_low() -> SyscallResult {
        Self::result(ErrorCode::VersionTooLow)
    }
}

pub fn do_syscall(curr: &super::process::Thread, args: &mut SyscallArgs) -> SyscallResult {
    if !crate::mm::virt::is_user(curr.rip()) {
        log::warn!(
            "do_syscall: thread 0x{:x} has bad RIP: 0x{:x}; killed",
            curr.tid().as_u64(),
            curr.rip()
        );
        // We want to kill the thread instead of just doing sys_exit, because
        // sys_exit does not kill the whole process, and we want to kill the whole process.
        curr.kill(crate::uspace::process::UserError::InvalidSyscallReturnPointer)
    }

    curr.on_syscall_enter(args.syscall_nr, args.operation);

    let result = match args.syscall_nr {
        syscalls::SYS_CPU => super::sys_cpu::sys_cpu_impl(curr, args),
        syscalls::SYS_MEM => super::sys_mem::sys_mem_impl(curr, args),
        syscalls::SYS_OBJ => super::sys_obj::sys_ctl_impl(curr, args),
        syscalls::SYS_RAY => super::sys_ray::sys_ray_impl(curr, args),
        _ => ResultBuilder::not_implemented(),
    };

    curr.on_syscall_exit();
    result
}
