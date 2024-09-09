/*
 * Four syscalls:
 * - SYS_OBJ: object management/configuration
 * - SYS_MEM: memory management (memory allocation and sharing)
 * - SYS_CPU: CPU management (scheduling)
 * - SYS_RAY: various statistics/tracing/debugging routines
 */

// Syscall numbers.
pub const SYS_CPU: u8 = 1;
pub const SYS_MEM: u8 = 2;
pub const SYS_OBJ: u8 = 3;
pub const SYS_RAY: u8 = 4;

use crate::ErrorCode;

// SyscallResult is passed on registers; x64, arm64, and risc-v all have
// enough argument/scratch registers to pass data back this way.
#[derive(Debug)]
#[repr(C)]
pub struct SyscallResult {
    pub result: u64,    // rax
    pub data: [u64; 6], // rdi, rsi, rdx, r10, r8, r9
}

impl SyscallResult {
    // Flags.
    pub const F_TIMED_OUT: u64 = 0x01_00_00;
    pub const F_HANDLE_ARRAY: u64 = 0x_02_00_00;

    pub fn is_ok(&self) -> bool {
        ((self.result & 0xFF_FF) as u16) == moto_rt::E_OK
    }

    pub fn timed_out(&self) -> bool {
        (self.result & Self::F_TIMED_OUT) != 0
    }

    pub fn error_code(&self) -> ErrorCode {
        (self.result & 0xFF_FF) as ErrorCode
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

/// Same as SysHandle, but calls SysObj::put on drop.
#[cfg(feature = "userspace")]
#[repr(C)]
pub struct RaiiHandle(u64);

#[cfg(feature = "userspace")]
impl Drop for RaiiHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            crate::sys_obj::SysObj::put(self.syshandle()).unwrap()
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

#[cfg(feature = "userspace")]
pub(crate) fn pack_nr_ver(syscall_number: u8, operation: u8, flags: u32, version: u16) -> u64 {
    ((syscall_number as u64) << 56)
        | ((operation as u64) << 48)
        | ((flags as u64) << 16)
        | (version as u64)
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
