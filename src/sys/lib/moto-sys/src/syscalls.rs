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

#[cfg(any(feature = "userspace", test))]
const MAX_ABSENT_PAGE_RETRIES: u32 = 4096;

#[cfg(any(feature = "userspace", test))]
fn retry_absent_pages(
    mut syscall: impl FnMut() -> SyscallResult,
    mut fault_page: impl FnMut(u64),
) -> SyscallResult {
    let mut retries = 0;
    loop {
        let result = syscall();
        if result.result != moto_rt::E_PAGE_ABSENT as u64 || retries == MAX_ABSENT_PAGE_RETRIES {
            return result;
        }
        fault_page(result.data[0]);
        retries += 1;
    }
}

/// Fault in absent caller buffers and retry. The kernel issues this refusal
/// only where retrying is safe. Return the last refusal if the bound is reached.
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
    retry_absent_pages(
        || raw_syscall(nr_ver, arg0, arg1, arg2, arg3, arg4, arg5),
        |page| unsafe {
            // A Rust pointer read requires a non-null pointer; page zero is a
            // valid file mapping. Assembly also prevents eliding the access.
            core::arch::asm!("test byte ptr [{page}], 0", page = in(reg) page, options(nostack, readonly));
        },
    )
}

// standard arguments: rdi, rsi, rdx, rcx, r8, r9
// our syscall arguments: rdi, rsi, rdx, r10, r8, r9
#[cfg(feature = "userspace")]
#[inline(never)]
fn raw_syscall(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_page_zero_is_touched_before_retry() {
        let mut calls = 0;
        let touched = core::cell::Cell::new(false);
        let result = retry_absent_pages(
            || {
                calls += 1;
                assert_eq!(touched.get(), calls > 1);
                SyscallResult {
                    result: if calls == 1 {
                        moto_rt::E_PAGE_ABSENT as u64
                    } else {
                        0
                    },
                    data: [0; 6],
                }
            },
            |page| {
                assert_eq!(page, 0);
                touched.set(true);
            },
        );
        assert!(result.is_ok());
        assert_eq!(calls, 2);
    }

    #[test]
    fn absent_page_retries_are_bounded() {
        let mut calls = 0;
        let mut touches = 0;
        let result = retry_absent_pages(
            || {
                calls += 1;
                SyscallResult {
                    result: moto_rt::E_PAGE_ABSENT as u64,
                    data: [4096; 6],
                }
            },
            |page| {
                assert_eq!(page, 4096);
                touches += 1;
            },
        );
        assert_eq!(result.error_code(), moto_rt::E_PAGE_ABSENT);
        assert_eq!(calls, MAX_ABSENT_PAGE_RETRIES + 1);
        assert_eq!(touches, MAX_ABSENT_PAGE_RETRIES);

        let ordinary = retry_absent_pages(
            || SyscallResult {
                result: moto_rt::E_INVALID_ARGUMENT as u64,
                data: [4096; 6],
            },
            |_| panic!("ordinary errors must not fault or retry"),
        );
        assert_eq!(ordinary.error_code(), moto_rt::E_INVALID_ARGUMENT);
    }
}
