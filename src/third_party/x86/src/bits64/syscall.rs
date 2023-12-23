//! Invokes an OS system-call handler at privilege level 0.
//!
//! It does so by loading RIP from the IA32_LSTAR MSR (after saving the address of the instruction
//! following SYSCALL into RCX).
//!
//! The code follows "A.2 AMD64 Linux Kernel Conventions" of System V Application
//! Binary Interface AMD64 Architecture Processor Supplement:
//!
//! * The kernel interface uses %rdi, %rsi, %rdx, %r10, %r8 and %r9.
//! * A system-call is done via the syscall instruction. The kernel destroys registers %rcx and %r11.
//! * The number of the syscall has to be passed in register %rax.
//! * System-calls are limited to six arguments, no argument is passed directly on the stack.
//! * Returning from the syscall, register %rax contains the result of the system-call.
//! * Only values of class INTEGER or class MEMORY are passed to the kernel.
//!
//! This code is inspired by the syscall.rs (https://github.com/kmcallister/syscall.rs/) project.

#[cfg(target_arch = "x86_64")]
use core::arch::asm;

#[macro_export]
macro_rules! syscall {
    ($arg0:expr) => {
        x86::bits64::syscall::syscall0($arg0 as u64)
    };

    ($arg0:expr, $arg1:expr) => {
        x86::bits64::syscall::syscall1($arg0 as u64, $arg1 as u64)
    };

    ($arg0:expr, $arg1:expr, $arg2:expr) => {
        x86::bits64::syscall::syscall2($arg0 as u64, $arg1 as u64, $arg2 as u64)
    };

    ($arg0:expr, $arg1:expr, $arg2:expr, $arg3:expr) => {
        x86::bits64::syscall::syscall3($arg0 as u64, $arg1 as u64, $arg2 as u64, $arg3 as u64)
    };

    ($arg0:expr, $arg1:expr, $arg2:expr, $arg3:expr, $arg4:expr) => {
        x86::bits64::syscall::syscall4(
            $arg0 as u64,
            $arg1 as u64,
            $arg2 as u64,
            $arg3 as u64,
            $arg4 as u64,
        )
    };

    ($arg0:expr, $arg1:expr, $arg2:expr, $arg3:expr, $arg4:expr, $arg5:expr) => {
        x86::bits64::syscall::syscall5(
            $arg0 as u64,
            $arg1 as u64,
            $arg2 as u64,
            $arg3 as u64,
            $arg4 as u64,
            $arg5 as u64,
        )
    };

    ($arg0:expr, $arg1:expr, $arg2:expr, $arg3:expr, $arg4:expr, $arg5:expr, $arg6:expr) => {
        x86::bits64::syscall::syscall6(
            $arg0 as u64,
            $arg1 as u64,
            $arg2 as u64,
            $arg3 as u64,
            $arg4 as u64,
            $arg5 as u64,
            $arg6 as u64,
        )
    };

    (
        $arg0:expr,
        $arg1:expr,
        $arg2:expr,
        $arg3:expr,
        $arg4:expr,
        $arg5:expr,
        $arg6:expr,
        $arg7:expr
    ) => {
        x86::bits64::syscall::syscall7(
            $arg0 as u64,
            $arg1 as u64,
            $arg2 as u64,
            $arg3 as u64,
            $arg4 as u64,
            $arg5 as u64,
            $arg6 as u64,
            $arg7 as u64,
        )
    };
}

/// Invoke a syscall.
///
/// # Safety
/// Throws `#UD` if IA32_EFER.SCE = 0.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[allow(unused_mut)]
pub unsafe fn syscall0(arg0: u64) -> u64 {
    let mut ret: u64;
    asm!("syscall", lateout("rax") ret, in("rax") arg0, options(att_syntax));
    ret
}

/// Invoke a syscall.
///
/// # Safety
/// Throws `#UD` if IA32_EFER.SCE = 0.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[allow(unused_mut)]
pub unsafe fn syscall1(arg0: u64, arg1: u64) -> u64 {
    let mut ret: u64;
    asm!(
        "syscall",
        lateout("rax") ret, in("rax") arg0, in("rdi") arg1,
        out("rcx") _, out("r11") _, options(att_syntax),
    );
    ret
}

/// Invoke a syscall.
///
/// # Safety
/// Throws `#UD` if IA32_EFER.SCE = 0.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[allow(unused_mut)]
pub unsafe fn syscall2(arg0: u64, arg1: u64, arg2: u64) -> u64 {
    let mut ret: u64;
    asm!(
        "syscall",
        lateout("rax") ret,
        in("rax") arg0, in("rdi") arg1, in("rsi") arg2,
        out("rcx") _, out("r11") _, options(att_syntax),
    );
    ret
}

/// Invoke a syscall.
///
/// # Safety
/// Throws `#UD` if IA32_EFER.SCE = 0.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[allow(unused_mut)]
pub unsafe fn syscall3(arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    let mut ret: u64;
    asm!(
        "syscall",
        lateout("rax") ret,
        in("rax") arg0, in("rdi") arg1, in("rsi") arg2, in("rdx") arg3,
        out("rcx") _, out("r11") _, options(att_syntax),
    );
    ret
}

/// Invoke a syscall.
///
/// # Safety
/// Throws `#UD` if IA32_EFER.SCE = 0.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[allow(unused_mut)]
pub unsafe fn syscall4(arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> u64 {
    let mut ret: u64;
    asm!(
        "syscall",
        lateout("rax") ret,
        in("rax") arg0, in("rdi") arg1, in("rsi") arg2, in("rdx") arg3, in("r10") arg4,
        out("rcx") _, out("r11") _, options(att_syntax),
    );
    ret
}

/// Invoke a syscall.
///
/// # Safety
/// Throws `#UD` if IA32_EFER.SCE = 0.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[allow(unused_mut)]
pub unsafe fn syscall5(arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> u64 {
    let mut ret: u64;
    asm!(
        "syscall",
        lateout("rax") ret,
        in("rax") arg0, in("rdi") arg1, in("rsi") arg2, in("rdx") arg3, in("r10") arg4, in("r8") arg5,
        out("rcx") _, out("r11") _, options(att_syntax),
    );
    ret
}

/// Invoke a syscall.
///
/// # Safety
/// Throws `#UD` if IA32_EFER.SCE = 0.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[allow(unused_mut)]
pub unsafe fn syscall6(
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
) -> u64 {
    let mut ret: u64;
    asm!(
        "syscall",
        lateout("rax") ret,
        in("rax") arg0, in("rdi") arg1, in("rsi") arg2, in("rdx") arg3,
        in("r10") arg4, in("r8") arg5, in("r9") arg6,
        out("rcx") _, out("r11") _, options(att_syntax),
    );
    ret
}
