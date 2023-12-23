//! Functions to read and write control registers.
//! See Intel Vol. 3a Section 2.5, especially Figure 2-7.

use bitflags::*;

use crate::arch::{_xgetbv, _xsetbv};
use core::arch::asm;

bitflags! {
    pub struct Cr0: usize {
        const CR0_ENABLE_PAGING = 1 << 31;
        const CR0_CACHE_DISABLE = 1 << 30;
        const CR0_NOT_WRITE_THROUGH = 1 << 29;
        const CR0_ALIGNMENT_MASK = 1 << 18;
        const CR0_WRITE_PROTECT = 1 << 16;
        const CR0_NUMERIC_ERROR = 1 << 5;
        const CR0_EXTENSION_TYPE = 1 << 4;
        const CR0_TASK_SWITCHED = 1 << 3;
        const CR0_EMULATE_COPROCESSOR = 1 << 2;
        const CR0_MONITOR_COPROCESSOR = 1 << 1;
        const CR0_PROTECTED_MODE = 1 << 0;
    }
}

bitflags! {
    pub struct Cr4: usize {
        /// Enables use of Protection Keys (MPK).
        const CR4_ENABLE_PROTECTION_KEY = 1 << 22;
        /// Enable Supervisor Mode Access Prevention.
        const CR4_ENABLE_SMAP = 1 << 21;
        /// Enable Supervisor Mode Execution Protection.
        const CR4_ENABLE_SMEP = 1 << 20;
        /// Enable XSAVE and Processor Extended States.
        const CR4_ENABLE_OS_XSAVE = 1 << 18;
        /// Enables process-context identifiers (PCIDs).
        const CR4_ENABLE_PCID = 1 << 17;
        /// Enables the instructions RDFSBASE, RDGSBASE, WRFSBASE, and WRGSBASE.
        const CR4_ENABLE_FSGSBASE = 1 << 16;
        /// Enables Safer Mode Extensions (Trusted Execution Technology (TXT)).
        const CR4_ENABLE_SMX = 1 << 14;
        /// Enables Virtual Machine Extensions.
        const CR4_ENABLE_VMX = 1 << 13;
        /// Enables 5-Level Paging.
        const CR4_ENABLE_LA57 = 1 << 12;
        /// Enable User-Mode Instruction Prevention (the SGDT, SIDT, SLDT, SMSW and STR instructions
        /// cannot be executed if CPL > 0).
        const CR4_ENABLE_UMIP = 1 << 11;
        /// Enables unmasked SSE exceptions.
        const CR4_UNMASKED_SSE = 1 << 10;
        /// Enables Streaming SIMD Extensions (SSE) instructions and fast FPU
        /// save & restore FXSAVE and FXRSTOR instructions.
        const CR4_ENABLE_SSE = 1 << 9;
        /// Enable Performance-Monitoring Counters
        const CR4_ENABLE_PPMC = 1 << 8;
        /// Enable shared (PDE or PTE) address translation between address spaces.
        const CR4_ENABLE_GLOBAL_PAGES = 1 << 7;
        /// Enable machine check interrupts.
        const CR4_ENABLE_MACHINE_CHECK = 1 << 6;
        /// Enable: Physical Address Extension (allows to address physical
        /// memory larger than 4 GiB).
        const CR4_ENABLE_PAE = 1 << 5;
        /// Enable Page Size Extensions (allows for pages larger than the traditional 4 KiB size)
        /// Note: If Physical Address Extension (PAE) is used, the size of large pages is reduced
        /// from 4 MiB down to 2 MiB, and PSE is always enabled, regardless of the PSE bit in CR4.
        const CR4_ENABLE_PSE = 1 << 4;
        /// If set, enables debug register based breaks on I/O space access.
        const CR4_DEBUGGING_EXTENSIONS = 1 << 3;
        /// If set, disables ability to take time-stamps.
        const CR4_TIME_STAMP_DISABLE = 1 << 2;
        /// If set, enables support for the virtual interrupt flag (VIF) in protected mode.
        const CR4_VIRTUAL_INTERRUPTS = 1 << 1;
        /// If set, enables support for the virtual interrupt flag (VIF) in virtual-8086 mode.
        const CR4_ENABLE_VME = 1 << 0;
    }
}

bitflags! {
    pub struct Xcr0: u64 {
        const XCR0_PKRU_STATE = 1 << 9;
        const XCR0_HI16_ZMM_STATE = 1 << 7;
        const XCR0_ZMM_HI256_STATE = 1 << 6;
        const XCR0_OPMASK_STATE = 1 << 5;
        const XCR0_BNDCSR_STATE = 1 << 4;
        const XCR0_BNDREG_STATE = 1 << 3;
        const XCR0_AVX_STATE = 1 << 2;
        const XCR0_SSE_STATE = 1 << 1;
        const XCR0_FPU_MMX_STATE = 1 << 0;
    }
}

/// Read cr0
///
/// # Safety
/// Needs CPL 0.
pub unsafe fn cr0() -> Cr0 {
    let ret: usize;
    asm!("mov %cr0, {0}", out(reg) ret, options(att_syntax));
    Cr0::from_bits_truncate(ret)
}

/// Write cr0.
///
/// # Safety
/// Needs CPL 0.
pub unsafe fn cr0_write(val: Cr0) {
    asm!("mov {0}, %cr0", in(reg) val.bits, options(att_syntax));
}

/// Contains page-fault linear address.
///
/// # Safety
/// Needs CPL 0.
pub unsafe fn cr2() -> usize {
    let ret: usize;
    asm!("mov %cr2, {0}", out(reg) ret, options(att_syntax));
    ret
}

/// Write cr2, for instance to reset cr2
///
/// # Safety
/// Needs CPL 0.
pub unsafe fn cr2_write(val: u64) {
    asm!("mov {0}, %cr2", in(reg) val as usize, options(att_syntax));
}

/// Contains page-table root pointer.
///
/// # Safety
/// Needs CPL 0.
pub unsafe fn cr3() -> u64 {
    let ret: usize;
    asm!("mov %cr3, {0}", out(reg) ret, options(att_syntax));
    ret as u64
}

/// Switch page-table PML4 pointer.
///
/// # Safety
/// Needs CPL 0.
pub unsafe fn cr3_write(val: u64) {
    asm!("mov {0}, %cr3", in(reg) val as usize, options(att_syntax));
}

/// Contains various flags to control operations in protected mode.
///
/// # Safety
/// Needs CPL 0.
pub unsafe fn cr4() -> Cr4 {
    let ret: usize;
    asm!("mov %cr4, {0}", out(reg) ret, options(att_syntax));
    Cr4::from_bits_truncate(ret)
}

/// Write cr4.
///
/// # Example
///
/// ```no_run
/// use x86::controlregs::*;
/// unsafe {
///   let cr4 = cr4();
///   let cr4 = cr4 | Cr4::CR4_ENABLE_PSE;
///   cr4_write(cr4);
/// }
/// ```
///
/// # Safety
/// Needs CPL 0.
pub unsafe fn cr4_write(val: Cr4) {
    asm!("mov {0}, %cr4", in(reg) val.bits, options(att_syntax));
}

/// Read Extended Control Register XCR0.
/// Only supported if CR4_ENABLE_OS_XSAVE is set.
///
/// # Safety
/// Needs CPL 0.
pub unsafe fn xcr0() -> Xcr0 {
    Xcr0::from_bits_truncate(_xgetbv(0))
}

/// Write to Extended Control Register XCR0.
/// Only supported if CR4_ENABLE_OS_XSAVE is set.
///
/// # Safety
/// Needs CPL 0.
pub unsafe fn xcr0_write(val: Xcr0) {
    _xsetbv(0, val.bits);
}
