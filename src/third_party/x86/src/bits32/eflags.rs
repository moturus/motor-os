//! Processor state stored in the EFLAGS register.

use bitflags::*;

use crate::Ring;
use core::arch::asm;

bitflags! {
    /// The EFLAGS register.
    pub struct EFlags: u32 {
        /// ID Flag (ID)
        const FLAGS_ID = 1 << 21;
        /// Virtual Interrupt Pending (VIP)
        const FLAGS_VIP = 1 << 20;
        /// Virtual Interrupt Flag (VIF)
        const FLAGS_VIF = 1 << 19;
        /// Alignment Check (AC)
        const FLAGS_AC = 1 << 18;
        /// Virtual-8086 Mode (VM)
        const FLAGS_VM = 1 << 17;
        /// Resume Flag (RF)
        const FLAGS_RF = 1 << 16;
        /// Nested Task (NT)
        const FLAGS_NT = 1 << 14;
        /// I/O Privilege Level (IOPL) 0
        const FLAGS_IOPL0 = 0b00 << 12;
        /// I/O Privilege Level (IOPL) 1
        const FLAGS_IOPL1 = 0b01 << 12;
        /// I/O Privilege Level (IOPL) 2
        const FLAGS_IOPL2 = 0b10 << 12;
        /// I/O Privilege Level (IOPL) 3
        const FLAGS_IOPL3 = 0b11 << 12;
        /// Overflow Flag (OF)
        const FLAGS_OF = 1 << 11;
        /// Direction Flag (DF)
        const FLAGS_DF = 1 << 10;
        /// Interrupt Enable Flag (IF)
        const FLAGS_IF = 1 << 9;
        /// Trap Flag (TF)
        const FLAGS_TF = 1 << 8;
        /// Sign Flag (SF)
        const FLAGS_SF = 1 << 7;
        /// Zero Flag (ZF)
        const FLAGS_ZF = 1 << 6;
        /// Auxiliary Carry Flag (AF)
        const FLAGS_AF = 1 << 4;
        /// Parity Flag (PF)
        const FLAGS_PF = 1 << 2;
        /// Bit 1 is always 1.
        const FLAGS_A1 = 1 << 1;
        /// Carry Flag (CF)
        const FLAGS_CF = 1 << 0;
    }
}

impl EFlags {
    /// Creates a new Flags entry. Ensures bit 1 is set.
    pub const fn new() -> EFlags {
        EFlags::FLAGS_A1
    }

    /// Creates a new Flags with the given I/O privilege level.
    pub const fn from_priv(iopl: Ring) -> EFlags {
        EFlags {
            bits: (iopl as u32) << 12,
        }
    }
}

#[cfg(target_arch = "x86")]
#[inline(always)]
pub unsafe fn read() -> EFlags {
    let r: u32;
    asm!("pushfl; popl {0}", out(reg) r, options(att_syntax));
    EFlags::from_bits_truncate(r)
}

#[cfg(target_arch = "x86")]
#[inline(always)]
pub unsafe fn set(val: EFlags) {
    asm!("pushl {0}; popfl", in(reg) val.bits(), options(att_syntax));
}

/// Clears the AC flag bit in EFLAGS register.
///
/// This disables any alignment checking of user-mode data accesses.
/// If the SMAP bit is set in the CR4 register, this disallows
/// explicit supervisor-mode data accesses to user-mode pages.
///
/// # Safety
///
/// This instruction is only valid in Ring 0 and requires
/// that the CPU supports the instruction (check CPUID).
#[inline(always)]
pub unsafe fn clac() {
    asm!("clac");
}

/// Sets the AC flag bit in EFLAGS register.
///
/// This may enable alignment checking of user-mode data accesses.
/// This allows explicit supervisor-mode data accesses to user-mode
/// pages even if the SMAP bit is set in the CR4 register.
///
/// # Safety
///
/// This instruction is only valid in Ring 0 and requires
/// that the CPU supports the instruction (check CPUID).
#[inline(always)]
pub unsafe fn stac() {
    asm!("stac");
}
