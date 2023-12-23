//! Shared interrupt description and set-up code.
//! See the `bits*::irq` modules for arch-specific portions.

use bitflags::*;

use core::arch::asm;
use core::fmt;

/// x86 Exception description (see also Intel Vol. 3a Chapter 6).
#[derive(Debug)]
pub struct InterruptDescription {
    pub vector: u8,
    pub mnemonic: &'static str,
    pub description: &'static str,
    pub irqtype: &'static str,
    pub source: &'static str,
}

impl fmt::Display for InterruptDescription {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} ({}, vec={}) {}",
            self.mnemonic, self.irqtype, self.vector, self.description
        )
    }
}

pub const DIVIDE_ERROR_VECTOR: u8 = 0;
pub const DEBUG_VECTOR: u8 = 1;
pub const NONMASKABLE_INTERRUPT_VECTOR: u8 = 2;
pub const BREAKPOINT_VECTOR: u8 = 3;
pub const OVERFLOW_VECTOR: u8 = 4;
pub const BOUND_RANGE_EXCEEDED_VECTOR: u8 = 5;
pub const INVALID_OPCODE_VECTOR: u8 = 6;
pub const DEVICE_NOT_AVAILABLE_VECTOR: u8 = 7;
pub const DOUBLE_FAULT_VECTOR: u8 = 8;
pub const COPROCESSOR_SEGMENT_OVERRUN_VECTOR: u8 = 9;
pub const INVALID_TSS_VECTOR: u8 = 10;
pub const SEGMENT_NOT_PRESENT_VECTOR: u8 = 11;
pub const STACK_SEGEMENT_FAULT_VECTOR: u8 = 12;
pub const GENERAL_PROTECTION_FAULT_VECTOR: u8 = 13;
pub const PAGE_FAULT_VECTOR: u8 = 14;
pub const X87_FPU_VECTOR: u8 = 16;
pub const ALIGNMENT_CHECK_VECTOR: u8 = 17;
pub const MACHINE_CHECK_VECTOR: u8 = 18;
pub const SIMD_FLOATING_POINT_VECTOR: u8 = 19;
pub const VIRTUALIZATION_VECTOR: u8 = 20;

/// x86 External Interrupts (1-32).
pub static EXCEPTIONS: [InterruptDescription; 32] = [
    InterruptDescription {
        vector: DIVIDE_ERROR_VECTOR,
        mnemonic: "#DE",
        description: "Divide Error",
        irqtype: "Fault",
        source: "DIV and IDIV instructions.",
    },
    InterruptDescription {
        vector: DEBUG_VECTOR,
        mnemonic: "#DB",
        description: "Debug",
        irqtype: "Fault / Trap",
        source: "Debug condition",
    },
    InterruptDescription {
        vector: NONMASKABLE_INTERRUPT_VECTOR,
        mnemonic: "NMI",
        description: "Nonmaskable Interrupt",
        irqtype: "Interrupt",
        source: "Nonmaskable external interrupt.",
    },
    InterruptDescription {
        vector: BREAKPOINT_VECTOR,
        mnemonic: "#BP",
        description: "Breakpoint",
        irqtype: "Trap",
        source: "INT 3 instruction.",
    },
    InterruptDescription {
        vector: OVERFLOW_VECTOR,
        mnemonic: "#OF",
        description: "Overflow",
        irqtype: "Trap",
        source: "INTO instruction.",
    },
    InterruptDescription {
        vector: BOUND_RANGE_EXCEEDED_VECTOR,
        mnemonic: "#BR",
        description: "BOUND Range Exceeded",
        irqtype: "Fault",
        source: "BOUND instruction.",
    },
    InterruptDescription {
        vector: INVALID_OPCODE_VECTOR,
        mnemonic: "#UD",
        description: "Invalid Opcode (Undefined \
                      Opcode)",
        irqtype: "Fault",
        source: "UD2 instruction or reserved \
                 opcode.",
    },
    InterruptDescription {
        vector: DEVICE_NOT_AVAILABLE_VECTOR,
        mnemonic: "#NM",
        description: "Device Not Available (No \
                      Math Coprocessor)",
        irqtype: "Fault",
        source: "Floating-point or WAIT/FWAIT \
                 instruction.",
    },
    InterruptDescription {
        vector: DOUBLE_FAULT_VECTOR,
        mnemonic: "#DF",
        description: "Double Fault",
        irqtype: "Abort",
        source: "Any instruction that can \
                 generate an exception, an NMI, \
                 or an INTR.",
    },
    InterruptDescription {
        vector: COPROCESSOR_SEGMENT_OVERRUN_VECTOR,
        mnemonic: "",
        description: "Coprocessor Segment Overrun",
        irqtype: "Fault",
        source: "Floating-point instruction.",
    },
    InterruptDescription {
        vector: INVALID_TSS_VECTOR,
        mnemonic: "#TS",
        description: "Invalid TSS",
        irqtype: "Fault",
        source: "Task switch or TSS access.",
    },
    InterruptDescription {
        vector: SEGMENT_NOT_PRESENT_VECTOR,
        mnemonic: "#NP",
        description: "Segment Not Present",
        irqtype: "Fault",
        source: "Loading segment registers or \
                 accessing system segments.",
    },
    InterruptDescription {
        vector: STACK_SEGEMENT_FAULT_VECTOR,
        mnemonic: "#SS",
        description: "Stack-Segment Fault",
        irqtype: "Fault",
        source: "Stack operations and SS register \
                 loads.",
    },
    InterruptDescription {
        vector: GENERAL_PROTECTION_FAULT_VECTOR,
        mnemonic: "#GP",
        description: "General Protection",
        irqtype: "Fault",
        source: "Any memory reference and other \
                 protection checks.",
    },
    InterruptDescription {
        vector: PAGE_FAULT_VECTOR,
        mnemonic: "#PF",
        description: "Page Fault",
        irqtype: "Fault",
        source: "Any memory reference.",
    },
    InterruptDescription {
        vector: 15,
        mnemonic: "",
        description: "RESERVED",
        irqtype: "",
        source: "None.",
    },
    InterruptDescription {
        vector: X87_FPU_VECTOR,
        mnemonic: "#MF",
        description: "x87 FPU Floating-Point",
        irqtype: "Fault",
        source: "x87 FPU instructions.",
    },
    InterruptDescription {
        vector: ALIGNMENT_CHECK_VECTOR,
        mnemonic: "#AC",
        description: "Alignment Check",
        irqtype: "Fault",
        source: "Unaligned memory access.",
    },
    InterruptDescription {
        vector: MACHINE_CHECK_VECTOR,
        mnemonic: "#MC",
        description: "Machine Check",
        irqtype: "Abort",
        source: "Internal machine error.",
    },
    InterruptDescription {
        vector: SIMD_FLOATING_POINT_VECTOR,
        mnemonic: "#XM",
        description: "SIMD Floating-Point",
        irqtype: "Fault",
        source: "SSE SIMD instructions.",
    },
    InterruptDescription {
        vector: VIRTUALIZATION_VECTOR,
        mnemonic: "#VE",
        description: "Virtualization",
        irqtype: "Fault",
        source: "EPT violation.",
    },
    InterruptDescription {
        vector: 21,
        mnemonic: "",
        description: "RESERVED",
        irqtype: "",
        source: ".",
    },
    InterruptDescription {
        vector: 22,
        mnemonic: "",
        description: "RESERVED",
        irqtype: "",
        source: ".",
    },
    InterruptDescription {
        vector: 23,
        mnemonic: "",
        description: "RESERVED",
        irqtype: "",
        source: ".",
    },
    InterruptDescription {
        vector: 24,
        mnemonic: "",
        description: "RESERVED",
        irqtype: "",
        source: ".",
    },
    InterruptDescription {
        vector: 25,
        mnemonic: "",
        description: "RESERVED",
        irqtype: "",
        source: ".",
    },
    InterruptDescription {
        vector: 26,
        mnemonic: "",
        description: "RESERVED",
        irqtype: "",
        source: ".",
    },
    InterruptDescription {
        vector: 27,
        mnemonic: "",
        description: "RESERVED",
        irqtype: "",
        source: "",
    },
    InterruptDescription {
        vector: 28,
        mnemonic: "",
        description: "",
        irqtype: "",
        source: "",
    },
    InterruptDescription {
        vector: 29,
        mnemonic: "",
        description: "RESERVED",
        irqtype: "",
        source: ".",
    },
    InterruptDescription {
        vector: 30,
        mnemonic: "",
        description: "RESERVED",
        irqtype: "",
        source: "",
    },
    InterruptDescription {
        vector: 31,
        mnemonic: "",
        description: "RESERVED",
        irqtype: "",
        source: "",
    },
];

bitflags! {
    // Taken from Intel Manual Section 4.7 Page-Fault Exceptions.
    pub struct PageFaultError: u32 {
        /// 0: The fault was caused by a non-present page.
        /// 1: The fault was caused by a page-level protection violation
        const P = bit!(0);

        /// 0: The access causing the fault was a read.
        /// 1: The access causing the fault was a write.
        const WR = bit!(1);

        /// 0: The access causing the fault originated when the processor
        /// was executing in supervisor mode.
        /// 1: The access causing the fault originated when the processor
        /// was executing in user mode.
        const US = bit!(2);

        /// 0: The fault was not caused by reserved bit violation.
        /// 1: The fault was caused by reserved bits set to 1 in a page directory.
        const RSVD = bit!(3);

        /// 0: The fault was not caused by an instruction fetch.
        /// 1: The fault was caused by an instruction fetch.
        const ID = bit!(4);

        /// 0: The fault was not by protection keys.
        /// 1: There was a protection key violation.
        const PK = bit!(5);
    }
}

impl fmt::Display for PageFaultError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let p = match self.contains(PageFaultError::P) {
            false => "The fault was caused by a non-present page.",
            true => "The fault was caused by a page-level protection violation.",
        };
        let wr = match self.contains(PageFaultError::WR) {
            false => "The access causing the fault was a read.",
            true => "The access causing the fault was a write.",
        };
        let us = match self.contains(PageFaultError::US) {
            false => {
                "The access causing the fault originated when the processor was executing in \
                 supervisor mode."
            }
            true => {
                "The access causing the fault originated when the processor was executing in user \
                 mode."
            }
        };
        let rsvd = match self.contains(PageFaultError::RSVD) {
            false => "The fault was not caused by reserved bit violation.",
            true => "The fault was caused by reserved bits set to 1 in a page directory.",
        };
        let id = match self.contains(PageFaultError::ID) {
            false => "The fault was not caused by an instruction fetch.",
            true => "The fault was caused by an instruction fetch.",
        };

        write!(f, "{}\n{}\n{}\n{}\n{}", p, wr, us, rsvd, id)
    }
}

/// Enable Interrupts.
///
/// # Safety
/// Only allowed if we have IO privileges for the current operating level in RFlags.
pub unsafe fn enable() {
    asm!("sti");
}

/// Disable Interrupts.
///
/// # Safety
/// Only allowed if we have IO privileges for the current operating level in RFlags.
pub unsafe fn disable() {
    asm!("cli");
}

/// Generate a software interrupt.
/// This is a macro argument needs to be an immediate.
#[macro_export]
macro_rules! int {
    ($x:expr) => {{
        core::arch::asm!("int ${vec}", vec = const ($x));
    }};
}

#[cfg(all(test, feature = "utest"))]
mod test {
    use super::*;
    #[test]
    fn bit_macro() {
        assert!(PageFaultError::PK.bits() == 0b100000);
        assert!(PageFaultError::ID.bits() == 0b10000);
        assert!(PageFaultError::RSVD.bits() == 0b1000);
        assert!(PageFaultError::US.bits() == 0b100);
        assert!(PageFaultError::WR.bits() == 0b10);
        assert!(PageFaultError::P.bits() == 0b1);
    }
}
