//! Helpers to program the task state segment.
//! See Intel 3a, Chapter 7, Section 7

use crate::Ring;

/// Although hardware task-switching is not supported in 64-bit mode,
/// a 64-bit task state segment (TSS) must exist.
///
/// The TSS holds information important to 64-bit mode and that is not
/// directly related to the task-switch mechanism. This information includes:
///
/// # RSPn
/// The full 64-bit canonical forms of the stack pointers (RSP) for privilege levels 0-2.
/// RSPx is loaded in whenever an interrupt causes the CPU to change RPL to x.
/// Note on a syscall entry this field is not used to load a stack, setting the stack there
/// is the handler's responsibility (however when using the int instruction in user-space,
/// we load the stack from RSPn).
///
/// # ISTn
/// The full 64-bit canonical forms of the interrupt stack table (IST) pointers.
/// You can set an interrupt vector to use an IST entry in the Interrupt Descriptor
/// Table by giving it a number from 0 - 7. If 0 is selected, then the IST mechanism
/// is not used. If any other number is selected then when that interrupt vector is
/// called the CPU will load RSP from the corresponding IST entry. This is useful for
/// handling things like double faults, since you don't have to worry about switching
/// stacks; the CPU will do it for you.
///
/// # I/O map base address
/// The 16-bit offset to the I/O permission bit map from the 64-bit TSS base.
///
/// The operating system must create at least one 64-bit TSS after activating IA-32e mode.
/// It must execute the LTR instruction (in 64-bit mode) to load the TR register with a
/// pointer to the 64-bit TSS responsible for both 64-bitmode programs and
/// compatibility-mode programs ([load_tr](crate::task::load_tr)).
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct TaskStateSegment {
    pub reserved: u32,
    /// The full 64-bit canonical forms of the stack pointers (RSP) for privilege levels 0-2.
    pub rsp: [u64; 3],
    pub reserved2: u64,
    /// The full 64-bit canonical forms of the interrupt stack table (IST) pointers.
    pub ist: [u64; 7],
    pub reserved3: u64,
    pub reserved4: u16,
    /// The 16-bit offset to the I/O permission bit map from the 64-bit TSS base.
    pub iomap_base: u16,
}

impl TaskStateSegment {
    /// Creates a new empty TSS.
    pub const fn new() -> TaskStateSegment {
        TaskStateSegment {
            reserved: 0,
            rsp: [0; 3],
            reserved2: 0,
            ist: [0; 7],
            reserved3: 0,
            reserved4: 0,
            iomap_base: 0,
        }
    }

    /// Sets the stack pointer (`stack_ptr`) to be used for when
    /// an interrupt causes the CPU to change RPL to `pl`.
    pub fn set_rsp(&mut self, pl: Ring, stack_ptr: u64) {
        match pl {
            Ring::Ring0 => self.rsp[0] = stack_ptr,
            Ring::Ring1 => self.rsp[1] = stack_ptr,
            Ring::Ring2 => self.rsp[2] = stack_ptr,
            Ring::Ring3 => unreachable!("Can't set stack for PL3"),
        }
    }

    /// Sets the stack pointer (`stack_ptr`) to be used when
    /// an interrupt with a corresponding IST entry in the Interrupt
    /// Descriptor table pointing to the given `index` is raised.
    pub fn set_ist(&mut self, index: usize, stack_ptr: u64) {
        match index {
            0 => self.ist[0] = stack_ptr,
            1 => self.ist[1] = stack_ptr,
            2 => self.ist[2] = stack_ptr,
            3 => self.ist[3] = stack_ptr,
            4 => self.ist[4] = stack_ptr,
            5 => self.ist[5] = stack_ptr,
            6 => self.ist[6] = stack_ptr,
            _ => unreachable!("Can't set IST for this index (out of bounds)."),
        }
    }
}
