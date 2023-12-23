//! Representations of various x86 specific structures and descriptor tables.

use crate::VirtAddr;

pub mod gdt;

pub mod idt;

pub mod paging;
pub mod port;
pub mod tss;

/// A struct describing a pointer to a descriptor table (GDT / IDT).
/// This is in a format suitable for giving to 'lgdt' or 'lidt'.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed(2))]
pub struct DescriptorTablePointer {
    /// Size of the DT.
    pub limit: u16,
    /// Pointer to the memory region containing the DT.
    pub base: VirtAddr,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    pub fn check_descriptor_pointer_size() {
        // Per the SDM, a descriptor pointer has to be 2+8=10 bytes
        assert_eq!(size_of::<DescriptorTablePointer>(), 10);
        // Make sure that we can reference a pointer's limit
        let p = DescriptorTablePointer {
            limit: 5,
            base: VirtAddr::zero(),
        };
        let _: &u16 = &p.limit;
    }
}
