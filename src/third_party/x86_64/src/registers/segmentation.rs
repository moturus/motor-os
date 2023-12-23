//! Abstractions for segment registers.

use super::model_specific::Msr;
use crate::{PrivilegeLevel, VirtAddr};
use bit_field::BitField;
use core::fmt;
// imports for intra doc links
#[cfg(doc)]
use crate::registers::control::Cr4Flags;

/// An x86 segment
///
/// Segment registers on x86 are 16-bit [`SegmentSelector`]s, which index into
/// the [`GlobalDescriptorTable`](crate::structures::gdt::GlobalDescriptorTable). The
/// corresponding GDT entry is used to
/// configure the segment itself. Note that most segmentation functionality is
/// disabled in 64-bit mode. See the individual segments for more information.
pub trait Segment {
    /// Returns the current value of the segment register.
    fn get_reg() -> SegmentSelector;
    /// Reload the segment register. Depending on the segment, this may also
    /// reconfigure the corresponding segment.
    ///
    /// ## Safety
    ///
    /// This function is unsafe because the caller must ensure that `sel`
    /// is a valid segment descriptor, and that reconfiguring the segment will
    /// not cause undefined behavior.
    unsafe fn set_reg(sel: SegmentSelector);
}

/// An x86 segment which is actually used in 64-bit mode
///
/// While most segments are unused in 64-bit mode, the FS and GS segments are
/// still partially used. Only the 64-bit segment base address is used, and this
/// address can be set via the GDT, or by using the `FSGSBASE` instructions.
pub trait Segment64: Segment {
    /// MSR containing the segment base. This MSR can be used to set the base
    /// when [`CR4.FSGSBASE`][Cr4Flags::FSGSBASE] is **not** set.
    const BASE: Msr;
    /// Reads the segment base address
    ///
    /// ## Exceptions
    ///
    /// If [`CR4.FSGSBASE`][Cr4Flags::FSGSBASE] is not set, this instruction will throw a `#UD`.
    fn read_base() -> VirtAddr;
    /// Writes the segment base address
    ///
    /// ## Exceptions
    ///
    /// If [`CR4.FSGSBASE`][Cr4Flags::FSGSBASE] is not set, this instruction will throw a `#UD`.
    ///
    /// ## Safety
    ///
    /// The caller must ensure that this write operation has no unsafe side
    /// effects, as the segment base address might be in use.
    unsafe fn write_base(base: VirtAddr);
}

/// Specifies which element to load into a segment from
/// descriptor tables (i.e., is a index to LDT or GDT table
/// with some additional flags).
///
/// See Intel 3a, Section 3.4.2 "Segment Selectors"
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SegmentSelector(pub u16);

impl SegmentSelector {
    /// Creates a new SegmentSelector
    ///
    /// # Arguments
    ///  * `index`: index in GDT or LDT array (not the offset)
    ///  * `rpl`: the requested privilege level
    #[inline]
    pub const fn new(index: u16, rpl: PrivilegeLevel) -> SegmentSelector {
        SegmentSelector(index << 3 | (rpl as u16))
    }

    /// Returns the GDT index.
    #[inline]
    pub fn index(self) -> u16 {
        self.0 >> 3
    }

    /// Returns the requested privilege level.
    #[inline]
    pub fn rpl(self) -> PrivilegeLevel {
        PrivilegeLevel::from_u16(self.0.get_bits(0..2))
    }

    /// Set the privilege level for this Segment selector.
    #[inline]
    pub fn set_rpl(&mut self, rpl: PrivilegeLevel) {
        self.0.set_bits(0..2, rpl as u16);
    }
}

impl fmt::Debug for SegmentSelector {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut s = f.debug_struct("SegmentSelector");
        s.field("index", &self.index());
        s.field("rpl", &self.rpl());
        s.finish()
    }
}

/// Code Segment
///
/// The segment base and limit are unused in 64-bit mode. Only the L (long), D
/// (default operation size), and DPL (descriptor privilege-level) fields of the
/// descriptor are recognized. So changing the segment register can be used to
/// change privilege level or enable/disable long mode.
#[derive(Debug)]
pub struct CS;

/// Stack Segment
///
/// Entirely unused in 64-bit mode; setting the segment register does nothing.
/// However, in ring 3, the SS register still has to point to a valid
/// [`Descriptor`](crate::structures::gdt::Descriptor) (it cannot be zero). This
/// means a user-mode read/write segment descriptor must be present in the GDT.
///
/// This register is also set by the `syscall`/`sysret` and
/// `sysenter`/`sysexit` instructions (even on 64-bit transitions). This is to
/// maintain symmetry with 32-bit transitions where setting SS actually will
/// actually have an effect.
#[derive(Debug)]
pub struct SS;

/// Data Segment
///
/// Entirely unused in 64-bit mode; setting the segment register does nothing.
#[derive(Debug)]
pub struct DS;

/// ES Segment
///
/// Entirely unused in 64-bit mode; setting the segment register does nothing.
#[derive(Debug)]
pub struct ES;

/// FS Segment
///
/// Only base is used in 64-bit mode, see [`Segment64`]. This is often used in
/// user-mode for Thread-Local Storage (TLS).
#[derive(Debug)]
pub struct FS;

/// GS Segment
///
/// Only base is used in 64-bit mode, see [`Segment64`]. In kernel-mode, the GS
/// base often points to a per-cpu kernel data structure.
#[derive(Debug)]
pub struct GS;
