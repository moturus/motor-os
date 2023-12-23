//! Provides functions to read and write segment registers.

pub use crate::registers::segmentation::{Segment, Segment64, CS, DS, ES, FS, GS, SS};
use crate::{
    registers::model_specific::{FsBase, GsBase, Msr},
    structures::gdt::SegmentSelector,
    VirtAddr,
};
use core::arch::asm;

macro_rules! get_reg_impl {
    ($name:literal, $asm_get:ident) => {
        fn get_reg() -> SegmentSelector {
            let segment: u16;
            unsafe {
                asm!(concat!("mov {0:x}, ", $name), out(reg) segment, options(nomem, nostack, preserves_flags));
            }
            SegmentSelector(segment)
        }
    };
}

macro_rules! segment_impl {
    ($type:ty, $name:literal, $asm_get:ident, $asm_load:ident) => {
        impl Segment for $type {
            get_reg_impl!($name, $asm_get);

            unsafe fn set_reg(sel: SegmentSelector) {
                unsafe {
                    asm!(concat!("mov ", $name, ", {0:x}"), in(reg) sel.0, options(nostack, preserves_flags));
                }
            }
        }
    };
}

macro_rules! segment64_impl {
    ($type:ty, $name:literal, $base:ty, $asm_rd:ident, $asm_wr:ident) => {
        impl Segment64 for $type {
            const BASE: Msr = <$base>::MSR;
            fn read_base() -> VirtAddr {
                unsafe {
                    let val: u64;
                    asm!(concat!("rd", $name, "base {}"), out(reg) val, options(nomem, nostack, preserves_flags));
                    VirtAddr::new_unsafe(val)
                }
            }

            unsafe fn write_base(base: VirtAddr) {
                unsafe{
                    asm!(concat!("wr", $name, "base {}"), in(reg) base.as_u64(), options(nostack, preserves_flags));
                }
            }
        }
    };
}

impl Segment for CS {
    get_reg_impl!("cs", x86_64_asm_get_cs);

    /// Note this is special since we cannot directly move to [`CS`]; x86 requires the instruction
    /// pointer and [`CS`] to be set at the same time. To do this, we push the new segment selector
    /// and return value onto the stack and use a "far return" (`retfq`) to reload [`CS`] and
    /// continue at the end of our function.
    ///
    /// Note we cannot use a "far call" (`lcall`) or "far jmp" (`ljmp`) to do this because then we
    /// would only be able to jump to 32-bit instruction pointers. Only Intel implements support
    /// for 64-bit far calls/jumps in long-mode, AMD does not.
    unsafe fn set_reg(sel: SegmentSelector) {
        unsafe {
            asm!(
                "push {sel}",
                "lea {tmp}, [1f + rip]",
                "push {tmp}",
                "retfq",
                "1:",
                sel = in(reg) u64::from(sel.0),
                tmp = lateout(reg) _,
                options(preserves_flags),
            );
        }
    }
}

segment_impl!(SS, "ss", x86_64_asm_get_ss, x86_64_asm_load_ss);
segment_impl!(DS, "ds", x86_64_asm_get_ds, x86_64_asm_load_ds);
segment_impl!(ES, "es", x86_64_asm_get_es, x86_64_asm_load_es);
segment_impl!(FS, "fs", x86_64_asm_get_fs, x86_64_asm_load_fs);
segment64_impl!(FS, "fs", FsBase, x86_64_asm_rdfsbase, x86_64_asm_wrfsbase);
segment_impl!(GS, "gs", x86_64_asm_get_gs, x86_64_asm_load_gs);
segment64_impl!(GS, "gs", GsBase, x86_64_asm_rdgsbase, x86_64_asm_wrgsbase);

impl GS {
    /// Swap `KernelGsBase` MSR and `GsBase` MSR.
    ///
    /// ## Safety
    ///
    /// This function is unsafe because the caller must ensure that the
    /// swap operation cannot lead to undefined behavior.
    pub unsafe fn swap() {
        unsafe {
            asm!("swapgs", options(nostack, preserves_flags));
        }
    }
}

/// Alias for [`CS::set_reg()`]
#[deprecated(since = "0.14.4", note = "use `CS::set_reg()` instead")]
#[allow(clippy::missing_safety_doc)]
#[inline]
pub unsafe fn set_cs(sel: SegmentSelector) {
    unsafe { CS::set_reg(sel) }
}
/// Alias for [`SS::set_reg()`]
#[deprecated(since = "0.14.4", note = "use `SS::set_reg()` instead")]
#[allow(clippy::missing_safety_doc)]
#[inline]
pub unsafe fn load_ss(sel: SegmentSelector) {
    unsafe { SS::set_reg(sel) }
}
/// Alias for [`DS::set_reg()`]
#[deprecated(since = "0.14.4", note = "use `DS::set_reg()` instead")]
#[allow(clippy::missing_safety_doc)]
#[inline]
pub unsafe fn load_ds(sel: SegmentSelector) {
    unsafe { DS::set_reg(sel) }
}
/// Alias for [`ES::set_reg()`]
#[deprecated(since = "0.14.4", note = "use `ES::set_reg()` instead")]
#[allow(clippy::missing_safety_doc)]
#[inline]
pub unsafe fn load_es(sel: SegmentSelector) {
    unsafe { ES::set_reg(sel) }
}
/// Alias for [`FS::set_reg()`]
#[deprecated(since = "0.14.4", note = "use `FS::set_reg()` instead")]
#[allow(clippy::missing_safety_doc)]
#[inline]
pub unsafe fn load_fs(sel: SegmentSelector) {
    unsafe { FS::set_reg(sel) }
}
/// Alias for [`GS::set_reg()`]
#[deprecated(since = "0.14.4", note = "use `GS::set_reg()` instead")]
#[allow(clippy::missing_safety_doc)]
#[inline]
pub unsafe fn load_gs(sel: SegmentSelector) {
    unsafe { GS::set_reg(sel) }
}
/// Alias for [`GS::swap()`]
#[deprecated(since = "0.14.4", note = "use `GS::swap()` instead")]
#[allow(clippy::missing_safety_doc)]
#[inline]
pub unsafe fn swap_gs() {
    unsafe { GS::swap() }
}
/// Alias for [`CS::get_reg()`]
#[deprecated(since = "0.14.4", note = "use `CS::get_reg()` instead")]
#[allow(clippy::missing_safety_doc)]
#[inline]
pub fn cs() -> SegmentSelector {
    CS::get_reg()
}
/// Alias for [`FS::write_base()`].
///
/// Panics if the provided address is non-canonical.
#[deprecated(since = "0.14.4", note = "use `FS::write_base()` instead")]
#[allow(clippy::missing_safety_doc)]
#[inline]
pub unsafe fn wrfsbase(val: u64) {
    unsafe { FS::write_base(VirtAddr::new(val)) }
}
/// Alias for [`FS::read_base()`]
#[deprecated(since = "0.14.4", note = "use `FS::read_base()` instead")]
#[allow(clippy::missing_safety_doc)]
#[inline]
pub unsafe fn rdfsbase() -> u64 {
    FS::read_base().as_u64()
}
/// Alias for [`GS::write_base()`].
///
/// Panics if the provided address is non-canonical.
#[deprecated(since = "0.14.4", note = "use `GS::write_base()` instead")]
#[allow(clippy::missing_safety_doc)]
#[inline]
pub unsafe fn wrgsbase(val: u64) {
    unsafe { GS::write_base(VirtAddr::new(val)) }
}
/// Alias for [`GS::read_base()`]
#[deprecated(since = "0.14.4", note = "use `GS::read_base()` instead")]
#[allow(clippy::missing_safety_doc)]
#[inline]
pub unsafe fn rdgsbase() -> u64 {
    GS::read_base().as_u64()
}
