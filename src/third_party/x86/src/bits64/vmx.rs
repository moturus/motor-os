//! Virtualize processor hardware for multiple software environments using Virtual Machine Extensions.

use crate::bits64::rflags::{self, RFlags};
use crate::vmx::{Result, VmFail};
use core::arch::asm;

/// Helper used to extract VMX-specific Result in accordance with
/// conventions described in Intel SDM, Volume 3C, Section 30.2.
// We inline this to provide an obstruction-free path from this function's
// call site to the moment where `rflags::read()` reads RFLAGS. Otherwise it's
// possible for RFLAGS register to be clobbered by a function prologue,
// see https://github.com/gz/rust-x86/pull/50.
#[inline(always)]
fn vmx_capture_status() -> Result<()> {
    let flags = rflags::read();

    if flags.contains(RFlags::FLAGS_ZF) {
        Err(VmFail::VmFailValid)
    } else if flags.contains(RFlags::FLAGS_CF) {
        Err(VmFail::VmFailInvalid)
    } else {
        Ok(())
    }
}

/// Enable VMX operation.
///
/// `addr` specifies a 4KB-aligned physical address of VMXON region initialized
/// in accordance with Intel SDM, Volume 3C, Section 24.11.5.
///
/// # Safety
/// Needs CPL 0.
pub unsafe fn vmxon(addr: u64) -> Result<()> {
    asm!("vmxon ({0})", in(reg) &addr, options(att_syntax));
    vmx_capture_status()
}

/// Disable VMX operation.
///
/// # Safety
/// Needs CPL 0.
pub unsafe fn vmxoff() -> Result<()> {
    asm!("vmxoff");
    vmx_capture_status()
}

/// Clear VMCS.
///
/// Ensures that VMCS data maintained on the processor is copied to the VMCS region
/// located at 4KB-aligned physical address `addr` and initializes some parts of it.
///
/// # Safety
/// Needs CPL 0.
pub unsafe fn vmclear(addr: u64) -> Result<()> {
    asm!("vmclear ({0})", in(reg) &addr, options(att_syntax));
    vmx_capture_status()
}

/// Load current VMCS pointer.
///
/// Marks the current-VMCS pointer valid and loads it with the physical address `addr`.
///
/// # Safety
/// Needs CPL 0.
pub unsafe fn vmptrld(addr: u64) -> Result<()> {
    asm!("vmptrld ({0})", in(reg) &addr, options(att_syntax));
    vmx_capture_status()
}

/// Return current VMCS pointer.
///
/// # Safety
/// Needs CPL 0.
pub unsafe fn vmptrst() -> Result<u64> {
    let value: u64 = 0;
    asm!("vmptrst ({0})", in(reg) &value, options(att_syntax));
    vmx_capture_status().and(Ok(value))
}

/// Read a specified field from a VMCS.
///
/// # Safety
/// Needs CPL 0.
pub unsafe fn vmread(field: u32) -> Result<u64> {
    let field: u64 = field.into();
    let value: u64;
    asm!("vmread {0}, {1}", in(reg) field, out(reg) value, options(att_syntax));
    vmx_capture_status().and(Ok(value))
}

/// Write to a specified field in a VMCS.
///
/// # Safety
/// Needs CPL 0.
pub unsafe fn vmwrite(field: u32, value: u64) -> Result<()> {
    let field: u64 = field.into();
    asm!("vmwrite {1}, {0}", in(reg) field, in(reg) value, options(att_syntax));
    vmx_capture_status()
}

/// Launch virtual machine.
///
/// # Safety
/// Needs CPL 0.
#[inline(always)]
pub unsafe fn vmlaunch() -> Result<()> {
    asm!("vmlaunch");
    vmx_capture_status()
}

/// Resume virtual machine.
///
/// # Safety
/// Needs CPL 0.
#[inline(always)]
pub unsafe fn vmresume() -> Result<()> {
    asm!("vmresume");
    vmx_capture_status()
}
