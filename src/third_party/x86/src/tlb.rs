//! Functions to flush the translation lookaside buffer (TLB).

use core::arch::asm;

/// Invalidate the given address in the TLB using the `invlpg` instruction.
///
/// # Safety
/// This function is unsafe as it causes a general protection fault (GP) if the current privilege
/// level is not 0.
pub unsafe fn flush(addr: usize) {
    asm!("invlpg ({})", in(reg) addr, options(att_syntax, nostack, preserves_flags));
}

/// Invalidate the TLB completely by reloading the CR3 register.
///
/// # Safety
/// This function is unsafe as it causes a general protection fault (GP) if the current privilege
/// level is not 0.
pub unsafe fn flush_all() {
    use crate::controlregs::{cr3, cr3_write};
    cr3_write(cr3())
}

#[cfg(all(test, feature = "vmtest"))]
mod x86testing {
    use super::*;
    use x86test::*;

    #[x86test]
    fn check_flush_all() {
        unsafe {
            flush_all();
        }
    }

    #[x86test]
    fn check_flush() {
        // A better test would be:
        // map page, read page, unmap page, read page, flush, read page -> pfault
        unsafe {
            flush(0xdeadbeef);
        }
    }
}
