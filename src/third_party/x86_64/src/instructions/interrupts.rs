//! Enabling and disabling interrupts

use core::arch::asm;

/// Returns whether interrupts are enabled.
#[inline]
pub fn are_enabled() -> bool {
    use crate::registers::rflags::{self, RFlags};

    rflags::read().contains(RFlags::INTERRUPT_FLAG)
}

/// Enable interrupts.
///
/// This is a wrapper around the `sti` instruction.
#[inline]
pub fn enable() {
    unsafe {
        asm!("sti", options(nomem, nostack));
    }
}

/// Disable interrupts.
///
/// This is a wrapper around the `cli` instruction.
#[inline]
pub fn disable() {
    unsafe {
        asm!("cli", options(nomem, nostack));
    }
}

/// Run a closure with disabled interrupts.
///
/// Run the given closure, disabling interrupts before running it (if they aren't already disabled).
/// Afterwards, interrupts are enabling again if they were enabled before.
///
/// If you have other `enable` and `disable` calls _within_ the closure, things may not work as expected.
///
/// # Examples
///
/// ```ignore
/// // interrupts are enabled
/// without_interrupts(|| {
///     // interrupts are disabled
///     without_interrupts(|| {
///         // interrupts are disabled
///     });
///     // interrupts are still disabled
/// });
/// // interrupts are enabled again
/// ```
#[inline]
pub fn without_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    // true if the interrupt flag is set (i.e. interrupts are enabled)
    let saved_intpt_flag = are_enabled();

    // if interrupts are enabled, disable them for now
    if saved_intpt_flag {
        disable();
    }

    // do `f` while interrupts are disabled
    let ret = f();

    // re-enable interrupts if they were previously enabled
    if saved_intpt_flag {
        enable();
    }

    // return the result of `f` to the caller
    ret
}

/// Atomically enable interrupts and put the CPU to sleep
///
/// Executes the `sti; hlt` instruction sequence. Since the `sti` instruction
/// keeps interrupts disabled until after the immediately following
/// instruction (called "interrupt shadow"), no interrupt can occur between the
/// two instructions. (One exception to this are non-maskable interrupts; this
/// is explained below.)
///
/// This function is useful to put the CPU to sleep without missing interrupts
/// that occur immediately before the `hlt` instruction:
///
/// ```ignore
/// // there is a race between the check and the `hlt` instruction here:
///
/// if nothing_to_do() {
///     // <- race when the interrupt occurs here
///     x86_64::instructions::hlt(); // wait for the next interrupt
/// }
///
/// // avoid this race by using `enable_and_hlt`:
///
/// x86_64::instructions::interrupts::disable();
/// if nothing_to_do() {
///     // <- no interrupts can occur here (interrupts are disabled)
///     x86_64::instructions::interrupts::enable_and_hlt();
/// }
///
/// ```
///
/// ## Non-maskable Interrupts
///
/// On some processors, the interrupt shadow of `sti` does not apply to
/// non-maskable interrupts (NMIs). This means that an NMI can occur between
/// the `sti` and `hlt` instruction, with the result that the CPU is put to
/// sleep even though a new interrupt occured.
///
/// To work around this, it is recommended to check in the NMI handler if
/// the interrupt occured between `sti` and `hlt` instructions. If this is the
/// case, the handler should increase the instruction pointer stored in the
/// interrupt stack frame so that the `hlt` instruction is skipped.
///
/// See <http://lkml.iu.edu/hypermail/linux/kernel/1009.2/01406.html> for more
/// information.
#[inline]
pub fn enable_and_hlt() {
    unsafe {
        asm!("sti; hlt", options(nomem, nostack));
    }
}

/// Cause a breakpoint exception by invoking the `int3` instruction.
#[inline]
pub fn int3() {
    unsafe {
        asm!("int3", options(nomem, nostack));
    }
}

/// Generate a software interrupt by invoking the `int` instruction.
///
/// This currently needs to be a macro because the `int` argument needs to be an
/// immediate. This macro will be replaced by a generic function when support for
/// const generics is implemented in Rust.
#[macro_export]
macro_rules! software_interrupt {
    ($x:expr) => {{
        asm!("int {id}", id = const $x, options(nomem, nostack));
    }};
}
