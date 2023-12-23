//! Intel fence instructions

use core::arch::asm;

/// mfence -- Memory Fence
///
/// Performs a serializing operation on all load-from-memory and store-to-memory
/// instructions that were issued prior the MFENCE instruction.
pub fn mfence() {
    unsafe { asm!("mfence") };
}

/// sfence -- Store Fence
///
/// Orders processor execution relative to all memory stores prior to the SFENCE
/// instruction. The processor ensures that every store prior to SFENCE is
/// globally visible before any store after SFENCE becomes globally visible.
pub fn sfence() {
    unsafe { asm!("sfence") };
}

/// lfence -- Load Fence
///
/// Performs a serializing operation on all load-from-memory instructions that
/// were issued prior the LFENCE instruction. Specifically, LFENCE does not
/// execute until all prior instructions have completed locally, and no later
/// instruction begins execution until LFENCE completes.
pub fn lfence() {
    unsafe { asm!("lfence") };
}
