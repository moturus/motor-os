use core::arch::asm;

/// Read the RIP register (instruction pointer).
#[inline(always)]
pub fn rip() -> u64 {
    let rip: u64;
    unsafe {
        asm!("leaq 0(%rip), {0}", out(reg) rip, options(att_syntax));
    }
    rip
}

/// Read the RSP register (stack pointer register).
#[inline(always)]
pub fn rsp() -> u64 {
    let rsp: u64;
    unsafe {
        asm!("mov %rsp, {0}", out(reg) rsp, options(att_syntax));
    }
    rsp
}

/// Read the RBP register (base pointer register).
#[inline(always)]
pub fn rbp() -> u64 {
    let rbp: u64;
    unsafe {
        asm!("mov %rbp, {0}", out(reg) rbp, options(att_syntax));
    }
    rbp
}
