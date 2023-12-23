#[inline(never)]
pub fn full_fence() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

pub fn write_to_port(port: u16, value: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
    }
}

pub fn enable_sse() {
    use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

    unsafe {
        core::arch::asm!("fninit");
    }

    let mut cr0 = Cr0::read();
    cr0.remove(Cr0Flags::EMULATE_COPROCESSOR);
    cr0.remove(Cr0Flags::TASK_SWITCHED);
    unsafe { Cr0::write(cr0) };
    let mut cr4 = Cr4::read();
    cr4.insert(Cr4Flags::OSFXSR); // Enable legacy fxsave/fxrstor.
    cr4.insert(Cr4Flags::OSXMMEXCPT_ENABLE);
    cr4.insert(Cr4Flags::OSXSAVE); // Enable modern xsave/xrstor.
    unsafe { Cr4::write(cr4) };

    // Enable AVX, see https://wiki.osdev.org/SSE.
    unsafe {
        core::arch::asm!(
            "
                push rax
                push rcx
                push rdx

                xor rcx, rcx
                xgetbv    // Load XCR0 register
                or eax, 7 // Set AVX, SSE, X87 bits
                xsetbv    // Save back to XCR0

                pop rdx
                pop rcx
                pop rax
            ",
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
        );
    }
}

pub fn vmm_exit() -> ! {
    crate::raw_log!("\n\r\n\rvm_exit: bye.\n\r");
    // First, try acpi_shutdown, which works in cloud-hypervisor.

    // Initially it worked with port 0x3c0.
    write_to_port(0x3c0, 0x34);

    // Later port number became 0x600, for some reason.
    write_to_port(0x600, 0x34);

    // Then, try Qemu exit.
    write_to_port(0xf4, 0x10);

    // The above did not work, so just loop.
    // Note that
    loop {}
}

pub fn rdtsc() -> u64 {
    let mut eax: u32;
    let mut edx: u32;

    unsafe {
        core::arch::asm!(
            "lfence",  // Prevent the CPU from reordering.
            "rdtsc",
            lateout("eax") eax,
            lateout("edx") edx,
            options(nostack)  // Don't say "nomem", otherwise the compiler might reorder.
        );
    }
    ((edx as u64) << 32) | (eax as u64)
}

/*
pub fn prng(add_entropy: bool) -> u32 {
    use core::ops::DerefMut;

    // https://en.wikipedia.org/wiki/Lehmer_random_number_generator
    static PRNG_BASE: spin::Mutex<core::num::Wrapping<u64>> =
        spin::Mutex::new(core::num::Wrapping(13));

    const MUL: core::num::Wrapping<u64> = core::num::Wrapping(48271);
    const MOD: core::num::Wrapping<u64> = core::num::Wrapping(2_147_483_647);

    let mut lock = PRNG_BASE.lock();
    let val = lock.deref_mut();

    *val *= MUL;

    if add_entropy {
        *val += core::num::Wrapping(rdtsc());
    }

    *val = *val % MOD;

    return (*val).0 as u32;
}
*/
