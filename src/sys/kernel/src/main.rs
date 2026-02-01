// This is the kernel's main. kloader has its own main.

#![no_std]
#![no_main]
#![allow(internal_features)]
#![feature(abi_x86_interrupt)]
#![feature(alloc_error_handler)]
#![feature(allocator_api)]
#![feature(assert_matches)]
#![feature(btreemap_alloc)]
#![feature(core_intrinsics)]
// #![feature(concat_idents)]
#![feature(get_mut_unchecked)]

// #[macro_use]
extern crate alloc;
pub mod arch;
pub mod config;
pub mod init;
pub mod mm;
pub mod sched;
pub mod uspace;
pub mod util;
pub mod xray;

pub use crate::arch::arch_raw_log as raw_log;
pub use crate::arch::arch_write_serial as write_serial;

#[cfg(not(test))]
#[alloc_error_handler]
fn alloc_error_handler(layout: alloc::alloc::Layout) -> ! {
    panic!("allocation error: {:#?}", layout)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::sync::atomic::AtomicBool;

    static PANIC: AtomicBool = AtomicBool::new(false);

    let cpu = crate::arch::apic_cpu_id_32();
    crate::raw_log!("KERNEL PANIC (cpu: {}): {}", cpu, info);

    if PANIC.swap(true, core::sync::atomic::Ordering::Relaxed) {
        // Logging detailed concurrent panic backtraces do not help.
        loop {}
    }

    crate::arch::log_backtrace("panic");

    crate::arch::kernel_exit()
}

// The entry point.
#[no_mangle]
pub extern "C" fn _start(arg: u64) -> ! {
    init::start_cpu(arg)
}
