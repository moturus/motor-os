#![no_std]
#![no_main]

mod load;
mod rt_alloc;
mod rt_thread;
mod rt_time;
mod rt_tls;

mod util {
    pub mod spin;
}

pub use util::spin;

extern crate alloc;

use core::sync::atomic::Ordering;
use moto_rt::RtVdsoVtableV1;

#[macro_export]
macro_rules! moto_log {
    ($($arg:tt)*) => {
        {
            extern crate alloc;
            moto_sys::SysRay::log(alloc::format!($($arg)*).as_str()).ok();
        }
    };
}

use core::panic::PanicInfo;

#[no_mangle]
pub fn moturus_log_panic(info: &PanicInfo<'_>) {
    moto_sys::SysRay::log("PANIC").ok(); // Log w/o allocations.
    let msg = alloc::format!("PANIC: {}", info);
    moto_sys::SysRay::log(msg.as_str()).ok();
}

#[cfg(not(test))]
#[panic_handler]
fn _panic(info: &PanicInfo<'_>) -> ! {
    moturus_log_panic(info);
    moto_sys::SysCpu::exit(u64::MAX)
}

// The entry point.
#[no_mangle]
pub extern "C" fn _rt_entry(version: u64) {
    assert_eq!(version, 1);

    let vtable = RtVdsoVtableV1::get();
    let self_addr = _rt_entry as *const () as usize as u64;
    assert_eq!(vtable.vdso_entry.load(Ordering::Acquire), self_addr);

    vtable.load_vdso.store(
        load::load_vdso as *const () as usize as u64,
        Ordering::Relaxed,
    );

    // Memory management.
    vtable.alloc.store(
        rt_alloc::alloc as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.alloc_zeroed.store(
        rt_alloc::alloc_zeroed as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.dealloc.store(
        rt_alloc::dealloc as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.realloc.store(
        rt_alloc::realloc as *const () as usize as u64,
        Ordering::Relaxed,
    );

    // Time management.
    vtable.time_instant_now.store(
        rt_time::time_instant_now as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.time_ticks_to_nanos.store(
        rt_time::ticks_to_nanos as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.time_nanos_to_ticks.store(
        rt_time::nanos_to_ticks as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.time_ticks_in_sec.store(
        moto_sys::KernelStaticPage::get().tsc_in_sec,
        Ordering::Relaxed,
    );
    vtable.time_abs_ticks_to_nanos.store(
        rt_time::abs_ticks_to_nanos as *const () as usize as u64,
        Ordering::Relaxed,
    );

    // Thread Local Storage.
    vtable.tls_create.store(
        rt_tls::create as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable
        .tls_set
        .store(rt_tls::set as *const () as usize as u64, Ordering::Relaxed);
    vtable
        .tls_get
        .store(rt_tls::get as *const () as usize as u64, Ordering::Relaxed);
    vtable.tls_destroy.store(
        rt_tls::destroy as *const () as usize as u64,
        Ordering::Relaxed,
    );

    // Thread management.
    vtable.thread_spawn.store(
        rt_thread::spawn as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.thread_yield.store(
        rt_thread::yield_now as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.thread_sleep.store(
        rt_thread::sleep as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.thread_set_name.store(
        rt_thread::set_name as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.thread_join.store(
        rt_thread::join as *const () as usize as u64,
        Ordering::Relaxed,
    );

    // The final fence.
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
}
