use core::arch::asm;
use core::sync::atomic::*;

use moto_sys::KernelStaticPage;

pub extern "C" fn time_instant_now() -> u64 {
    rdtsc()
}

// This returns "absolute" time.
pub extern "C" fn abs_ticks_to_nanos(ticks: u64, out_hi_ptr: *mut u64, out_lo_ptr: *mut u64) {
    /*  see https://www.kernel.org/doc/Documentation/virt/kvm/msr.rst
        time = (current_tsc - tsc_timestamp)
        if (tsc_shift >= 0)
            time <<= tsc_shift;
        else
            time >>= -tsc_shift;
        time = (time * tsc_to_system_mul) >> 32
        time = time + system_time
    */
    fence(Ordering::Acquire);

    let page = KernelStaticPage::get();
    let mut time = ticks - page.tsc_ts;
    let tsc_shift = page.tsc_shift;
    if tsc_shift >= 0 {
        time <<= tsc_shift;
    } else {
        time >>= -tsc_shift;
    }

    // The multiplication below MUST be done with higher precision, as
    // doing it in u64 overflows and leads to wrong time.
    let mul = (time as u128) * (page.tsc_mul as u128);

    let mut time = mul >> 32;
    time += page.system_time as u128;

    let result: u128 = page.base_nsec as u128 + time;
    unsafe {
        *out_hi_ptr = (result >> 64) as u64;
        *out_lo_ptr = ((result << 64) >> 64) as u64;
    }
}

// This returns "Duration".
pub extern "C" fn ticks_to_nanos(ticks: u64, out_hi_ptr: *mut u64, out_lo_ptr: *mut u64) {
    /*  see https://www.kernel.org/doc/Documentation/virt/kvm/msr.rst
        time = (current_tsc - tsc_timestamp)
        if (tsc_shift >= 0)
            time <<= tsc_shift;
        else
            time >>= -tsc_shift;
        time = (time * tsc_to_system_mul) >> 32
        time = time + system_time
    */
    fence(Ordering::Acquire);
    let page = KernelStaticPage::get();

    let mut nanos = ticks as u128;
    let tsc_shift = page.tsc_shift;
    if tsc_shift >= 0 {
        nanos <<= tsc_shift;
    } else {
        nanos >>= -tsc_shift;
    }

    let result: u128 = (nanos * (page.tsc_mul as u128)) >> 32;
    unsafe {
        *out_hi_ptr = (result >> 64) as u64;
        *out_lo_ptr = ((result << 64) >> 64) as u64;
    }
}

pub extern "C" fn nanos_to_ticks(nanos: u64) -> u64 {
    fence(Ordering::Acquire);
    let page = KernelStaticPage::get();

    let tsc_shift = page.tsc_shift;

    // TODO: optimize?
    // TODO: fix panic on overflow.
    let mut res = if nanos >= (1u64 << 32) {
        (nanos >> 4) * ((1u64 << 36) / (page.tsc_mul as u64))
    } else {
        (nanos << 32) / (page.tsc_mul as u64)
    };

    if tsc_shift >= 0 {
        res >> tsc_shift
    } else {
        res << -tsc_shift
    }
}

fn rdtsc() -> u64 {
    let mut eax: u32;
    let mut edx: u32;

    unsafe {
        asm!(
            "lfence",  // Prevent the CPU from reordering.
            "rdtsc",
            lateout("eax") eax,
            lateout("edx") edx,
            options(nostack)  // Don't say "nomem", otherwise the compiler might reorder.
        );
    }
    ((edx as u64) << 32) | (eax as u64)
}
