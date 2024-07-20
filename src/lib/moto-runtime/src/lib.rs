#![no_std]
#![allow(internal_features)]
#![feature(core_intrinsics)]
#![feature(linkage)]
#![feature(waker_getters)]
#![allow(elided_lifetimes_in_paths)]

#[cfg(feature = "rustc-dep-of-std")]
pub mod args;
#[cfg(feature = "rustc-dep-of-std")]
pub mod env;
#[cfg(feature = "rustc-dep-of-std")]
pub mod fs;

#[cfg(any(feature = "rustc-dep-of-std", feature = "rt-api"))]
pub mod net;

#[cfg(feature = "rustc-dep-of-std")]
pub mod process;
#[cfg(feature = "rustc-dep-of-std")]
pub mod std_rt;
#[cfg(feature = "rustc-dep-of-std")]
pub mod stdio;
#[cfg(any(feature = "rustc-dep-of-std", feature = "rt-api"))]
pub mod thread;
#[cfg(feature = "rustc-dep-of-std")]
pub mod time;
#[cfg(feature = "rustc-dep-of-std")]
pub mod tls;

#[cfg(feature = "rustc-dep-of-std")]
pub use moto_ipc::sync_pipe;

#[cfg(feature = "rustc-dep-of-std")]
pub use std_rt::*;

#[cfg(any(feature = "rustc-dep-of-std", feature = "rt-api"))]
pub mod rt_api;

#[cfg(any(feature = "rustc-dep-of-std", feature = "rt-api"))]
pub mod futex;

#[cfg(any(feature = "rustc-dep-of-std", feature = "rt-api"))]
pub use futex::*;

#[cfg(any(feature = "rustc-dep-of-std", feature = "rt-api"))]
pub mod mutex;

#[cfg(feature = "rt-api")]
extern crate alloc;

#[cfg(any(feature = "rustc-dep-of-std", feature = "rt-api"))]
pub mod util;

#[cfg(feature = "rustc-dep-of-std")]
mod libc;

#[allow(unused)]
mod external;

// Needed by bitflags!.
pub extern crate core as _core;

#[cfg(feature = "rustc-dep-of-std")]
pub fn hashmap_random_keys() -> (u64, u64) {
    let mut val1 = 0_u64;
    let mut val2 = 0_u64;
    unsafe {
        let _ = core::arch::x86_64::_rdrand64_step(&mut val1);
        let _ = core::arch::x86_64::_rdrand64_step(&mut val2);
    }
    if val1 != 0 && val2 != 0 {
        (val1, val2)
    } else {
        (7, 13)
    }
}

pub fn print_stacktace() {
    extern "C" {
        fn moturus_print_stacktrace();
    }

    unsafe { moturus_print_stacktrace() };
}
