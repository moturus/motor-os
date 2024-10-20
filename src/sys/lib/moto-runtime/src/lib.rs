#![no_std]
#![allow(internal_features)]
#![feature(core_intrinsics)]
#![feature(exposed_provenance)]
#![feature(linkage)]
#![allow(elided_lifetimes_in_paths)]

pub use moto_rt::futex::*;

#[cfg(any(feature = "rustc-dep-of-std", feature = "rt-api"))]
pub mod net;

#[cfg(any(feature = "rustc-dep-of-std", feature = "rt-api"))]
pub mod rt_api;

#[cfg(any(feature = "rustc-dep-of-std", feature = "rt-api"))]
pub mod mutex;

#[cfg(feature = "rt-api")]
extern crate alloc;

#[cfg(any(feature = "rustc-dep-of-std", feature = "rt-api"))]
pub mod util;

#[allow(unused)]
mod external;

// Needed by bitflags!.
pub extern crate core as _core;

pub fn print_stacktace() {
    extern "C" {
        fn moturus_print_stacktrace();
    }

    unsafe { moturus_print_stacktrace() };
}

// This is defined as weak because it is defined in std_rt,
// which is always linked; but LDD complains without the weak
// definition.
#[cfg(not(feature = "rustc-dep-of-std"))]
#[linkage = "weak"]
#[no_mangle]
pub extern "C" fn moturus_print_stacktrace() {}
