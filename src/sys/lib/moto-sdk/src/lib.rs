//! Motor OS SDK: the libraries that Motor OS services and applications use
//! to reach the system: IPC, the async runtime, file and network I/O, logging,
//! and stats.
//!
//! Most modules exist only on Motor OS. `async_fs`, `iobuf::IoBuf` and
//! `tooling::mode2048` also build on Unix, for image tools and host tests.
//! The default `std` feature enables the std-only parts; rt.vdso builds the
//! SDK without it, with `core` and `alloc` only.

#![no_std]
#![cfg_attr(target_os = "motor", feature(allocator_api))]
#![cfg_attr(target_os = "motor", feature(async_trait_bounds))]
#![cfg_attr(target_os = "motor", feature(likely_unlikely))]
#![cfg_attr(target_os = "motor", feature(local_waker))]
#![cfg_attr(target_os = "motor", feature(negative_impls))]
#![cfg_attr(target_os = "motor", feature(trait_alias))]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(all(target_os = "motor", feature = "std"))]
pub use moto_rt as rt;
#[cfg(all(target_os = "motor", feature = "std"))]
pub use moto_sys as sys;

// Supported Unix builds enable std, which the Unix filesystem code needs.
#[cfg(any(target_os = "motor", all(unix, feature = "std")))]
pub mod async_fs;
#[cfg(any(target_os = "motor", unix))]
pub mod iobuf;
#[cfg(any(target_os = "motor", unix))]
pub mod tooling;

#[cfg(target_os = "motor")]
pub mod async_runtime;
#[cfg(target_os = "motor")]
pub mod io;
#[cfg(target_os = "motor")]
#[doc(hidden)]
pub mod io_internal;
#[cfg(target_os = "motor")]
pub mod ipc;
#[cfg(all(target_os = "motor", feature = "std"))]
pub mod log;
#[cfg(target_os = "motor")]
pub mod mpmc;
#[cfg(target_os = "motor")]
pub mod stats;
#[cfg(target_os = "motor")]
pub mod sys_io;
