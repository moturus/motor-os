//! Motor OS Runtime Library. It is a stub/proxy to Motor OS Runtime VDSO
//! (Virtual Dynamic Shared Object) which is loaded into every userspace process.
//!
//! The Runtime API surface is explicitly designed to provide Rust standard
//! library PAL (platform abstraction layer); while it may evolve later into
//! a more universal Runtime API (e.g. to be used in Go runtime, Java runtime,
//! libc, etc.), at the moment only supporting Rust Standard Library PAL
//! is on the roadmap.
//!
//! Note: RT.VDSO is a "fat" runtime: it creates an IO thread to interact with
//!       sys-io, and stdio threads to provide stdin/stdout/stderr abstractions,
//!       if needed.
//!
//! While it is possible to do everything RT.VDSO does by directly interacting
//! with the OS kernel and sys-io, there are two main benefits of using a VDSO
//! and this RT library as its proxy:
//! - simplified integration with Rust Standard Library: instead of a "fat"
//!   Motor OS PAL that needs heavy maintenance, this "thin" RT library
//!   is designed to be relatively stable, even if the underlying system code
//!   and runtime undergo extensive changes;
//! - OS/runtime updates are automatically picked up by existing/compiled
//!   binaries without recompilation; while this is common in Windows and Linux
//!   with dll/so libraries, this benefit is worth mentioning here, as
//!   Motor OS, which is based on Rust, does not support dynamic libraries,
//!   as Rust does not support them "natively" (as in rdylib).
#![no_std]

// Mod error is the only one currently shared b/w the kernel and the userspace.
#[macro_use]
pub mod error;
pub use error::*;

// Constants from moto-sys: we replicate them here to avoid depending on moto-sys.
// NOTE: do not change these numbers unless they are also changed in moto-sys!
#[doc(hidden)]
pub const MOTO_SYS_CUSTOM_USERSPACE_REGION_START: u64 = (1_u64 << 45) + (1_u64 << 40);
#[doc(hidden)]
const MOTO_SYS_CUSTOM_USERSPACE_REGION_END: u64 =
    MOTO_SYS_CUSTOM_USERSPACE_REGION_START + (1_u64 << 40);
#[doc(hidden)]
const MOTO_SYS_PAGE_SIZE_SMALL: u64 = 4096;

// At this address rt.vdso object will be mapped/loaded into every process/binary.
#[doc(hidden)]
pub const RT_VDSO_START: u64 = MOTO_SYS_CUSTOM_USERSPACE_REGION_END - (1_u64 << 32); // 4GB for RT_VDSO.

// At this address rt.vdso bytes will be mapped/loaded into every process/binary.
// NOTE: this is a temporary arrangement; when process start is moved to sys-io (or another binary),
//       having the bytes in every process will no longer be needed.
#[doc(hidden)]
pub const RT_VDSO_BYTES_ADDR: u64 = RT_VDSO_START - (1_u64 << 32); // 4GB for RT_VDSO.

// At this address the loader will initialize RtVdsoVtable.
#[doc(hidden)]
pub const RT_VDSO_VTABLE_VADDR: u64 = RT_VDSO_START - MOTO_SYS_PAGE_SIZE_SMALL;

#[cfg(not(feature = "base"))]
const RT_VERSION: u64 = 1;

#[cfg(not(feature = "base"))]
pub mod alloc;
#[cfg(not(feature = "base"))]
pub mod fs;
#[cfg(not(feature = "base"))]
pub mod futex;
#[cfg(not(feature = "base"))]
pub mod process;
#[cfg(not(feature = "base"))]
pub mod thread;
#[cfg(not(feature = "base"))]
pub mod time;
#[cfg(not(feature = "base"))]
pub mod tls;

#[cfg(not(feature = "base"))]
pub use futex::*;

#[cfg(not(feature = "base"))]
use core::sync::atomic::{AtomicU64, Ordering};

/// Runtime FD (file descriptor). While Motor OS uses SysHandle
/// for file objects internally, Rust defines std::os::fd::RawFd
/// as c_int, so we have to follow suit to make our lives easier.
#[cfg(not(feature = "base"))]
pub type RtFd = i32;

#[cfg(not(feature = "base"))]
#[doc(hidden)]
#[repr(C)]
pub struct RtVdsoVtableV1 {
    pub vdso_entry: AtomicU64,
    pub vdso_bytes_sz: AtomicU64,

    // Self-replicate into a remote address space.
    pub load_vdso: AtomicU64,

    // Logging facility.
    pub log_to_kernel: AtomicU64,

    // Memory management.
    pub alloc: AtomicU64,
    pub alloc_zeroed: AtomicU64,
    pub realloc: AtomicU64,
    pub dealloc: AtomicU64,

    // Time management.
    pub time_instant_now: AtomicU64,
    pub time_ticks_to_nanos: AtomicU64,
    pub time_nanos_to_ticks: AtomicU64,
    pub time_ticks_in_sec: AtomicU64,
    pub time_abs_ticks_to_nanos: AtomicU64,

    // Futex.
    pub futex_wait: AtomicU64,
    pub futex_wake: AtomicU64,
    pub futex_wake_all: AtomicU64,

    // Process-related.
    pub proc_get_full_env: AtomicU64,
    pub proc_getenv: AtomicU64,
    pub proc_setenv: AtomicU64,

    // Thread Local Storage.
    pub tls_create: AtomicU64,
    pub tls_set: AtomicU64,
    pub tls_get: AtomicU64,
    pub tls_destroy: AtomicU64,

    // Thread management.
    pub thread_spawn: AtomicU64,
    pub thread_sleep: AtomicU64,
    pub thread_yield: AtomicU64,
    pub thread_set_name: AtomicU64,
    pub thread_join: AtomicU64,

    // Filesystem.
    pub fs_open: AtomicU64,
    pub fs_close: AtomicU64,
    pub fs_get_file_attr: AtomicU64,
    pub fs_fsync: AtomicU64,
    pub fs_datasync: AtomicU64,
    pub fs_truncate: AtomicU64,
    pub fs_read: AtomicU64,
    pub fs_write: AtomicU64,
    pub fs_seek: AtomicU64,
    pub fs_mkdir: AtomicU64,
    pub fs_unlink: AtomicU64,
    pub fs_rename: AtomicU64,
    pub fs_rmdir: AtomicU64,
    pub fs_rmdir_all: AtomicU64,
    pub fs_set_perm: AtomicU64,
    pub fs_stat: AtomicU64,
    pub fs_canonicalize: AtomicU64,
    pub fs_copy: AtomicU64,
    pub fs_opendir: AtomicU64,
    pub fs_closedir: AtomicU64,
    pub fs_readdir: AtomicU64,
    pub fs_getcwd: AtomicU64,
    pub fs_chdir: AtomicU64,
}

#[cfg(not(feature = "base"))]
const _SIZE_CHECK: () = assert!(size_of::<RtVdsoVtableV1>() <= 4096);

#[cfg(not(feature = "base"))]
#[doc(hidden)]
impl RtVdsoVtableV1 {
    pub fn get() -> &'static Self {
        // Safety: sys-io is supposed to have taken care of this.
        unsafe {
            (RT_VDSO_VTABLE_VADDR as usize as *const RtVdsoVtableV1)
                .as_ref()
                .unwrap_unchecked()
        }
    }
}

#[cfg(not(feature = "base"))]
#[doc(hidden)]
pub fn init() {
    assert_ne!(0, RtVdsoVtableV1::get().vdso_entry.load(Ordering::Acquire));
    let vdso_entry: extern "C" fn(u64) = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().vdso_entry.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    vdso_entry(RT_VERSION)
}

// This is a temporary function that takes a remote address space handle
// and loads vdso into it. The function will be removed once load_program()
// is implemented in vdso.
#[cfg(not(feature = "base"))]
#[doc(hidden)]
pub fn load_vdso(address_space: u64) -> ErrorCode {
    let vdso_load: extern "C" fn(u64) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().load_vdso.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    vdso_load(address_space)
}

/// The number of CPUs available.
#[cfg(not(feature = "base"))]
pub fn num_cpus() -> usize {
    todo!()
}
