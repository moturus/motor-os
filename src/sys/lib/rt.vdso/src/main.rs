#![no_std]
#![no_main]
#![allow(unused)]

mod load;
mod rt_alloc;
mod rt_fs;
mod rt_futex;
mod rt_process;
mod rt_thread;
mod rt_time;
mod rt_tls;
mod stdio;

#[macro_use]
mod util {
    pub mod fd;
    #[macro_use]
    pub mod logging;
    pub mod mutex;
    pub mod scopeguard;
    pub mod spin;
}

pub(crate) use util::logging::moto_log;
pub use util::spin;

extern crate alloc;

use core::{ptr::copy_nonoverlapping, sync::atomic::Ordering};
use moto_rt::RtVdsoVtableV1;

// The entry point.
#[no_mangle]
pub extern "C" fn _rt_entry(version: u64) {
    assert_eq!(version, 1);

    let vtable = RtVdsoVtableV1::get();
    let self_addr = _rt_entry as *const () as usize as u64;
    assert_eq!(vtable.vdso_entry.load(Ordering::Acquire), self_addr);

    vtable.log_to_kernel.store(
        log_to_kernel as *const () as usize as u64,
        Ordering::Relaxed,
    );

    vtable.fill_random_bytes.store(
        fill_random_bytes as *const () as usize as u64,
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
    vtable.release_handle.store(
        rt_alloc::release_handle as *const () as usize as u64,
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

    // Futex.
    vtable.futex_wait.store(
        rt_futex::futex_wait as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.futex_wake.store(
        rt_futex::futex_wake as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.futex_wake_all.store(
        rt_futex::futex_wake_all as *const () as usize as u64,
        Ordering::Relaxed,
    );

    // Process-related.
    vtable.proc_args.store(
        rt_process::args as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.proc_get_full_env.store(
        rt_process::get_full_env as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.proc_getenv.store(
        rt_process::getenv as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.proc_setenv.store(
        rt_process::setenv as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.proc_spawn.store(
        rt_process::spawn as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.proc_kill.store(
        rt_process::kill as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.proc_wait.store(
        rt_process::wait as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.proc_status.store(
        rt_process::status as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.proc_exit.store(
        rt_process::exit as *const () as usize as u64,
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

    // Filesystem.
    vtable.fs_is_terminal.store(
        rt_fs::is_terminal as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable
        .fs_open
        .store(rt_fs::open as *const () as usize as u64, Ordering::Relaxed);
    vtable
        .fs_close
        .store(rt_fs::close as *const () as usize as u64, Ordering::Relaxed);
    vtable.fs_get_file_attr.store(
        rt_fs::get_file_attr as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable
        .fs_fsync
        .store(rt_fs::fsync as *const () as usize as u64, Ordering::Relaxed);
    vtable.fs_datasync.store(
        rt_fs::datasync as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.fs_truncate.store(
        rt_fs::truncate as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable
        .fs_read
        .store(rt_fs::read as *const () as usize as u64, Ordering::Relaxed);
    vtable
        .fs_write
        .store(rt_fs::write as *const () as usize as u64, Ordering::Relaxed);
    vtable
        .fs_flush
        .store(rt_fs::flush as *const () as usize as u64, Ordering::Relaxed);
    vtable
        .fs_seek
        .store(rt_fs::seek as *const () as usize as u64, Ordering::Relaxed);
    vtable
        .fs_mkdir
        .store(rt_fs::mkdir as *const () as usize as u64, Ordering::Relaxed);
    vtable.fs_unlink.store(
        rt_fs::unlink as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.fs_rename.store(
        rt_fs::rename as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable
        .fs_rmdir
        .store(rt_fs::rmdir as *const () as usize as u64, Ordering::Relaxed);
    vtable.fs_rmdir_all.store(
        rt_fs::rmdir_all as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.fs_set_perm.store(
        rt_fs::set_perm as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable
        .fs_stat
        .store(rt_fs::stat as *const () as usize as u64, Ordering::Relaxed);
    vtable.fs_canonicalize.store(
        rt_fs::canonicalize as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable
        .fs_copy
        .store(rt_fs::copy as *const () as usize as u64, Ordering::Relaxed);
    vtable.fs_opendir.store(
        rt_fs::opendir as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.fs_closedir.store(
        rt_fs::closedir as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.fs_readdir.store(
        rt_fs::readdir as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.fs_getcwd.store(
        rt_fs::getcwd as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable
        .fs_chdir
        .store(rt_fs::chdir as *const () as usize as u64, Ordering::Relaxed);

    // The final fence.
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);

    let _ = moto_sys::set_current_thread_name("main");
    stdio::init();
}

pub extern "C" fn log_to_kernel(ptr: *const u8, size: usize) {
    let bytes = unsafe { core::slice::from_raw_parts(ptr, size) };
    let msg = unsafe { core::str::from_utf8_unchecked(bytes) };
    moto_sys::SysRay::log(msg).ok();
}

pub extern "C" fn fill_random_bytes(ptr: *mut u8, size: usize) {
    let mut curr_pos = 0_usize;
    let mut remainder = size;
    unsafe {
        while remainder > 0 {
            let mut val = 0_u64;
            let _ = core::arch::x86_64::_rdrand64_step(&mut val);
            if val == 0 {
                panic!("rdrand64_step failed");
            }
            let to_copy = remainder.min(8);
            copy_nonoverlapping(
                &val as *const u64 as usize as *const u8,
                ptr.add(curr_pos),
                to_copy,
            );
            remainder -= to_copy;
            curr_pos += to_copy;
        }
    }
}
