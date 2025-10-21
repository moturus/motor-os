#![no_std]
#![no_main]
#![allow(unused)]
#![feature(maybe_uninit_write_slice)]
#![feature(str_from_raw_parts)]

mod load;
mod posix;
mod proc_fd;
mod rt_alloc;
mod rt_fs;
mod rt_futex;
mod rt_poll;
mod rt_process;
mod rt_thread;
mod rt_time;
mod rt_tls;
mod runtime;
mod stdio;

mod net {
    pub mod inner_rx_stream;
    pub mod rt_net;
    pub mod rt_tcp;
    pub mod rt_udp;
}

#[macro_use]
mod util {
    #[macro_use]
    pub mod logging;
    pub mod scopeguard;
}

pub(crate) use util::logging::moto_log;
extern crate alloc;

use core::{ptr::copy_nonoverlapping, sync::atomic::Ordering};
use moto_rt::RtVdsoVtable;

const RT_VERSION: u64 = 15;

// The entry point.
#[unsafe(no_mangle)]
pub extern "C" fn motor_start(version: u64) {
    if version != RT_VERSION {
        // Doing an assert or panic will #PF, so we use lower-level API.
        moto_log!("VDSO: unsupported version: {version}.");
        moto_sys::sys_cpu::SysCpu::exit(1)
    }

    let vtable = RtVdsoVtable::get();
    let self_addr = motor_start as *const () as usize as u64;
    assert_eq!(vtable.vdso_entry.load(Ordering::Acquire), self_addr);

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
    vtable.fs_close.store(
        posix::posix_close as *const () as usize as u64,
        Ordering::Relaxed,
    );
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
    vtable.fs_read.store(
        posix::posix_read as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.fs_read_vectored.store(
        posix::posix_read_vectored as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.fs_write.store(
        posix::posix_write as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.fs_write_vectored.store(
        posix::posix_write_vectored as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.fs_flush.store(
        posix::posix_flush as *const () as usize as u64,
        Ordering::Relaxed,
    );
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
    vtable.fs_set_file_perm.store(
        rt_fs::set_file_perm as *const () as usize as u64,
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
    vtable.fs_duplicate.store(
        posix::posix_duplicate as *const () as usize as u64,
        Ordering::Relaxed,
    );

    // Networking.
    vtable.dns_lookup.store(
        net::rt_net::dns_lookup as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.net_bind.store(
        net::rt_net::bind as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.net_listen.store(
        net::rt_net::listen as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.net_accept.store(
        net::rt_net::accept as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.net_tcp_connect.store(
        net::rt_net::tcp_connect as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.net_udp_connect.store(
        net::rt_net::udp_connect as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.net_socket_addr.store(
        net::rt_net::socket_addr as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.net_peer_addr.store(
        net::rt_net::peer_addr as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.net_setsockopt.store(
        net::rt_net::setsockopt as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.net_getsockopt.store(
        net::rt_net::getsockopt as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.net_peek.store(
        net::rt_net::peek as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.net_udp_recv_from.store(
        net::rt_net::udp_recv_from as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.net_udp_peek_from.store(
        net::rt_net::udp_peek_from as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.net_udp_send_to.store(
        net::rt_net::udp_send_to as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.net_udp_multicast_op_v4.store(
        vdso_unimplemented as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.net_udp_multicast_op_v6.store(
        vdso_unimplemented as *const () as usize as u64,
        Ordering::Relaxed,
    );

    // Poll.
    vtable
        .poll_new
        .store(rt_poll::new as *const () as usize as u64, Ordering::Relaxed);
    vtable
        .poll_add
        .store(rt_poll::add as *const () as usize as u64, Ordering::Relaxed);
    vtable
        .poll_set
        .store(rt_poll::set as *const () as usize as u64, Ordering::Relaxed);
    vtable
        .poll_del
        .store(rt_poll::del as *const () as usize as u64, Ordering::Relaxed);
    vtable.poll_wait.store(
        rt_poll::wait as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.poll_wake.store(
        rt_poll::wake as *const () as usize as u64,
        Ordering::Relaxed,
    );

    // Misc.
    vtable.log_to_kernel.store(
        util::logging::log_to_kernel as *const () as usize as u64,
        Ordering::Relaxed,
    );

    vtable.log_backtrace.store(
        util::logging::log_backtrace as *const () as usize as u64,
        Ordering::Relaxed,
    );

    vtable.fill_random_bytes.store(
        fill_random_bytes as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.internal_helper.store(
        vdso_internal_helper as *const () as usize as u64,
        Ordering::Relaxed,
    );
    vtable.current_exe.store(
        rt_process::current_exe as *const () as usize as u64,
        Ordering::Relaxed,
    );

    vtable
        .num_cpus
        .store(num_cpus as *const () as usize as u64, Ordering::Relaxed);

    // The final fence.
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);

    let _ = moto_sys::set_current_thread_name("main");
    stdio::init();
}

/// # Safety
///
/// Assumes ptr is properly allocated.
pub unsafe extern "C" fn fill_random_bytes(ptr: *mut u8, size: usize) {
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

pub extern "C" fn num_cpus() -> usize {
    moto_sys::num_cpus() as usize
}

pub extern "C" fn vdso_internal_helper(
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> u64 {
    match a0 {
        0 => net::rt_net::vdso_internal_helper(a1, a2, a3, a4, a5),
        _ => panic!("Unrecognized option {a0}"),
    }
}

pub extern "C" fn vdso_unimplemented() {
    moto_log!("VDSO: unimplemented");
    panic!("unimplemented")
}
