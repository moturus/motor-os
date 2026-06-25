use moto_sys::stats::{MetricDescWire, MetricEntry, ProcessInfoV1, PID_KERNEL, PID_SYSTEM};
use moto_sys::{syscalls::SyscallResult, SysHandle, SysRay};

use crate::xray::stats::{KProcessStats, MetricType};

use super::syscall::{ResultBuilder, SyscallArgs};

fn sys_query_process_status(thread: &super::process::Thread, args: &SyscallArgs) -> SyscallResult {
    if args.version > 0 {
        return ResultBuilder::version_too_high();
    }

    if args.flags != SysRay::F_QUERY_STATUS {
        return ResultBuilder::invalid_argument();
    }

    match super::sysobject::object_from_handle::<super::process::Process>(
        &thread.owner(),
        SysHandle::from_u64(args.args[0]),
    ) {
        Some(proc) => match proc.status() {
            super::process::ProcessStatus::Created
            | super::process::ProcessStatus::Running
            | super::process::ProcessStatus::PausedDebuggee
            | super::process::ProcessStatus::Exiting(_) => {
                ResultBuilder::result(moto_rt::E_ALREADY_IN_USE)
            }
            super::process::ProcessStatus::Exited(code) => ResultBuilder::ok_1(code),
            super::process::ProcessStatus::Error(_) => ResultBuilder::ok_1(u32::MAX as u64),
            super::process::ProcessStatus::Killed => ResultBuilder::ok_1(u32::MAX as u64),
        },
        None => ResultBuilder::result(moto_rt::E_INVALID_ARGUMENT),
    }
}

fn sys_query_process_list(thread: &super::process::Thread, args: &SyscallArgs) -> SyscallResult {
    if args.version > 1 {
        return ResultBuilder::version_too_high();
    } else if args.version == 0 {
        return ResultBuilder::invalid_argument();
    }

    let flat_list = match args.flags {
        SysRay::F_QUERY_LIST => true,
        SysRay::F_QUERY_LIST_CHILDREN => false,
        _ => return ResultBuilder::invalid_argument(),
    };

    let pid = super::process::ProcessId::from_u64(args.args[0]);
    let dest_addr = args.args[1] as usize;
    let dest_num = args.args[2] as usize; // Number of structs, not number of bytes.
    if dest_num < 1 {
        return ResultBuilder::invalid_argument();
    }

    let mut counter = 0;
    let counter_ref = &mut counter;

    let address_space = thread.owner().address_space().clone();

    let mut error = moto_rt::E_OK;
    let error_ref = &mut error;

    let func = |val: &KProcessStats| -> bool {
        let mut stats = ProcessInfoV1::default();
        val.into_v1(&mut stats);

        unsafe {
            let dest_ptr = dest_addr + *counter_ref * core::mem::size_of::<ProcessInfoV1>();
            let buf: &[u8] = core::slice::from_raw_parts(
                &stats as *const _ as *const u8,
                core::mem::size_of::<ProcessInfoV1>(),
            );
            if let Err(err) = address_space.copy_to_user(buf, dest_ptr as u64) {
                *error_ref = err;
                return false;
            }
        }
        *counter_ref += 1;
        *counter_ref < dest_num
    };

    KProcessStats::iterate(pid, flat_list, func);

    if error != moto_rt::E_OK {
        return ResultBuilder::result(error);
    }

    ResultBuilder::ok_1(counter as u64)
}

/// Describe the kernel's metric catalog. The kernel is a single, unified stats
/// provider: every metric — per-process counters, per-process stats, and
/// system-wide memory — is a `MetricType`. Userspace learns the (id, name)
/// mapping here rather than hardcoding it.
fn sys_describe_stats(thread: &super::process::Thread, args: &SyscallArgs) -> SyscallResult {
    if args.version > 1 {
        return ResultBuilder::version_too_high();
    } else if args.version == 0 {
        return ResultBuilder::invalid_argument();
    }

    let dest_addr = args.args[0] as usize;
    let dest_num = args.args[1] as usize; // Number of MetricDescWire, not bytes.

    let mut catalog = alloc::vec::Vec::<MetricDescWire>::new();
    for idx in 0..(MetricType::TotalMetricTypes as usize) {
        let mt = MetricType::from_idx(idx);
        catalog.push(MetricDescWire::new(idx as u32, mt.name()));
    }

    let total = catalog.len();
    let n = total.min(dest_num);

    if n > 0 {
        unsafe {
            let src = core::slice::from_raw_parts(
                catalog.as_ptr() as *const u8,
                n * core::mem::size_of::<MetricDescWire>(),
            );
            if let Err(err) = thread
                .owner()
                .address_space()
                .copy_to_user(src, dest_addr as u64)
            {
                return ResultBuilder::result(err);
            }
        }
    }

    ResultBuilder::ok_2(n as u64, total as u64)
}

/// Read the kernel's metric values for `scope` (a PID; PID_SYSTEM is the
/// system-wide aggregate, which additionally carries the global memory metrics).
fn sys_query_stats_values(thread: &super::process::Thread, args: &SyscallArgs) -> SyscallResult {
    if args.version > 1 {
        return ResultBuilder::version_too_high();
    } else if args.version == 0 {
        return ResultBuilder::invalid_argument();
    }

    let scope = args.args[0];
    let dest_addr = args.args[1] as usize;
    let dest_num = args.args[2] as usize; // Number of MetricEntry, not bytes.

    let now = crate::arch::time::Instant::now().as_u64();
    let mut entries = alloc::vec::Vec::<MetricEntry>::new();

    // Metrics for the requested scope (PID_SYSTEM additionally carries the
    // system-wide memory metrics, filled by collect_metrics).
    match scope {
        PID_SYSTEM => {
            crate::xray::stats::system_stats_ref().collect_metrics(scope, now, &mut entries)
        }
        PID_KERNEL => {
            crate::xray::stats::kernel_stats_ref().collect_metrics(scope, now, &mut entries)
        }
        pid => {
            if let Some(ps) = crate::xray::stats::stats_from_pid(pid) {
                ps.collect_metrics(scope, now, &mut entries);
            }
        }
    }

    let total = entries.len();
    let n = total.min(dest_num);

    if n > 0 {
        unsafe {
            let src = core::slice::from_raw_parts(
                entries.as_ptr() as *const u8,
                n * core::mem::size_of::<MetricEntry>(),
            );
            if let Err(err) = thread
                .owner()
                .address_space()
                .copy_to_user(src, dest_addr as u64)
            {
                return ResultBuilder::result(err);
            }
        }
    }

    ResultBuilder::ok_2(n as u64, total as u64)
}

fn sys_log(
    curr_thread: &super::process::Thread,
    flags: u32,
    virt_addr: u64,
    sz: u64,
) -> SyscallResult {
    if (curr_thread.owner().capabilities() & moto_sys::caps::CAP_LOG) == 0 {
        return ResultBuilder::result(moto_rt::E_NOT_ALLOWED);
    }

    if flags != 0 {
        return ResultBuilder::invalid_argument();
    }

    let sz = u64::min(256, sz);
    let address_space = curr_thread.owner().address_space().clone();
    let bytes = match address_space.read_from_user(virt_addr, sz) {
        Ok(bytes) => bytes,
        Err(err) => {
            log::debug!("sys_log: read from user failed: {err:?}");
            return ResultBuilder::invalid_argument();
        }
    };

    use core::str;
    match str::from_utf8(bytes.as_slice()) {
        Ok(str) => {
            if !super::serial_console::log_to_uspace(str) {
                crate::xray::logger::log_user(curr_thread, str);
            }
        }
        Err(_) => return ResultBuilder::result(moto_rt::E_INVALID_ARGUMENT),
    };

    ResultBuilder::ok()
}

pub(super) fn sys_ray_impl(thread: &super::process::Thread, args: &SyscallArgs) -> SyscallResult {
    match args.operation {
        SysRay::OP_DBG => super::sys_ray_dbg::sys_ray_dbg_impl(thread, args),

        SysRay::OP_QUERY_PROCESS => match args.flags {
            SysRay::F_QUERY_STATUS => sys_query_process_status(thread, args),
            SysRay::F_QUERY_LIST | SysRay::F_QUERY_LIST_CHILDREN => {
                sys_query_process_list(thread, args)
            }
            _ => ResultBuilder::invalid_argument(),
        },

        SysRay::OP_QUERY_STATS => match args.flags {
            SysRay::F_STATS_DESCRIBE => sys_describe_stats(thread, args),
            SysRay::F_STATS_QUERY => sys_query_stats_values(thread, args),
            _ => ResultBuilder::invalid_argument(),
        },

        SysRay::OP_LOG => {
            if args.args[2] != 0 || args.args[3] != 0 || args.args[4] != 0 || args.args[5] != 0 {
                return ResultBuilder::invalid_argument();
            }
            sys_log(
                thread,
                args.flags,
                args.args[0], // virt_addr
                args.args[1], // sz
            )
        }

        SysRay::OP_SYS_PANIC_NOTIFY => {
            super::serial_console::sys_panic_notify();
            ResultBuilder::ok()
        }

        _ => ResultBuilder::invalid_argument(),
    }
}
