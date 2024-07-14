use moto_sys::{stats::ProcessStatsV1, syscalls::SyscallResult, ErrorCode, SysHandle, SysRay};

use crate::xray::stats::KProcessStats;

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
                ResultBuilder::result(ErrorCode::AlreadyInUse)
            }
            super::process::ProcessStatus::Exited(code) => ResultBuilder::ok_1(code),
            super::process::ProcessStatus::Error(_) => ResultBuilder::ok_1(u32::MAX as u64),
            super::process::ProcessStatus::Killed => ResultBuilder::ok_1(u32::MAX as u64),
        },
        None => ResultBuilder::result(ErrorCode::InvalidArgument),
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

    let mut error = ErrorCode::Ok;
    let error_ref = &mut error;

    let now = crate::arch::time::Instant::now().as_u64();

    let func = |val: &KProcessStats| -> bool {
        let mut stats = ProcessStatsV1::default();
        val.into_v1(&mut stats, now);

        unsafe {
            let dest_ptr = dest_addr + *counter_ref * core::mem::size_of::<ProcessStatsV1>();
            let buf: &[u8] = core::slice::from_raw_parts(
                &stats as *const _ as *const u8,
                core::mem::size_of::<ProcessStatsV1>(),
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

    if error != ErrorCode::Ok {
        return ResultBuilder::result(error);
    }

    ResultBuilder::ok_1(counter as u64)
}

fn sys_log(
    curr_thread: &super::process::Thread,
    flags: u32,
    virt_addr: u64,
    sz: u64,
) -> SyscallResult {
    if (curr_thread.owner().capabilities() & moto_sys::caps::CAP_LOG) == 0 {
        return ResultBuilder::result(ErrorCode::NotAllowed);
    }

    if flags != 0 {
        return ResultBuilder::invalid_argument();
    }

    let sz = u64::min(256, sz);
    let address_space = curr_thread.owner().address_space().clone();
    let bytes = match address_space.read_from_user(virt_addr, sz) {
        Ok(bytes) => bytes,
        Err(err) => {
            log::debug!("sys_debug: read from user failed: {:?}", err);
            return ResultBuilder::invalid_argument();
        }
    };

    use core::str;
    match str::from_utf8(bytes.as_slice()) {
        Ok(str) => {
            crate::xray::logger::log_user(curr_thread, str);
        }
        Err(_) => return ResultBuilder::result(ErrorCode::InvalidArgument),
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
        SysRay::OP_LOG => {
            if args.args[2] != 0 || args.args[3] != 0 || args.args[4] != 0 || args.args[5] != 0 {
                return ResultBuilder::invalid_argument();
            }
            return sys_log(
                thread,
                args.flags,
                args.args[0], // virt_addr
                args.args[1], // sz
            );
        }
        _ => ResultBuilder::invalid_argument(),
    }
}
