use moto_sys::{stats::ProcessStatsV1, syscalls::SyscallResult, ErrorCode, SysHandle, SysRay};

use crate::stats::KProcessStats;

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
            super::process::ProcessStatus::Created => {
                ResultBuilder::result(ErrorCode::AlreadyInUse)
            }
            super::process::ProcessStatus::Running => {
                ResultBuilder::result(ErrorCode::AlreadyInUse)
            }
            super::process::ProcessStatus::Exiting(_) => {
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

pub(super) fn sys_ray_impl(thread: &super::process::Thread, args: &SyscallArgs) -> SyscallResult {
    match args.operation {
        SysRay::OP_QUERY_PROCESS => match args.flags {
            SysRay::F_QUERY_STATUS => sys_query_process_status(thread, args),
            SysRay::F_QUERY_LIST | SysRay::F_QUERY_LIST_CHILDREN => {
                sys_query_process_list(thread, args)
            }
            _ => ResultBuilder::invalid_argument(),
        },
        _ => ResultBuilder::invalid_argument(),
    }
}
