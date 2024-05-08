use crate::mm::PageType;
use crate::stats::KProcessStats;

use super::syscall::*;
use super::SysObject;
use alloc::sync::Arc;
use alloc::{borrow::ToOwned, string::String};
use log::LevelFilter;
use moto_sys::stats::ProcessStatsV1;
use moto_sys::syscalls::*;
use moto_sys::ErrorCode;

fn get_url(
    owner: &super::process::Process,
    bytes_addr: u64,
    bytes_len: u64,
) -> Result<String, ErrorCode> {
    if bytes_len > crate::config::MAX_URL_SIZE {
        return Err(ErrorCode::InvalidArgument);
    }

    let bytes = owner
        .address_space()
        .read_from_user(bytes_addr, bytes_len)?;
    let url = core::str::from_utf8(bytes.as_slice()).map_err(|_| ErrorCode::InvalidArgument)?;
    Ok(url.to_owned())
}

fn sys_handle_create(
    thread: &super::process::Thread,
    parent: SysHandle,
    url: &str,
) -> Result<SysHandle, ErrorCode> {
    if let Some((prefix, suffix)) = url.split_once(':') {
        match prefix {
            "address_space" => {
                if parent != SysHandle::NONE {
                    return Err(ErrorCode::InvalidArgument);
                }
                if thread.capabilities() & moto_sys::caps::CAP_SPAWN == 0 {
                    return Err(ErrorCode::NotAllowed);
                }

                if !suffix.starts_with("debug_name=") {
                    log::debug!("SysHandle::create: bad url: '{}'", url);
                    return Err(ErrorCode::InvalidArgument);
                }

                let debug_name = if let Some((_, s)) = suffix.split_once('=') {
                    s
                } else {
                    log::debug!("SysHandle::create: bad url: '{}'", url);
                    return Err(ErrorCode::InvalidArgument);
                };

                const NEW_PROCESS_THRESHOLD: u64 = 1 << 20; // TODO: do we need to be more precise?
                if crate::mm::oom_for_user(NEW_PROCESS_THRESHOLD) {
                    return Err(ErrorCode::OutOfMemory);
                }

                let address_space = crate::mm::user::UserAddressSpace::new().unwrap();
                let sys_object = SysObject::new_owned(
                    Arc::new(moto_sys::url_decode(debug_name)),
                    address_space,
                    alloc::sync::Weak::new(),
                );
                log::debug!("created {}", url);
                return Ok(thread.owner().add_object(sys_object));
            }
            "process" => {
                if let Ok(process) = super::process::Process::new_child(
                    thread,
                    parent,
                    &moto_sys::url_decode(suffix),
                ) {
                    log::debug!("created {}", url);
                    return Ok(thread.owner().add_object(process.self_object().unwrap()));
                } else {
                    log::debug!("Error creating process '{}'", url);
                    return Err(ErrorCode::InvalidArgument);
                }
            }
            "shared" => {
                return sys_handle_shared(SysCtl::OP_CREATE, thread, parent, suffix);
            }
            _ => {}
        }
    }
    log::debug!("SysHandle::CREATE: bad url: '{}'", url);
    Err(ErrorCode::InvalidArgument)
}

fn sys_handle_shared(
    op: u8,
    thread: &super::process::Thread,
    parent: SysHandle,
    args: &str,
) -> Result<SysHandle, ErrorCode> {
    if parent != SysHandle::SELF {
        return Err(ErrorCode::InvalidArgument);
    }

    /*
    if op == SysCtl::OP_CREATE && (thread.owner().capabilities() & moto_sys::caps::CAP_SHARE == 0)
    {
        log::debug!("Create shared {}: no CAP_SHARE.", args);
        return Err(ErrorCode::NotAllowed);
    }
    */

    let mut url = None;
    let mut address = None;
    let mut page_type = None;
    let mut page_num = None;

    for entry in args.split(';') {
        if let Some((prefix, suffix)) = entry.split_once('=') {
            match prefix {
                "url" => url = Some(moto_sys::url_decode(suffix)),
                "address" => {
                    if let Ok(num) = suffix.parse::<u64>() {
                        address = Some(num);
                    } else {
                        log::debug!("SysHandle::CREATE shared: bad argument: {}", entry);
                        return Err(ErrorCode::InvalidArgument);
                    }
                }
                "page_type" => match suffix {
                    "small" => page_type = Some(PageType::SmallPage),
                    "mid" => page_type = Some(PageType::MidPage),
                    _ => {
                        log::debug!("SysHandle::CREATE shared: bad argument: {}", entry);
                        return Err(ErrorCode::InvalidArgument);
                    }
                },
                "page_num" => {
                    if let Ok(num) = suffix.parse::<u16>() {
                        page_num = Some(num);
                    } else {
                        log::debug!("SysHandle::CREATE shared: bad argument: {}", entry);
                        return Err(ErrorCode::InvalidArgument);
                    }
                }
                _ => {
                    log::debug!("SysHandle::CREATE shared: bad argument: {}", entry);
                    return Err(ErrorCode::InvalidArgument);
                }
            }
        } else {
            log::debug!("SysHandle::CREATE shared: bad argument: {}", entry);
            return Err(ErrorCode::InvalidArgument);
        }
    }

    if url.is_none() || address.is_none() || page_type.is_none() || page_num.is_none() {
        log::debug!("SysHandle::CREATE shared: bad arguments: {}", args);
        return Err(ErrorCode::InvalidArgument);
    }

    let obj = match op {
        SysCtl::OP_CREATE => super::shared::create(
            thread.owner(),
            url.unwrap(),
            address.unwrap(),
            page_type.unwrap(),
            page_num.unwrap(),
        )?,
        SysCtl::OP_GET => super::shared::get(
            thread.owner(),
            url.unwrap(),
            address.unwrap(),
            page_type.unwrap(),
            page_num.unwrap(),
        )?,
        _ => unreachable!(),
    };
    Ok(thread.owner().add_object(obj))
}

fn sys_handle_get(
    thread: &super::process::Thread,
    parent: SysHandle,
    url: &str,
) -> Result<SysHandle, ErrorCode> {
    match url {
        "capabilities" => {
            if parent == SysHandle::SELF {
                Ok(SysHandle::from_u64(thread.owner().capabilities()))
            } else {
                log::error!("Implement gettings caps for !SELF.");
                Err(ErrorCode::NotImplemented)
            }
        }
        "main_thread" => {
            if let Some(process) = super::sys_object::object_from_handle::<super::process::Process>(
                &thread.owner(),
                parent,
            ) {
                match process.main_thread() {
                    None => Err(ErrorCode::InvalidArgument),
                    Some(mt) => match mt.self_object() {
                        None => Err(ErrorCode::InvalidArgument),
                        Some(obj) => Ok(thread.owner().add_object(obj)),
                    },
                }
            } else {
                log::error!("bad handle");
                Err(ErrorCode::InvalidArgument)
            }
        }
        "serial_console" => {
            if parent != SysHandle::KERNEL {
                return Err(ErrorCode::InvalidArgument);
            }
            let res = super::serial_console::get_for_process(&thread.owner())?;

            #[cfg(debug_assertions)]
            log::trace!("Delegated serial console to {}", thread.debug_name());
            Ok(thread.owner().add_object(res))
        }
        _ => {
            if let Some((prefix, suffix)) = url.split_once(':') {
                match prefix {
                    "irq_wait" => {
                        if parent != SysHandle::KERNEL {
                            return Err(ErrorCode::InvalidArgument);
                        }
                        if let Ok(irq) = suffix.parse::<u8>() {
                            let res = crate::sched::get_irq_wait_handle(&thread.owner(), irq)?;

                            #[cfg(debug_assertions)]
                            log::trace!(
                                "Created IRQ wait handle for irq {} for proc {}",
                                irq,
                                thread.debug_name()
                            );
                            return Ok(thread.owner().add_object(res));
                        }
                    }
                    "shared" => {
                        return sys_handle_shared(SysCtl::OP_GET, thread, parent, suffix);
                    }
                    _ => {}
                }
            }
            log::debug!("SysHandle::GET: bad url: '{}'", url);
            Err(ErrorCode::InvalidArgument)
        }
    }
}

fn sys_handle_put(
    thread: &super::process::Thread,
    owner: SysHandle,
    handle: SysHandle,
    arg: u64,
) -> Result<(), ErrorCode> {
    if owner == SysHandle::SELF && handle == SysHandle::SELF {
        log::debug!("sys_handle_put: thread exit");
        thread.finish();
    }

    if arg != 0 {
        return Err(ErrorCode::InvalidArgument);
    }

    let this_process = thread.owner();
    if owner == SysHandle::SELF {
        return this_process
            .put_object(&handle)
            .map_err(|_| ErrorCode::InvalidArgument);
    }

    match super::sys_object::object_from_handle::<super::Process>(&this_process, owner) {
        Some(proc) => proc
            .put_object(&handle)
            .map_err(|_| ErrorCode::InvalidArgument),
        None => {
            log::debug!("sys_handle_put: bad process handle");
            return Err(ErrorCode::InvalidArgument);
        }
    }
}

fn sys_query_process_status(thread: &super::process::Thread, args: &SyscallArgs) -> SyscallResult {
    if args.version > 0 {
        return ResultBuilder::version_too_high();
    }

    if args.flags != SysCtl::F_QUERY_STATUS {
        return ResultBuilder::invalid_argument();
    }

    match super::sys_object::object_from_handle::<super::process::Process>(
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
        SysCtl::F_QUERY_LIST => true,
        SysCtl::F_QUERY_LIST_CHILDREN => false,
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

fn sys_query_handle(thread: &super::process::Thread, args: &SyscallArgs) -> SyscallResult {
    if args.version > 0 {
        return ResultBuilder::version_too_high();
    }

    let handle = SysHandle::from_u64(args.args[0]);

    // See process_wait_handle in SysCpu.
    let process = thread.owner();
    let obj = process.get_object(&handle);
    if let Some(obj) = obj {
        if obj.sys_object.sibling_dropped() {
            log::debug!(
                "sys_wait: object {} has it's sibling dropped in pid {}.",
                handle.as_u64(),
                process.pid().as_u64()
            );
            return ResultBuilder::bad_handle(handle);
        }
        return ResultBuilder::ok();
    } else {
        log::debug!(
            "sys_wait: object not found in pid {} for handle {}.",
            process.pid().as_u64(),
            handle.as_u64()
        );
        return ResultBuilder::bad_handle(handle);
    }
}

pub(super) fn sys_ctl_impl(thread: &super::process::Thread, args: &SyscallArgs) -> SyscallResult {
    let parent = SysHandle::from_u64(args.args[0]);

    let io_manager = thread.owner().capabilities() & moto_sys::caps::CAP_IO_MANAGER != 0;

    match args.operation {
        SysCtl::OP_CREATE => {
            const OP_CREATE_MEMORY_THRESHOLD: u64 = 64 << 10; // TODO: do we need to be more precise?
            if !io_manager && crate::mm::oom_for_user(OP_CREATE_MEMORY_THRESHOLD) {
                return ResultBuilder::result(ErrorCode::OutOfMemory);
            }

            if args.version > 0 {
                return ResultBuilder::version_too_high();
            }

            if args.flags != 0 {
                return ResultBuilder::invalid_argument();
            }

            let url = match get_url(thread.owner().as_ref(), args.args[1], args.args[2]) {
                Ok(url) => url,
                Err(_) => {
                    log::debug!("SysHandle::GET: failed to parse URL");
                    return ResultBuilder::invalid_argument();
                }
            };

            if url == "ipc_pair" {
                match super::shared::create_ipc_pair(
                    thread,
                    parent,
                    SysHandle::from_u64(args.args[3]),
                ) {
                    Ok((h1, h2)) => return ResultBuilder::ok_2(h1.as_u64(), h2.as_u64()),
                    Err(err) => return ResultBuilder::result(err),
                }
            }

            match sys_handle_create(thread, parent, &url) {
                Ok(handle) => ResultBuilder::ok_1(handle.as_u64()),
                Err(err) => ResultBuilder::result(err),
            }
        }
        SysCtl::OP_GET => {
            if args.version > 0 {
                return ResultBuilder::version_too_high();
            }

            let mut flags = args.flags;
            let wake_peer = flags & SysCtl::F_WAKE_PEER != 0;
            if wake_peer {
                flags ^= SysCtl::F_WAKE_PEER;
            }

            if flags != 0 {
                return ResultBuilder::invalid_argument();
            }

            let url = match get_url(thread.owner().as_ref(), args.args[1], args.args[2]) {
                Ok(url) => url,
                Err(_) => {
                    log::debug!("SysHandle::GET: failed to parse URL");
                    return ResultBuilder::invalid_argument();
                }
            };

            match sys_handle_get(thread, parent, &url) {
                Ok(handle) => {
                    if wake_peer
                        && super::sys_cpu::do_wake(thread, handle, SysHandle::NONE, false).is_err()
                    {
                        log::warn!(
                            "{}: failed to wake peer for url '{}'",
                            thread.debug_name(),
                            url
                        );
                        sys_handle_put(thread, SysHandle::SELF, handle, 0).unwrap();
                        ResultBuilder::invalid_argument();
                    }
                    ResultBuilder::ok_1(handle.as_u64())
                }
                Err(err) => ResultBuilder::result(err),
            }
        }
        SysCtl::OP_PUT => {
            if args.version > 0 {
                return ResultBuilder::version_too_high();
            }

            if args.flags != 0 {
                return ResultBuilder::invalid_argument();
            }

            match sys_handle_put(
                thread,
                parent,
                SysHandle::from_u64(args.args[1]),
                args.args[2],
            ) {
                Ok(()) => ResultBuilder::ok(),
                Err(err) => ResultBuilder::result(err),
            }
        }
        SysCtl::OP_QUERY_PROCESS => match args.flags {
            SysCtl::F_QUERY_STATUS => sys_query_process_status(thread, args),
            SysCtl::F_QUERY_LIST | SysCtl::F_QUERY_LIST_CHILDREN => {
                sys_query_process_list(thread, args)
            }
            _ => ResultBuilder::invalid_argument(),
        },

        SysCtl::OP_QUERY_HANDLE => sys_query_handle(thread, args),

        SysCtl::OP_SET_LOG_LEVEL => {
            if args.version > 0 {
                return ResultBuilder::version_too_high();
            }

            if args.flags != 0 {
                return ResultBuilder::invalid_argument();
            }

            if thread.owner().capabilities() & moto_sys::caps::CAP_LOG == 0 {
                return ResultBuilder::result(ErrorCode::NotAllowed);
            }

            let curr_log_level = log::max_level() as usize as u64;
            let next_log_level = args.args[0] as usize;

            let level = match next_log_level {
                1 => LevelFilter::Error,
                2 => LevelFilter::Warn,
                3 => LevelFilter::Info,
                4 => LevelFilter::Debug,
                5 => LevelFilter::Trace,
                _ => {
                    return ResultBuilder::invalid_argument();
                }
            };

            log::set_max_level(level);
            log::info!(
                "Thread {} set log level to {:?}",
                thread.debug_name(),
                level
            );
            ResultBuilder::ok_1(curr_log_level)
        }
        _ => ResultBuilder::invalid_argument(),
    }
}
