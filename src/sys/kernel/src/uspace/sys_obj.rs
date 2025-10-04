use crate::mm::PageType;

use super::syscall::*;
use super::SysObject;
use alloc::string::String;
use alloc::sync::Arc;
use moto_sys::ErrorCode;
use moto_sys::*;
use syscalls::SyscallResult;

fn get_url(
    owner: &super::process::Process,
    bytes_addr: u64,
    bytes_len: u64,
) -> Result<String, ErrorCode> {
    if bytes_len > crate::config::MAX_URL_SIZE {
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }

    let bytes = owner
        .address_space()
        .read_from_user(bytes_addr, bytes_len)?;
    let url = core::str::from_utf8(bytes.as_slice()).map_err(|_| moto_rt::E_INVALID_ARGUMENT)?;
    Ok(alloc::borrow::ToOwned::to_owned(url))
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
                    return Err(moto_rt::E_INVALID_ARGUMENT);
                }
                if thread.capabilities() & moto_sys::caps::CAP_SPAWN == 0 {
                    return Err(moto_rt::E_NOT_ALLOWED);
                }

                if !suffix.starts_with("debug_name=") {
                    log::debug!("SysHandle::create: bad url: '{url}'");
                    return Err(moto_rt::E_INVALID_ARGUMENT);
                }

                let debug_name = if let Some((_, s)) = suffix.split_once('=') {
                    s
                } else {
                    log::debug!("SysHandle::create: bad url: '{url}'");
                    return Err(moto_rt::E_INVALID_ARGUMENT);
                };

                const NEW_PROCESS_THRESHOLD: u64 = 1 << 20; // TODO: do we need to be more precise?
                if crate::mm::oom_for_user(NEW_PROCESS_THRESHOLD) {
                    return Err(moto_rt::E_OUT_OF_MEMORY);
                }

                let address_space = crate::mm::user::UserAddressSpace::new().unwrap();
                let sys_object = SysObject::new_owned(
                    Arc::new(moto_sys::url_decode(debug_name)),
                    address_space,
                    alloc::sync::Weak::new(),
                );
                log::debug!("created {url}");
                return Ok(thread.owner().add_object(sys_object));
            }
            "process" => {
                if let Ok(process) = super::process::Process::new_child(
                    thread,
                    parent,
                    &moto_sys::url_decode(suffix),
                ) {
                    log::debug!("created {url}");
                    return Ok(thread.owner().add_object(process.self_object().unwrap()));
                } else {
                    log::debug!("Error creating process '{url}'");
                    return Err(moto_rt::E_INVALID_ARGUMENT);
                }
            }
            "shared" => {
                return sys_handle_shared(SysObj::OP_CREATE, thread, parent, suffix);
            }
            _ => {}
        }
    }
    log::debug!("SysHandle::CREATE: bad url: '{url}'");
    Err(moto_rt::E_INVALID_ARGUMENT)
}

fn sys_handle_shared(
    op: u8,
    thread: &super::process::Thread,
    parent: SysHandle,
    args: &str,
) -> Result<SysHandle, ErrorCode> {
    if parent != SysHandle::SELF {
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }

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
                        log::debug!("SysHandle::CREATE shared: bad argument: {entry}");
                        return Err(moto_rt::E_INVALID_ARGUMENT);
                    }
                }
                "page_type" => match suffix {
                    "small" => page_type = Some(PageType::SmallPage),
                    "mid" => page_type = Some(PageType::MidPage),
                    _ => {
                        log::debug!("SysHandle::CREATE shared: bad argument: {entry}");
                        return Err(moto_rt::E_INVALID_ARGUMENT);
                    }
                },
                "page_num" => {
                    if let Ok(num) = suffix.parse::<u16>() {
                        page_num = Some(num);
                    } else {
                        log::debug!("SysHandle::CREATE shared: bad argument: {entry}");
                        return Err(moto_rt::E_INVALID_ARGUMENT);
                    }
                }
                _ => {
                    log::debug!("SysHandle::CREATE shared: bad argument: {entry}");
                    return Err(moto_rt::E_INVALID_ARGUMENT);
                }
            }
        } else {
            log::debug!("SysHandle::CREATE shared: bad argument: {entry}");
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
    }

    if url.is_none() || address.is_none() || page_type.is_none() || page_num.is_none() {
        log::debug!("sys_handle_shared: bad arguments: {args}");
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }

    let obj = match op {
        SysObj::OP_CREATE => super::shared::create(
            thread.owner(),
            url.unwrap(),
            address.unwrap(),
            page_type.unwrap(),
            page_num.unwrap(),
        )?,
        SysObj::OP_GET => super::shared::get(
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
                Err(moto_rt::E_NOT_IMPLEMENTED)
            }
        }
        "main_thread" => {
            if let Some(process) = super::sysobject::object_from_handle::<super::process::Process>(
                &thread.owner(),
                parent,
            ) {
                match process.main_thread() {
                    None => Err(moto_rt::E_INVALID_ARGUMENT),
                    Some(mt) => match mt.self_object() {
                        None => Err(moto_rt::E_INVALID_ARGUMENT),
                        Some(obj) => Ok(thread.owner().add_object(obj)),
                    },
                }
            } else {
                log::error!("bad handle");
                Err(moto_rt::E_INVALID_ARGUMENT)
            }
        }
        "serial_console" => {
            if parent != SysHandle::KERNEL {
                return Err(moto_rt::E_INVALID_ARGUMENT);
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
                            return Err(moto_rt::E_INVALID_ARGUMENT);
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
                        return sys_handle_shared(SysObj::OP_GET, thread, parent, suffix);
                    }
                    _ => {}
                }
            }
            log::debug!("SysHandle::GET: bad url: '{url}'");
            Err(moto_rt::E_INVALID_ARGUMENT)
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
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }

    let this_process = thread.owner();
    if owner == SysHandle::SELF {
        return this_process
            .put_object(&handle)
            .map_err(|_| moto_rt::E_BAD_HANDLE);
    }

    match super::sysobject::object_from_handle::<super::Process>(&this_process, owner) {
        Some(proc) => proc
            .put_object(&handle)
            .map_err(|_| moto_rt::E_INVALID_ARGUMENT),
        None => {
            log::debug!("sys_handle_put: bad process handle");
            Err(moto_rt::E_INVALID_ARGUMENT)
        }
    }
}

fn sys_query_handle(thread: &super::process::Thread, args: &SyscallArgs) -> SyscallResult {
    if args.version > 0 {
        return ResultBuilder::version_too_high();
    }

    let handle = SysHandle::from_u64(args.args[0]);

    let (return_pid, query_peer) = match args.flags {
        0 => (false, false),
        SysObj::F_QUERY_PID => (true, false),
        SysObj::F_QUERY_PEER => (false, true),
        _ => return ResultBuilder::invalid_argument(),
    };

    // See process_wait_handle in SysCpu.
    let process = thread.owner();
    let obj = process.get_object(&handle);
    if let Some(obj) = obj {
        if obj.sys_object.sibling_dropped() {
            log::debug!(
                "sys_query_handle: object {} has it's sibling dropped in pid {}.",
                handle.as_u64(),
                process.pid().as_u64()
            );
            return ResultBuilder::bad_handle(handle);
        }

        if query_peer {
            match super::shared::has_peer(&obj.sys_object) {
                Ok(connected) => {
                    if connected {
                        return ResultBuilder::ok();
                    } else {
                        return ResultBuilder::result(moto_rt::E_NOT_CONNECTED);
                    }
                }
                Err(err) => return ResultBuilder::result(err),
            }
        }

        if !return_pid {
            return ResultBuilder::ok();
        }

        let Some(proc) = super::shared::peer_owner(thread.owner().pid(), &obj.sys_object) else {
            return ResultBuilder::result(moto_rt::E_NOT_FOUND);
        };

        ResultBuilder::ok_1(proc.pid().as_u64())
    } else {
        log::debug!(
            "sys_query_handle: object not found in pid {} for handle {}.",
            process.pid().as_u64(),
            handle.as_u64()
        );
        ResultBuilder::bad_handle(handle)
    }
}

pub(super) fn sys_ctl_impl(thread: &super::process::Thread, args: &SyscallArgs) -> SyscallResult {
    let parent = SysHandle::from_u64(args.args[0]);

    let io_manager = thread.owner().capabilities() & moto_sys::caps::CAP_IO_MANAGER != 0;

    match args.operation {
        SysObj::OP_CREATE => {
            const OP_CREATE_MEMORY_THRESHOLD: u64 = 64 << 10; // TODO: do we need to be more precise?
            if !io_manager && crate::mm::oom_for_user(OP_CREATE_MEMORY_THRESHOLD) {
                return ResultBuilder::result(moto_rt::E_OUT_OF_MEMORY);
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
        SysObj::OP_GET => {
            if args.version > 0 {
                return ResultBuilder::version_too_high();
            }

            let mut flags = args.flags;
            let wake_peer = flags & SysObj::F_WAKE_PEER != 0;
            if wake_peer {
                flags ^= SysObj::F_WAKE_PEER;
            }

            if flags != 0 {
                return ResultBuilder::invalid_argument();
            }

            let Ok(url) = get_url(thread.owner().as_ref(), args.args[1], args.args[2]) else {
                log::debug!("SysHandle::GET: failed to parse URL");
                return ResultBuilder::invalid_argument();
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
                        return ResultBuilder::invalid_argument();
                    }
                    ResultBuilder::ok_1(handle.as_u64())
                }
                Err(err) => ResultBuilder::result(err),
            }
        }
        SysObj::OP_PUT => {
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
        SysObj::OP_QUERY_HANDLE => sys_query_handle(thread, args),

        _ => ResultBuilder::invalid_argument(),
    }
}
