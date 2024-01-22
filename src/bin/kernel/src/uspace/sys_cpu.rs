use alloc::vec::Vec;
use core::sync::atomic::*;
use moto_sys::caps::CAP_IO_MANAGER;
use moto_sys::syscalls::*;
use moto_sys::ErrorCode;

use crate::config::uCpus;

use super::syscall::*;

fn process_wait_handles(
    curr: &super::process::Thread,
    args: &SyscallArgs,
    next_arg: usize,
) -> SyscallResult {
    let flags = args.flags;

    let handles: Vec<SysHandle> = if flags & SysCpu::F_HANDLE_ARRAY != 0 {
        let h_ptr = args.args[next_arg];
        let h_sz = args.args[next_arg + 1];

        if h_ptr & 3 != 0 {
            log::debug!("wait handles ptr not aligned");
            return ResultBuilder::invalid_argument();
        }

        if h_sz
            > (crate::config::get()
                .max_wait_handles
                .load(Ordering::Relaxed) as u64)
            || (h_sz == 0)
        {
            log::info!("too many wait handles: {}", h_sz);
            return ResultBuilder::invalid_argument();
        }

        let buf = match curr.owner().address_space().read_from_user(h_ptr, h_sz * 8) {
            Ok(buf) => buf,
            Err(err) => return ResultBuilder::result(err),
        };
        debug_assert_eq!(buf.len() >> 3, h_sz as usize);

        let mut handles = Vec::with_capacity(h_sz as usize);
        let mut src = buf.as_ptr();
        for _idx in 0..h_sz {
            let mut handle: u64 = 0;
            unsafe {
                let dst: *mut u8 = &mut handle as *mut u64 as *mut u8;
                core::intrinsics::copy_nonoverlapping(src, dst, 8);
                src = src.add(8);
            }

            if handle == 0 {
                continue;
            }

            handles.push(SysHandle::from_u64(handle));
        }

        handles
    } else {
        let mut handles = Vec::with_capacity(6);
        for idx in next_arg..6 {
            if args.args[idx] != 0 {
                handles.push(SysHandle::from_u64(args.args[idx]));
            }
        }

        handles
    };

    if handles.is_empty() {
        return ResultBuilder::ok();
    }

    let process = curr.owner();

    let mut objects = Vec::with_capacity(handles.len());

    for handle in &handles {
        let obj = process.get_object(handle);
        if let Some(obj) = obj {
            if obj.sys_object.sibling_dropped() {
                log::debug!(
                    "sys_wait: object {} has it's sibling dropped in pid {}.",
                    handle.as_u64(),
                    process.pid().as_u64()
                );
                return ResultBuilder::bad_handle(*handle);
            }
            objects.push((handle.clone(), obj.clone()));
        } else {
            log::debug!(
                "sys_wait: object not found in pid {} for handle {}.",
                process.pid().as_u64(),
                handle.as_u64()
            );
            return ResultBuilder::bad_handle(*handle);
        }
    }

    for (handle, obj) in &objects {
        obj.sys_object.add_waiting_thread(curr, handle.clone());
        if obj.wake_count < obj.sys_object.wake_count() || obj.sys_object.done() {
            // obj has unconsumed wakes, so queue it as a waker to the current thread.
            curr.add_waker(handle.clone())
        }
    }

    let mut wait_objects = Vec::with_capacity(objects.len());
    for (_, obj) in objects {
        wait_objects.push(obj.clone());
    }
    curr.add_wait_objects(wait_objects);

    ResultBuilder::ok()
}

pub(super) fn sys_wait_impl(curr: &super::process::Thread, args: &SyscallArgs) -> SyscallResult {
    if args.version < 1 {
        return ResultBuilder::version_too_low();
    }
    if args.version > 1 {
        log::error!("version: {}", args.version);
        return ResultBuilder::version_too_high();
    }

    let mut flags = args.flags;
    let mut timeout: u64 = u64::MAX;
    let mut wake_target = SysHandle::NONE;
    let mut wake_this_cpu = false;
    let mut next_arg = 0_usize;

    if flags & SysCpu::F_DONTBLOCK != 0 {
        if flags & SysCpu::F_TIMEOUT != 0 {
            return ResultBuilder::invalid_argument();
        }
        timeout = 0;
        flags ^= SysCpu::F_DONTBLOCK;
    }

    if flags & SysCpu::F_TIMEOUT != 0 {
        flags ^= SysCpu::F_TIMEOUT;
        timeout = args.args[next_arg];
        next_arg += 1;
    }

    if flags & SysCpu::F_SWAP_TARGET != 0 {
        flags ^= SysCpu::F_SWAP_TARGET;
        wake_target = SysHandle::from_u64(args.args[next_arg]);
        wake_this_cpu = true;
        next_arg += 1;
    }

    if flags & SysCpu::F_WAKE_TARGET != 0 {
        if wake_this_cpu {
            return ResultBuilder::invalid_argument();
        }
        flags ^= SysCpu::F_WAKE_TARGET;
        wake_target = SysHandle::from_u64(args.args[next_arg]);
        next_arg += 1;
    }

    if (flags & !SysCpu::F_HANDLE_ARRAY) != 0 {
        log::debug!("sys_wait_impl: bad flags: 0x{:x}", args.flags);
        return ResultBuilder::invalid_argument();
    }

    if wake_target != SysHandle::NONE {
        match do_wake(curr, wake_target, wake_this_cpu) {
            Err(err) => match err {
                ErrorCode::BadHandle => return ResultBuilder::bad_handle(wake_target),
                _ => return ResultBuilder::result(err),
            },
            _ => {}
        }
    }

    let result = process_wait_handles(curr, args, next_arg);
    if !result.is_ok() {
        return result;
    }

    if timeout != u64::MAX {
        curr.new_timeout(crate::arch::time::Instant::from_u64(timeout));
    }

    // We always deschedule the thread here, even if it has wakers; this is WAI, as
    // wait is at least a yield(). If this is not what the userspace wants, it should
    // use shared memory and avoid syscalls altogether.
    // (This is not necessarily true for I/O threads).
    let (timed_out, wakers) = if (timeout == 0) && (curr.capabilities() & CAP_IO_MANAGER != 0) {
        (false, curr.take_wakers())
    } else {
        curr.wait()
    };

    if wakers.len() > 6 {
        todo!()
    } // Do HANDLE_ARRAY

    let mut data = [0_u64; 6];

    for idx in 0..data.len() {
        if idx < wakers.len() {
            data[idx] = wakers[idx].as_u64();
        } else {
            data[idx] = 0;
        }
    }

    if timed_out {
        SyscallResult {
            result: ErrorCode::TimedOut as u64,
            data,
        }
    } else {
        SyscallResult {
            result: ErrorCode::Ok as u64,
            data,
        }
    }
}

pub(super) fn do_wake(
    waker: &super::process::Thread,
    handle: SysHandle,
    this_cpu: bool,
) -> Result<(), ErrorCode> {
    if let Some(obj) = waker.owner().get_object(&handle) {
        if super::shared::try_wake(&obj.sys_object, this_cpu).is_ok() {
            return Ok(());
        }
    }

    let maybe_thread =
        super::sys_object::object_from_handle::<super::process::Thread>(&waker.owner(), handle);

    if maybe_thread.is_none() {
        log::debug!(
            "bad handle 0x{:x} for process {}",
            handle.as_u64(),
            &waker.owner().pid().as_u64()
        );
        return Err(ErrorCode::BadHandle);
    }

    let thread = maybe_thread.unwrap();

    thread.post_wake(this_cpu);
    Ok(())
}

fn sys_wake_impl(waker: &super::process::Thread, args: &SyscallArgs) -> SyscallResult {
    if args.version > 0 {
        return ResultBuilder::version_too_high();
    }
    if args.flags != 0 {
        log::info!("bad flags: 0x{:x}", args.flags);
        return ResultBuilder::invalid_argument();
    }

    match do_wake(waker, SysHandle::from_u64(args.args[0]), false) {
        Ok(()) => ResultBuilder::ok(),
        Err(err) => ResultBuilder::result(err),
    }
}

fn sys_kill_impl(killer: &super::process::Thread, args: &SyscallArgs) -> SyscallResult {
    if args.version > 0 {
        return ResultBuilder::version_too_high();
    }
    if args.flags != 0 {
        log::info!("bad flags: 0x{:x}", args.flags);
        return ResultBuilder::invalid_argument();
    }

    let target = SysHandle::from_u64(args.args[0]);
    if let Err(err) = killer.owner().kill(target) {
        return ResultBuilder::result(err);
    }

    // Need to wait.
    let target_obj = killer.owner().get_object(&target).unwrap();
    target_obj
        .sys_object
        .add_waiting_thread(killer, target.clone());
    if target_obj.wake_count < target_obj.sys_object.wake_count() {
        // obj has unconsumed wakes, so queue it as a waker to the current thread.
        killer.add_waker(target.clone())
    }

    killer.add_wait_objects(alloc::vec![target_obj]);
    let _ = killer.wait();
    ResultBuilder::ok()
}

fn sys_spawn_impl(thread: &super::process::Thread, args: &SyscallArgs) -> SyscallResult {
    if args.version > 0 {
        return ResultBuilder::version_too_high();
    }
    if args.flags != 0 {
        return ResultBuilder::invalid_argument();
    }

    let handle = SysHandle::from_u64(args.args[0]);
    if handle != SysHandle::SELF {
        return ResultBuilder::invalid_argument();
    }

    if (args.args[4] | args.args[5]) != 0 {
        return ResultBuilder::invalid_argument();
    }

    let stack_size = args.args[1];
    let thread_fn = args.args[2];
    let thread_arg = args.args[3];

    match thread
        .owner()
        .spawn_thread(stack_size, thread_fn, thread_arg)
    {
        Ok(handle) => ResultBuilder::ok_1(handle.as_u64()),
        Err(ErrorCode::OutOfMemory) => ResultBuilder::result(ErrorCode::OutOfMemory),
        Err(_) => ResultBuilder::invalid_argument(),
    }
}

fn sys_cpu_usage_impl(curr: &super::process::Thread, args: &mut SyscallArgs) -> SyscallResult {
    if args.version > 0 {
        return ResultBuilder::version_too_high();
    }
    if args.flags != 0 {
        return ResultBuilder::invalid_argument();
    }

    let addr = args.args[0];
    let len = args.args[1];

    if addr == 0 || len == 0 {
        return ResultBuilder::invalid_argument();
    }

    if len < (crate::arch::num_cpus() as u64) {
        return ResultBuilder::invalid_argument();
    }

    if args.args[2] != 0 || args.args[3] != 0 || args.args[4] != 0 || args.args[5] != 0 {
        return ResultBuilder::invalid_argument();
    }

    let mut usage: Vec<f32> = Vec::with_capacity(crate::arch::num_cpus() as usize);
    for _ in 0..crate::arch::num_cpus() {
        usage.push(0.0);
    }
    crate::sched::get_usage(usage.as_mut());

    unsafe {
        let bytes = core::slice::from_raw_parts(
            usage.as_ptr() as *const u8,
            usage.len() * core::mem::size_of::<f32>(),
        );

        if curr
            .owner()
            .address_space()
            .copy_to_user(bytes, addr)
            .is_err()
        {
            return ResultBuilder::invalid_argument();
        }
    }

    ResultBuilder::ok()
}

fn sys_affine_cpu(curr: &super::process::Thread, args: &mut SyscallArgs) -> SyscallResult {
    if args.version > 0 {
        return ResultBuilder::version_too_high();
    }
    if args.flags != 0 {
        return ResultBuilder::invalid_argument();
    }

    let arg0 = args.args[0];
    let cpu = if arg0 == u64::MAX {
        None
    } else {
        if arg0 >= (crate::arch::num_cpus() as u64) {
            return ResultBuilder::invalid_argument();
        } else {
            Some(arg0 as uCpus)
        }
    };

    if let Some(0) = cpu {
        if (curr.capabilities() & moto_sys::caps::CAP_IO_MANAGER) == 0 {
            return ResultBuilder::result(ErrorCode::NotAllowed);
        }
    }

    curr.set_cpu_affinity(cpu);

    ResultBuilder::ok()
}

pub(super) fn sys_cpu_impl(curr: &super::process::Thread, args: &mut SyscallArgs) -> SyscallResult {
    match args.operation {
        SysCpu::OP_WAIT => sys_wait_impl(curr, args),
        SysCpu::OP_WAKE => sys_wake_impl(curr, args),
        SysCpu::OP_KILL => sys_kill_impl(curr, args),
        SysCpu::OP_SPAWN => sys_spawn_impl(curr, args),
        SysCpu::OP_USAGE => sys_cpu_usage_impl(curr, args),
        SysCpu::OP_AFFINE_CPU => sys_affine_cpu(curr, args),
        // Note: curr.exit() below does not return, and the compiler puts ud2 after call,
        //       so if we get INVALID_OPCODE interrupt, we screwed up in syscall_exit_asm().
        SysCpu::OP_EXIT => curr.exit(args.args[0]),
        _ => {
            log::debug!("sys_cpu: bad op: {}", args.operation);
            return ResultBuilder::invalid_argument();
        }
    }
}
