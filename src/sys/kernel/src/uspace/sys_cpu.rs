use alloc::vec::Vec;
use core::sync::atomic::*;
use moto_sys::caps::CAP_IO_MANAGER;
use moto_sys::ErrorCode;
use moto_sys::*;
use syscalls::SyscallResult;

use crate::config::uCpus;

use super::syscall::*;

fn process_wait_handles(
    curr: &super::process::Thread,
    args: &SyscallArgs,
    next_arg: usize,
) -> SyscallResult {
    // NOTE: if this changes, you may need to change sys_ctl::sys_query_handle().
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

fn process_wake_handles(
    curr: &super::process::Thread,
    args: &SyscallArgs,
    next_arg: usize,
    wakers: Vec<SysHandle>,
    timed_out: bool,
) -> SyscallResult {
    if wakers.len() < 6 {
        let mut data = [0_u64; 6];

        for idx in 0..data.len() {
            if idx < wakers.len() {
                data[idx] = wakers[idx].as_u64();
            } else {
                data[idx] = 0;
            }
        }

        if timed_out {
            return SyscallResult {
                result: moto_rt::E_TIMED_OUT as u64,
                data,
            };
        } else {
            return SyscallResult {
                result: moto_rt::E_OK as u64,
                data,
            };
        }
    }

    // We assume, below, that args have been validated in process_wait_handles().
    assert_ne!(0, args.flags & SysCpu::F_HANDLE_ARRAY);
    let h_ptr = args.args[next_arg];
    let h_sz = args.args[next_arg + 1];
    assert!(wakers.len() <= h_sz as usize);

    let mut idx = 0;
    for handle in &wakers {
        let val = u64::from(handle);
        let buf: &[u8] =
            unsafe { core::slice::from_raw_parts(&val as *const _ as usize as *const u8, 8) };
        curr.owner()
            .address_space()
            .copy_to_user(buf, h_ptr + 8 * idx)
            .unwrap();
        idx += 1;
    }

    let zero = 0_u64;
    let buf_zero: &[u8] =
        unsafe { core::slice::from_raw_parts(&zero as *const _ as usize as *const u8, 8) };
    for pos in idx..h_sz {
        curr.owner()
            .address_space()
            .copy_to_user(buf_zero, h_ptr + 8 * pos)
            .unwrap();
    }

    let mut result = ResultBuilder::ok();
    result.result |= SyscallResult::F_HANDLE_ARRAY;
    if timed_out {
        result.result |= moto_rt::E_TIMED_OUT as u64;
    }

    result
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
        match do_wake(curr, wake_target, SysHandle::NONE, wake_this_cpu) {
            Err(err) => match err {
                moto_rt::E_BAD_HANDLE => return ResultBuilder::bad_handle(wake_target),
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

    process_wake_handles(curr, args, next_arg, wakers, timed_out)
}

pub(super) fn do_wake(
    waker: &super::process::Thread,
    wake_target: SysHandle,
    wakee_thread: SysHandle,
    this_cpu: bool,
) -> Result<(), ErrorCode> {
    if wake_target == SysHandle::SELF && wakee_thread != SysHandle::NONE {
        if let Some(thread) = super::sysobject::object_from_handle::<super::process::Thread>(
            &waker.owner(),
            wakee_thread,
        ) {
            thread.post_wake(this_cpu);
            return Ok(());
        }
        log::debug!(
            "{}: in-process wakee_thread 0x{:x} not found",
            waker.debug_name(),
            wakee_thread.as_u64()
        );
        return Err(moto_rt::E_BAD_HANDLE);
    }

    if let Some(obj) = waker.owner().get_object(&wake_target) {
        if super::shared::try_wake(&obj.sys_object, wakee_thread, this_cpu).is_ok() {
            return Ok(());
        }
    } else if wakee_thread != SysHandle::NONE {
        log::debug!(
            "{}: wakee thread 0x{:x} not found",
            waker.debug_name(),
            wakee_thread.as_u64()
        );
        return Err(moto_rt::E_BAD_HANDLE);
    }

    if let Some(thread) =
        super::sysobject::object_from_handle::<super::process::Thread>(&waker.owner(), wake_target)
    {
        thread.post_wake(this_cpu);
        Ok(())
    } else {
        log::debug!(
            "{}: wakee 0x{:x} not found",
            waker.debug_name(),
            wake_target.as_u64()
        );
        Err(moto_rt::E_BAD_HANDLE)
    }
}

fn sys_wake_impl(waker: &super::process::Thread, args: &SyscallArgs) -> SyscallResult {
    if args.version > 0 {
        return ResultBuilder::version_too_high();
    }
    if args.flags != 0 {
        log::debug!("bad flags: 0x{:x}", args.flags);
        return ResultBuilder::invalid_argument();
    }

    match do_wake(waker, args.args[0].into(), args.args[1].into(), false) {
        Ok(()) => ResultBuilder::ok(),
        Err(err) => ResultBuilder::result(err),
    }
}

fn sys_kill_impl(killer: &super::process::Thread, args: &SyscallArgs) -> SyscallResult {
    if args.version > 0 {
        return ResultBuilder::version_too_high();
    }
    let target = SysHandle::from_u64(args.args[0]);

    if args.flags == SysCpu::F_KILL_PEER {
        if (killer.capabilities() & moto_sys::caps::CAP_IO_MANAGER) == 0 {
            // This is used by sys-io.
            return ResultBuilder::result(moto_rt::E_NOT_ALLOWED);
        }
        if let Some(obj) = killer.owner().get_object(&target) {
            if let Some(victim) = super::shared::peer_owner(killer.owner().pid(), &obj.sys_object) {
                log::info!(
                    "{} killing remote {}",
                    killer.debug_name(),
                    victim.debug_name()
                );
                victim.die();
                return ResultBuilder::ok();
            }
        }
        return ResultBuilder::result(moto_rt::E_BAD_HANDLE);
    }

    if args.flags == SysCpu::F_KILL_PID {
        let target_pid = args.args[0];
        if let Some(target_stats) = crate::xray::stats::stats_from_pid(target_pid) {
            if let Some(target) = target_stats.owner.upgrade() {
                if target.capabilities() & moto_sys::caps::CAP_SYS != 0 {
                    return ResultBuilder::result(moto_rt::E_NOT_ALLOWED);
                } else {
                    log::debug!(
                        "process {} killed by {}",
                        target.debug_name(),
                        killer.owner().debug_name()
                    );
                    target.die();
                    return ResultBuilder::ok();
                }
            } else {
                return ResultBuilder::result(moto_rt::E_INVALID_ARGUMENT);
            }
        } else {
            return ResultBuilder::result(moto_rt::E_INVALID_ARGUMENT);
        }
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

    const NEW_THREAD_THRESHOLD: u64 = 1024 * 256; // TODO: do we need to be more precise?
    if crate::mm::oom_for_user(NEW_THREAD_THRESHOLD) {
        return ResultBuilder::result(moto_rt::E_OUT_OF_MEMORY);
    }

    let stack_size = args.args[1];
    let thread_fn = args.args[2];
    let thread_arg = args.args[3];

    match thread
        .owner()
        .spawn_thread(stack_size, thread_fn, thread_arg)
    {
        Ok(handle) => ResultBuilder::ok_1(handle.as_u64()),
        Err(moto_rt::E_OUT_OF_MEMORY) => ResultBuilder::result(moto_rt::E_OUT_OF_MEMORY),
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
            return ResultBuilder::result(moto_rt::E_NOT_ALLOWED);
        }
    }

    curr.set_cpu_affinity(cpu);

    ResultBuilder::ok()
}

fn sys_query_percpu_stats(curr: &super::process::Thread, args: &mut SyscallArgs) -> SyscallResult {
    if args.version > 0 {
        return ResultBuilder::version_too_high();
    }
    if args.flags != 0 {
        return ResultBuilder::invalid_argument();
    }

    let user_page_addr = args.args[0];
    let page_addr = if let Ok(addr) = curr
        .owner()
        .address_space()
        .get_user_page_as_kernel(user_page_addr)
    {
        addr
    } else {
        return ResultBuilder::invalid_argument();
    };

    let num_entries = crate::xray::stats::fill_percpu_stats_page(page_addr as usize);
    ResultBuilder::ok_1(num_entries as u64)
}

pub(super) fn sys_cpu_impl(curr: &super::process::Thread, args: &mut SyscallArgs) -> SyscallResult {
    match args.operation {
        SysCpu::OP_WAIT => sys_wait_impl(curr, args),
        SysCpu::OP_WAKE => sys_wake_impl(curr, args),
        SysCpu::OP_KILL => sys_kill_impl(curr, args),
        SysCpu::OP_SPAWN => sys_spawn_impl(curr, args),
        SysCpu::OP_USAGE => sys_cpu_usage_impl(curr, args),
        SysCpu::OP_AFFINE_CPU => sys_affine_cpu(curr, args),
        SysCpu::OP_QUERY_PERCPU_STATS => sys_query_percpu_stats(curr, args),
        // Note: curr.exit() below does not return, and the compiler puts ud2 after call,
        //       so if we get INVALID_OPCODE interrupt, we screwed up in syscall_exit_asm().
        SysCpu::OP_EXIT => curr.exit(args.args[0]),
        _ => {
            log::debug!("sys_cpu: bad op: {}", args.operation);
            return ResultBuilder::invalid_argument();
        }
    }
}
