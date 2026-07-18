use alloc::vec::Vec;
use core::sync::atomic::*;
use moto_sys::caps::CAP_IO_MANAGER;
use moto_sys::ErrorCode;
use moto_sys::*;
use syscalls::SyscallResult;

use crate::config::uCpus;

use super::syscall::*;

// S13: the dominant waits pass 1-3 handles (sync RPC, io_channel clients);
// sys-io's reactor passes one per registered channel. Up to this many
// handles, the whole registration below runs off stack buffers and the
// thread's retained wait list - no heap allocations.
const INLINE_WAIT_HANDLES: usize = 16;

fn process_wait_handles(
    curr: &super::process::Thread,
    args: &SyscallArgs,
    next_arg: usize,
) -> SyscallResult {
    // NOTE: if this changes, you may need to change sys_ctl::sys_query_handle().
    let flags = args.flags;

    let mut inline_handles = [0_u64; INLINE_WAIT_HANDLES];
    let mut heap_handles: Vec<u64>;

    let handles: &[u64] = if flags & SysCpu::F_HANDLE_ARRAY != 0 {
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
            log::info!("too many wait handles: {h_sz}");
            return ResultBuilder::invalid_argument();
        }

        let dst: &mut [u64] = if (h_sz as usize) <= INLINE_WAIT_HANDLES {
            &mut inline_handles[..(h_sz as usize)]
        } else {
            heap_handles = alloc::vec![0_u64; h_sz as usize];
            &mut heap_handles
        };
        let dst_bytes = unsafe {
            core::slice::from_raw_parts_mut(dst.as_mut_ptr() as *mut u8, dst.len() * 8)
        };
        if let Err(err) = curr
            .owner()
            .address_space()
            .read_from_user_into(h_ptr, dst_bytes)
        {
            return ResultBuilder::result(err);
        }
        dst
    } else {
        &args.args[next_arg..6]
    };

    let process = curr.owner();

    // Zero handles are skipped; bad handles fail the whole call before any
    // object is registered (as before). Validated objects are staged on the
    // stack; only a wait on more than INLINE_WAIT_HANDLES objects spills.
    let mut staged: [Option<(SysHandle, super::process::WaitObject)>; INLINE_WAIT_HANDLES] =
        core::array::from_fn(|_| None);
    let mut spill: Vec<(SysHandle, super::process::WaitObject)> = Vec::new();
    let mut count = 0_usize;

    for &raw_handle in handles {
        if raw_handle == 0 {
            continue;
        }
        let handle = SysHandle::from_u64(raw_handle);

        let Some(obj) = process.get_object(&handle) else {
            log::debug!(
                "sys_wait: object not found in pid {} for handle {}.",
                process.pid().as_u64(),
                handle.as_u64()
            );
            return ResultBuilder::bad_handle(handle);
        };
        if obj.sys_object.sibling_dropped() {
            log::debug!(
                "sys_wait: object {} has it's sibling dropped in pid {}.",
                handle.as_u64(),
                process.pid().as_u64()
            );
            return ResultBuilder::bad_handle(handle);
        }

        if count < INLINE_WAIT_HANDLES {
            staged[count] = Some((handle, obj));
        } else {
            spill.push((handle, obj));
        }
        count += 1;
    }

    if count == 0 {
        return ResultBuilder::ok();
    }

    for (handle, obj) in staged
        .iter()
        .flatten()
        .chain(spill.iter())
        .map(|(handle, obj)| (*handle, obj))
    {
        obj.sys_object.add_waiting_thread(curr, handle);
        if obj.wake_count < obj.sys_object.wake_count() || obj.sys_object.done() {
            // obj has unconsumed wakes, so queue it as a waker to the current thread.
            curr.wake_by_object(handle, true);
        }
    }

    curr.add_wait_objects(
        staged
            .iter_mut()
            .filter_map(|slot| slot.take().map(|(_, obj)| obj))
            .chain(spill.into_iter().map(|(_, obj)| obj)),
    );

    ResultBuilder::ok()
}

fn process_wake_handles(
    curr: &super::process::Thread,
    args: &SyscallArgs,
    next_arg: usize,
    wakers: &[SysHandle],
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
    for handle in wakers {
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
    curr.process_stats
        .adjust_metric(crate::xray::stats::MetricType::SysCpuWaits, 1);

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

    // W7: a swap wake (F_SWAP_TARGET) tries to *claim* the wakee for a
    // direct context switch instead of posting its resume job on this CPU.
    let mut switch_to: Option<alloc::sync::Arc<super::process::Thread>> = None;
    if wake_target != SysHandle::NONE {
        let wake_result = if wake_this_cpu {
            match do_wake_for_switch(curr, wake_target) {
                Ok(claimed) => {
                    switch_to = claimed;
                    Ok(())
                }
                Err(err) => Err(err),
            }
        } else {
            do_wake(curr, wake_target, SysHandle::NONE, false)
        };
        if let Err(err) = wake_result {
            match err {
                moto_rt::E_BAD_HANDLE => return ResultBuilder::bad_handle(wake_target),
                _ => return ResultBuilder::result(err),
            }
        }
    }

    let result = process_wait_handles(curr, args, next_arg);
    if !result.is_ok() {
        if let Some(next) = switch_to {
            next.release_switch_claim();
        }
        return result;
    }

    if let Some(next) = switch_to {
        if (timeout == 0) && (curr.capabilities() & CAP_IO_MANAGER != 0) {
            // A non-blocking IO-manager poll never deschedules (see the
            // take_wakers branch below) — keep that: release the claim,
            // which posts the wakee's job on this CPU as the queue path
            // would have.
            next.release_switch_claim();
        } else {
            // Direct switch: hand the CPU to the wakee right now — no
            // queue round trip, no sched-loop iteration, no pause/resume
            // pair. The swap semantic ("hand the CPU over") makes this the
            // real yield; if we have pending wakes, our park bookkeeping
            // re-posts us immediately (see on_thread_paused via
            // finish_direct_switch).
            crate::xray::stats::kernel_stats()
                .adjust_metric(crate::xray::stats::MetricType::DirectSwitch, 1);
            if timeout != u64::MAX {
                curr.new_timeout(crate::arch::time::Instant::from_u64(timeout));
            }
            let (timed_out, wakers) = curr.wait_and_switch(next);
            return process_wake_handles(curr, args, next_arg, wakers.as_slice(), timed_out);
        }
    } else if wake_this_cpu {
        crate::xray::stats::kernel_stats()
            .adjust_metric(crate::xray::stats::MetricType::DirectSwitchMiss, 1);
    }

    // W5 fast path: wait is "at least a yield()" — but when wakes are
    // already queued and this CPU has nothing else ready to run, the pause
    // is a pure no-op round trip through the scheduler (on_thread_paused()
    // re-posts the thread immediately, often with a migration): take the
    // wakers without descheduling. When something IS runnable on this CPU —
    // including a swap target woken onto it above — the yield is real and
    // the pause is kept. Placed before the timeout registration so no timer
    // is created and cancelled for nothing.
    if curr.has_pending_wakes() && crate::sched::this_cpu_has_no_ready_work() {
        crate::xray::stats::kernel_stats()
            .adjust_metric(crate::xray::stats::MetricType::WaitFastPath, 1);
        let wakers = curr.take_wakers();
        return process_wake_handles(curr, args, next_arg, wakers.as_slice(), false);
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
        crate::xray::stats::kernel_stats()
            .adjust_metric(crate::xray::stats::MetricType::WaitPaused, 1);
        curr.wait()
    };

    process_wake_handles(curr, args, next_arg, wakers.as_slice(), timed_out)
}

// W7: do_wake(waker, wake_target, SysHandle::NONE, true), but claiming the
// wakee for a direct switch when it is InWait. Ok(Some(_)) = claimed (the
// caller MUST switch to it or release it); Ok(None) = woken (or nothing to
// wake) via the normal paths.
fn do_wake_for_switch(
    waker: &super::process::Thread,
    wake_target: SysHandle,
) -> Result<Option<alloc::sync::Arc<super::process::Thread>>, ErrorCode> {
    if let Some(obj) = waker.owner().get_object(&wake_target) {
        if let Ok(claimed) = super::shared::try_wake_for_switch(&obj.sys_object) {
            return Ok(claimed);
        }
    }

    if let Some(thread) =
        super::sysobject::object_from_handle::<super::process::Thread>(&waker.owner(), wake_target)
    {
        Ok(thread.post_wake_for_switch())
    } else {
        log::debug!(
            "{}: waker 0x{:x} not found",
            waker.debug_name(),
            wake_target.as_u64()
        );
        Err(moto_rt::E_BAD_HANDLE)
    }
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
            "{}: waker 0x{:x} not found",
            waker.debug_name(),
            wake_target.as_u64()
        );
        Err(moto_rt::E_BAD_HANDLE)
    }
}

fn sys_wake_impl(waker: &super::process::Thread, args: &SyscallArgs) -> SyscallResult {
    waker
        .process_stats
        .adjust_metric(crate::xray::stats::MetricType::SysCpuWakes, 1);

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
    if target == SysHandle::KERNEL {
        if killer.capabilities() & moto_sys::caps::CAP_SHUTDOWN != 0 {
            log::info!("Shutting down via `{}`", killer.owner().debug_name());
            crate::arch::kernel_exit();
        }
        // TODO: check for CAP_SHUTDOWN.
        return ResultBuilder::result(moto_rt::E_NOT_ALLOWED);
    }

    if let Err(err) = killer.owner().kill(target) {
        return ResultBuilder::result(err);
    }

    // Need to wait.
    let target_obj = killer.owner().get_object(&target).unwrap();
    target_obj.sys_object.add_waiting_thread(killer, target);
    if target_obj.wake_count < target_obj.sys_object.wake_count() {
        // obj has unconsumed wakes, so queue it as a waker to the current thread.
        killer.add_waker(target)
    }

    killer.add_wait_objects(core::iter::once(target_obj));
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

    let mut usage: Vec<f32> = alloc::vec![0.0; crate::arch::num_cpus() as usize];
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
    } else if arg0 >= (crate::arch::num_cpus() as u64) {
        return ResultBuilder::invalid_argument();
    } else {
        Some(arg0 as uCpus)
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
    curr.process_stats
        .adjust_metric(crate::xray::stats::MetricType::SysCpuCalls, 1);

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
        SysCpu::OP_EXIT_PROCESS => curr.exit_process(args.args[0]),
        _ => {
            log::debug!("sys_cpu: bad op: {}", args.operation);
            ResultBuilder::invalid_argument()
        }
    }
}
