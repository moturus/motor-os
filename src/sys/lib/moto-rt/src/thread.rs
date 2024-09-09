use core::sync::atomic::Ordering;

use super::error::ErrorCode;

use crate::RtVdsoVtableV1;

pub type ThreadHandle = u64;

pub fn spawn(
    thread_fn: extern "C" fn(thread_arg: u64),
    stack_size: usize,
    thread_arg: u64,
) -> Result<ThreadHandle, ErrorCode> {
    let vdso_spawn: extern "C" fn(extern "C" fn(thread_arg: u64), usize, u64) -> u64 = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().thread_spawn.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let res = vdso_spawn(thread_fn, stack_size, thread_arg);
    if res < u16::MAX as u64 {
        Err(res as ErrorCode)
    } else {
        Ok(res)
    }
}

pub fn yield_now() {
    let vdso_yield: extern "C" fn() = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().thread_yield.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    vdso_yield()
}

pub fn sleep_until(deadline: crate::time::Instant) {
    let vdso_sleep: extern "C" fn(u64) = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().thread_sleep.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    vdso_sleep(deadline.as_u64())
}

pub fn set_name(name: &str) -> ErrorCode {
    let vdso_set_name: extern "C" fn(*const u8, usize) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get()
                .thread_set_name
                .load(Ordering::Relaxed) as usize as *const (),
        )
    };

    vdso_set_name(name.as_ptr(), name.len())
}

pub fn join(handle: ThreadHandle) -> ErrorCode {
    let vdso_join: extern "C" fn(u64) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().thread_join.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    vdso_join(handle)
}
