use crate::ok_or_error;
use crate::to_result;
use crate::ErrorCode;
use crate::RtFd;
use crate::RtVdsoVtable;
use core::sync::atomic::Ordering;

#[cfg(not(feature = "rustc-dep-of-std"))]
extern crate alloc;

pub const POLL_READABLE: u64 = 1;
pub const POLL_WRITABLE: u64 = 2;
pub const POLL_READ_CLOSED: u64 = 4;
pub const POLL_WRITE_CLOSED: u64 = 8;
pub const POLL_ERROR: u64 = 16;

pub type Token = u64;
pub type Interests = u64;
pub type EventBits = u64;

#[derive(Clone, Copy, Debug)]
pub struct Event {
    pub token: Token,
    pub events: EventBits,
}

pub fn new() -> Result<RtFd, ErrorCode> {
    let vdso_poll_new: extern "C" fn() -> RtFd = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().poll_new.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    to_result!(vdso_poll_new())
}

pub fn add(
    poll_fd: RtFd,
    source_fd: RtFd,
    token: Token,
    interests: Interests,
) -> Result<(), ErrorCode> {
    let vdso_poll_add: extern "C" fn(RtFd, RtFd, u64, u64) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().poll_add.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    ok_or_error(vdso_poll_add(poll_fd, source_fd, token, interests))
}

pub fn set(
    poll_fd: RtFd,
    source_fd: RtFd,
    token: Token,
    interests: Interests,
) -> Result<(), ErrorCode> {
    let vdso_poll_set: extern "C" fn(RtFd, RtFd, u64, u64) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().poll_set.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    ok_or_error(vdso_poll_set(poll_fd, source_fd, token, interests))
}

pub fn del(poll_fd: RtFd, source_fd: RtFd) -> Result<(), ErrorCode> {
    let vdso_poll_del: extern "C" fn(RtFd, RtFd) -> ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().poll_del.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    ok_or_error(vdso_poll_del(poll_fd, source_fd))
}

pub fn wait(
    poll_fd: RtFd,
    events: *mut Event,
    events_num: usize,
    timeout: Option<crate::time::Instant>,
) -> Result<usize, ErrorCode> {
    let vdso_poll_wait: extern "C" fn(RtFd, u64, *mut Event, usize) -> i32 = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().poll_wait.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let timeout = if let Some(timo) = timeout {
        timo.as_u64()
    } else {
        u64::MAX
    };

    let res = vdso_poll_wait(poll_fd, timeout, events, events_num);
    if res < 0 {
        return Err((-res) as ErrorCode);
    }

    Ok(res as usize)
}
