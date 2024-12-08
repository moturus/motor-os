use crate::posix;
use crate::posix::PosixFile;
use crate::runtime::Registry;
use alloc::collections::btree_map::BTreeMap;
use alloc::sync::Arc;
use core::any::Any;
use moto_rt::poll::Event;
use moto_rt::ErrorCode;
use moto_rt::RtFd;
use moto_rt::E_BAD_HANDLE;

pub extern "C" fn new() -> RtFd {
    posix::new_file(|fd| Arc::new(Registry::new(fd)))
}

pub extern "C" fn add(poll_fd: RtFd, source_fd: RtFd, token: u64, events: u64) -> ErrorCode {
    let Some(posix_file) = posix::get_file(poll_fd) else {
        return E_BAD_HANDLE;
    };
    let Some(registry) = (posix_file.as_ref() as &dyn Any).downcast_ref::<Registry>() else {
        return E_BAD_HANDLE;
    };

    registry.add(source_fd, token, events)
}

pub extern "C" fn set(poll_fd: RtFd, source_fd: RtFd, token: u64, events: u64) -> ErrorCode {
    let Some(posix_file) = posix::get_file(poll_fd) else {
        return E_BAD_HANDLE;
    };
    let Some(registry) = (posix_file.as_ref() as &dyn Any).downcast_ref::<Registry>() else {
        return E_BAD_HANDLE;
    };

    registry.set(source_fd, token, events)
}

pub extern "C" fn del(poll_fd: RtFd, source_fd: RtFd) -> ErrorCode {
    let Some(posix_file) = posix::get_file(poll_fd) else {
        return E_BAD_HANDLE;
    };
    let Some(registry) = (posix_file.as_ref() as &dyn Any).downcast_ref::<Registry>() else {
        return E_BAD_HANDLE;
    };

    registry.del(source_fd)
}

// Returns the number of events or minus error code.
pub unsafe extern "C" fn wait(
    poll_fd: RtFd,
    timeout: u64,
    events_ptr: *mut Event,
    events_num: usize,
) -> i32 {
    assert!(events_num < (i32::MAX as usize));

    let Some(posix_file) = posix::get_file(poll_fd) else {
        return -(E_BAD_HANDLE as i32);
    };
    let Some(registry) = (posix_file.as_ref() as &dyn Any).downcast_ref::<Registry>() else {
        return -(E_BAD_HANDLE as i32);
    };

    let events = core::slice::from_raw_parts_mut(events_ptr, events_num);
    let deadline = if timeout == u64::MAX {
        None
    } else {
        Some(moto_rt::time::Instant::from_u64(timeout))
    };
    registry.wait(events, deadline)
}
