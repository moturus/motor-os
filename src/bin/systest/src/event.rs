use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use moto_sys::{ErrorCode, SysHandle};

fn test_single_event() {
    let event_handle = moto_sys::SysObj::create_local_event().unwrap();

    let mut wait_handles = [event_handle];
    let result = moto_sys::SysCpu::wait(
        &mut wait_handles,
        SysHandle::NONE,
        SysHandle::NONE,
        Some(moto_sys::time::Instant::now() + Duration::from_millis(10)),
    );

    assert_eq!(result.err().unwrap(), ErrorCode::TimedOut);

    let barrier_here = Arc::new(AtomicU64::new(0));
    let barrier_there = barrier_here.clone();
    let thread = std::thread::spawn(move || {
        let mut wait_handles = [event_handle];
        moto_sys::SysCpu::wait(&mut wait_handles, SysHandle::NONE, SysHandle::NONE, None).unwrap();
        assert_eq!(1, wait_handles.len());
        assert_eq!(event_handle, wait_handles[0]);
        barrier_there.fetch_add(1, Ordering::AcqRel);
    });

    std::thread::sleep(Duration::from_millis(10));
    assert_eq!(0, barrier_here.load(Ordering::Acquire));
    moto_sys::SysCpu::wake(event_handle).unwrap();
    thread.join().unwrap();
    assert_eq!(1, barrier_here.load(Ordering::Acquire));

    moto_sys::SysObj::put(event_handle).unwrap();
    println!("event::test_single_event() PASS");
}

fn test_early_wake() {
    let event_handle = moto_sys::SysObj::create_local_event().unwrap();

    // Wake first.
    moto_sys::SysCpu::wake(event_handle).unwrap();

    // Make sure the wait does not block: the event is woken.
    let mut wait_handles = [event_handle];
    moto_sys::SysCpu::wait(&mut wait_handles, SysHandle::NONE, SysHandle::NONE, None).unwrap();
    assert_eq!(1, wait_handles.len());
    assert_eq!(event_handle, wait_handles[0]);

    moto_sys::SysObj::put(event_handle).unwrap();
    println!("event::test_early_wake() PASS");
}

fn test_second_wait() {
    let event_handle = moto_sys::SysObj::create_local_event().unwrap();

    // Wake first.
    moto_sys::SysCpu::wake(event_handle).unwrap();

    // Make sure the wait does not block: the event is woken.
    let mut wait_handles = [event_handle];
    moto_sys::SysCpu::wait(&mut wait_handles, SysHandle::NONE, SysHandle::NONE, None).unwrap();
    assert_eq!(1, wait_handles.len());
    assert_eq!(event_handle, wait_handles[0]);

    // But the second wait should block/timeout, because the first wake has been consumed.
    let result = moto_sys::SysCpu::wait(
        &mut wait_handles,
        SysHandle::NONE,
        SysHandle::NONE,
        Some(moto_sys::time::Instant::now() + Duration::from_millis(10)),
    );

    assert_eq!(result.err().unwrap(), ErrorCode::TimedOut);

    moto_sys::SysObj::put(event_handle).unwrap();
    println!("event::test_second_wake() PASS");
}

pub fn test() {
    test_single_event();
    test_early_wake();
    test_second_wait();
}
