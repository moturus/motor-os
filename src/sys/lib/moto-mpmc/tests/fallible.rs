#![cfg(not(target_os = "motor"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Clone, Copy, Default)]
struct Tracking {
    fail_at: usize,
    attempts: usize,
    live_bytes: isize,
    failed_bytes: usize,
}

thread_local! {
    static TRACKING: Cell<Option<Tracking>> = const { Cell::new(None) };
}

struct Allocator;

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let fail = TRACKING
            .try_with(|tracking| {
                let Some(mut state) = tracking.get() else {
                    return false;
                };
                state.attempts += 1;
                let fail = state.attempts == state.fail_at;
                if fail {
                    state.failed_bytes = layout.size();
                }
                tracking.set(Some(state));
                fail
            })
            .unwrap_or(false);
        if fail {
            return std::ptr::null_mut();
        }
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let _ = TRACKING.try_with(|tracking| {
                if let Some(mut state) = tracking.get() {
                    state.live_bytes += layout.size() as isize;
                    tracking.set(Some(state));
                }
            });
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _ = TRACKING.try_with(|tracking| {
            if let Some(mut state) = tracking.get() {
                state.live_bytes -= layout.size() as isize;
                tracking.set(Some(state));
            }
        });
        unsafe { System.dealloc(ptr, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

fn construction(fail_at: usize) -> (moto_rt::Result<()>, Tracking) {
    TRACKING.set(Some(Tracking {
        fail_at,
        ..Tracking::default()
    }));
    // Same slot size and capacity as the network channel. Drop successful
    // construction inside the measured interval, so zero means no live storage.
    let result = moto_mpmc::try_bounded::<[u64; 7]>(64).map(drop);
    let state = TRACKING.take().unwrap();
    (result, state)
}

#[test]
fn allocation_failures_release_partial_construction() {
    for fail_at in [1, 2] {
        let (result, state) = construction(fail_at);
        assert_eq!(result, Err(moto_rt::Error::OutOfMemory));
        assert_eq!(state.attempts, fail_at);
        assert_eq!(state.live_bytes, 0);
        assert!(state.failed_bytes > 0);
        if fail_at == 1 {
            assert_eq!(state.failed_bytes, 4096);
        }
        let (result, state) = construction(0);
        assert_eq!(result, Ok(()));
        assert_eq!(state.attempts, 2);
        assert_eq!(state.live_bytes, 0);
    }
}

#[test]
fn invalid_capacities_are_errors() {
    for cap in [0, usize::MAX, 1 << (usize::BITS - 2)] {
        assert_eq!(
            moto_mpmc::try_bounded::<u8>(cap).err(),
            Some(moto_rt::Error::InvalidArgument)
        );
    }
    assert_eq!(
        moto_mpmc::try_bounded::<[u64; 64]>(isize::MAX as usize / 512 + 1).err(),
        Some(moto_rt::Error::InvalidArgument)
    );
}

#[test]
fn nonblocking_capacity_wraparound_and_disconnect() {
    for cap in [1, 3, 64] {
        let (sender, receiver) = moto_mpmc::try_bounded(cap).unwrap();
        for round in 0..100 {
            assert!(receiver.is_empty());
            for value in 0..cap {
                sender.try_send((round, value)).unwrap();
            }
            assert!(sender.is_full());
            assert_eq!(
                sender.try_send((0, cap)).unwrap_err().into_inner(),
                (0, cap)
            );
            for value in 0..cap {
                assert_eq!(receiver.try_recv(), Ok((round, value)));
            }
        }
        drop(sender);
        assert_eq!(
            receiver.try_recv(),
            Err(moto_mpmc::TryRecvError::Disconnected)
        );
    }
}

#[test]
fn queued_values_are_dropped_once() {
    struct Item(Arc<AtomicUsize>);
    impl Drop for Item {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let dropped = Arc::new(AtomicUsize::new(0));
    let (sender, receiver) = moto_mpmc::try_bounded(3).unwrap();
    for _ in 0..3 {
        assert!(sender.try_send(Item(dropped.clone())).is_ok());
    }
    drop(receiver.try_recv().unwrap());
    drop((sender, receiver));
    assert_eq!(dropped.load(Ordering::Relaxed), 3);
}

#[test]
fn concurrent_nonblocking_senders_preserve_order() {
    let (sender, receiver) = moto_mpmc::try_bounded(64).unwrap();
    std::thread::scope(|scope| {
        for producer in 0..4 {
            let sender = sender.clone();
            scope.spawn(move || {
                for sequence in 0..1000 {
                    while sender.try_send((producer, sequence)).is_err() {
                        std::thread::yield_now();
                    }
                }
            });
        }
        let mut next = [0; 4];
        for _ in 0..4000 {
            let (producer, sequence) = loop {
                if let Ok(msg) = receiver.try_recv() {
                    break msg;
                }
                std::thread::yield_now();
            };
            assert_eq!(sequence, next[producer]);
            next[producer] += 1;
        }
        assert_eq!(next, [1000; 4]);
    });
}
