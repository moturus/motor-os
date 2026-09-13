#![cfg(not(target_os = "motor"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

#[derive(Clone, Copy, Default)]
struct Tracking {
    fail_at: usize,
    attempts: usize,
    live_bytes: isize,
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
    let result = moto_async::LocalRuntime::try_new().map(drop);
    let state = TRACKING.take().unwrap();
    (result, state)
}

#[test]
fn allocation_failures_release_partial_construction() {
    let (result, state) = construction(0);
    assert_eq!(result, Ok(()));
    assert_eq!(state.attempts, 4);
    assert_eq!(state.live_bytes, 0);

    for fail_at in 1..=state.attempts {
        let (result, state) = construction(fail_at);
        assert_eq!(result, Err(moto_rt::Error::OutOfMemory));
        assert_eq!(state.attempts, fail_at);
        assert_eq!(state.live_bytes, 0);
    }
}
