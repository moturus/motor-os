//! Copyable retry state. Owning syscall helpers must return before `park()`:
//! killing a suspended syscall discards its stack without running destructors.

use super::{state, Thread};
use crate::mm::{
    phys, AllocationClass, AllocationFailure, RefusalKind, RetryDecision, StateSnapshot, WaitReason,
};
use alloc::{sync::Weak, vec::Vec};
use moto_sys::ErrorCode;

// The caller serializes these queue operations with the OOM bookkeeping lock.
// Removal transfers sole ownership of the resume; blocked entries stay put.
pub(super) fn register<T>(
    waiters: &mut Vec<(Weak<T>, WaitReason)>,
    thread: Weak<T>,
    reason: WaitReason,
    snapshot: impl FnOnce() -> StateSnapshot,
) -> Option<Weak<T>> {
    waiters.push((thread, reason));
    if reason.ready(snapshot()) {
        waiters.pop().map(|(thread, _)| thread)
    } else {
        None
    }
}

pub(super) fn take_ready<T>(
    waiters: &mut Vec<(Weak<T>, WaitReason)>,
    snapshot: StateSnapshot,
) -> Vec<Weak<T>> {
    waiters
        .extract_if(.., |(thread, reason)| {
            thread.strong_count() == 0 || reason.ready(snapshot)
        })
        .map(|(thread, _)| thread)
        .collect()
}

/// Whether the syscall queue still owns `thread`'s resume. Called by
/// `Thread::on_thread_paused()` under the thread's status lock.
pub(crate) fn is_parked(thread: &Thread) -> bool {
    let me = core::ptr::from_ref(thread);
    state()
        .work
        .lock(line!())
        .syscall_waiters
        .iter()
        .any(|(queued, _)| queued.as_ptr() == me)
}

#[cfg(debug_assertions)]
pub(super) fn test() {
    use alloc::sync::Arc;
    // Queue ownership needs only weak lifetimes, not a running thread; the
    // fault and syscall queues share these operations. The unarmed boot
    // snapshot opens gates, but a same-generation shortage is still blocked.
    // Armed policy transitions are tested in phys_blocks.
    let snapshot = phys::oom_snapshot().0;
    assert!(!snapshot.armed());
    let mut waiters = Vec::new();
    let alive = Arc::new(());
    let weak = Arc::downgrade(&alive);
    let pending = WaitReason::shortage(AllocationClass::System, snapshot.generation());
    assert!(register(&mut waiters, weak.clone(), pending, || snapshot).is_none());
    assert!(take_ready(&mut waiters, snapshot).is_empty()); // Spurious dispatch.
    assert_eq!(waiters.len(), 1); // Still owned by the queue, never reinserted.
    let ready = WaitReason::gate(AllocationClass::User);
    // Recovery before registration: only the registering caller gets the resume.
    assert!(register(&mut waiters, weak.clone(), ready, || snapshot).is_some());
    assert_eq!(waiters.len(), 1);
    // A ready entry left to dispatch is claimed exactly once.
    waiters.push((weak, ready));
    assert_eq!(take_ready(&mut waiters, snapshot).len(), 1);
    assert!(take_ready(&mut waiters, snapshot).is_empty());
    drop(alive); // Cancellation/death discards even a blocked weak entry.
    assert_eq!(take_ready(&mut waiters, snapshot).len(), 1);
    assert!(waiters.is_empty());
    assert!(take_ready(&mut waiters, snapshot).is_empty());
    crate::raw_log!("OOM waiter tests PASS");
}

pub(super) fn resolve(
    failure: AllocationFailure,
    fault: bool,
) -> Result<Option<WaitReason>, ErrorCode> {
    loop {
        let (snapshot, free) = phys::oom_snapshot();
        match failure.retry_decision(snapshot, free, fault) {
            RetryDecision::Retry => return Ok(None),
            RetryDecision::Wait(reason) => return Ok(Some(reason)),
            RetryDecision::Error(code) => return Err(code),
            RetryDecision::Request(class) => {
                if let Some(generation) = phys::request_oom() {
                    return Ok(Some(WaitReason::shortage(class, generation)));
                }
                // Recovery won the request CAS. Reconcile the original receipt
                // with that recovery instead of issuing a stale request.
            }
        }
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Retry {
    pending: Option<WaitReason>,
}

impl Retry {
    /// Called by the inner helper after resolving its current recipient. A
    /// spurious wake must not let a System shortage retry in the same run.
    pub(crate) fn check(&self, class: AllocationClass) -> Result<(), AllocationFailure> {
        let (state, free_pages) = phys::oom_snapshot();
        if let Some(reason) = self.pending.map(|reason| reason.with_class(class)) {
            if !reason.ready(state) {
                return Err(AllocationFailure::Waiting(reason));
            }
        }
        if !state.gate_closed(class) {
            return Ok(());
        }
        Err(AllocationFailure::Pressure {
            class,
            kind: RefusalKind::Gate,
            state,
            free_pages,
        })
    }

    pub(crate) fn check_space(
        &self,
        space: &crate::mm::user::UserAddressSpace,
        bytes: u64,
    ) -> Result<(), AllocationFailure> {
        space.check_allocation(bytes)?;
        self.check(space.allocation_class())
    }

    /// Call only after the inner attempt returned and dropped all resources.
    /// This frame and every suspended caller may hold only borrowed/copyable data.
    pub(crate) fn after_failure(
        &mut self,
        thread: &Thread,
        failure: AllocationFailure,
    ) -> Result<(), ErrorCode> {
        self.pending = resolve(failure, false)?;
        if let Some(reason) = self.pending {
            park(thread, reason);
        }
        Ok(())
    }
}

/// Sleeps until `attend()` finds `reason` satisfied, or returns at once if it
/// already is. A kill ends the thread inside `Thread::oom_wait()`.
fn park(thread: &Thread, reason: WaitReason) {
    super::count_park(thread, crate::xray::stats::MetricType::OomParkedSyscalls);
    let me = core::ptr::from_ref(thread);
    let ready = {
        let mut work = state().work.lock(line!());
        // Read under the same lock as removal, after the entry is present.
        register(&mut work.syscall_waiters, thread.get_weak(), reason, || {
            phys::oom_snapshot().0
        })
    };
    if ready.is_some() {
        return;
    }
    // The pause sleeps only while the entry is still queued; its removal by
    // attend() resumes the thread. A wake latched for the userspace wait that
    // follows the syscall can also return early: take back an entry the
    // scheduler has not claimed, so no resume is owed and the next
    // registration cannot duplicate it.
    thread.oom_wait();
    state()
        .work
        .lock(line!())
        .syscall_waiters
        .retain(|(queued, _)| queued.as_ptr() != me);
}
