use alloc::vec::Vec;
use core::task::Waker;
use moto_rt::mutex::Mutex;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WaiterId(u64);

struct Waiter {
    id: WaiterId,
    waker: Waker,
}

struct WaitSetInner {
    next_id: u64,
    waiters: Vec<Waiter>,
}

/// A thread-safe set of cancellation-aware waker registrations.
///
/// The future owns its `WaiterId` and unregisters it on drop. A wake removes
/// registrations before invoking their wakers; a future that still cannot
/// make progress registers a fresh identity when it is polled again.
pub(super) struct WaitSet {
    inner: Mutex<WaitSetInner>,
}

impl WaitSet {
    pub(super) const fn new() -> Self {
        Self {
            inner: Mutex::new(WaitSetInner {
                next_id: 0,
                waiters: Vec::new(),
            }),
        }
    }

    pub(super) fn register(&self, id: &mut Option<WaiterId>, waker: &Waker) {
        let mut inner = self.inner.lock();
        if let Some(id) = *id
            && let Some(registered) = inner.waiters.iter_mut().find(|entry| entry.id == id)
        {
            if !registered.waker.will_wake(waker) {
                registered.waker.clone_from(waker);
            }
            return;
        }

        let new_id = WaiterId(inner.next_id);
        inner.next_id = inner
            .next_id
            .checked_add(1)
            .expect("waker registration identity exhausted");
        inner.waiters.push(Waiter {
            id: new_id,
            waker: waker.clone(),
        });
        *id = Some(new_id);
    }

    pub(super) fn unregister(&self, id: &mut Option<WaiterId>) {
        let Some(id) = id.take() else {
            return;
        };
        let mut inner = self.inner.lock();
        if let Some(index) = inner.waiters.iter().position(|entry| entry.id == id) {
            inner.waiters.swap_remove(index);
        }
    }

    pub(super) fn wake_all(&self) {
        let mut waiters = {
            let mut inner = self.inner.lock();
            core::mem::take(&mut inner.waiters)
        };
        for waiter in waiters.drain(..) {
            waiter.waker.wake();
        }

        // Recycle the largest allocation. Re-polling is allowed to register
        // while wakers run, so preserve any new entries when swapping it back.
        let mut inner = self.inner.lock();
        if waiters.capacity() > inner.waiters.capacity() {
            waiters.append(&mut inner.waiters);
            core::mem::swap(&mut inner.waiters, &mut waiters);
        }
    }

    #[cfg(feature = "netdev")]
    pub(super) fn len(&self) -> usize {
        self.inner.lock().waiters.len()
    }
}
