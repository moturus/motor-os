extern crate alloc;

use alloc::collections::VecDeque;
use core::cell::{Cell, RefCell};
use core::future::Future;
use core::pin::Pin;
use core::task::LocalWaker;
use core::task::{Context, Poll};

#[derive(PartialEq, Eq, Clone, Copy)]
struct WaiterId(u64);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum WaiterState {
    Waiting,
    NotifiedOne,
    NotifiedAll,
}

struct Waiter {
    id: WaiterId,
    state: WaiterState,
    waker: Option<LocalWaker>,
}

/// A single-threaded, local version of tokio::sync::Notify.
///
/// Any number of concurrent waiters is allowed. `notify_one` wakes the
/// oldest un-notified waiter, or stores a single permit if there is
/// none; `notify_all` wakes every current waiter and stores nothing.
/// A notified-but-cancelled waiter passes its notification on (drop
/// re-dispatch), so cancellation cannot lose a notify_one.
pub struct LocalNotify {
    notified: Cell<bool>,
    waiters: RefCell<VecDeque<Waiter>>,
    next_id: Cell<u64>,
}

impl Default for LocalNotify {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalNotify {
    pub const fn new() -> Self {
        Self {
            notified: Cell::new(false),
            waiters: RefCell::new(VecDeque::new()),
            next_id: Cell::new(0),
        }
    }

    fn fire(waiter: &mut Waiter, state: WaiterState) {
        debug_assert_eq!(waiter.state, WaiterState::Waiting);
        debug_assert_ne!(state, WaiterState::Waiting);
        waiter.state = state;
        if let Some(waker) = waiter.waker.take() {
            waker.wake();
        }
    }

    /// Wakes the oldest waiter, or stores a permit for the next one.
    pub fn notify_one(&self) {
        if let Some(waiter) = self
            .waiters
            .borrow_mut()
            .iter_mut()
            .find(|w| w.state == WaiterState::Waiting)
        {
            Self::fire(waiter, WaiterState::NotifiedOne);
        } else {
            self.notified.set(true);
        }
    }

    /// Wakes all current waiters. No permit is stored: a waiter that
    /// arrives later needs its own notification.
    pub fn notify_all(&self) {
        for waiter in self.waiters.borrow_mut().iter_mut() {
            if waiter.state == WaiterState::Waiting {
                Self::fire(waiter, WaiterState::NotifiedAll);
            }
        }
    }

    /// Returns a future that resolves when notified. The waiter queues
    /// at creation time (not first poll), so notification order follows
    /// notified() call order.
    pub fn notified(&self) -> NotifiedFuture<'_> {
        let id = WaiterId(self.next_id.get());
        self.next_id.set(id.0 + 1);
        self.waiters.borrow_mut().push_back(Waiter {
            id,
            state: WaiterState::Waiting,
            waker: None,
        });
        NotifiedFuture { notify: self, id }
    }
}

/// The Future returned by `notified()`.
pub struct NotifiedFuture<'a> {
    notify: &'a LocalNotify,
    id: WaiterId,
}

impl Drop for NotifiedFuture<'_> {
    fn drop(&mut self) {
        let mut waiters = self.notify.waiters.borrow_mut();
        let Some(pos) = waiters.iter().position(|w| w.id == self.id) else {
            return; // Completed; nothing queued.
        };
        let waiter = waiters.remove(pos).unwrap();
        if waiter.state == WaiterState::NotifiedOne {
            // A cancelled notify_one must pass its permit on. A notify_all
            // wake belongs only to the waiters present at that broadcast,
            // so cancelling one of those waiters must not re-dispatch it.
            if let Some(next) = waiters
                .iter_mut()
                .find(|w| w.state == WaiterState::Waiting)
            {
                LocalNotify::fire(next, WaiterState::NotifiedOne);
            } else {
                self.notify.notified.set(true);
            }
        }
    }
}

impl Future for NotifiedFuture<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut waiters = self.notify.waiters.borrow_mut();
        let Some(pos) = waiters.iter().position(|w| w.id == self.id) else {
            return Poll::Ready(()); // Polled again after Ready.
        };

        if waiters[pos].state != WaiterState::Waiting || self.notify.notified.replace(false) {
            waiters.remove(pos);
            return Poll::Ready(());
        }

        waiters[pos].waker = Some(cx.local_waker().clone());
        Poll::Pending
    }
}
