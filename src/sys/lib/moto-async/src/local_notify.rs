use core::cell::Cell;
use core::future::Future;
use core::pin::Pin;
use core::task::LocalWaker;
use core::task::{Context, Poll};

#[derive(Default)]
enum Waiter {
    #[default]
    None,
    Waiting,
    Waker(LocalWaker),
}

/// A single-threaded, local version of tokio::sync::Notify.
pub struct LocalNotify {
    notified: Cell<bool>,
    waiter: Cell<Waiter>,
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
            waiter: Cell::new(Waiter::None),
        }
    }

    /// Triggers the notification and wakes the waiting task (if any).
    pub fn notify_one(&self) {
        self.notified.set(true);
        match self.waiter.take() {
            Waiter::Waker(waker) => {
                waker.wake();
                self.waiter.set(Waiter::Waiting);
            }
            Waiter::Waiting => {
                self.waiter.set(Waiter::Waiting);
            }
            Waiter::None => {}
        }
    }

    /// Returns a future that resolves when notify_one() is called.
    ///
    /// # Panics
    /// Panics if multiple `NotifiedFuture`s for this `LocalNotify` are alive concurrently.
    pub fn notified(&self) -> NotifiedFuture<'_> {
        let prev = self.waiter.replace(Waiter::Waiting);
        if !matches!(prev, Waiter::None) {
            self.waiter.set(prev); // restore state before panic
            panic!("Multiple NotifiedFutures for the same LocalNotify are not supported.");
        }
        NotifiedFuture { notify: self }
    }
}

/// The Future returned by `notified()`.
pub struct NotifiedFuture<'a> {
    notify: &'a LocalNotify,
}

impl<'a> Drop for NotifiedFuture<'a> {
    fn drop(&mut self) {
        self.notify.waiter.set(Waiter::None);
    }
}

impl<'a> Future for NotifiedFuture<'a> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.notify.notified.get() {
            // We were notified: consume the notification and wake up.
            self.notify.notified.set(false);
            Poll::Ready(())
        } else {
            // We haven't been notified yet. Store the current task's waker
            // so `notify_one()` knows who to wake up later.
            self.notify
                .waiter
                .set(Waiter::Waker(cx.local_waker().clone()));
            Poll::Pending
        }
    }
}
