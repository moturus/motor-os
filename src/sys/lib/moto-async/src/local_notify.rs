use core::cell::{Cell, RefCell};
use core::future::Future;
use core::pin::Pin;
use core::task::LocalWaker;
use core::task::{Context, Poll};

/// A single-threaded, local version of tokio::sync::Notify.
pub struct LocalNotify {
    notified: Cell<bool>,
    waker: RefCell<Option<LocalWaker>>,
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
            waker: RefCell::new(None),
        }
    }

    /// Triggers the notification and wakes the waiting task (if any).
    pub fn notify_one(&self) {
        self.notified.set(true);
        // If a task is waiting on this notify, wake it up!
        if let Some(waker) = self.waker.borrow_mut().take() {
            waker.wake();
        }
    }

    /// Returns a future that resolves when notify_one() is called.
    pub fn notified(&self) -> NotifiedFuture<'_> {
        NotifiedFuture { notify: self }
    }
}

/// The Future returned by `notified()`.
pub struct NotifiedFuture<'a> {
    notify: &'a LocalNotify,
}

impl<'a> Future for NotifiedFuture<'a> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.notify.notified.get() {
            // We were notified! Consume the notification and wake up.
            self.notify.notified.set(false);
            Poll::Ready(())
        } else {
            // We haven't been notified yet. Store the current task's waker
            // so `notify_one()` knows who to wake up later.
            *self.notify.waker.borrow_mut() = Some(cx.local_waker().clone());
            Poll::Pending
        }
    }
}
