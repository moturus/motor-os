//! Async timers.

use core::future::Future;
use core::pin::Pin;
use core::task::Context;
use core::task::Poll;
use core::time::Duration;

pub use moto_rt::time::Instant;

/// Future returned by [`sleep`](sleep) and [`sleep_until`](sleep_until).
///
/// Mimics the API of tokio::time::Sleep.
pub struct Sleep {
    deadline: Instant,
    // Some once we have registered a timer in the runtime's queue. Cancelled (and
    // cleared) when the timer fires or when this future is dropped, so that a
    // dropped Sleep never leaves a live timer behind.
    timer: Option<crate::timeq::Timer>,
}

impl Sleep {
    pub fn new_timeout(deadline: Instant) -> Sleep {
        Sleep {
            deadline,
            timer: None,
        }
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if Instant::now() >= self.deadline {
            // Fired. Cancel the queued timer in case it has not been popped yet,
            // so it won't fire a redundant wakeup later.
            if let Some(timer) = self.timer.take() {
                timer.cancel();
            }
            return Poll::Ready(());
        }

        if self.timer.is_some() {
            return Poll::Pending;
        }

        self.timer = Some(crate::LocalRuntime::add_timer(self.deadline, cx));

        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        // Cancel a still-pending timer so it does not linger in the runtime's
        // queue and fire a spurious wakeup after this future is gone (e.g. the
        // losing branch of a `select!`). Without this, such timers accumulate
        // without bound and eventually starve the runtime.
        if let Some(timer) = self.timer.take() {
            timer.cancel();
        }
    }
}

pub fn sleep(duration: Duration) -> Sleep {
    Sleep::new_timeout(Instant::now() + duration)
}

pub fn sleep_until(deadline: Instant) -> Sleep {
    Sleep::new_timeout(deadline)
}
