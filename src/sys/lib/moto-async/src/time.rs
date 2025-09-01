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
    registered: bool,
}

impl Sleep {
    pub fn new_timeout(deadline: Instant) -> Sleep {
        Sleep {
            deadline,
            registered: false,
        }
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if Instant::now() >= self.deadline {
            return Poll::Ready(());
        }

        if self.registered {
            log::debug!("Polled while registered.");
            return Poll::Pending;
        }

        self.registered = true;
        crate::LocalRuntime::add_timer(self.deadline, cx);

        Poll::Pending
    }
}

pub fn sleep(duration: Duration) -> Sleep {
    Sleep::new_timeout(Instant::now() + duration)
}
