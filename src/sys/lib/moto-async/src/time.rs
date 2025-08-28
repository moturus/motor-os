//! Async timers.

use core::future::Future;
use core::pin::Pin;
use core::task::Context;
use core::task::Poll;

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

    // `poll_elapsed` can return an error in two cases:
    //
    // - AtCapacity: this is a pathological case where far too many
    //   sleep instances have been scheduled.
    // - Shutdown: No timer has been setup, which is a mis-use error.
    //
    // Both cases are extremely rare, and pretty accurately fit into
    // "logic errors", so we just panic in this case. A user couldn't
    // really do much better if we passed the error onwards.
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if Instant::now() >= self.deadline {
            return Poll::Ready(());
        }

        let local_executor = crate::local_executor::get_local_executor();
        if local_executor.is_null() {
            log::warn!("LocalExecutor missing.");
            return Poll::Pending;
        }

        // Validate that we are running in the proper context.
        // TODO: is the check/panic below valid?
        let local_waker = cx.local_waker();
        if (local_waker.data() as usize) != (local_executor as usize) {
            panic!("Unexpected context/waker");
        }

        if self.registered {
            log::debug!("Polled while registered.");
            return Poll::Pending;
        }

        // Register the timeout.
        //
        // Safety: safe by construction.
        unsafe {
            local_executor.as_mut().unwrap().add_timer(self.deadline);
        };
        self.registered = true;

        Poll::Pending
    }
}
