// This is a minimal copy of https://crates.io/crates/futures-time that
// does not pull in a ton of depedencies.

pub mod time {
    use core::future::Future;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    #[derive(Debug, PartialEq, PartialOrd, Ord, Eq, Hash, Clone, Copy)]
    pub struct Duration {
        inner: std::time::Duration,
        timeout: std::time::Instant,
    }

    impl Future for Duration {
        type Output = io::Result<()>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let now = std::time::Instant::now();
            if now >= self.timeout {
                return Poll::Ready(Ok(()));
            }

            // TODO: do something smarter.
            let waker = cx.waker().clone();
            let timeout = self.timeout;
            let _ = std::thread::spawn(move || {
                std::thread::sleep(timeout - now);
                waker.wake()
            });
            Poll::Pending
        }
    }

    impl From<std::time::Duration> for Duration {
        fn from(inner: std::time::Duration) -> Self {
            Self {
                inner,
                timeout: std::time::Instant::now() + inner,
            }
        }
    }

    impl Into<std::time::Duration> for Duration {
        fn into(self) -> std::time::Duration {
            self.inner
        }
    }
}

pub mod future {
    use core::future::Future;
    use core::future::IntoFuture;

    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use pin_project_lite::pin_project;

    pin_project! {
        /// A future that times out after a duration of time.
        ///
        /// This `struct` is created by the [`timeout`] method on [`FutureExt`]. See its
        /// documentation for more.
        ///
        /// [`timeout`]: crate::future::FutureExt::timeout
        /// [`FutureExt`]: crate::future::futureExt
        #[must_use = "futures do nothing unless polled or .awaited"]
        pub struct Timeout<F, D> {
            #[pin]
            future: F,
            #[pin]
            deadline: D,
            completed: bool,
        }
    }

    impl<F, D> Timeout<F, D> {
        pub(super) fn new(future: F, deadline: D) -> Self {
            Self {
                future,
                deadline,
                completed: false,
            }
        }
    }

    impl<F: Future, D: Future> Future for Timeout<F, D> {
        type Output = io::Result<F::Output>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.project();

            assert!(!*this.completed, "future polled after completing");

            match this.future.poll(cx) {
                Poll::Ready(v) => {
                    *this.completed = true;
                    Poll::Ready(Ok(v))
                }
                Poll::Pending => match this.deadline.poll(cx) {
                    Poll::Ready(_) => {
                        *this.completed = true;
                        Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "foo",
                        )))
                    }
                    Poll::Pending => Poll::Pending,
                },
            }
        }
    }

    pub trait FutureExt: Future {
        fn timeout<D>(self, deadline: D) -> Timeout<Self, D::IntoFuture>
        where
            Self: Sized,
            D: IntoFuture,
        {
            Timeout::new(self, deadline.into_future())
        }
    }
    impl<T> FutureExt for T where T: Future {}
}
