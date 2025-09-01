use std::{
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    task::Poll,
    time::Duration,
};

use futures::FutureExt;
use moto_rt::time::Instant;

// A timeout future that returns the number of polls it got.
struct TimeoutFuture {
    polls: u64,
    inner: moto_async::time::Sleep,
}

impl TimeoutFuture {
    fn new(timo: std::time::Duration) -> Self {
        Self {
            polls: 0,
            inner: moto_async::time::Sleep::new_timeout(Instant::now() + timo),
        }
    }
}

impl core::future::Future for TimeoutFuture {
    type Output = u64;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.polls += 1;
        match self.inner.poll_unpin(cx) {
            Poll::Ready(_) => Poll::Ready(self.polls),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn test_timeout() {
    let start = Instant::now();
    let timo = std::time::Duration::from_millis(15);

    let fut = TimeoutFuture::new(timo);

    // Make sure that the future got at most two polls:
    // one the initial pending, and one the final ready.
    // If there are delays, the first poll may be ready.
    let poll_calls = moto_async::LocalRuntime::new().block_on(fut);
    assert!(start.elapsed() >= timo);

    if poll_calls == 1 {
        log::info!("test_timeout: a single poll() call");
    } else if poll_calls > 2 {
        panic!("Too many poll calls: {poll_calls}.");
    }

    println!("----- moto_async::test_timeout PASS");
}

fn test_select() {
    let counter = Arc::new(AtomicU32::new(0));

    let c1 = counter.clone();
    let c2 = counter.clone();

    let f1 = async move {
        moto_async::time::sleep(Duration::from_millis(50)).await;

        c1.fetch_add(1, Ordering::AcqRel);
    };

    let f2 = async move {
        moto_async::time::sleep(Duration::from_millis(150)).await;

        c2.fetch_add(2, Ordering::AcqRel);
    };

    let res = moto_async::LocalRuntime::new().block_on(async move {
        futures::select! {_ = f1.fuse() => 1, _ = f2.fuse() => 2}
    });

    assert_eq!(1, res);
    assert_eq!(1, counter.load(Ordering::Acquire));

    println!("----- moto_async::test_select PASS");
}

fn test_basic() {
    assert_eq!(42, moto_async::LocalRuntime::new().block_on(async { 42 }));
    println!("----- moto_async::test_basic PASS");
}

pub fn run_all_tests() {
    test_basic();
    test_timeout();
    test_select();

    println!("moto_async all PASS");
}
