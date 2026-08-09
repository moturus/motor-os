//! Shared harness for reserved-path (host-owned channel) native net tests:
//! the `NetClient`/`NetDriver` preamble and the bounded awaits that keep a
//! wedged teardown from stalling the suite into the harness timeout.

use core::future::Future;
use core::task::Poll;
use std::time::Duration;

use moto_io::net::NetClient;

/// Connect a host-owned channel and drive it on the current `LocalRuntime`.
/// Must be called from task context (inside `block_on`).
pub async fn host_channel() -> (NetClient, moto_async::JoinHandle<()>) {
    let (client, driver) = moto_io::net::connect()
        .await
        .expect("async connect to sys-io failed");
    let driver_task = moto_async::LocalRuntime::spawn(driver.run());
    (client, driver_task)
}

/// Await `fut`, bounded. True iff `fut` completed.
pub async fn bounded<F: Future>(fut: F, secs: u64) -> bool {
    bounded_output(fut, secs).await.is_some()
}

/// Await `fut`, bounded; its output, or `None` on timeout.
pub async fn bounded_output<F: Future>(fut: F, secs: u64) -> Option<F::Output> {
    let mut fut = core::pin::pin!(fut);
    let mut deadline = core::pin::pin!(moto_async::sleep(Duration::from_secs(secs)));
    core::future::poll_fn(|cx| {
        if let Poll::Ready(out) = fut.as_mut().poll(cx) {
            return Poll::Ready(Some(out));
        }
        if deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        Poll::Pending
    })
    .await
}

/// Connect a host-owned channel whose driver runs on a dedicated thread --
/// the pool-channel-thread topology. For tests that block the channel
/// runtime with the global test hooks (arm_*_test) while the test thread
/// acts: with the driver on the test's own runtime those hooks would
/// deadlock. The driver exits when the last reservation drops (or on
/// request_shutdown); join the returned thread after that.
pub fn host_channel_on_thread() -> (NetClient, std::thread::JoinHandle<()>) {
    let (tx, rx) = std::sync::mpsc::channel();
    let driver_thread = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async {
            let (client, driver) = moto_io::net::connect()
                .await
                .expect("async connect to sys-io failed");
            tx.send(client).expect("harness receiver gone");
            driver.run().await;
        });
    });
    (
        rx.recv().expect("driver thread died before connect"),
        driver_thread,
    )
}

/// Async poll-wait with the standard 2s budget. Sleeping (rather than
/// spinning) is what lets the channel's NetDriver -- a task on the same
/// LocalRuntime -- make the progress the condition is waiting for.
pub async fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !cond() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        moto_async::sleep(Duration::from_millis(10)).await;
    }
}

/// Shut the client down and require the driver to drain promptly.
pub async fn drain_host_channel(client: NetClient, driver_task: moto_async::JoinHandle<()>) {
    client.request_shutdown();
    assert!(
        bounded(driver_task, 5).await,
        "the NetDriver did not exit after request_shutdown()"
    );
}
