//! Native `NetDriver` host tests (vdso-rewrite design section 4).
//!
//! The executable statement of what vDSO Stage 4 delivers, grown patch by
//! patch: a native host that names nothing from the vdso creates its own
//! LocalRuntime, connects a `NetClient`/`NetDriver` pair, drives the driver
//! explicitly, and observes a clean driver exit.

use core::future::Future;
use core::task::Poll;
use std::time::Duration;

use moto_io::net::ReserveError;

/// Await `fut`, bounded: a wedged teardown must fail a test assertion, not
/// stall the suite into the harness timeout. True iff `fut` completed.
async fn bounded<F: Future>(fut: F, secs: u64) -> bool {
    let mut fut = core::pin::pin!(fut);
    let mut deadline = core::pin::pin!(moto_async::sleep(Duration::from_secs(secs)));
    core::future::poll_fn(|cx| {
        if fut.as_mut().poll(cx).is_ready() {
            return Poll::Ready(true);
        }
        if deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(false);
        }
        Poll::Pending
    })
    .await
}

/// Connect, drive, shut down: a host-owned channel comes up without a
/// thread, a pool entry, or a vdso object, and `request_shutdown` alone (no
/// reservation was ever taken) drains its driver to completion. I/O through
/// a host-owned channel becomes provable once explicit reservations land;
/// the driver's liveness is meanwhile covered by every other net test, since
/// the compatibility host runs the same `NetDriver::run`.
fn test_connect_drive_shutdown() {
    let completed = moto_async::LocalRuntime::new().block_on(async {
        let (client, driver) = moto_io::net::connect()
            .await
            .expect("async connect to sys-io failed");
        let driver_task = moto_async::LocalRuntime::spawn(driver.run());
        client.request_shutdown();
        bounded(driver_task, 5).await
    });
    assert!(
        completed,
        "the NetDriver did not exit after request_shutdown()"
    );

    println!("net_driver::test_connect_drive_shutdown PASS");
}

/// The reservation protocol: `try_reserve` fills exactly `capacity()`
/// slots, refuses the next with `AtCapacity`, and releasing the last
/// reservation -- with no `request_shutdown` anywhere -- closes the channel
/// to new reservations and exits the driver.
fn test_reservation_lifecycle() {
    let completed = moto_async::LocalRuntime::new().block_on(async {
        let (client, driver) = moto_io::net::connect()
            .await
            .expect("async connect to sys-io failed");
        let driver_task = moto_async::LocalRuntime::spawn(driver.run());

        let capacity = client.capacity();
        assert!(capacity > 0);
        let mut reservations = Vec::new();
        for held in 0..capacity {
            assert_eq!(client.reservations(), held);
            reservations.push(client.try_reserve().expect("reserve within capacity"));
        }
        assert_eq!(
            client.try_reserve().err(),
            Some(ReserveError::AtCapacity),
            "a full channel accepted a fifth reservation"
        );

        // Not the last release: the channel must stay open.
        drop(reservations.pop());
        assert_eq!(client.reservations(), capacity - 1);
        reservations.push(client.try_reserve().expect("a freed slot was not reusable"));

        drop(reservations);
        assert_eq!(client.reservations(), 0);
        assert_eq!(
            client.try_reserve().err(),
            Some(ReserveError::ShuttingDown),
            "the last release did not close the channel"
        );
        bounded(driver_task, 5).await
    });
    assert!(
        completed,
        "the NetDriver did not exit after the last reservation was released"
    );

    println!("net_driver::test_reservation_lifecycle PASS");
}

pub fn run_all_tests() {
    test_connect_drive_shutdown();
    test_reservation_lifecycle();
}
