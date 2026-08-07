//! Native `NetDriver` host tests (vdso-rewrite design section 4).
//!
//! The executable statement of what vDSO Stage 4 delivers, grown patch by
//! patch: a native host that names nothing from the vdso creates its own
//! LocalRuntime, connects a `NetClient`/`NetDriver` pair, drives the driver
//! explicitly, and observes a clean driver exit.

use core::task::Poll;
use std::time::Duration;

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
        let mut driver_task = core::pin::pin!(moto_async::LocalRuntime::spawn(driver.run()));
        client.request_shutdown();

        // Bounded: a wedged teardown must fail the assertion below, not
        // stall the suite into the harness timeout.
        let mut deadline = core::pin::pin!(moto_async::sleep(Duration::from_secs(5)));
        core::future::poll_fn(|cx| {
            if driver_task.as_mut().poll(cx).is_ready() {
                return Poll::Ready(true);
            }
            if deadline.as_mut().poll(cx).is_ready() {
                return Poll::Ready(false);
            }
            Poll::Pending
        })
        .await
    });
    assert!(
        completed,
        "the NetDriver did not exit after request_shutdown()"
    );

    println!("net_driver::test_connect_drive_shutdown PASS");
}

pub fn run_all_tests() {
    test_connect_drive_shutdown();
}
