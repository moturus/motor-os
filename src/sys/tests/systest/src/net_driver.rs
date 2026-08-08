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

/// Real I/O over a host-owned channel. Two UDP sockets bound with this
/// client's reservations exchange a datagram, and a TCP stream connected
/// with a third writes to a std echo peer (which runs on the ordinary pool
/// path) and reads its own bytes back -- all progress made only because
/// this host drives the channel's `NetDriver`. Dropping the sockets then
/// releases the last reservation and the driver exits on its own.
fn test_reserved_socket_io() {
    let echo_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_thread = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let (mut peer, _) = echo_listener.accept().unwrap();
        let mut buf = [0u8; 4];
        peer.read_exact(&mut buf).unwrap();
        peer.write_all(&buf).unwrap();
    });

    let completed = moto_async::LocalRuntime::new().block_on(async {
        let (client, driver) = moto_io::net::connect()
            .await
            .expect("async connect to sys-io failed");
        let driver_task = moto_async::LocalRuntime::spawn(driver.run());

        let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let a = moto_io::net::udp::UdpSocket::bind_reserved(
            client.try_reserve().unwrap(),
            &loopback,
            None,
        )
        .await
        .expect("reserved UDP bind (a)");
        let b = moto_io::net::udp::UdpSocket::bind_reserved(
            client.try_reserve().unwrap(),
            &loopback,
            None,
        )
        .await
        .expect("reserved UDP bind (b)");

        assert_eq!(
            a.try_send_to(b"host channel", b.local_addr()),
            Ok(b"host channel".len())
        );
        let mut buf = [0u8; 64];
        let (len, from) = b
            .recv_from_future(&mut buf, false)
            .await
            .expect("reserved UDP recv");
        assert_eq!(&buf[..len], b"host channel");
        assert_eq!(&from, a.local_addr());

        let stream = moto_io::net::tcp::TcpStream::connect_reserved(
            client.try_reserve().unwrap(),
            &echo_addr,
            None,
            None,
        )
        .await
        .expect("reserved TCP connect");
        let mut written = 0;
        while written < 4 {
            match stream.try_write(&[&b"ping"[written..]]) {
                Ok(n) => written += n,
                Err(moto_rt::E_NOT_READY) => stream.writable().await,
                Err(err) => panic!("reserved TCP write failed: {err:?}"),
            }
        }
        let mut echoed = Vec::new();
        while echoed.len() < 4 {
            let mut buf = [0u8; 8];
            match stream.try_read(&mut [&mut buf], false) {
                Ok(0) => panic!("reserved TCP stream closed before the echo"),
                Ok(n) => echoed.extend_from_slice(&buf[..n]),
                Err(moto_rt::E_NOT_READY) => stream.readable().await,
                Err(err) => panic!("reserved TCP read failed: {err:?}"),
            }
        }
        assert_eq!(&echoed, b"ping");

        assert_eq!(client.reservations(), 3);
        drop((a, b, stream));
        bounded(driver_task, 5).await && client.reservations() == 0
    });
    assert!(
        completed,
        "the NetDriver did not exit after the reserved sockets dropped"
    );
    echo_thread.join().unwrap();

    println!("net_driver::test_reserved_socket_io PASS");
}

/// A host-owned listener: bound on one reservation, accepts armed only by
/// donation (`post_accept`), served by `try_accept`. This is the decision 2
/// flow end to end: sys-io completes the pre-posted request when the
/// connection arrives, this host's own driver poll queues it locally, and
/// `try_accept` claims it -- with no request posted, `try_accept` could
/// never succeed. The donated reservation becomes the accepted stream's
/// channel slot, and everything releases back to zero.
fn test_reserved_listener_accept() {
    let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

    let mut runtime = moto_async::LocalRuntime::new();
    let (completed, peer_thread) = runtime.block_on(async {
        let (client, driver) = moto_io::net::connect()
            .await
            .expect("async connect to sys-io failed");
        let driver_task = moto_async::LocalRuntime::spawn(driver.run());

        let listener = moto_io::net::tcp::TcpListener::bind_reserved(
            client.try_reserve().unwrap(),
            &loopback,
            None,
        )
        .await
        .expect("reserved TCP listener bind");
        listener.post_accept(client.try_reserve().unwrap());
        assert_eq!(client.reservations(), 2);

        // Nothing is queued before a connection arrives.
        assert_eq!(listener.try_accept().err(), Some(moto_rt::E_NOT_READY));

        let listener_addr = *listener.socket_addr();
        let peer_thread = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let mut peer = std::net::TcpStream::connect(listener_addr).unwrap();
            peer.write_all(b"ping").unwrap();
            let mut buf = [0u8; 4];
            peer.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"pong");
        });

        // try_accept is local: it sees the connection only after this
        // host's driver polls the completion in. Sleep-loop, bounded.
        let mut accepted = None;
        for _ in 0..2000 {
            match listener.try_accept() {
                Ok(ok) => {
                    accepted = Some(ok);
                    break;
                }
                Err(moto_rt::E_NOT_READY) => {
                    moto_async::sleep(Duration::from_millis(5)).await;
                }
                Err(err) => panic!("reserved try_accept failed: {err:?}"),
            }
        }
        let (stream, _remote_addr) = accepted.expect("no connection within 10s");
        // The donated slot became the stream's; the listener keeps its own.
        assert_eq!(client.reservations(), 2);

        let mut pinged = Vec::new();
        while pinged.len() < 4 {
            let mut buf = [0u8; 8];
            match stream.try_read(&mut [&mut buf], false) {
                Ok(0) => panic!("reserved accepted stream closed early"),
                Ok(n) => pinged.extend_from_slice(&buf[..n]),
                Err(moto_rt::E_NOT_READY) => stream.readable().await,
                Err(err) => panic!("reserved accepted read failed: {err:?}"),
            }
        }
        assert_eq!(&pinged, b"ping");
        let mut written = 0;
        while written < 4 {
            match stream.try_write(&[&b"pong"[written..]]) {
                Ok(n) => written += n,
                Err(moto_rt::E_NOT_READY) => stream.writable().await,
                Err(err) => panic!("reserved accepted write failed: {err:?}"),
            }
        }

        drop(stream);
        drop(listener);
        let exited = bounded(driver_task, 5).await;
        (exited && client.reservations() == 0, peer_thread)
    });
    assert!(
        completed,
        "the NetDriver did not exit after the reserved listener and stream dropped"
    );
    peer_thread.join().unwrap();

    println!("net_driver::test_reserved_listener_accept PASS");
}

/// Like [`bounded`], but hands back what `fut` produced.
async fn bounded_output<F: Future>(fut: F, secs: u64) -> Option<F::Output> {
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

/// Spawn a std-path peer that connects, pings, and expects the pong. The
/// byte round-trip is what proves a redelivered connection live.
fn spawn_pingpong_peer(addr: std::net::SocketAddr) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        let mut peer = std::net::TcpStream::connect(addr).unwrap();
        peer.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        peer.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
    })
}

/// Serve one ping/pong exchange on the native side of an accepted stream.
async fn serve_pingpong(stream: &moto_io::net::tcp::TcpStream) {
    let mut pinged = Vec::new();
    while pinged.len() < 4 {
        let mut buf = [0u8; 8];
        match stream.try_read(&mut [&mut buf], false) {
            Ok(0) => panic!("peer closed before the ping"),
            Ok(n) => pinged.extend_from_slice(&buf[..n]),
            Err(moto_rt::E_NOT_READY) => stream.readable().await,
            Err(err) => panic!("native read failed: {err:?}"),
        }
    }
    assert_eq!(&pinged, b"ping");
    let mut written = 0;
    while written < 4 {
        match stream.try_write(&[&b"pong"[written..]]) {
            Ok(n) => written += n,
            Err(moto_rt::E_NOT_READY) => stream.writable().await,
            Err(err) => panic!("native write failed: {err:?}"),
        }
    }
}

/// Decision 2's park contract, pinned from the sharp side: with a
/// connection already established and waiting inside sys-io, an accept on
/// a host-owned listener with no donation outstanding must NOT complete --
/// nothing was posted, so nothing may arrive. The donation then completes
/// the same accept flow and serves that waiting connection.
fn test_reserved_accept_parks_until_donation() {
    let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

    let mut runtime = moto_async::LocalRuntime::new();
    let (completed, peer_thread) = runtime.block_on(async {
        let (client, driver) = moto_io::net::connect()
            .await
            .expect("async connect to sys-io failed");
        let driver_task = moto_async::LocalRuntime::spawn(driver.run());

        let listener = moto_io::net::tcp::TcpListener::bind_reserved(
            client.try_reserve().unwrap(),
            &loopback,
            None,
        )
        .await
        .expect("reserved TCP listener bind");
        let peer_thread = spawn_pingpong_peer(*listener.socket_addr());

        // The peer's connect establishes inside sys-io regardless; the
        // undonated accept still must sit out the whole bound.
        assert!(
            !bounded(listener.accept(), 2).await,
            "an accept with no donation outstanding completed"
        );

        listener.post_accept(client.try_reserve().unwrap());
        let (stream, _addr) = bounded_output(listener.accept(), 5)
            .await
            .expect("donated accept did not complete")
            .expect("donated accept failed");
        serve_pingpong(&stream).await;

        drop(stream);
        drop(listener);
        let exited = bounded(driver_task, 5).await;
        (exited && client.reservations() == 0, peer_thread)
    });
    assert!(completed, "the NetDriver did not exit after teardown");
    peer_thread.join().unwrap();

    println!("net_driver::test_reserved_accept_parks_until_donation PASS");
}

/// Reserved sibling of `test_cancelled_native_accept_redelivers_connection`
/// (Stage 4 decision 5): an accept cancelled while parked on a host-owned
/// listener spends nothing -- the donated request's connection reaches the
/// next caller, alive.
fn test_reserved_cancelled_accept_redelivers() {
    let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

    let mut runtime = moto_async::LocalRuntime::new();
    let (completed, peer_thread) = runtime.block_on(async {
        let (client, driver) = moto_io::net::connect()
            .await
            .expect("async connect to sys-io failed");
        let driver_task = moto_async::LocalRuntime::spawn(driver.run());

        let listener = moto_io::net::tcp::TcpListener::bind_reserved(
            client.try_reserve().unwrap(),
            &loopback,
            None,
        )
        .await
        .expect("reserved TCP listener bind");
        listener.post_accept(client.try_reserve().unwrap());

        // Park a caller (the donation is the outstanding request; parking
        // posts nothing), then cancel it before any connection exists.
        {
            let mut accept = Box::pin(listener.accept());
            let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
            assert!(accept.as_mut().poll(&mut cx).is_pending());
        }

        let peer_thread = spawn_pingpong_peer(*listener.socket_addr());
        let (stream, _addr) = bounded_output(listener.accept(), 5)
            .await
            .expect("the connection was not redelivered to the next caller")
            .expect("redelivered accept failed");
        serve_pingpong(&stream).await;

        drop(stream);
        drop(listener);
        let exited = bounded(driver_task, 5).await;
        (exited && client.reservations() == 0, peer_thread)
    });
    assert!(completed, "the NetDriver did not exit after teardown");
    peer_thread.join().unwrap();

    println!("net_driver::test_reserved_cancelled_accept_redelivers PASS");
}

/// Reserved sibling of `test_delivered_then_cancelled_native_accept_
/// redelivers` (Stage 4 decision 5): the response reaches the cancelled
/// caller's one-shot, the caller drops without polling, and the rollback
/// re-queues the live connection for the next caller.
fn test_reserved_delivered_then_cancelled_accept_redelivers() {
    struct WakeFlag(std::sync::atomic::AtomicBool);

    impl std::task::Wake for WakeFlag {
        fn wake(self: std::sync::Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &std::sync::Arc<Self>) {
            self.0.store(true, std::sync::atomic::Ordering::Release);
        }
    }

    let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

    let mut runtime = moto_async::LocalRuntime::new();
    let (completed, peer_thread) = runtime.block_on(async {
        let (client, driver) = moto_io::net::connect()
            .await
            .expect("async connect to sys-io failed");
        let driver_task = moto_async::LocalRuntime::spawn(driver.run());

        let listener = moto_io::net::tcp::TcpListener::bind_reserved(
            client.try_reserve().unwrap(),
            &loopback,
            None,
        )
        .await
        .expect("reserved TCP listener bind");
        listener.post_accept(client.try_reserve().unwrap());

        let mut accept = Box::pin(listener.accept());
        let flag = std::sync::Arc::new(WakeFlag(std::sync::atomic::AtomicBool::new(false)));
        let waker = std::task::Waker::from(flag.clone());
        let mut cx = core::task::Context::from_waker(&waker);
        assert!(accept.as_mut().poll(&mut cx).is_pending());

        let peer_thread = spawn_pingpong_peer(*listener.socket_addr());

        // The driver task delivers the response into the parked caller's
        // one-shot and fires this waker; only then is dropping the future
        // the delivered-then-cancelled window.
        let mut waited = 0;
        while !flag.0.load(std::sync::atomic::Ordering::Acquire) {
            assert!(waited < 2000, "accept response was never delivered");
            moto_async::sleep(Duration::from_millis(5)).await;
            waited += 1;
        }
        drop(accept);

        let (stream, _addr) = bounded_output(listener.accept(), 5)
            .await
            .expect("the connection was not redelivered after cancellation")
            .expect("redelivered accept failed");
        serve_pingpong(&stream).await;

        drop(stream);
        drop(listener);
        let exited = bounded(driver_task, 5).await;
        (exited && client.reservations() == 0, peer_thread)
    });
    assert!(completed, "the NetDriver did not exit after teardown");
    peer_thread.join().unwrap();

    println!("net_driver::test_reserved_delivered_then_cancelled_accept_redelivers PASS");
}

pub fn run_all_tests() {
    test_connect_drive_shutdown();
    test_reservation_lifecycle();
    test_reserved_socket_io();
    test_reserved_listener_accept();
    test_reserved_accept_parks_until_donation();
    test_reserved_cancelled_accept_redelivers();
    test_reserved_delivered_then_cancelled_accept_redelivers();
}
