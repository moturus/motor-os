//! Native `NetDriver` host tests (vdso-rewrite.md, git history, section 4).
//!
//! The executable statement of what vDSO Stage 4 delivers, grown patch by
//! patch: a native host that names nothing from the vdso creates its own
//! LocalRuntime, connects a `NetClient`/`NetDriver` pair, drives the driver
//! explicitly, and observes a clean driver exit.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use moto_io::net::ReserveError;

use crate::net_harness::{bounded, bounded_output, host_channel};

/// Connect, drive, shut down: a host-owned channel comes up without a
/// thread, a pool entry, or a vdso object, and `request_shutdown` alone (no
/// reservation was ever taken) drains its driver to completion. I/O through
/// a host-owned channel becomes provable once explicit reservations land;
/// the driver's liveness is meanwhile covered by every other net test, since
/// the compatibility host runs the same `NetDriver::run`.
fn test_connect_drive_shutdown() {
    let completed = moto_async::LocalRuntime::new().block_on(async {
        let (client, driver_task) = host_channel().await;
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
        let (client, driver_task) = host_channel().await;

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
        let (client, driver_task) = host_channel().await;

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
        let (client, driver_task) = host_channel().await;

        let listener = moto_io::net::tcp::TcpListener::bind_reserved(
            client.try_reserve().unwrap(),
            &loopback,
            None,
        )
        .await
        .expect("reserved TCP listener bind");
        // The accept load the vdso pump's policy reads: nothing before the
        // donation, one posted request after it.
        assert_eq!(listener.accept_load(), (0, 0));
        listener.post_accept(client.try_reserve().unwrap());
        assert_eq!(listener.accept_load(), (1, 0));
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

        // The completion is local: it is queued only once this host's
        // driver polls it in. Wait for the ready queue, bounded; the
        // posted request has then become the queued connection, and the
        // load must track that transition and empty after the claim.
        let mut arrived = false;
        for _ in 0..2000 {
            if listener.has_async_accepts() {
                arrived = true;
                break;
            }
            moto_async::sleep(Duration::from_millis(5)).await;
        }
        assert!(arrived, "no connection within 10s");
        assert_eq!(listener.accept_load(), (0, 1));
        let (stream, _remote_addr) = listener.try_accept().expect("queued reserved accept");
        assert_eq!(listener.accept_load(), (0, 0));
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
        let (client, driver_task) = host_channel().await;

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
        let (client, driver_task) = host_channel().await;

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
        let (client, driver_task) = host_channel().await;

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

/// Read this process's published-channel count from its vdso pool.
fn pool_client_count() -> u64 {
    moto_rt::internal_helper(0, 1, 0, 0, 0, 0)
}

/// The Stage 5 coalescing regression: from a cold pool, N simultaneous
/// sockets must share channels (about ceil(N / capacity) of them), not get
/// one each. Runs in a spawned child so its pool really is cold.
pub fn pool_cold_start_child() -> ! {
    use std::sync::{Arc, Barrier};

    const N: usize = 16;
    let barrier = Arc::new(Barrier::new(N));
    let sockets: Vec<_> = (0..N)
        .map(|_| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                std::net::UdpSocket::bind("127.0.0.1:0").unwrap()
            })
        })
        .collect();
    let sockets: Vec<_> = sockets.into_iter().map(|t| t.join().unwrap()).collect();

    // 16 concurrent sockets, capacity 4 per channel: 4 channels, with +1 of
    // provisioning-race slack.
    let channels = pool_client_count();
    assert!(
        (4..=5).contains(&channels),
        "cold start provisioned {channels} channels for {N} sockets"
    );
    drop(sockets);
    std::process::exit(0);
}

fn test_pool_cold_start_coalesces() {
    let status = std::process::Command::new(std::env::args().next().unwrap())
        .arg("pool-cold-start-child")
        .status()
        .expect("failed to spawn the cold-start child");
    assert!(status.success(), "cold-start child failed: {status:?}");
    println!("net_driver::test_pool_cold_start_coalesces PASS");
}

/// The fail-all policy: with sys-io connects poisoned and the pool cold,
/// a socket constructor fails promptly instead of hanging; unpoisoning
/// restores service.
fn test_sys_io_unavailable_fails_all() {
    // The pool must be cold, or an existing channel satisfies the
    // reservation without provisioning. Idle channels self-close when
    // their last reservation releases; earlier tests' have drained by now.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while pool_client_count() != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the pool did not go cold; {} channel(s) live",
            pool_client_count()
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    moto_rt::internal_helper(0, 2, 1, 0, 0, 0);
    let result = std::net::UdpSocket::bind("127.0.0.1:0");
    moto_rt::internal_helper(0, 2, 0, 0, 0, 0);
    assert!(
        result.is_err(),
        "a bind succeeded while sys-io connects were poisoned"
    );

    let recovered = std::net::UdpSocket::bind("127.0.0.1:0");
    assert!(recovered.is_ok(), "bind did not recover after unpoisoning");
    println!("net_driver::test_sys_io_unavailable_fails_all PASS");
}

/// Accept requests riding donations from two different channels must not
/// collide in the listener's in-flight map. Request ids were per-channel
/// counters, each starting at 1, and the map is keyed by bare id: with one
/// accept outstanding on channel A (its id 2, after the bind's id 1), the
/// second accept on a fresh channel B also drew id 2 and hit the
/// `post_accept_reservation` uniqueness assert -- a vdso panic that killed
/// the process with 0xbadc0de (observed as systest dying with ssh status
/// 222). Ids are process-global now; this pins the cross-channel shape the
/// vdso accept pump produces whenever the pool hands it another channel's
/// slot.
fn test_accept_ids_unique_across_channels() {
    let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

    // Channel B on its own runtime thread, as in production: one
    // LocalRuntime hosts one channel driver (the wake-on-sleep slot is
    // single-handle). The thread ends when B's last reservation releases.
    let (client_b_tx, client_b_rx) = std::sync::mpsc::channel();
    let driver_b_thread = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async move {
            let (client, driver) = moto_io::net::connect()
                .await
                .expect("async connect to sys-io failed");
            client_b_tx.send(client).unwrap();
            driver.run().await;
        });
    });
    let client_b = client_b_rx.recv().unwrap();

    let mut runtime = moto_async::LocalRuntime::new();
    let result = runtime.block_on(async {
        let (client_a, _driver_a) = host_channel().await;

        let listener = moto_io::net::tcp::TcpListener::bind_reserved(
            client_a.try_reserve().unwrap(),
            &loopback,
            None,
        )
        .await
        .expect("reserved TCP listener bind");

        // One in-flight accept on A, then two on B: the pre-fix
        // per-channel id counters made the second B request reuse A's
        // outstanding id.
        listener.post_accept(client_a.try_reserve().unwrap());
        listener.post_accept(client_b.try_reserve().unwrap());
        listener.post_accept(client_b.try_reserve().unwrap());
        assert_eq!(listener.accept_load(), (3, 0));

        let listener_addr = *listener.socket_addr();
        let peer_threads: Vec<_> = (0..3)
            .map(|_| {
                std::thread::spawn(move || {
                    use std::io::Write;
                    let mut peer = std::net::TcpStream::connect(listener_addr).unwrap();
                    peer.write_all(b"ping").unwrap();
                })
            })
            .collect();

        // Hold the accepted streams until the peers are done: dropping one
        // eagerly closes it, and a peer whose 4-byte write loses that race
        // sees NotConnected (observed as a release-gate flake).
        let mut accepted = Vec::new();
        let mut all_accepted = true;
        for _ in 0..3 {
            match bounded_output(listener.accept(), 5).await {
                Some(result) => accepted.push(result.expect("cross-channel accept failed")),
                None => all_accepted = false,
            }
        }
        (all_accepted, accepted, peer_threads)
    });
    let (all_accepted, accepted, peer_threads) = result;
    assert!(all_accepted, "cross-channel accept did not complete");
    for peer in peer_threads {
        peer.join().unwrap();
    }
    drop(accepted);
    drop(client_b);
    driver_b_thread.join().unwrap();
    println!("net_driver::test_accept_ids_unique_across_channels PASS");
}

/// A partial nonblocking write must be answered by a WRITABLE edge once
/// space returns. Under epoll semantics a partial write means "buffer
/// full, an edge is owed when it drains", and tokio's PollEvented clears
/// its cached WRITABLE on `n < buf.len()` without ever seeing a
/// WouldBlock; before the fix only an E_NOT_READY armed the re-raise, so
/// a mid-write page-pool exhaustion parked such a writer forever (the
/// russhd SFTP stall).
///
/// The channel TX pool is finite and the peer reads nothing during the
/// fill, so exhaustion is deterministic. A 4-page write returns partial
/// when fewer than 4 pages remain; if the pool size is an exact multiple
/// of 4 the first fill ends in E_NOT_READY instead -- then the peer
/// drains, and a second fill led by one 1-page write shifts alignment so
/// its tail is guaranteed partial.
fn test_partial_write_raises_writable() {
    use moto_io::net::readiness::{NetEventListener, Readiness};

    struct CountingObserver {
        writable: AtomicUsize,
    }
    impl NetEventListener for CountingObserver {
        fn on_readiness(&self, edges: Readiness) {
            if edges.contains(Readiness::WRITABLE) {
                self.writable.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    const PAGE: usize = moto_ipc::io_channel::PAGE_SIZE;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let (drain_tx, drain_rx) = std::sync::mpsc::channel::<()>();
    let peer_thread = std::thread::spawn(move || {
        use std::io::Read;
        let (mut peer, _) = listener.accept().unwrap();
        // Bounded reads: each drain pass ends at a timeout, not at EOF.
        peer.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut total = 0usize;
        let mut buf = vec![0u8; 64 * 1024];
        // Drain on demand; EOF or a dropped sender ends the loop.
        while drain_rx.recv().is_ok() {
            loop {
                match peer.read(&mut buf) {
                    Ok(0) => return total,
                    Ok(n) => total += n,
                    Err(_) => break, // timeout: drained for now
                }
            }
        }
        total
    });

    let observer = Arc::new(CountingObserver {
        writable: AtomicUsize::new(0),
    });

    let mut runtime = moto_async::LocalRuntime::new();
    let saw_edge = runtime.block_on(async {
        let (client, _driver_task) = host_channel().await;

        let stream = moto_io::net::tcp::TcpStream::connect_reserved(
            client.try_reserve().unwrap(),
            &peer_addr,
            None,
            Some(observer.clone() as Arc<dyn NetEventListener>),
        )
        .await
        .expect("reserved TCP connect");

        let big = vec![7u8; 4 * PAGE];
        let lead = vec![7u8; PAGE];

        let mut partial = false;
        for fill in 0..2 {
            if fill == 1 {
                // Exact-multiple pool: drain, then shift alignment by one
                // page so this fill's tail cannot land on a boundary.
                drain_tx.send(()).unwrap();
                let mut spins = 0;
                loop {
                    match stream.try_write(&[&lead]) {
                        Ok(n) if n == PAGE => break,
                        Ok(_) | Err(_) => {
                            spins += 1;
                            assert!(spins < 2000, "pool never refilled after drain");
                            moto_async::sleep(Duration::from_millis(5)).await;
                        }
                    }
                }
            }
            loop {
                match stream.try_write(&[&big]) {
                    Ok(n) if n == big.len() => continue,
                    Ok(n) => {
                        assert!(n > 0 && n < big.len());
                        partial = true;
                        break;
                    }
                    Err(err) => {
                        assert_eq!(err, moto_rt::E_NOT_READY);
                        break;
                    }
                }
            }
            if partial {
                break;
            }
        }
        assert!(partial, "the fill never produced a partial write");

        // The claim: draining (space returning) must raise WRITABLE even
        // though the last write was partial, not E_NOT_READY.
        let edges_before = observer.writable.load(Ordering::SeqCst);
        drain_tx.send(()).unwrap();
        for _ in 0..2000 {
            if observer.writable.load(Ordering::SeqCst) > edges_before {
                return true;
            }
            moto_async::sleep(Duration::from_millis(5)).await;
        }
        false
    });
    assert!(saw_edge, "no WRITABLE edge after a partial write");

    drop(drain_tx);
    drop(runtime);
    let _ = peer_thread.join().unwrap();
    println!("net_driver::test_partial_write_raises_writable PASS");
}

pub fn run_all_tests() {
    test_connect_drive_shutdown();
    test_reservation_lifecycle();
    test_reserved_socket_io();
    test_reserved_listener_accept();
    test_reserved_accept_parks_until_donation();
    test_reserved_cancelled_accept_redelivers();
    test_reserved_delivered_then_cancelled_accept_redelivers();
    test_accept_ids_unique_across_channels();
    test_partial_write_raises_writable();
    test_pool_cold_start_coalesces();
    test_sys_io_unavailable_fails_all();
}
