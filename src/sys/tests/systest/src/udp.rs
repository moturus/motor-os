#![allow(clippy::slow_vector_initialization)]

use std::sync::Arc;

use moto_io::net::readiness::{NetEventListener, Readiness};
use moto_io::net::udp::UdpSocket as NativeUdpSocket;

struct NoopNetEventListener;

impl NetEventListener for NoopNetEventListener {
    fn on_readiness(&self, _edges: Readiness) {}

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Bind, tolerating a transient `AlreadyInUse` left behind by a previous run.
///
/// These tests use fixed loopback ports, and sys-io reclaims a dead process's
/// sockets asynchronously. A run starting seconds after one that was killed or
/// panicked -- which is exactly what the stress harness does -- can still see
/// the old bind, so a single attempt is a race rather than a real conflict.
/// A port held indefinitely still fails the test.
fn bind_retry(addr: std::net::SocketAddr) -> std::net::UdpSocket {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match std::net::UdpSocket::bind(addr) {
            Ok(sock) => return sock,
            Err(err) => {
                assert!(
                    err.kind() == std::io::ErrorKind::AlreadyExists
                        && std::time::Instant::now() < deadline,
                    "UdpSocket::bind({addr}): {err:?}"
                );
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
}

fn test_udp_basic() {
    let a1 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:1234").unwrap();
    let a2 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:5678").unwrap();
    let s1 = bind_retry(a1);
    let s2 = bind_retry(a2);

    assert_eq!(a1, s1.local_addr().unwrap());
    assert_eq!(a2, s2.local_addr().unwrap());

    let buf1 = [7; 10];
    assert_eq!(buf1.len(), s1.send_to(&buf1, a2).unwrap());

    let mut buf2 = [0; 100];

    let (amt, src) = s2.peek_from(&mut buf2).unwrap();
    assert_eq!(amt, buf1.len());
    assert_eq!(src, a1);
    assert_eq!(&buf1, &buf2[0..amt]);

    let (amt, src) = s2.recv_from(&mut buf2).unwrap();

    assert_eq!(amt, buf1.len());
    assert_eq!(src, a1);
    assert_eq!(&buf1, &buf2[0..amt]);

    println!("-- test_udp_basic() PASS");
}

fn test_native_udp_ttl() {
    let socket = NativeUdpSocket::bind(
        &"127.0.0.1:0".parse().unwrap(),
        Arc::new(NoopNetEventListener),
    )
    .unwrap();
    moto_async::LocalRuntime::new().block_on(async {
        assert_eq!(socket.ttl_async().await.unwrap(), 64);
        socket.set_ttl_async(37).await.unwrap();
        assert_eq!(socket.ttl_async().await.unwrap(), 37);
        assert_eq!(
            socket.set_ttl_async(0).await,
            Err(moto_rt::E_INVALID_ARGUMENT)
        );
        assert_eq!(
            socket.set_ttl_async(u8::MAX as u32 + 1).await,
            Err(moto_rt::E_INVALID_ARGUMENT)
        );
    });
    println!("-- test_native_udp_ttl() PASS");
}

fn test_udp_large_packets() {
    let a1 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:1234").unwrap();
    let a2 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:5678").unwrap();
    let s1 = bind_retry(a1);
    let s2 = bind_retry(a2);

    let mut buf1 = vec![];
    buf1.resize(moto_rt::net::MAX_UDP_PAYLOAD, 0); // 65493

    let mut buf2 = vec![];
    buf2.resize(moto_rt::net::MAX_UDP_PAYLOAD, 0);

    #[cfg(debug_assertions)]
    const NUM_PACKETS: i32 = 10;
    #[cfg(not(debug_assertions))]
    const NUM_PACKETS: i32 = 100;

    let started = std::time::Instant::now();
    for idx in 0..NUM_PACKETS {
        buf1[4097] = (idx % 255) as u8;
        assert_eq!(buf1.len(), s1.send_to(&buf1, a2).unwrap());
        let (amt, src) = s2.recv_from(&mut buf2).unwrap();

        assert_eq!(amt, buf1.len());
        assert_eq!(src, a1);
        assert_eq!(buf2[4097], (idx % 255) as u8);
    }
    let elapsed = started.elapsed();

    println!(
        "-- test_udp_large_packets() PASS: {} usec/roundtrip",
        elapsed.as_micros() / (NUM_PACKETS as u128)
    );
}

fn test_udp_double_bind() {
    let addr = std::net::SocketAddr::parse_ascii(b"127.0.0.1:1234").unwrap();
    let sock = bind_retry(addr);
    assert!(std::net::UdpSocket::bind(addr).is_err()); // Can't bind again to the same address.
    drop(sock);
    // The rebind must eventually succeed, but `sock`'s teardown -- like any
    // socket release -- reaches sys-io asynchronously, so an immediate retry can
    // still observe the old bind. bind_retry waits for the release; the strict
    // is_err() above already proved the double-bind is rejected while live.
    let _ = bind_retry(addr); // Can bind now that `sock` is dropped.
    println!("-- test_udp_double_bind() PASS");
}

fn test_udp_connect() {
    let a1 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:10000").unwrap();
    let a2 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:10001").unwrap();
    let a3 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:10002").unwrap();
    let s1 = bind_retry(a1);
    let s2 = bind_retry(a2);
    let s3 = bind_retry(a3);

    s1.connect(a2).unwrap();
    assert_eq!(s1.local_addr().unwrap(), a1);
    assert_eq!(s1.peer_addr().unwrap(), a2);
    assert_eq!(
        s2.peer_addr().err().unwrap().kind(),
        std::io::ErrorKind::NotConnected
    );

    s2.connect(a1).unwrap();
    assert_eq!(s2.local_addr().unwrap(), a2);
    assert_eq!(s2.peer_addr().unwrap(), a1);

    let buf1 = [7; 10];
    // s3 -> s2 packet is dropped, but s1 -> s2 is received.
    assert_eq!(buf1.len(), s3.send_to(&buf1, a2).unwrap());
    assert_eq!(buf1.len(), s1.send(&buf1).unwrap());

    let mut buf2 = [0; 100];

    // s1 -> s2 send works.
    let (amt, src) = s2.peek_from(&mut buf2).unwrap();
    assert_eq!(amt, buf1.len());
    assert_eq!(src, a1);
    assert_eq!(&buf1, &buf2[0..amt]);

    let amt = s2.peek(&mut buf2).unwrap();
    assert_eq!(amt, buf1.len());
    assert_eq!(&buf1, &buf2[0..amt]);

    let amt = s2.recv(&mut buf2).unwrap();

    assert_eq!(amt, buf1.len());
    assert_eq!(&buf1, &buf2[0..amt]);

    println!("-- test_udp_connect() PASS");
}

fn test_udp_timeouts() {
    let a1 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:1234").unwrap();
    let s1 = bind_retry(a1);

    // No timeouts by default.
    assert!(s1.write_timeout().unwrap().is_none());
    assert!(s1.read_timeout().unwrap().is_none());

    // Set timeouts.
    let timo = std::time::Duration::from_millis(1);
    s1.set_write_timeout(Some(timo)).unwrap();
    s1.set_read_timeout(Some(timo)).unwrap();

    assert_eq!(timo, s1.write_timeout().unwrap().unwrap());
    assert_eq!(timo, s1.read_timeout().unwrap().unwrap());

    #[allow(unused)]
    let mut buf = &mut [0; 64];
    assert_eq!(
        s1.peek_from(buf).err().unwrap().kind(),
        std::io::ErrorKind::TimedOut
    );
    assert_eq!(
        s1.recv_from(buf).err().unwrap().kind(),
        std::io::ErrorKind::TimedOut
    );

    // Clear timeouts.
    s1.set_write_timeout(None).unwrap();
    s1.set_read_timeout(None).unwrap();

    assert!(s1.write_timeout().unwrap().is_none());
    assert!(s1.read_timeout().unwrap().is_none());

    // Disallow zero timeouts: see
    // https://doc.rust-lang.org/std/net/struct.UdpSocket.html#method.set_write_timeout
    let zero = std::time::Duration::new(0, 0);
    assert_eq!(
        s1.set_write_timeout(Some(zero)).err().unwrap().kind(),
        std::io::ErrorKind::InvalidInput
    );
    assert_eq!(
        s1.set_read_timeout(Some(zero)).err().unwrap().kind(),
        std::io::ErrorKind::InvalidInput
    );

    println!("-- test_udp_timeouts() PASS");
}

fn test_cancelled_native_io_waiters_are_removed() {
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    struct DistinctWake(AtomicUsize);
    impl Wake for DistinctWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    let addr = std::net::SocketAddr::parse_ascii(b"127.0.0.1:0").unwrap();
    let socket = NativeUdpSocket::bind(&addr, Arc::new(NoopNetEventListener)).unwrap();

    for _ in 0..128 {
        let waker = Waker::from(Arc::new(DistinctWake(AtomicUsize::new(0))));
        let mut cx = Context::from_waker(&waker);
        let mut future = Box::pin(socket.readable());
        assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
        assert_eq!(socket.rx_waiter_count(), 1);
        drop(future);
        assert_eq!(socket.rx_waiter_count(), 0);
    }

    for _ in 0..128 {
        let waker = Waker::from(Arc::new(DistinctWake(AtomicUsize::new(0))));
        let mut cx = Context::from_waker(&waker);
        let mut byte = [0_u8; 1];
        let mut future = Box::pin(socket.recv_from_future(&mut byte, false));
        assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
        assert_eq!(socket.rx_waiter_count(), 1);
        drop(future);
        assert_eq!(socket.rx_waiter_count(), 0);
    }

    socket.with_tx_pages_exhausted_for_test(|| {
        let destination = std::net::SocketAddr::parse_ascii(b"127.0.0.1:9").unwrap();
        let byte = [1_u8];
        let mut queued = 0;
        loop {
            match socket.try_send_to(&byte, &destination) {
                Ok(1) => {
                    queued += 1;
                    assert!(queued < 64, "UDP TX queue did not fill");
                }
                Err(moto_rt::E_NOT_READY) => break,
                result => panic!("unexpected UDP send result: {result:?}"),
            }
        }

        for _ in 0..128 {
            let waker = Waker::from(Arc::new(DistinctWake(AtomicUsize::new(0))));
            let mut cx = Context::from_waker(&waker);
            let mut future = Box::pin(socket.writable());
            assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
            assert_eq!(socket.tx_waiter_count(), 1);
            drop(future);
            assert_eq!(socket.tx_waiter_count(), 0);
        }

        for _ in 0..128 {
            let waker = Waker::from(Arc::new(DistinctWake(AtomicUsize::new(0))));
            let mut cx = Context::from_waker(&waker);
            let mut future = Box::pin(socket.send_to_future(&byte, &destination));
            assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
            assert_eq!(socket.tx_waiter_count(), 1);
            drop(future);
            assert_eq!(socket.tx_waiter_count(), 0);
        }
    });

    println!("-- test_cancelled_native_io_waiters_are_removed() PASS");
}

fn test_udp_tx_progresses_after_page_free() {
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::Duration;

    struct CountingWake(AtomicUsize);
    impl Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    let receiver = bind_retry("127.0.0.1:0".parse().unwrap());
    receiver
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let destination = receiver.local_addr().unwrap();
    let queued_socket = NativeUdpSocket::bind(
        &"127.0.0.1:0".parse().unwrap(),
        Arc::new(NoopNetEventListener),
    )
    .unwrap();

    let first = [0x5a];
    queued_socket.with_tx_pages_exhausted_for_test(|| {
        assert_eq!(
            queued_socket.try_send_to(&first, &destination),
            Ok(first.len())
        );
    });
    let mut received = [0_u8; 1];
    assert_eq!(receiver.recv_from(&mut received).unwrap().0, first.len());
    assert_eq!(received, first);

    let wake_count = Arc::new(CountingWake(AtomicUsize::new(0)));
    let waker = Waker::from(wake_count.clone());
    let mut cx = Context::from_waker(&waker);
    let pending = [0xa5];
    let socket = NativeUdpSocket::bind(
        &"127.0.0.1:0".parse().unwrap(),
        Arc::new(NoopNetEventListener),
    )
    .unwrap();
    assert_eq!(socket.channel_udp_socket_count_for_test(), 2);
    drop(queued_socket);
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while socket.channel_udp_socket_count_for_test() != 1 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(socket.channel_udp_socket_count_for_test(), 1);

    let mut future = Box::pin(socket.send_to_future(&pending, &destination));
    socket.with_tx_pages_exhausted_for_test(|| {
        let queued = [0x33];
        loop {
            match socket.try_send_to(&queued, &destination) {
                Ok(1) => {}
                Err(moto_rt::E_NOT_READY) => break,
                result => panic!("unexpected UDP send result: {result:?}"),
            }
        }
        assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
    });

    assert_ne!(
        wake_count.0.load(Ordering::Relaxed),
        0,
        "channel progress did not wake the UDP sender"
    );
    assert_eq!(
        future.as_mut().poll(&mut cx),
        Poll::Ready(Ok(pending.len()))
    );

    println!("-- test_udp_tx_progresses_after_page_free() PASS");
}

pub fn run_all_tests() {
    test_udp_basic();
    test_native_udp_ttl();
    test_udp_large_packets();
    test_udp_double_bind();
    test_udp_connect();
    test_udp_timeouts();
    test_cancelled_native_io_waiters_are_removed();
    test_udp_tx_progresses_after_page_free();
    println!("UDP tests PASS");
}
