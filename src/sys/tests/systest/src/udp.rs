#![allow(clippy::slow_vector_initialization)]

use std::sync::Arc;

use moto_io::net::udp::UdpSocket as NativeUdpSocket;

fn test_udp_basic() {
    let a1 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:1234").unwrap();
    let a2 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:5678").unwrap();
    let s1 = std::net::UdpSocket::bind(a1).unwrap();
    let s2 = std::net::UdpSocket::bind(a2).unwrap();

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
    moto_async::LocalRuntime::new().block_on(async {
        let socket = NativeUdpSocket::bind(&"127.0.0.1:0".parse().unwrap(), None)
            .await
            .unwrap();
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

/// The UDP TTL option through the POSIX ABI, which reaches the same remote
/// RPCs as [`test_native_udp_ttl`] but through the blocking bridge.
fn test_posix_udp_ttl() {
    use std::os::fd::AsRawFd;

    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let fd = socket.as_raw_fd();

    assert_eq!(moto_rt::net::ttl(fd).unwrap(), 64);
    moto_rt::net::set_ttl(fd, 37).unwrap();
    assert_eq!(moto_rt::net::ttl(fd).unwrap(), 37);
    assert_eq!(
        moto_rt::net::set_ttl(fd, u8::MAX as u32 + 1),
        Err(moto_rt::Error::InvalidArgument)
    );
    assert_eq!(moto_rt::net::ttl(fd).unwrap(), 37);

    println!("-- test_posix_udp_ttl() PASS");
}

fn test_udp_large_packets() {
    let a1 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:1234").unwrap();
    let a2 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:5678").unwrap();
    let s1 = std::net::UdpSocket::bind(a1).unwrap();
    let s2 = std::net::UdpSocket::bind(a2).unwrap();

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
    let sock = std::net::UdpSocket::bind(addr).unwrap();
    assert!(std::net::UdpSocket::bind(addr).is_err()); // Can't bind again to the same address.
    drop(sock);
    // Closing the socket releases its address before drop() returns, so the
    // rebind needs no wait; see udp_rebind_after_close_test.
    let _ = std::net::UdpSocket::bind(addr).unwrap();
    println!("-- test_udp_double_bind() PASS");
}

fn test_udp_connect() {
    let a1 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:10000").unwrap();
    let a2 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:10001").unwrap();
    let a3 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:10002").unwrap();
    let s1 = std::net::UdpSocket::bind(a1).unwrap();
    let s2 = std::net::UdpSocket::bind(a2).unwrap();
    let s3 = std::net::UdpSocket::bind(a3).unwrap();

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
    let s1 = std::net::UdpSocket::bind(a1).unwrap();

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

// `O_NONBLOCK` and `SO_*TIMEO` belong to the open file description, so two
// FDs from one `try_clone` share them. That is why they live on the vdso's
// `RtUdpSocket` -- the object the FD table shares between dups -- rather than
// on the native socket or per descriptor, and nothing else in the suite pins
// it. Each flag is both *read back* through the other FD and *acted on*
// through it, because the getter and the blocking path are separate readers
// and only the second one is the behavior.
fn test_udp_dup_shares_posix_flags() {
    let addr = std::net::SocketAddr::parse_ascii(b"127.0.0.1:1237").unwrap();
    let s1 = std::net::UdpSocket::bind(addr).unwrap();
    let s2 = s1.try_clone().unwrap();
    let buf = &mut [0_u8; 64];

    assert!(s2.read_timeout().unwrap().is_none());

    let timo = std::time::Duration::from_millis(1);
    s1.set_read_timeout(Some(timo)).unwrap();
    assert_eq!(timo, s2.read_timeout().unwrap().unwrap());
    assert_eq!(
        s2.recv_from(buf).err().unwrap().kind(),
        std::io::ErrorKind::TimedOut,
        "a timeout set on one FD did not bound a receive on its dup"
    );

    s2.set_read_timeout(None).unwrap();
    assert!(s1.read_timeout().unwrap().is_none());

    // A deadline stays set here only so that an unshared `O_NONBLOCK` fails
    // the assertion below instead of hanging: the blocking path consults the
    // flag first, so a shared one returns WouldBlock at once and an unshared
    // one gets as far as parking and comes back TimedOut.
    s1.set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    s1.set_nonblocking(true).unwrap();
    assert_eq!(
        s2.recv_from(buf).err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock,
        "O_NONBLOCK set on one FD did not reach its dup"
    );

    println!("-- test_udp_dup_shares_posix_flags() PASS");
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
    let socket = moto_async::LocalRuntime::new()
        .block_on(NativeUdpSocket::bind(&addr, None))
        .unwrap();

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

    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let destination = receiver.local_addr().unwrap();
    let queued_socket = moto_async::LocalRuntime::new()
        .block_on(NativeUdpSocket::bind(&"127.0.0.1:0".parse().unwrap(), None))
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
    let socket = moto_async::LocalRuntime::new()
        .block_on(NativeUdpSocket::bind(&"127.0.0.1:0".parse().unwrap(), None))
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

/// A UDP socket released through `close()` must free its address before the
/// call returns: an immediate rebind of the same address must succeed.
///
/// The failure this guards is a lost race, so the loop runs long enough to lose
/// it. The background sender is what makes it losable: every channel IO-thread
/// pass briefly upgrades the weak reference the channel keeps to each live UDP
/// socket, and a pass that overlaps the close leaves the IO thread holding the
/// last reference -- so the close message is posted after `close()` returned,
/// behind the rebind.
pub fn udp_rebind_after_close_test() {
    use std::sync::atomic::{AtomicBool, Ordering};

    const ITERS: u32 = 2000;

    let addr = std::net::SocketAddr::parse_ascii(b"127.0.0.1:1234").unwrap();
    let peer = std::net::UdpSocket::bind("127.0.0.1:1235").unwrap();
    let peer_addr = peer.local_addr().unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let noise_stop = stop.clone();
    let noise = std::thread::spawn(move || {
        let sock = std::net::UdpSocket::bind("127.0.0.1:1236").unwrap();
        while !noise_stop.load(Ordering::Relaxed) {
            let _ = sock.send_to(&[0_u8; 16], peer_addr);
        }
    });

    for idx in 0..ITERS {
        let sock = match std::net::UdpSocket::bind(addr) {
            Ok(sock) => sock,
            Err(err) => {
                stop.store(true, Ordering::Relaxed);
                noise.join().unwrap();
                panic!("iteration {idx}: bind({addr}) after close: {err:?}");
            }
        };
        // The socket must have sent: a TX makes the IO thread run a pass, and
        // only a pass can leave it holding the last reference at close time.
        sock.send_to(&[idx as u8], peer_addr).unwrap();
        drop(sock);
    }

    stop.store(true, Ordering::Relaxed);
    noise.join().unwrap();
    println!("-- udp_rebind_after_close_test() PASS");
}

/// A close must not overtake the datagrams its socket already handed to the
/// channel.
///
/// The close travels on the driver's teardown queue, which outranks ordinary
/// staged work, so without the record's staging fence it would reach sys-io
/// first: sys-io would drop the socket and then discard the datagram as
/// addressed to a handle it no longer has, counting it in `net.udp.tx_dropped`.
/// That counter is the only client-visible trace of the reordering, because
/// sys-io drops a UDP socket's unsent bytes either way (its own teardown does
/// not flush them).
///
/// Every iteration sends before closing, so the gauge must not move at all.
fn udp_close_does_not_overtake_tx_test() {
    const ITERS: u8 = 200;

    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let sockets_before = crate::tcp::read_sys_io_metric("net.udp_sockets");
    let dropped_before = crate::tcp::read_sys_io_metric("net.udp.tx_dropped");

    for idx in 0..ITERS {
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(sender.send_to(&[idx], receiver_addr).unwrap(), 1);
        // The close is queued here, behind the datagram above.
        drop(sender);
    }

    // Every sender is gone from sys-io, so it has processed all the closes and
    // whatever they overtook.
    crate::tcp::wait_for_sys_io_metric("net.udp_sockets", |value| value == sockets_before);
    assert_eq!(
        crate::tcp::read_sys_io_metric("net.udp.tx_dropped"),
        dropped_before,
        "sys-io discarded a datagram staged before its socket's close"
    );

    println!("-- udp_close_does_not_overtake_tx_test() PASS");
}

pub fn run_all_tests() {
    test_udp_basic();
    test_native_udp_ttl();
    test_posix_udp_ttl();
    test_udp_large_packets();
    test_udp_double_bind();
    test_udp_connect();
    test_udp_timeouts();
    test_udp_dup_shares_posix_flags();
    test_cancelled_native_io_waiters_are_removed();
    test_udp_tx_progresses_after_page_free();
    udp_rebind_after_close_test();
    udp_close_does_not_overtake_tx_test();
    println!("UDP tests PASS");
}
