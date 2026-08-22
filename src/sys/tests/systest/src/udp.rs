#![allow(clippy::slow_vector_initialization)]

use std::sync::Arc;

use moto_io::net::udp::UdpSocket as NativeUdpSocket;
use moto_ipc::io_channel;

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
        let (client, driver_task) = crate::net_harness::host_channel().await;
        {
            let socket = NativeUdpSocket::bind_reserved(
                client.try_reserve().unwrap(),
                &"127.0.0.1:0".parse().unwrap(),
                None,
            )
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
        }
        crate::net_harness::drain_host_channel(client, driver_task).await;
    });
    println!("-- test_native_udp_ttl() PASS");
}

fn test_native_udp_size_limit() {
    moto_async::LocalRuntime::new().block_on(async {
        let (client, driver_task) = crate::net_harness::host_channel().await;
        {
            let socket = NativeUdpSocket::bind_reserved(
                client.try_reserve().unwrap(),
                &"127.0.0.1:0".parse().unwrap(),
                None,
            )
            .await
            .unwrap();
            let destination = "127.0.0.1:9".parse().unwrap();
            let oversized = vec![0; moto_rt::net::MAX_UDP_PAYLOAD + 1];
            assert_eq!(
                socket.try_send_to(&oversized, &destination),
                Err(moto_rt::E_INVALID_ARGUMENT)
            );
            assert_eq!(
                socket.send_to_future(&oversized, &destination).await,
                Err(moto_rt::E_INVALID_ARGUMENT)
            );
        }
        crate::net_harness::drain_host_channel(client, driver_task).await;
    });
    println!("-- test_native_udp_size_limit() PASS");
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

fn test_unsupported_udp_options_return_errors() {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::fd::AsRawFd;

    fn assert_unsupported<T: core::fmt::Debug>(result: std::io::Result<T>) {
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Unsupported);
    }

    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    assert_unsupported(socket.set_broadcast(true));
    assert_unsupported(socket.broadcast());
    assert_unsupported(socket.set_multicast_loop_v4(true));
    assert_unsupported(socket.multicast_loop_v4());
    assert_unsupported(socket.set_multicast_ttl_v4(2));
    assert_unsupported(socket.multicast_ttl_v4());
    assert_unsupported(socket.set_multicast_loop_v6(true));
    assert_unsupported(socket.multicast_loop_v6());

    let multicast_v4 = "239.1.2.3".parse().unwrap();
    assert_unsupported(socket.join_multicast_v4(&multicast_v4, &Ipv4Addr::UNSPECIFIED));
    assert_unsupported(socket.leave_multicast_v4(&multicast_v4, &Ipv4Addr::UNSPECIFIED));
    let multicast_v6: Ipv6Addr = "ff02::1".parse().unwrap();
    assert_unsupported(socket.join_multicast_v6(&multicast_v6, 0));
    assert_unsupported(socket.leave_multicast_v6(&multicast_v6, 0));

    let fd = socket.as_raw_fd();
    assert_eq!(
        moto_rt::net::set_only_v6(fd, true),
        Err(moto_rt::Error::NotImplemented)
    );
    assert_eq!(
        moto_rt::net::only_v6(fd),
        Err(moto_rt::Error::NotImplemented)
    );

    println!("-- test_unsupported_udp_options_return_errors() PASS");
}

/// Exercise source fragmentation and reassembly through the real tap device.
pub fn test_tap_udp_fragmentation(destination: &str) {
    // Above every supported Ethernet IP MTU, but small enough to keep failures
    // easy to diagnose and independent of the maximum-datagram boundary tests.
    const PAYLOAD_LEN: usize = 4096;

    let destination: std::net::SocketAddr = destination.parse().unwrap();
    let local = match destination {
        std::net::SocketAddr::V4(_) => "192.168.4.2:0",
        std::net::SocketAddr::V6(_) => "[2001:db8::2]:0",
    };
    let socket = std::net::UdpSocket::bind(local).unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();

    let payload: Vec<u8> = (0..PAYLOAD_LEN)
        .map(|offset| (offset.wrapping_mul(37).wrapping_add(11) & 0xff) as u8)
        .collect();
    assert_eq!(
        socket.send_to(&payload, destination).unwrap(),
        payload.len()
    );

    let mut echoed = vec![0_u8; PAYLOAD_LEN + 1];
    let (len, source) = socket.recv_from(&mut echoed).unwrap();
    assert_eq!(source, destination);
    assert_eq!(len, payload.len());
    assert_eq!(&echoed[..len], payload);
    println!("-- tap UDP fragmentation via {destination} PASS");
}

fn test_udp_large_packets() {
    let a1 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:1234").unwrap();
    let a2 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:5678").unwrap();
    let s1 = std::net::UdpSocket::bind(a1).unwrap();
    let s2 = std::net::UdpSocket::bind(a2).unwrap();

    let oversized = vec![0; moto_rt::net::MAX_UDP_PAYLOAD + 1];
    assert_eq!(
        s1.send_to(&oversized, a2).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );

    let mut buf1 = vec![];
    buf1.resize(moto_rt::net::MAX_UDP_PAYLOAD, 0);

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
    moto_async::LocalRuntime::new().block_on(async {
        let (client, driver_task) = crate::net_harness::host_channel().await;
        let socket = NativeUdpSocket::bind_reserved(client.try_reserve().unwrap(), &addr, None)
            .await
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
            assert_eq!(queued, 16, "unexpected UDP TX datagram limit");

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

        drop(socket);
        crate::net_harness::drain_host_channel(client, driver_task).await;
    });

    println!("-- test_cancelled_native_io_waiters_are_removed() PASS");
}

fn test_native_udp_tx_byte_limit() {
    let addr = std::net::SocketAddr::parse_ascii(b"127.0.0.1:0").unwrap();
    let destination = std::net::SocketAddr::parse_ascii(b"127.0.0.1:9").unwrap();
    let datagram = vec![0_u8; moto_rt::net::MAX_UDP_PAYLOAD];

    moto_async::LocalRuntime::new().block_on(async {
        let (client, driver_task) = crate::net_harness::host_channel().await;
        let socket = NativeUdpSocket::bind_reserved(client.try_reserve().unwrap(), &addr, None)
            .await
            .unwrap();

        socket.with_tx_pages_exhausted_for_test(|| {
            for _ in 0..4 {
                assert_eq!(
                    socket.try_send_to(&datagram, &destination),
                    Ok(datagram.len())
                );
            }
            assert_eq!(
                socket.try_send_to(&datagram, &destination),
                Err(moto_rt::E_NOT_READY)
            );
        });

        drop(socket);
        crate::net_harness::drain_host_channel(client, driver_task).await;
    });

    println!("-- test_native_udp_tx_byte_limit() PASS");
}

fn test_native_udp_rx_queue_limit() {
    let addr = std::net::SocketAddr::parse_ascii(b"127.0.0.1:0").unwrap();

    moto_async::LocalRuntime::new().block_on(async {
        let (client, driver_task) = crate::net_harness::host_channel().await;
        let socket = NativeUdpSocket::bind_reserved(client.try_reserve().unwrap(), &addr, None)
            .await
            .unwrap();

        for port in 1..=17 {
            socket.inject_empty_rx_for_test(([127, 0, 0, 1], port).into());
        }

        let mut byte = [0_u8; 1];
        for port in 1..=16 {
            assert_eq!(
                socket.try_recv_from(&mut byte, false),
                Ok((0, ([127, 0, 0, 1], port).into()))
            );
        }
        assert_eq!(
            socket.try_recv_from(&mut byte, false),
            Err(moto_rt::E_NOT_READY),
            "the newest datagram survived RX queue overflow"
        );

        drop(socket);
        crate::net_harness::drain_host_channel(client, driver_task).await;
    });

    println!("-- test_native_udp_rx_queue_limit() PASS");
}

fn test_native_close_ends_udp_io() {
    use std::future::Future;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    struct WakeFlag(AtomicBool);
    impl Wake for WakeFlag {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::Release);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::Release);
        }
    }

    let addr = std::net::SocketAddr::parse_ascii(b"127.0.0.1:0").unwrap();
    let destination = std::net::SocketAddr::parse_ascii(b"127.0.0.1:9").unwrap();
    moto_async::LocalRuntime::new().block_on(async {
        let (client, driver_task) = crate::net_harness::host_channel().await;
        let socket = NativeUdpSocket::bind_reserved(client.try_reserve().unwrap(), &addr, None)
            .await
            .unwrap();

        let recv_wake = Arc::new(WakeFlag(AtomicBool::new(false)));
        let recv_waker = Waker::from(recv_wake.clone());
        let mut recv_cx = Context::from_waker(&recv_waker);
        let mut recv_buf = [0_u8; 1];
        let mut recv = Box::pin(socket.recv_from_future(&mut recv_buf, false));
        assert!(matches!(recv.as_mut().poll(&mut recv_cx), Poll::Pending));

        let readable_wake = Arc::new(WakeFlag(AtomicBool::new(false)));
        let readable_waker = Waker::from(readable_wake.clone());
        let mut readable_cx = Context::from_waker(&readable_waker);
        let mut readable = Box::pin(socket.readable());
        assert!(matches!(
            readable.as_mut().poll(&mut readable_cx),
            Poll::Pending
        ));
        assert_eq!(socket.rx_waiter_count(), 2);

        socket.with_tx_pages_exhausted_for_test(|| {
            let queued = [1_u8];
            loop {
                match socket.try_send_to(&queued, &destination) {
                    Ok(1) => {}
                    Err(moto_rt::E_NOT_READY) => break,
                    result => panic!("unexpected UDP send result: {result:?}"),
                }
            }

            let send_wake = Arc::new(WakeFlag(AtomicBool::new(false)));
            let send_waker = Waker::from(send_wake.clone());
            let mut send_cx = Context::from_waker(&send_waker);
            let pending = [2_u8];
            let mut send = Box::pin(socket.send_to_future(&pending, &destination));
            assert!(matches!(send.as_mut().poll(&mut send_cx), Poll::Pending));

            let writable_wake = Arc::new(WakeFlag(AtomicBool::new(false)));
            let writable_waker = Waker::from(writable_wake.clone());
            let mut writable_cx = Context::from_waker(&writable_waker);
            let mut writable = Box::pin(socket.writable());
            assert!(matches!(
                writable.as_mut().poll(&mut writable_cx),
                Poll::Pending
            ));
            assert_eq!(socket.tx_waiter_count(), 2);

            socket.close();

            assert!(recv_wake.0.load(Ordering::Acquire));
            assert!(readable_wake.0.load(Ordering::Acquire));
            assert!(send_wake.0.load(Ordering::Acquire));
            assert!(writable_wake.0.load(Ordering::Acquire));
            assert_eq!(socket.rx_waiter_count(), 0);
            assert_eq!(socket.tx_waiter_count(), 0);

            assert_eq!(
                recv.as_mut().poll(&mut recv_cx),
                Poll::Ready(Err(moto_rt::E_NOT_CONNECTED))
            );
            assert_eq!(
                send.as_mut().poll(&mut send_cx),
                Poll::Ready(Err(moto_rt::E_NOT_CONNECTED))
            );
            assert_eq!(readable.as_mut().poll(&mut readable_cx), Poll::Ready(()));
            assert_eq!(writable.as_mut().poll(&mut writable_cx), Poll::Ready(()));

            assert_eq!(
                socket.try_recv_from(&mut [0_u8; 1], false),
                Err(moto_rt::E_NOT_CONNECTED)
            );
            assert_eq!(
                socket.try_send_to(&[3_u8], &destination),
                Err(moto_rt::E_NOT_CONNECTED)
            );
        });

        drop((recv, readable));
        drop(socket);
        crate::net_harness::drain_host_channel(client, driver_task).await;
    });

    println!("-- test_native_close_ends_udp_io() PASS");
}

fn test_udp_tx_progresses_after_page_free() {
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    struct CountingWake(AtomicUsize);
    impl Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver.set_nonblocking(true).unwrap();
    let destination = receiver.local_addr().unwrap();

    moto_async::LocalRuntime::new().block_on(async {
        let (client, driver_task) = crate::net_harness::host_channel().await;
        let queued_socket = NativeUdpSocket::bind_reserved(
            client.try_reserve().unwrap(),
            &"127.0.0.1:0".parse().unwrap(),
            None,
        )
        .await
        .unwrap();

        let first = [0x5a];
        queued_socket.with_tx_pages_exhausted_for_test(|| {
            assert_eq!(
                queued_socket.try_send_to(&first, &destination),
                Ok(first.len())
            );
        });
        // The queued datagram only leaves once the driver runs; the async
        // wait drives it.
        let mut received = [0_u8; 1];
        crate::net_harness::wait_until("the queued datagram", || {
            match receiver.recv_from(&mut received) {
                Ok((len, _)) => {
                    assert_eq!(len, first.len());
                    true
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => false,
                Err(err) => panic!("receiver failed: {err:?}"),
            }
        })
        .await;
        assert_eq!(received, first);

        let wake_count = Arc::new(CountingWake(AtomicUsize::new(0)));
        let waker = Waker::from(wake_count.clone());
        let mut cx = Context::from_waker(&waker);
        let pending = [0xa5];
        let socket = NativeUdpSocket::bind_reserved(
            client.try_reserve().unwrap(),
            &"127.0.0.1:0".parse().unwrap(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(socket.channel_udp_socket_count_for_test(), 2);
        drop(queued_socket);
        crate::net_harness::wait_until("the dropped socket to unregister", || {
            socket.channel_udp_socket_count_for_test() == 1
        })
        .await;

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

        drop(future);
        drop(socket);
        crate::net_harness::drain_host_channel(client, driver_task).await;
    });

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

fn recv_raw(connection: &io_channel::ClientConnection) -> io_channel::Msg {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match connection.recv() {
            Ok(msg) => return msg,
            Err(moto_rt::Error::NotReady) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "timed out waiting for raw sys-io response"
                );
                std::thread::yield_now();
            }
            Err(err) => panic!("raw sys-io receive failed: {err:?}"),
        }
    }
}

fn send_fragment(
    connection: &io_channel::ClientConnection,
    socket_id: u64,
    fragment_id: u16,
    size: u16,
    destination: std::net::SocketAddr,
) {
    let msg = if size == 0 {
        let mut msg = moto_sys_io::api_net::udp_socket_tx_rx_empty_msg(socket_id, &destination);
        msg.payload.args_16_mut()[9] = fragment_id;
        msg
    } else {
        let page = connection.alloc_page(u64::MAX).unwrap();
        moto_sys_io::api_net::udp_socket_tx_rx_msg(socket_id, page, fragment_id, size, &destination)
    };
    connection.send(msg).unwrap();
}

fn send_valid_fragment(
    connection: &io_channel::ClientConnection,
    socket_id: u64,
    fragment_id: u16,
    destination: std::net::SocketAddr,
) {
    send_fragment(
        connection,
        socket_id,
        fragment_id,
        io_channel::PAGE_SIZE as u16,
        destination,
    );
    let ack = recv_raw(connection);
    assert_eq!(
        ack.command,
        moto_sys_io::api_net::NetCmd::UdpSocketTxRxAck as u16
    );
}

pub(crate) fn run_malformed_fragment_child(kind: &str) {
    use std::io::Write;

    let connection = io_channel::ClientConnection::connect("sys-io").unwrap();
    let bind_addr = "127.0.0.1:0".parse().unwrap();
    connection
        .send(moto_sys_io::api_net::bind_udp_socket_request(&bind_addr, 0))
        .unwrap();
    let response = recv_raw(&connection);
    response.status().unwrap();
    let socket_id = response.handle;
    let destination = "127.0.0.1:9".parse().unwrap();
    let other_destination = "127.0.0.1:10".parse().unwrap();
    let full = io_channel::PAGE_SIZE as u16;

    match kind {
        "empty" => {}
        "terminal" | "short" => {}
        "skip" | "address" => send_valid_fragment(&connection, socket_id, 1, destination),
        "too_many" | "too_long" => {
            for fragment_id in 1..16 {
                send_valid_fragment(&connection, socket_id, fragment_id, destination);
            }
        }
        _ => panic!("unknown malformed UDP fragment kind: {kind}"),
    }

    println!("malformed_udp_fragment: armed");
    std::io::stdout().flush().unwrap();
    match kind {
        "empty" => send_fragment(&connection, socket_id, 1, 0, destination),
        "terminal" => send_fragment(&connection, socket_id, u16::MAX, 1, destination),
        "short" => send_fragment(&connection, socket_id, 1, full - 1, destination),
        "skip" => send_fragment(&connection, socket_id, 3, full, destination),
        "address" => send_fragment(&connection, socket_id, u16::MAX, 1, other_destination),
        "too_many" => send_fragment(&connection, socket_id, 16, full, destination),
        "too_long" => {
            let tail = moto_rt::net::MAX_UDP_PAYLOAD - 15 * io_channel::PAGE_SIZE + 1;
            send_fragment(&connection, socket_id, u16::MAX, tail as u16, destination);
        }
        _ => unreachable!(),
    }

    std::thread::sleep(std::time::Duration::from_secs(2));
    std::process::exit(0);
}

fn malformed_udp_fragments_only_kill_the_client() {
    for kind in [
        "empty", "terminal", "short", "skip", "address", "too_many", "too_long",
    ] {
        let mut child = crate::subcommand::spawn();
        child.malformed_udp_fragment(kind);
        assert!(
            !child.wait().unwrap().success(),
            "sys-io accepted malformed UDP fragment kind {kind}"
        );
    }

    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .send_to(b"alive", receiver.local_addr().unwrap())
        .unwrap();
    let mut bytes = [0; 5];
    assert_eq!(receiver.recv(&mut bytes).unwrap(), 5);
    assert_eq!(&bytes, b"alive");

    println!("-- malformed_udp_fragments_only_kill_the_client() PASS");
}

pub fn run_all_tests() {
    test_udp_basic();
    test_native_udp_ttl();
    test_native_udp_size_limit();
    test_posix_udp_ttl();
    test_unsupported_udp_options_return_errors();
    test_udp_large_packets();
    test_udp_double_bind();
    test_udp_connect();
    test_udp_timeouts();
    test_udp_dup_shares_posix_flags();
    test_native_udp_tx_byte_limit();
    test_native_udp_rx_queue_limit();
    test_cancelled_native_io_waiters_are_removed();
    test_native_close_ends_udp_io();
    test_udp_tx_progresses_after_page_free();
    udp_rebind_after_close_test();
    udp_close_does_not_overtake_tx_test();
    malformed_udp_fragments_only_kill_the_client();
    println!("UDP tests PASS");
}
