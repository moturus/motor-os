#![allow(unused)]
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, atomic::*};
use std::task::{Context, Poll};
use std::time::Duration;

use moto_io::net::tcp::{
    Shutdown as NativeShutdown, TcpListener as NativeTcpListener, TcpStream as NativeTcpStream,
};

pub(crate) fn read_sys_io_metric(name: &str) -> u64 {
    let provider = moto_stats::Collector::provider_by_name("sys-io")
        .expect("sys-io stats provider is not registered");
    let metric = moto_stats::Collector::describe(&provider)
        .unwrap()
        .into_iter()
        .find(|metric| metric.name == name)
        .unwrap_or_else(|| panic!("sys-io metric {name:?} is not described"));
    // read() polls sys-io's net runtime for a live snapshot; under load that
    // round-trip can come back empty and surface as NotFound for a metric that
    // always exists (same race as fs.rs::read_sys_io_fs_metrics). Retry to a
    // deadline; a metric that never appears still fails.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        match moto_stats::Collector::read(&provider, metric.id, moto_stats::SCOPE_GLOBAL) {
            Ok(value) => return value,
            Err(err) => {
                assert!(
                    err == moto_rt::E_NOT_FOUND && std::time::Instant::now() < deadline,
                    "read sys-io metric {name:?}: {err}"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn read_tcp_socket_stats() -> Vec<moto_sys_io::stats::TcpSocketStatsV1> {
    let mut service = moto_sys_io::stats::IoStatsService::connect().unwrap();
    let mut result = Vec::new();
    let mut start_id = 0;
    loop {
        let page = service.get_tcp_socket_stats(start_id).unwrap();
        let Some(last) = page.last() else {
            return result;
        };
        let next_id = last.id + 1;
        let done = page.len() < moto_sys_io::stats::MAX_TCP_SOCKET_STATS;
        result.extend_from_slice(page);
        if done {
            return result;
        }
        start_id = next_id;
    }
}

pub(crate) fn wait_for_sys_io_metric(name: &str, predicate: impl Fn(u64) -> bool) -> u64 {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let value = read_sys_io_metric(name);
        if predicate(value) {
            return value;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {name}; last value was {value}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn recv_raw_net_response(
    connection: &moto_ipc::io_channel::ClientConnection,
) -> moto_ipc::io_channel::Msg {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
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

/// Whether a socket has left ESTABLISHED for one of the closing states, i.e.
/// whether something on this side has closed it.
///
/// This is what "sys-io reclaimed the abandoned socket" looks like while its
/// peer is still held open: the close is a FIN, so the socket sits in FIN-WAIT
/// until the peer answers it, and only then is it dropped. Testing for the
/// socket's *disappearance* instead would be testing that the close was a
/// reset, which it is only for SO_LINGER(0).
fn is_closing(state: moto_sys_io::stats::TcpProtocolState) -> bool {
    use moto_sys_io::stats::TcpProtocolState;

    match state {
        TcpProtocolState::FinWait1
        | TcpProtocolState::FinWait2
        | TcpProtocolState::Closing
        | TcpProtocolState::LastAck
        | TcpProtocolState::TimeWait
        | TcpProtocolState::Closed => true,
        TcpProtocolState::Listen
        | TcpProtocolState::SynSent
        | TcpProtocolState::SynReceived
        | TcpProtocolState::Established
        | TcpProtocolState::CloseWait => false,
    }
}

fn wait_for_tcp_pair(listener_addr: SocketAddr, client_addr: SocketAddr) {
    use moto_sys_io::stats::TcpProtocolState;

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let sockets = read_tcp_socket_stats();
        let client = sockets.iter().find(|socket| {
            socket.local_addr() == Some(client_addr) && socket.remote_addr() == Some(listener_addr)
        });
        let server = sockets.iter().find(|socket| {
            socket.local_addr() == Some(listener_addr) && socket.remote_addr() == Some(client_addr)
        });
        if let (Some(client), Some(server)) = (client, server) {
            assert_eq!(client.smoltcp_state, TcpProtocolState::Established);
            assert_eq!(server.smoltcp_state, TcpProtocolState::Established);
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for accepted socket pair; matching sockets: {:?}",
            sockets
                .iter()
                .filter(|socket| {
                    socket.local_addr() == Some(listener_addr)
                        || socket.local_addr() == Some(client_addr)
                })
                .collect::<Vec<_>>()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_tcp_socket_state(
    local_addr: SocketAddr,
    remote_addr: Option<SocketAddr>,
    tcp_state: moto_sys_io::api_net::TcpState,
    protocol_state: moto_sys_io::stats::TcpProtocolState,
) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let sockets = read_tcp_socket_stats();
        let matching: Vec<_> = sockets
            .iter()
            .filter(|socket| {
                socket.local_addr() == Some(local_addr) && socket.remote_addr() == remote_addr
            })
            .collect();
        if matching
            .iter()
            .any(|socket| socket.tcp_state == tcp_state && socket.smoltcp_state == protocol_state)
        {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {tcp_state:?}/{protocol_state:?}; matching sockets: {matching:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn cancelled_connects_reclaimed(pairs: &[(SocketAddr, SocketAddr)]) -> bool {
    let sockets = read_tcp_socket_stats();
    pairs.iter().all(|(listener_addr, client_addr)| {
        let server_is_live = sockets.iter().any(|socket| {
            socket.local_addr() == Some(*listener_addr)
                && socket.remote_addr() == Some(*client_addr)
        });
        // The server half is held open by the caller, so the abandoned
        // connect is reclaimed only after it lets go; until then closing
        // is what it can reach.
        let abandoned_connect_is_live = sockets.iter().any(|socket| {
            socket.local_addr() == Some(*client_addr)
                && socket.remote_addr() == Some(*listener_addr)
                && !is_closing(socket.smoltcp_state)
        });
        server_is_live && !abandoned_connect_is_live
    })
}

/// A dropped native connect future must not strand the socket that sys-io
/// creates when the already-posted connect RPC later completes. The held
/// NetClient keeps the channel open after each future releases its own
/// reservation, reproducing the leak's required condition.
fn test_cancelled_native_connect_closes_socket() {
    use std::future::Future;

    const CONNECTIONS: usize = 4;

    let total_before = read_sys_io_metric("net.total_tcp_sockets");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listener_addr = listener.local_addr().unwrap();

    moto_async::LocalRuntime::new().block_on(async {
        let (client, driver_task) = crate::net_harness::host_channel().await;
        // Releasing a client's last reservation shuts the channel down; the
        // keeper holds it open across the reserve/drop cycles below (the
        // role the pool version gave a keeper listener).
        let keeper = client.try_reserve().unwrap();

        for _ in 0..CONNECTIONS {
            let mut connect = Box::pin(NativeTcpStream::connect_reserved(
                client.try_reserve().unwrap(),
                &listener_addr,
                None,
                None,
                None,
            ));
            let waker = futures::task::noop_waker();
            let mut context = Context::from_waker(&waker);
            assert!(matches!(connect.as_mut().poll(&mut context), Poll::Pending));
            drop(connect);
        }

        // The queued connect requests only reach sys-io when the driver runs;
        // waiting on the monotonic total drives it and proves the sockets
        // were created (so the reclaim below means something).
        crate::net_harness::wait_until("cancelled connects to reach sys-io", || {
            read_sys_io_metric("net.total_tcp_sockets") >= total_before + (CONNECTIONS as u64) * 2
        })
        .await;

        let mut servers = Vec::with_capacity(CONNECTIONS);
        let mut pairs = Vec::with_capacity(CONNECTIONS);
        for _ in 0..CONNECTIONS {
            let (server, client_addr) = listener.accept().unwrap();
            pairs.push((listener_addr, client_addr));
            servers.push(server);
        }

        crate::net_harness::wait_until("cancelled connect reclaim", || {
            cancelled_connects_reclaimed(&pairs)
        })
        .await;

        // Releasing the server halves answers the abandoned sockets' FINs,
        // which is what lets sys-io finally drop them. The close having been
        // *started* is what the wait above checks; this is the resource
        // actually coming back.
        drop(servers);
        for (_, client_addr) in &pairs {
            crate::net_harness::wait_until("cancelled connect release", || {
                sockets_on_addr_released(*client_addr)
            })
            .await;
        }

        drop(listener);
        drop(keeper);
        crate::net_harness::drain_host_channel(client, driver_task).await;
    });
    println!("test_cancelled_native_connect_closes_socket() PASS");
}

/// Distinct cancelled native futures must physically remove their I/O wakers;
/// a quiet live socket provides no later event that could clean stale entries.
fn test_cancelled_native_io_waiters_are_removed() {
    use std::future::Future;
    use std::task::{Wake, Waker};

    struct DistinctWake(AtomicUsize);
    impl Wake for DistinctWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let release_peer = Arc::new(AtomicBool::new(false));
    let peer_release = release_peer.clone();
    let peer = std::thread::spawn(move || {
        let (_stream, _) = listener.accept().unwrap();
        while !peer_release.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
    });

    moto_async::LocalRuntime::new().block_on(async {
        let (client, driver_task) = crate::net_harness::host_channel().await;
        let stream = NativeTcpStream::connect_reserved(
            client.try_reserve().unwrap(),
            &listener_addr,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        for _ in 0..128 {
            let waker = Waker::from(Arc::new(DistinctWake(AtomicUsize::new(0))));
            let mut cx = Context::from_waker(&waker);
            let mut future = Box::pin(stream.readable());
            assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
            assert_eq!(stream.rx_waiter_count(), 1);
            drop(future);
            assert_eq!(stream.rx_waiter_count(), 0);
        }

        for _ in 0..128 {
            let waker = Waker::from(Arc::new(DistinctWake(AtomicUsize::new(0))));
            let mut cx = Context::from_waker(&waker);
            let mut byte = [0_u8; 1];
            let mut bufs: [&mut [u8]; 1] = [&mut byte];
            let mut future = Box::pin(stream.read_future(&mut bufs, false));
            assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
            assert_eq!(stream.rx_waiter_count(), 1);
            drop(future);
            assert_eq!(stream.rx_waiter_count(), 0);
        }

        // TX-page waiters park on the stream's channel, whose page pool is shared:
        // sys-io returning a page an earlier test still had in flight can make the
        // poll Ready (the page slipped past the drain) or consume the parked
        // waiter before it is counted. Neither run exercises the claim -- a
        // still-parked waiter is removed by dropping its future -- so such an
        // iteration retries with the pool re-drained; the returns are teardown
        // stragglers and dry up. A waiter leak still fails on the post-drop count.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut verified = 0;
        while verified < 128 {
            assert!(
                std::time::Instant::now() < deadline,
                "no undisturbed poll of an exhausted TX pool in 10s"
            );
            stream.with_tx_pages_exhausted_for_test(|| {
                let waker = Waker::from(Arc::new(DistinctWake(AtomicUsize::new(0))));
                let mut cx = Context::from_waker(&waker);
                let mut future = Box::pin(stream.writable());
                if matches!(future.as_mut().poll(&mut cx), Poll::Pending)
                    && stream.tx_waiter_count() == 1
                {
                    drop(future);
                    assert_eq!(stream.tx_waiter_count(), 0);
                    verified += 1;
                }
            });
        }

        let byte = [0_u8; 1];
        let bufs: [&[u8]; 1] = [&byte];
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut verified = 0;
        while verified < 128 {
            assert!(
                std::time::Instant::now() < deadline,
                "no undisturbed poll of an exhausted TX pool in 10s"
            );
            stream.with_tx_pages_exhausted_for_test(|| {
                let waker = Waker::from(Arc::new(DistinctWake(AtomicUsize::new(0))));
                let mut cx = Context::from_waker(&waker);
                let mut future = Box::pin(stream.write_future(&bufs));
                if matches!(future.as_mut().poll(&mut cx), Poll::Pending)
                    && stream.tx_waiter_count() == 1
                {
                    drop(future);
                    assert_eq!(stream.tx_waiter_count(), 0);
                    verified += 1;
                }
            });
        }

        drop(stream);
        release_peer.store(true, Ordering::Release);
        crate::net_harness::drain_host_channel(client, driver_task).await;
    });
    peer.join().unwrap();
    println!("test_cancelled_native_io_waiters_are_removed() PASS");
}

fn test_cancelled_native_rpc_response_is_tolerated() {
    use std::future::Future;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let release_peer = Arc::new(AtomicBool::new(false));
    let peer_release = release_peer.clone();
    let peer = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(&[0x5a]).unwrap();
        while !peer_release.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
    });

    let (net_client, driver_thread) = crate::net_harness::host_channel_on_thread();
    let stream = moto_async::LocalRuntime::new()
        .block_on(NativeTcpStream::connect_reserved(
            net_client.try_reserve().unwrap(),
            &listener_addr,
            None,
            None,
            None,
        ))
        .unwrap();

    moto_io::net::channel::arm_rpc_response_cancel_test();
    let mut future = Box::pin(stream.nodelay_async());
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !moto_io::net::channel::rpc_response_cancel_test_is_held() {
        assert!(
            std::time::Instant::now() < deadline,
            "channel runtime did not hold the RPC response"
        );
        std::thread::yield_now();
    }
    drop(future);
    moto_io::net::channel::release_rpc_response_cancel_test();

    while !moto_io::net::channel::rpc_response_cancel_test_is_done() {
        assert!(
            std::time::Instant::now() < deadline,
            "channel runtime did not finish the cancelled RPC response"
        );
        std::thread::yield_now();
    }

    moto_async::LocalRuntime::new().block_on(async {
        stream.set_nodelay_async(true).await.unwrap();
        assert!(stream.nodelay_async().await.unwrap());
        stream.set_nodelay_async(false).await.unwrap();
        assert!(!stream.nodelay_async().await.unwrap());
        stream.set_ttl_async(43).await.unwrap();
        assert_eq!(stream.ttl_async().await.unwrap(), 43);
        assert_eq!(stream.linger_async().await.unwrap(), None);
        stream
            .set_linger_async(Some(Duration::from_secs(7)))
            .await
            .unwrap();
        assert_eq!(
            stream.linger_async().await.unwrap(),
            Some(Duration::from_secs(7))
        );
        stream.set_linger_async(Some(Duration::MAX)).await.unwrap();
        assert_eq!(
            stream.linger_async().await.unwrap(),
            Some(Duration::from_secs(u32::MAX as u64))
        );
        stream.set_linger_async(None).await.unwrap();
        assert_eq!(stream.linger_async().await.unwrap(), None);
        stream.readable().await;
    });
    assert!(stream.has_rx_bytes());

    moto_io::net::channel::arm_rpc_response_cancel_test();
    let mut future = Box::pin(stream.shutdown_async(NativeShutdown::Read));
    assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !moto_io::net::channel::rpc_response_cancel_test_is_held() {
        assert!(
            std::time::Instant::now() < deadline,
            "channel runtime did not hold the shutdown response"
        );
        std::thread::yield_now();
    }
    assert!(!stream.has_rx_bytes());
    let mut empty = [0_u8; 1];
    assert_eq!(stream.try_read(&mut [&mut empty], false), Ok(0));
    drop(future);
    moto_io::net::channel::release_rpc_response_cancel_test();
    while !moto_io::net::channel::rpc_response_cancel_test_is_done() {
        assert!(
            std::time::Instant::now() < deadline,
            "channel runtime did not finish the cancelled shutdown response"
        );
        std::thread::yield_now();
    }

    drop(stream);
    release_peer.store(true, Ordering::Release);
    driver_thread.join().unwrap();
    peer.join().unwrap();
    println!("test_cancelled_native_rpc_response_is_tolerated() PASS");
}

fn test_native_async_shutdown() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let expected = vec![0x5a_u8; 256 * 1024];
    let peer = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).unwrap();
        received
    });

    moto_async::LocalRuntime::new().block_on(async {
        let (client, driver_task) = crate::net_harness::host_channel().await;
        let stream = NativeTcpStream::connect_reserved(
            client.try_reserve().unwrap(),
            &listener_addr,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        let mut written = 0;
        while written < expected.len() {
            let bufs = [&expected[written..]];
            let n = stream.write_future(&bufs).await.unwrap();
            assert!(n > 0);
            written += n;
        }
        stream.shutdown_async(NativeShutdown::Write).await.unwrap();
        assert_eq!(
            stream.try_write(&[b"after shutdown"]),
            Err(moto_rt::E_NOT_CONNECTED)
        );

        drop(stream);
        crate::net_harness::drain_host_channel(client, driver_task).await;
    });
    assert_eq!(peer.join().unwrap(), expected);
    println!("test_native_async_shutdown() PASS");
}

/// Dropping a stream with pending bytes must neither block on a full staging
/// queue nor let its close overtake those bytes.
fn test_native_stream_drop_under_backpressure() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let release_trigger = Arc::new(AtomicBool::new(false));
    let release_trigger_peer = release_trigger.clone();
    let peer = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        while !release_trigger_peer.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        stream.write_all(&[1]).unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).unwrap();
        received
    });

    let (net_client, driver_thread) = crate::net_harness::host_channel_on_thread();
    let stream = moto_async::LocalRuntime::new()
        .block_on(NativeTcpStream::connect_reserved(
            net_client.try_reserve().unwrap(),
            &listener_addr,
            None,
            None,
            None,
        ))
        .unwrap();
    moto_io::net::channel::arm_stream_drop_backpressure_test(stream.handle());
    release_trigger.store(true, Ordering::Release);

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !moto_io::net::channel::stream_drop_backpressure_test_is_held() {
        assert!(
            std::time::Instant::now() < deadline,
            "channel runtime did not reach the stream-drop backpressure hook"
        );
        std::thread::yield_now();
    }

    // Sixteen pages become two multi-page teardown messages. Their ordinary
    // queue markers remain ahead of the placeholders used to fill staging.
    let expected = vec![0x5a_u8; 64 * 1024];
    let bufs = [expected.as_slice()];
    assert_eq!(stream.try_write(&bufs), Ok(expected.len()));
    stream.fill_stream_drop_send_queue_for_test();

    let drop_done = Arc::new(AtomicBool::new(false));
    let drop_done_thread = drop_done.clone();
    let drop_thread = std::thread::spawn(move || {
        drop(stream);
        drop_done_thread.store(true, Ordering::Release);
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !drop_done.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
        std::thread::yield_now();
    }
    let drop_was_nonblocking = drop_done.load(Ordering::Acquire);

    // Always release the runtime before asserting so a regression reports
    // cleanly instead of stranding the test process.
    moto_io::net::channel::release_stream_drop_backpressure_test();
    drop_thread.join().unwrap();
    assert!(
        drop_was_nonblocking,
        "TcpStream::drop waited for staging-queue room"
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !moto_io::net::channel::stream_drop_backpressure_test_is_done() {
        assert!(
            std::time::Instant::now() < deadline,
            "TcpStream::drop blocked its channel runtime on a full send queue"
        );
        std::thread::yield_now();
    }

    driver_thread.join().unwrap();
    assert_eq!(peer.join().unwrap(), expected);
    println!("test_native_stream_drop_under_backpressure() PASS");
}

/// Prove a redelivered connection is live end to end: the std client pings,
/// the native stream echoes, the client reads the echo back.
fn exchange_bytes_with_client(
    runtime: &mut moto_async::LocalRuntime,
    stream: &NativeTcpStream,
    client: &mut std::net::TcpStream,
) {
    client.write_all(b"ping").unwrap();
    let mut received = Vec::new();
    while received.len() < 4 {
        let mut buf = [0_u8; 8];
        let mut bufs: [&mut [u8]; 1] = [&mut buf];
        let n = runtime
            .block_on(stream.read_future(&mut bufs, false))
            .unwrap();
        assert!(n > 0);
        received.extend_from_slice(&buf[..n]);
    }
    assert_eq!(&received[..], &b"ping"[..]);

    let bufs: [&[u8]; 1] = [b"pong"];
    assert_eq!(runtime.block_on(stream.write_future(&bufs)).unwrap(), 4);
    let mut echo = [0_u8; 4];
    client.read_exact(&mut echo).unwrap();
    assert_eq!(&echo, b"pong");
}

/// Releasing the final listener reference on another thread must remain
/// nonblocking while its channel runtime is held with a full staging queue.
fn test_native_listener_drop_under_backpressure() {
    use std::future::Future;

    struct DistinctWake;

    impl std::task::Wake for DistinctWake {
        fn wake(self: Arc<Self>) {}
    }

    let (net_client, driver_thread) = crate::net_harness::host_channel_on_thread();
    let listener = moto_async::LocalRuntime::new()
        .block_on(NativeTcpListener::bind_reserved(
            net_client.try_reserve().unwrap(),
            &"127.0.0.1:0".parse().unwrap(),
            None,
            None,
        ))
        .unwrap();
    moto_async::LocalRuntime::new().block_on(async {
        listener.set_ttl_async(41).await.unwrap();
        assert_eq!(listener.ttl_async().await.unwrap(), 41);
        assert_eq!(
            listener.set_ttl_async(u8::MAX as u32 + 1).await,
            Err(moto_rt::E_INVALID_ARGUMENT)
        );
    });
    moto_io::net::channel::arm_listener_drop_backpressure_test(listener.handle());

    // Post an accept (the donation is the outstanding request) and park and
    // cancel a caller. The donation's eventual response then arrives with no
    // caller, which makes the channel runtime temporarily upgrade the
    // listener Weak to an Arc.
    listener.post_accept(net_client.try_reserve().unwrap());
    let mut accept = Box::pin(listener.accept());
    let waker = futures::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    assert!(matches!(accept.as_mut().poll(&mut context), Poll::Pending));
    drop(accept);

    let client = std::net::TcpStream::connect(*listener.socket_addr()).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !moto_io::net::channel::listener_drop_backpressure_test_is_held() {
        assert!(
            std::time::Instant::now() < deadline,
            "channel runtime did not reach the listener-drop backpressure hook"
        );
        std::thread::yield_now();
    }

    // The held channel runtime cannot drain its now-full staging queue. Each
    // TTL query therefore registers both an RPC response and a queue-space
    // waiter. Cancelling must remove both before the next query is polled.
    for _ in 0..128 {
        let waker = std::task::Waker::from(Arc::new(DistinctWake));
        let mut context = Context::from_waker(&waker);
        let mut ttl = Box::pin(listener.ttl_async());
        assert!(matches!(ttl.as_mut().poll(&mut context), Poll::Pending));
        assert_eq!(listener.channel_tx_waiter_count_for_test(), 1);
        assert_eq!(listener.channel_rpc_waiter_count_for_test(), 1);
        drop(ttl);
        assert_eq!(listener.channel_tx_waiter_count_for_test(), 0);
        assert_eq!(listener.channel_rpc_waiter_count_for_test(), 0);
    }

    // The hook released its temporary Arc before publishing HELD, so this
    // thread performs the last drop while the channel runtime cannot make
    // staging-queue progress. A blocking destructor would strand this thread
    // until the hook is released.
    let drop_done = Arc::new(AtomicBool::new(false));
    let drop_done_thread = drop_done.clone();
    let drop_thread = std::thread::spawn(move || {
        drop(listener);
        drop_done_thread.store(true, Ordering::Release);
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !drop_done.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
        std::thread::yield_now();
    }
    let drop_was_nonblocking = drop_done.load(Ordering::Acquire);
    moto_io::net::channel::release_listener_drop_backpressure_test();
    drop_thread.join().unwrap();
    assert!(
        drop_was_nonblocking,
        "TcpListener::drop waited for staging-queue room"
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !moto_io::net::channel::listener_drop_backpressure_test_is_done() {
        assert!(
            std::time::Instant::now() < deadline,
            "TcpListener::drop blocked its channel runtime on a full send queue"
        );
        std::thread::yield_now();
    }

    driver_thread.join().unwrap();
    drop(client);
    println!("test_native_listener_drop_under_backpressure() PASS");
}

/// Bind the same address until it is free, or fail once the cancelled bind's
/// rollback is clearly not coming. A stranded listener holds the port forever,
/// so this converges only if the rollback really closed the handle. Sleeping
/// async keeps the caller's channel driver running between attempts.
async fn wait_for_bind_to_succeed(
    client: &moto_io::net::NetClient,
    addr: SocketAddr,
) -> Arc<NativeTcpListener> {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let result =
            NativeTcpListener::bind_reserved(client.try_reserve().unwrap(), &addr, None, None)
                .await;
        match result {
            Ok(listener) => return listener,
            Err(err) => assert!(
                err == moto_rt::E_ALREADY_IN_USE && std::time::Instant::now() < deadline,
                "cancelled bind never released {addr}: {err}"
            ),
        }
        moto_async::sleep(Duration::from_millis(10)).await;
    }
}

/// A native bind future cancelled after its request reached the staging queue
/// must not strand the listener sys-io then creates: the address it took has
/// to come back. Uses a fixed port so the leak is directly observable.
fn test_cancelled_native_bind_releases_addr() {
    use std::future::Future;

    let addr: SocketAddr = "127.0.0.1:3342".parse().unwrap();
    let total_before = read_sys_io_metric("net.total_tcp_sockets");

    moto_async::LocalRuntime::new().block_on(async {
        let (client, driver_task) = crate::net_harness::host_channel().await;
        // Releasing a client's last reservation shuts the channel down; hold
        // it open across the cancel/rebind cycle.
        let keeper = client.try_reserve().unwrap();

        // The first poll takes the reservation and queues the bind request,
        // so the drop below is the post-send cancellation this covers.
        let mut bind = Box::pin(NativeTcpListener::bind_reserved(
            client.try_reserve().unwrap(),
            &addr,
            None,
            None,
        ));
        let waker = futures::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        assert!(matches!(bind.as_mut().poll(&mut context), Poll::Pending));
        drop(bind);

        // The queued request still reaches sys-io (once the driver runs),
        // which creates the listening socket. Checking the monotonic total
        // rather than a live gauge keeps this from racing the rollback, and
        // it is what makes the rebind below mean something: without it the
        // test would also pass if nothing was created.
        crate::net_harness::wait_until("cancelled bind to reach sys-io", || {
            read_sys_io_metric("net.total_tcp_sockets") > total_before
        })
        .await;

        let listener = wait_for_bind_to_succeed(&client, addr).await;
        assert_eq!(*listener.socket_addr(), addr);
        drop(listener);
        drop(keeper);
        crate::net_harness::drain_host_channel(client, driver_task).await;
    });
    println!("test_cancelled_native_bind_releases_addr() PASS");
}

/// Cancellation after the bind response reached the one-shot but before the
/// future consumed it must release the address too. This rolls back from the
/// caller's thread rather than from response dispatch.
fn test_delivered_then_cancelled_native_bind_releases_addr() {
    use std::future::Future;

    struct WakeFlag(AtomicBool);

    impl std::task::Wake for WakeFlag {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::Release);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::Release);
        }
    }

    let addr: SocketAddr = "127.0.0.1:3343".parse().unwrap();

    moto_async::LocalRuntime::new().block_on(async {
        let (client, driver_task) = crate::net_harness::host_channel().await;
        // Releasing a client's last reservation shuts the channel down; hold
        // it open across the cancel/rebind cycle.
        let keeper = client.try_reserve().unwrap();

        let mut bind = Box::pin(NativeTcpListener::bind_reserved(
            client.try_reserve().unwrap(),
            &addr,
            None,
            None,
        ));
        let wake_flag = Arc::new(WakeFlag(AtomicBool::new(false)));
        let waker = std::task::Waker::from(wake_flag.clone());
        let mut context = Context::from_waker(&waker);
        assert!(matches!(bind.as_mut().poll(&mut context), Poll::Pending));

        // The driver task delivers the response (and fires the waker) while
        // this wait sleeps.
        crate::net_harness::wait_until("bind response delivery", || {
            wake_flag.0.load(Ordering::Acquire)
        })
        .await;

        // Do not poll the woken future: dropping it must drop the successful
        // PendingBind still sitting in the one-shot, which closes the
        // listener.
        drop(bind);

        let listener = wait_for_bind_to_succeed(&client, addr).await;
        assert_eq!(*listener.socket_addr(), addr);
        drop(listener);
        drop(keeper);
        crate::net_harness::drain_host_channel(client, driver_task).await;
    });
    println!("test_delivered_then_cancelled_native_bind_releases_addr() PASS");
}

/// A control message may be dequeued and spawned immediately before sys-io
/// observes that its raw channel closed. The unpolled task must not create a
/// socket after connection teardown removed its client bookkeeping.
fn test_disconnect_discards_queued_control() {
    let clients_before = read_sys_io_metric("net.active_clients");
    let sockets_before = read_sys_io_metric("net.udp_sockets");
    let connection = moto_ipc::io_channel::ClientConnection::connect("sys-io").unwrap();
    wait_for_sys_io_metric("net.active_clients", |value| value > clients_before);
    let addr = "127.0.0.1:0".parse().unwrap();

    connection
        .send(moto_sys_io::api_net::bind_udp_socket_request(&addr, 0))
        .unwrap();
    drop(connection);

    wait_for_sys_io_metric("net.active_clients", |value| value == clients_before);
    wait_for_sys_io_metric("net.udp_sockets", |value| value == sockets_before);
    println!("test_disconnect_discards_queued_control() PASS");
}

fn test_stale_cross_connection_accept_is_requeued() {
    use moto_sys_io::api_net;

    let clients_before = read_sys_io_metric("net.active_clients");
    let listener_connection = moto_ipc::io_channel::ClientConnection::connect("sys-io").unwrap();
    wait_for_sys_io_metric("net.active_clients", |value| value == clients_before + 1);

    let bind_addr = "127.0.0.1:0".parse().unwrap();
    listener_connection
        .send(api_net::bind_tcp_listener_request(&bind_addr, Some(1)))
        .unwrap();
    let bind_resp = recv_raw_net_response(&listener_connection);
    bind_resp.status().unwrap();
    let listener_id = bind_resp.handle;
    let listener_addr = api_net::get_socket_addr(&bind_resp.payload);

    let stale_connection = moto_ipc::io_channel::ClientConnection::connect("sys-io").unwrap();
    wait_for_sys_io_metric("net.active_clients", |value| value == clients_before + 2);
    stale_connection
        .send(api_net::accept_tcp_listener_request(listener_id, 0))
        .unwrap();

    // A second FIFO control task is a barrier proving the accept task above
    // reached the listener before this connection is closed.
    let invalid_addr = "0.0.0.0:0".parse().unwrap();
    stale_connection
        .send(api_net::bind_udp_socket_request(&invalid_addr, 0))
        .unwrap();
    let barrier_resp = recv_raw_net_response(&stale_connection);
    assert_eq!(barrier_resp.command, api_net::NetCmd::UdpSocketBind as u16);
    assert!(barrier_resp.status().is_err());

    drop(stale_connection);
    wait_for_sys_io_metric("net.active_clients", |value| value == clients_before + 1);

    let client_connection = moto_ipc::io_channel::ClientConnection::connect("sys-io").unwrap();
    wait_for_sys_io_metric("net.active_clients", |value| value == clients_before + 2);
    client_connection
        .send(api_net::tcp_stream_connect_request(&listener_addr, 0))
        .unwrap();
    let connect_resp = recv_raw_net_response(&client_connection);
    connect_resp.status().unwrap();
    let client_addr = api_net::get_socket_addr(&connect_resp.payload);
    wait_for_tcp_pair(listener_addr, client_addr);

    listener_connection
        .send(api_net::accept_tcp_listener_request(listener_id, 0))
        .unwrap();
    let accept_resp = recv_raw_net_response(&listener_connection);
    accept_resp.status().unwrap();
    assert_ne!(accept_resp.handle, 0);
    assert_eq!(api_net::get_socket_addr(&accept_resp.payload), client_addr);

    drop(client_connection);
    drop(listener_connection);
    wait_for_sys_io_metric("net.active_clients", |value| value == clients_before);

    // A client going away closes its sockets, it does not make them vanish:
    // the established pair here exchanges FINs first. Leaving that in flight
    // would put a moving socket count under the next test's baseline.
    wait_for_sockets_released(listener_addr);
    wait_for_sockets_released(client_addr);
    println!("test_stale_cross_connection_accept_is_requeued() PASS");
}

fn test_failed_tcp_setup_rolls_back_socket() {
    use moto_sys_io::api_net;

    let clients_before = read_sys_io_metric("net.active_clients");
    let sockets_before = read_sys_io_metric("net.tcp_sockets");
    let total_before = read_sys_io_metric("net.total_tcp_sockets");
    let connection = moto_ipc::io_channel::ClientConnection::connect("sys-io").unwrap();
    wait_for_sys_io_metric("net.active_clients", |value| value == clients_before + 1);

    let invalid_remote = "127.0.0.1:0".parse().unwrap();
    connection
        .send(api_net::tcp_stream_connect_request(&invalid_remote, 0))
        .unwrap();
    let response = recv_raw_net_response(&connection);
    assert_eq!(response.command, api_net::NetCmd::TcpStreamConnect as u16);
    assert!(response.status().is_err());

    assert_eq!(
        read_sys_io_metric("net.total_tcp_sockets"),
        total_before + 1
    );
    assert_eq!(
        read_sys_io_metric("net.tcp_sockets"),
        sockets_before,
        "the failed connect changed the socket count; live sockets: {:?}",
        read_tcp_socket_stats()
    );

    drop(connection);
    wait_for_sys_io_metric("net.active_clients", |value| value == clients_before);
    println!("test_failed_tcp_setup_rolls_back_socket() PASS");
}

fn test_total_clients_is_monotonic() {
    let clients_before = read_sys_io_metric("net.active_clients");
    let mut expected_total = read_sys_io_metric("net.total_clients");

    for _ in 0..2 {
        let connection = moto_ipc::io_channel::ClientConnection::connect("sys-io").unwrap();
        wait_for_sys_io_metric("net.active_clients", |value| value > clients_before);
        expected_total += 1;
        assert_eq!(read_sys_io_metric("net.total_clients"), expected_total);

        drop(connection);
        wait_for_sys_io_metric("net.active_clients", |value| value == clients_before);
        assert_eq!(read_sys_io_metric("net.total_clients"), expected_total);
    }

    println!("test_total_clients_is_monotonic() PASS");
}

fn test_resolved_listener_bind_conflicts() {
    use moto_sys_io::api_net;

    let clients_before = read_sys_io_metric("net.active_clients");
    let connection = moto_ipc::io_channel::ClientConnection::connect("sys-io").unwrap();
    wait_for_sys_io_metric("net.active_clients", |value| value == clients_before + 1);

    // A port held by a listener must be skipped by ephemeral allocation.
    // The first bind asks for port 0 rather than hardcoding 49152: loopback
    // allocation is lowest-free, so the bottom of the range is whatever an
    // earlier test's lingering sockets have not pinned -- hardcoding the
    // first ephemeral port made this test hostage to close-linger timing.
    let ephemeral_addr = "127.0.0.1:0".parse().unwrap();
    connection
        .send(api_net::bind_tcp_listener_request(&ephemeral_addr, Some(1)))
        .unwrap();
    let first = recv_raw_net_response(&connection);
    first.status().unwrap();
    let first_addr = api_net::get_socket_addr(&first.payload);

    connection
        .send(api_net::bind_tcp_listener_request(&ephemeral_addr, Some(1)))
        .unwrap();
    let ephemeral = recv_raw_net_response(&connection);
    ephemeral.status().unwrap();
    assert_ne!(api_net::get_socket_addr(&ephemeral.payload), first_addr);

    let wildcard_addr = "0.0.0.0:3344".parse().unwrap();
    connection
        .send(api_net::bind_tcp_listener_request(&wildcard_addr, Some(1)))
        .unwrap();
    recv_raw_net_response(&connection).status().unwrap();

    let overlap_addr = "127.0.0.1:3344".parse().unwrap();
    connection
        .send(api_net::bind_tcp_listener_request(&overlap_addr, Some(1)))
        .unwrap();
    assert_eq!(
        recv_raw_net_response(&connection).status(),
        Err(moto_rt::Error::AlreadyInUse)
    );

    drop(connection);
    wait_for_sys_io_metric("net.active_clients", |value| value == clients_before);
    println!("test_resolved_listener_bind_conflicts() PASS");
}

pub fn test_native_net_cancellation() {
    // Run this first, while test_channel_teardown's assert-empty guarantee
    // still provides stable baselines for the global sys-io gauges.
    test_total_clients_is_monotonic();
    test_resolved_listener_bind_conflicts();
    test_disconnect_discards_queued_control();
    test_stale_cross_connection_accept_is_requeued();
    test_failed_tcp_setup_rolls_back_socket();
    test_cancelled_native_connect_closes_socket();
    test_cancelled_native_io_waiters_are_removed();
    test_cancelled_native_rpc_response_is_tolerated();
    test_native_async_shutdown();
    test_native_stream_drop_under_backpressure();
    test_cancelled_native_bind_releases_addr();
    test_delivered_then_cancelled_native_bind_releases_addr();
}

pub fn test_native_listener_drop_backpressure() {
    test_native_listener_drop_under_backpressure();
}

/// A failed asynchronous TX is reported with a `TcpStreamTx` message. If RX
/// data is already queued, that control message must not become part of the RX
/// stream: dropping the socket drains the queue as RX pages and used to assert
/// that the TX command was `TcpStreamRx`.
pub fn test_tx_error_with_queued_rx() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let release_peer = Arc::new(AtomicBool::new(false));
    let peer_release = release_peer.clone();

    let peer = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(b"unread").unwrap();
        while !peer_release.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
    });

    moto_async::LocalRuntime::new().block_on(async {
        let (client, driver_task) = crate::net_harness::host_channel().await;
        let stream = NativeTcpStream::connect_reserved(
            client.try_reserve().unwrap(),
            &listener_addr,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        crate::net_harness::wait_until("peer data to reach the native stream", || {
            stream.has_rx_bytes()
        })
        .await;

        // sys-io returns the original id-zero TX message when it rejects an
        // asynchronous write (for example, because the peer has closed).
        // Inject that protocol result after real RX data to deterministically
        // exercise the same ordering seen under HTTP production traffic.
        let mut tx_error = moto_ipc::io_channel::Msg::new();
        tx_error.command = moto_sys_io::api_net::NetCmd::TcpStreamTx as u16;
        tx_error.handle = stream.handle();
        tx_error.status = moto_rt::E_NOT_CONNECTED;
        stream.process_incoming_msg(tx_error);

        drop(stream);
        release_peer.store(true, Ordering::Release);
        crate::net_harness::drain_host_channel(client, driver_task).await;
    });
    peer.join().unwrap();
    println!("test_tx_error_with_queued_rx() PASS");
}

fn test_connect_reset_is_not_a_timeout() {
    let error = std::net::TcpStream::connect_timeout(
        &"127.0.0.1:1".parse().unwrap(),
        Duration::from_secs(2),
    )
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::NotConnected);
    println!("test_connect_reset_is_not_a_timeout() PASS");
}

/// Wait until sys-io holds no socket bound to `addr`, which for an ephemeral
/// `addr` is also when its port is released: the port reservation is dropped
/// with the last socket holding it.
fn sockets_on_addr_released(addr: SocketAddr) -> bool {
    read_tcp_socket_stats()
        .iter()
        .all(|socket| socket.local_addr() != Some(addr))
}

fn wait_for_sockets_released(addr: SocketAddr) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        if sockets_on_addr_released(addr) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "sockets on {addr} were not released"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Set up the self-connect for `test_simultaneous_open`: bind port zero,
/// release it, and reconnect, so sys-io's lowest-free ephemeral allocation
/// hands the connect the port the listener just gave back.
///
/// That is deterministic only while no other socket frees a lower ephemeral
/// port between the release and the connect; a previous test's sockets can
/// still be draining (close lingers up to 60 seconds), and one of them
/// getting there first sends the SYN from the stolen port to the dead one,
/// which RSTs the connect. Rebind and retry: every success still exercises
/// the real assertions, and exhaustion surfaces the last error.
fn simultaneous_open_self_connect() -> (std::net::TcpStream, SocketAddr) {
    const ATTEMPTS: u32 = 16;
    for attempt in 1..=ATTEMPTS {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        wait_for_sockets_released(addr);

        match std::net::TcpStream::connect(addr) {
            Ok(stream) => return (stream, addr),
            Err(err) => assert!(
                attempt < ATTEMPTS,
                "self-connect failed after {ATTEMPTS} attempts: {err:?}"
            ),
        }
    }
    unreachable!()
}

/// RFC 9293 simultaneous open: a bare SYN arriving in SYN-SENT moves the
/// socket to SYN-RECEIVED, the state the connect task used to `panic!` on --
/// one packet from the peer we dialed, no handshake needed. A self-connect
/// drives that exact transition.
fn test_simultaneous_open() {
    use std::os::fd::AsRawFd;

    const PROBE: &[u8] = b"simultaneous";

    let (mut stream, addr) = simultaneous_open_self_connect();
    assert_eq!(
        stream.local_addr().unwrap(),
        addr,
        "connect did not reuse the freed ephemeral port: not a self-connect"
    );
    assert_eq!(stream.peer_addr().unwrap(), addr);

    stream.write_all(PROBE).unwrap();
    let mut buf = [0_u8; PROBE.len()];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(buf, PROBE);

    // The socket's own ACK of PROBE is still outstanding, so an ordinary close
    // would linger for a second and drop the socket under a later test's
    // gauge baseline. Measured: 1.008s vs 0 with SO_LINGER.
    moto_rt::net::set_linger(stream.as_raw_fd(), Some(Duration::ZERO)).unwrap();
    drop(stream);
    wait_for_sockets_released(addr);
    println!("test_simultaneous_open() PASS");
}

fn test_tcp_socket_state_transitions() {
    use moto_sys_io::api_net::TcpState;
    use moto_sys_io::stats::TcpProtocolState;
    use std::os::fd::AsRawFd;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listener_addr = listener.local_addr().unwrap();
    wait_for_tcp_socket_state(
        listener_addr,
        None,
        TcpState::Listening,
        TcpProtocolState::Listen,
    );

    let mut client = std::net::TcpStream::connect(listener_addr).unwrap();
    let client_addr = client.local_addr().unwrap();
    let (mut server, peer_addr) = listener.accept().unwrap();
    assert_eq!(peer_addr, client_addr);

    wait_for_tcp_socket_state(
        client_addr,
        Some(listener_addr),
        TcpState::ReadWrite,
        TcpProtocolState::Established,
    );
    wait_for_tcp_socket_state(
        listener_addr,
        Some(client_addr),
        TcpState::ReadWrite,
        TcpProtocolState::Established,
    );

    client.shutdown(std::net::Shutdown::Write).unwrap();
    let mut byte = [0_u8; 1];
    assert_eq!(server.read(&mut byte).unwrap(), 0);
    wait_for_tcp_socket_state(
        client_addr,
        Some(listener_addr),
        TcpState::ReadOnly,
        TcpProtocolState::FinWait2,
    );
    wait_for_tcp_socket_state(
        listener_addr,
        Some(client_addr),
        TcpState::WriteOnly,
        TcpProtocolState::CloseWait,
    );

    server.write_all(b"z").unwrap();
    client.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"z");
    server.shutdown(std::net::Shutdown::Write).unwrap();
    assert_eq!(client.read(&mut byte).unwrap(), 0);

    moto_rt::net::set_linger(client.as_raw_fd(), Some(Duration::ZERO)).unwrap();
    moto_rt::net::set_linger(server.as_raw_fd(), Some(Duration::ZERO)).unwrap();
    drop(client);
    drop(server);
    drop(listener);
    wait_for_sockets_released(client_addr);
    wait_for_sockets_released(listener_addr);
    println!("test_tcp_socket_state_transitions() PASS");
}

// Stage-E channel teardown (design 5.5): churn more concurrent connections
// than one channel holds (api_net::IO_SUBCHANNELS == 4) across several rounds,
// close everything, then assert the net runtime tore every channel down.
// Before stage E, NetChannel::drop was a todo!() and channels were pooled
// forever, so this leak check could never pass.
fn test_channel_teardown() {
    const N: usize = 12;
    const ROUNDS: usize = 3;
    let addr = "127.0.0.1:3340";
    let listener = Arc::new(std::net::TcpListener::bind(addr).unwrap());

    for _round in 0..ROUNDS {
        let acceptor_listener = listener.clone();
        let acceptor = std::thread::spawn(move || {
            let mut servers = Vec::with_capacity(N);
            for _ in 0..N {
                let (mut server, _) = acceptor_listener.accept().unwrap();
                let mut byte = [0_u8; 1];
                server.read_exact(&mut byte).unwrap();
                server.write_all(&byte).unwrap();
                servers.push(server);
            }
            // Every accepted stream drops here, on this (non-runtime) thread.
        });

        let mut clients = Vec::with_capacity(N);
        for i in 0..N {
            let mut client = std::net::TcpStream::connect(addr).unwrap();
            client.write_all(&[i as u8]).unwrap();
            let mut byte = [0_u8; 1];
            client.read_exact(&mut byte).unwrap();
            assert_eq!(byte[0], i as u8);
            clients.push(client);
        }
        acceptor.join().unwrap();
        drop(clients); // Close every client socket.
    }

    drop(listener); // Close the listener and release its pending accepts.

    // internal_helper(0, 0, ..) routes to NET.assert_empty(), which sleeps
    // briefly and then panics on any surviving channel, listener or socket --
    // so a clean return proves teardown completed.
    moto_rt::internal_helper(0, 0, 0, 0, 0, 0);

    std::thread::sleep(Duration::from_millis(10));
    println!("test_channel_teardown() PASS");
    std::thread::sleep(Duration::from_millis(10));
}

fn handle_client(mut stream: std::net::TcpStream, stop: Arc<AtomicBool>) {
    stream.set_read_timeout(Some(Duration::from_millis(1000)));
    let mut data = [0_u8; 17];
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        match stream.read(&mut data) {
            Ok(size) => {
                if size == 0 {
                    break;
                }
                for byte in &mut data {
                    *byte = 255 - *byte;
                }
                stream.write_all(&data[0..size]).unwrap();
            }
            Err(_) => {
                break;
            }
        }
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

fn server_thread(start: Arc<AtomicBool>, stop: Arc<AtomicBool>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:3333").unwrap();
    assert!(std::net::TcpListener::bind("127.0.0.1:3333").is_err());
    start.store(true, Ordering::Release);

    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let stop_clone = stop.clone();
                std::thread::spawn(move || handle_client(stream, stop_clone));
            }
            Err(e) => {
                std::thread::sleep(std::time::Duration::from_secs(1));
                println!("Error: ----------- {e} ----------------");
                panic!("{e}")
                /* connection failed */
            }
        }
    }
}

fn client_iter() {
    let addrs: Vec<_> = "localhost:3333".to_socket_addrs().unwrap().collect();
    assert_eq!(addrs.len(), 1);
    let mut stream =
        std::net::TcpStream::connect_timeout(&addrs[0], Duration::from_millis(1000)).unwrap();
    let tx: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    stream.write_all(&tx).unwrap();

    let mut rx = [0_u8; 8];
    match stream.read_exact(&mut rx) {
        Ok(_) => {
            assert_eq!(rx, [254, 253, 252, 251, 250, 249, 248, 247]);
        }
        Err(e) => {
            println!("Failed to receive data: {e}");
            panic!("{e:?}")
        }
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

fn test_io_latency() {
    let addrs: Vec<_> = "localhost:3333".to_socket_addrs().unwrap().collect();
    assert_eq!(addrs.len(), 1);
    let stream =
        std::net::TcpStream::connect_timeout(&addrs[0], Duration::from_millis(1000)).unwrap();

    // set_nodelay() is a good way to measure local I/O latency, as for the loopback
    // device it is a NOOP.
    let mut iters = 0_u64;
    const DUR: Duration = Duration::from_millis(500);
    let start = std::time::Instant::now();
    while start.elapsed() < DUR {
        stream.set_nodelay(true).unwrap();
        iters += 1;
    }

    let elapsed = start.elapsed();
    let _ = stream.shutdown(std::net::Shutdown::Both);
    println!(
        "IO latency of TcpStream::set_nodelay(): {:.3} usec/IO",
        elapsed.as_secs_f64() * 1000.0 * 1000.0 / (iters as f64)
    );
}

fn test_read_timeout() {
    let started_listener = Arc::new(AtomicBool::new(false));
    let started_sender = started_listener.clone();
    let stop_sender = Arc::new(AtomicBool::new(false));
    let stop_listener = stop_sender.clone();
    let server = std::thread::spawn(move || {
        let listener = std::net::TcpListener::bind("127.0.0.1:3334").unwrap();
        assert!(std::net::TcpListener::bind("127.0.0.1:3334").is_err());
        started_sender.store(true, Ordering::Release);

        let mut stream = listener.incoming().next().unwrap().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        // Read, don't write.
        let mut data = [0_u8; 64];
        while !stop_listener.load(Ordering::Relaxed) {
            let _ = stream.read(&mut data);
        }
        let _ = stream.shutdown(std::net::Shutdown::Both);
    });

    while !started_listener.load(Ordering::Relaxed) {
        core::hint::spin_loop()
    }

    let addrs: Vec<_> = "localhost:3334".to_socket_addrs().unwrap().collect();
    assert_eq!(addrs.len(), 1);
    let mut stream =
        std::net::TcpStream::connect_timeout(&addrs[0], Duration::from_millis(1000)).unwrap();
    let tx: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    stream.write_all(&tx).unwrap();

    assert!(stream.read_timeout().unwrap().is_none());
    stream
        .set_read_timeout(Some(Duration::from_millis(600)))
        .unwrap();

    let mut rx = [0_u8; 8];
    let start = std::time::Instant::now();
    match stream.read(&mut rx) {
        Ok(_) => {
            panic!("test_read_timeout: did read something")
        }
        Err(e) => {
            assert_eq!(e.kind(), std::io::ErrorKind::TimedOut);
        }
    }
    let timo = std::time::Instant::now() - start;
    assert!(timo.as_millis() >= 600);

    assert_eq!(stream.read_timeout().unwrap().unwrap().as_millis(), 600);
    stream.set_read_timeout(None).unwrap();
    assert!(stream.read_timeout().unwrap().is_none());

    assert!(stream.write_timeout().unwrap().is_none());
    stream
        .set_write_timeout(Some(Duration::from_millis(2)))
        .unwrap();
    assert_eq!(stream.write_timeout().unwrap().unwrap().as_millis(), 2);
    stream.set_write_timeout(None).unwrap();
    assert!(stream.write_timeout().unwrap().is_none());

    // Test nodelay get/set.
    stream.set_nodelay(true).unwrap();
    assert!(stream.nodelay().unwrap());
    stream.set_nodelay(false).unwrap();
    assert!(!stream.nodelay().unwrap());

    stream.set_ttl(43).unwrap();
    assert_eq!(43, stream.ttl().unwrap());

    let _ = stream.shutdown(std::net::Shutdown::Both);
    stop_sender.store(true, Ordering::Relaxed);

    // TODO: server.join() below sometimes (rarely) hangs, indicating that stream.shutdown()
    //       above and in the server thread don't fully mesh together.
    //       This is a bug that needs fixing.
    // server.join();
}

fn test_tcp_loopback() {
    assert!(std::net::TcpStream::connect("localhost:3333").is_err());
    let start = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let start_server = start.clone();
    let stop_server = stop.clone();
    let server = std::thread::spawn(|| server_thread(start_server, stop_server));

    while !start.load(Ordering::Acquire) {
        core::hint::spin_loop()
    }

    client_iter();
    client_iter();
    client_iter();
    std::thread::sleep(Duration::from_millis(100));
    println!("will test latency");
    std::thread::sleep(Duration::from_millis(100));
    test_io_latency();

    stop.store(true, Ordering::Release);
    // Kick the listener.
    // TODO: is there a better way?
    while !server.is_finished() {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let socket_addr = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            3333,
        );
        let stream = std::net::TcpStream::connect_timeout(&socket_addr, Duration::from_millis(100));
        std::thread::sleep(std::time::Duration::from_millis(100));
        if let Ok(stream) = stream {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
    server.join().unwrap();

    std::thread::sleep(std::time::Duration::from_millis(10));
    test_read_timeout();
    // TODO: how can we test write timeout?

    // Wrap the output in sleeps to avoid debug console output mangling.
    std::thread::sleep(std::time::Duration::from_millis(10));
    println!("test_tcp_loopback() PASS");
    std::thread::sleep(std::time::Duration::from_millis(10));
}

/// The listener TTL option through the POSIX ABI: the only caller of the
/// listener's remote option RPCs outside the native tests.
fn test_tcp_listener_ttl() {
    use std::os::fd::AsRawFd;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let fd = listener.as_raw_fd();

    moto_rt::net::set_ttl(fd, 41).unwrap();
    assert_eq!(moto_rt::net::ttl(fd).unwrap(), 41);
    assert_eq!(
        moto_rt::net::set_ttl(fd, u8::MAX as u32 + 1),
        Err(moto_rt::Error::InvalidArgument)
    );
    assert_eq!(moto_rt::net::ttl(fd).unwrap(), 41);

    println!("test_tcp_listener_ttl() PASS");
}

/// Pre-SYN buffer sizes on the native API: the requested sizes ride the
/// connect and bind requests themselves (payload bytes 18/19) and read
/// back effective -- rounded up to the wire's power-of-two granularity.
fn test_native_buffer_options() {
    use moto_io::net::tcp::TcpSocketOptions;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let accept_thread = std::thread::spawn(move || listener.accept().unwrap().0);

    moto_async::LocalRuntime::new().block_on(async {
        let (client, driver_task) = crate::net_harness::host_channel().await;

        let stream = moto_io::net::tcp::TcpStream::connect_reserved(
            client.try_reserve().unwrap(),
            &addr,
            None,
            None,
            Some(&TcpSocketOptions {
                rx_buf: 512 * 1024,
                tx_buf: 100_000,
            }),
        )
        .await
        .expect("connect with options");
        // rx is a power of two within the cap, honored exactly; the tx
        // request rounds up to the next 16 KiB power-of-two step.
        assert_eq!(stream.buffer_size_async(true).await.unwrap(), 512 * 1024);
        assert_eq!(stream.buffer_size_async(false).await.unwrap(), 128 * 1024);
        drop(stream);

        let native_listener = moto_io::net::tcp::TcpListener::bind_reserved(
            client.try_reserve().unwrap(),
            &"127.0.0.1:0".parse().unwrap(),
            None,
            Some(&TcpSocketOptions {
                rx_buf: 256 * 1024,
                tx_buf: 64 * 1024,
            }),
        )
        .await
        .expect("bind with options");
        assert_eq!(
            native_listener.buffer_size_async(true).await.unwrap(),
            256 * 1024
        );
        assert_eq!(
            native_listener.buffer_size_async(false).await.unwrap(),
            64 * 1024
        );
        drop(native_listener);

        crate::net_harness::drain_host_channel(client, driver_task).await;
    });

    let _peer = accept_thread.join().unwrap();
    println!("test_native_buffer_options() PASS");
}

fn test_tcp_buffer_sizes() {
    use std::os::fd::AsRawFd;

    const DEFAULT: u64 = 128 * 1024;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let lfd = listener.as_raw_fd();

    // The listener reports its accepted-socket configuration.
    assert_eq!(moto_rt::net::recv_buffer_size(lfd).unwrap(), DEFAULT);
    assert_eq!(moto_rt::net::send_buffer_size(lfd).unwrap(), DEFAULT);

    // A connected stream starts at the defaults.
    let client = std::net::TcpStream::connect(addr).unwrap();
    let (peer, _) = listener.accept().unwrap();
    let cfd = client.as_raw_fd();
    assert_eq!(moto_rt::net::recv_buffer_size(cfd).unwrap(), DEFAULT);
    assert_eq!(moto_rt::net::send_buffer_size(cfd).unwrap(), DEFAULT);

    // SNDBUF grows and reads back effective.
    moto_rt::net::set_send_buffer_size(cfd, 512 * 1024).unwrap();
    assert_eq!(moto_rt::net::send_buffer_size(cfd).unwrap(), 512 * 1024);

    // RCVBUF growth clamps at what the announced window scale can express:
    // a 128 KiB socket announced scale 2, so the ceiling is 65535 << 2 --
    // and the getter must report the clamp, not the request.
    moto_rt::net::set_recv_buffer_size(cfd, 1024 * 1024).unwrap();
    assert_eq!(moto_rt::net::recv_buffer_size(cfd).unwrap(), 65535 << 2);

    // Shrinking is not supported: a smaller request leaves the size as is.
    moto_rt::net::set_recv_buffer_size(cfd, 16 * 1024).unwrap();
    assert_eq!(moto_rt::net::recv_buffer_size(cfd).unwrap(), 65535 << 2);

    drop(client);
    drop(peer);

    // Sizes configured on an armed listener apply to accepts served by
    // backlog sockets built after the change. The pool pre-builds sockets
    // with the old sizes and its demux order is not specified, so drain:
    // the new sizes must appear within a bounded number of accepts.
    moto_rt::net::set_recv_buffer_size(lfd, 512 * 1024).unwrap();
    moto_rt::net::set_send_buffer_size(lfd, 256 * 1024).unwrap();
    assert_eq!(moto_rt::net::recv_buffer_size(lfd).unwrap(), 512 * 1024);
    assert_eq!(moto_rt::net::send_buffer_size(lfd).unwrap(), 256 * 1024);

    let mut inherited = false;
    for _ in 0..16 {
        let client = std::net::TcpStream::connect(addr).unwrap();
        let (peer, _) = listener.accept().unwrap();
        let pfd = peer.as_raw_fd();
        let rx = moto_rt::net::recv_buffer_size(pfd).unwrap();
        let tx = moto_rt::net::send_buffer_size(pfd).unwrap();
        drop(client);
        drop(peer);
        if rx == 512 * 1024 && tx == 256 * 1024 {
            inherited = true;
            break;
        }
        // Until then only the old configuration may appear.
        assert_eq!(rx, DEFAULT);
        assert_eq!(tx, DEFAULT);
    }
    assert!(
        inherited,
        "listener buffer config never reached accepted sockets"
    );

    println!("test_tcp_buffer_sizes() PASS");
}

fn test_tcp_linger() {
    use std::os::fd::AsRawFd;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::scope(|scope| {
        let accept = scope.spawn(move || listener.accept().unwrap().0);
        let client = std::net::TcpStream::connect(addr).unwrap();
        let peer = accept.join().unwrap();
        let fd = client.as_raw_fd();

        assert_eq!(moto_rt::net::linger(fd).unwrap(), None);

        moto_rt::net::set_linger(fd, Some(Duration::ZERO)).unwrap();
        assert_eq!(moto_rt::net::linger(fd).unwrap(), Some(Duration::ZERO));

        moto_rt::net::set_linger(fd, Some(Duration::from_secs(7))).unwrap();
        assert_eq!(
            moto_rt::net::linger(fd).unwrap(),
            Some(Duration::from_secs(7))
        );

        moto_rt::net::set_linger(fd, Some(Duration::from_secs(120))).unwrap();
        assert_eq!(
            moto_rt::net::linger(fd).unwrap(),
            Some(Duration::from_secs(60))
        );

        moto_rt::net::set_linger(fd, None).unwrap();
        assert_eq!(moto_rt::net::linger(fd).unwrap(), None);

        drop(client);
        drop(peer);
    });
    println!("test_tcp_linger() PASS");
}

pub fn test_zero_port_listen() {
    static HELLO: &[u8] = b"hello";
    static BYE: &[u8] = b"see you later";

    let port = Arc::new(AtomicU16::new(0));
    let response_received = AtomicBool::new(false);

    std::thread::scope(|scope| {
        // server/listener
        scope.spawn(|| {
            let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listener = std::net::TcpListener::bind(addr).unwrap();
            port.store(listener.local_addr().unwrap().port(), Ordering::Release);

            let (mut conn, _) = listener.accept().unwrap();

            let mut buf = [0_u8; HELLO.len()];
            conn.read_exact(&mut buf).unwrap();
            assert_eq!(buf, HELLO);
            conn.write_all(BYE).unwrap();
            // If the server is dropped now, the write above may not be delivered.
            while !response_received.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        });

        // Client: wait for the listener to start.
        while port.load(Ordering::Relaxed) == 0 {
            core::hint::spin_loop();
        }

        let addr: SocketAddr = format!("127.0.0.1:{}", port.load(Ordering::Relaxed))
            .parse()
            .unwrap();
        let mut conn = std::net::TcpStream::connect(addr).unwrap();
        conn.write_all(HELLO).unwrap();
        let mut buf = [0_u8; BYE.len()];
        conn.read_exact(&mut buf).unwrap();
        assert_eq!(buf, BYE);
        response_received.store(true, Ordering::Relaxed);
    });
    std::thread::sleep(std::time::Duration::from_millis(10));
    println!("test_zero_port_listen() PASS");
    std::thread::sleep(std::time::Duration::from_millis(10));
}

fn test_peek() {
    const N: usize = 1024 * 1024 * 3 + 1001;

    let listener = std::net::TcpListener::bind("127.0.0.1:333").unwrap();
    let done_reading = AtomicBool::new(false);

    std::thread::scope(|s| {
        s.spawn(|| {
            let (mut server, _) = listener.accept().unwrap();

            let mut buf = [0_u8; 1024];
            #[allow(clippy::needless_range_loop)]
            #[allow(clippy::manual_slice_fill)]
            for pos in 0..buf.len() {
                buf[pos] = (pos & 255) as u8;
            }

            let mut total_written = 0;
            while total_written < N {
                total_written += server.write(&buf).unwrap();
            }

            // If we drop `server` here, some written bytes in flight may get lost.
            while !done_reading.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        });

        let mut client = std::net::TcpStream::connect("127.0.0.1:333").unwrap();
        let mut buf = [0_u8; 1024];
        let mut total_received = 0;
        let mut peek = false;
        while total_received < N {
            if peek {
                let sz = client.peek(&mut buf).unwrap();
                assert!(sz > 0);
                #[allow(clippy::needless_range_loop)]
                for pos in 0..sz {
                    assert_eq!(buf[pos], ((total_received + pos) & 255) as u8);
                }
            }
            let sz = client.read(&mut buf).unwrap();
            assert!(sz > 0);
            #[allow(clippy::needless_range_loop)]
            for pos in 0..sz {
                assert_eq!(buf[pos], ((total_received + pos) & 255) as u8);
            }
            total_received += sz;
        }

        done_reading.store(true, Ordering::Relaxed);
    });

    // Wrap the output in sleeps to avoid debug console output mangling.
    std::thread::sleep(std::time::Duration::from_millis(10));
    println!("test_peek() PASS");
    std::thread::sleep(std::time::Duration::from_millis(10));
}

pub(crate) fn test_ipv6() {
    const N: usize = 1024 * 1024 * 3 + 1001;

    let done_reading = AtomicBool::new(false);
    let listener = std::net::TcpListener::bind("[::1]:333").unwrap();

    std::thread::scope(|s| {
        s.spawn(|| {
            let (mut server, _) = listener.accept().unwrap();

            let mut buf = [0_u8; 1024];
            #[allow(clippy::needless_range_loop)]
            #[allow(clippy::manual_slice_fill)]
            for pos in 0..buf.len() {
                buf[pos] = (pos & 255) as u8;
            }

            let mut total_written = 0;
            while total_written < N {
                server.write_all(&buf).unwrap();
                total_written += buf.len();
            }

            // If we drop `server` now, some of the queued TX bytes
            // may get dropped.
            while !done_reading.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        });

        let mut client = std::net::TcpStream::connect("[::1]:333").unwrap();
        let mut buf = [0_u8; 1024];
        let mut total_received = 0;
        while total_received < N {
            let sz = client.read(&mut buf).unwrap();
            assert!(sz > 0);
            #[allow(clippy::needless_range_loop)]
            for pos in 0..sz {
                assert_eq!(buf[pos], ((total_received + pos) & 255) as u8);
            }
            total_received += sz;
        }

        done_reading.store(true, Ordering::Relaxed);
    });

    // Wrap the output in sleeps to avoid debug console output mangling.
    std::thread::sleep(std::time::Duration::from_millis(10));
    println!("test_ipv6() PASS");
    std::thread::sleep(std::time::Duration::from_millis(10));
}

// A blocking write with SO_SNDTIMEO against a peer that never reads makes
// partial progress while the pipeline has room, then returns Err(TimedOut)
// once every buffer fills -- a deterministic zero-progress stall. (A peer
// that reads even slowly keeps freeing room, so a real write never times
// out; that is the correct SO_SNDTIMEO contract, exercised separately by
// the backpressure test below.) The peer stays silent until released, then
// drains to EOF so the scope join can never strand on it.
fn test_write_timeout() {
    let listener = std::net::TcpListener::bind("127.0.0.1:3335").unwrap();
    let release = Arc::new(AtomicBool::new(false));

    std::thread::scope(|s| {
        let release_ref = &release;
        s.spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            // Read nothing until released: the writer's pipeline fills and
            // its write times out.
            while !release_ref.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(10));
            }
            let mut sink = [0_u8; 4096];
            loop {
                match conn.read(&mut sink) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });

        let mut client = std::net::TcpStream::connect("127.0.0.1:3335").unwrap();
        client
            .set_write_timeout(Some(Duration::from_millis(100)))
            .unwrap();

        let chunk = [0xa5_u8; 16 * 1024];
        let mut sent = 0_usize;
        let mut hit_timeout = false;
        for _ in 0..4096 {
            match std::io::Write::write(&mut client, &chunk) {
                Ok(n) => {
                    assert!(n > 0, "write returned Ok(0)");
                    sent += n;
                }
                Err(e) => {
                    assert_eq!(e.kind(), std::io::ErrorKind::TimedOut);
                    hit_timeout = true;
                    break;
                }
            }
        }
        assert!(hit_timeout, "write never timed out against a silent peer");
        assert!(sent > 0, "no partial progress before the timeout");

        // Release the peer and close so it drains to EOF and returns.
        release.store(true, Ordering::Release);
        let _ = client.shutdown(std::net::Shutdown::Write);
    });

    std::thread::sleep(Duration::from_millis(10));
    println!("test_write_timeout() PASS");
    std::thread::sleep(Duration::from_millis(10));
}

// One backpressure exchange: bulk-write `N` bytes to a deliberately slow
// reader (forcing send-queue backpressure), then shutdown(Write). Returns
// (bytes the reader received, whether every received byte was correct). A
// correct stack yields (N, true): shutdown must drain the accepted send queue
// before FIN, so the reader sees every acknowledged byte then a clean EOF.
// `port` differs per call so a lingering socket from the previous iteration
// cannot collide on rebind.
fn run_write_backpressure_once(port: u16, n: usize) -> (usize, bool) {
    let listener = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    let received = Arc::new(AtomicUsize::new(0));
    let ok = Arc::new(AtomicBool::new(true));

    std::thread::scope(|s| {
        let received_ref = &received;
        let ok_ref = &ok;
        s.spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = [0_u8; 4096];
            let mut total = 0_usize;
            loop {
                match conn.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        for (pos, b) in buf[..n].iter().enumerate() {
                            if *b != ((total + pos) & 255) as u8 {
                                ok_ref.store(false, Ordering::Release);
                            }
                        }
                        total += n;
                        // Slow consumer: keep the writer's send queue full.
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => {
                        ok_ref.store(false, Ordering::Release);
                        break;
                    }
                }
            }
            received_ref.store(total, Ordering::Release);
        });

        let mut client = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut chunk = [0_u8; 64 * 1024];
        let mut sent = 0_usize;
        while sent < n {
            for (pos, b) in chunk.iter_mut().enumerate() {
                *b = ((sent + pos) & 255) as u8;
            }
            let want = (n - sent).min(chunk.len());
            match std::io::Write::write(&mut client, &chunk[..want]) {
                Ok(w) => {
                    assert!(w > 0, "write returned Ok(0)");
                    sent += w;
                }
                Err(e) => panic!("unexpected write error: {e:?}"),
            }
        }
        client.shutdown(std::net::Shutdown::Write).unwrap();
    });

    (received.load(Ordering::Acquire), ok.load(Ordering::Acquire))
}

// Bulk write to a slow reader forces send-queue backpressure -- the write
// future's retract-and-recopy path -- with no write timeout set, so writes
// block until they progress. Every byte must arrive exactly once and in
// order: a double-count or a loss in that path is the bug being hunted. A
// lost backpressure wake would hang here (the watchdog flags it), not fail.
fn test_write_backpressure_integrity() {
    const N: usize = 2 * 1024 * 1024;
    let (received, ok) = run_write_backpressure_once(3338, N);
    assert!(ok, "reader saw wrong bytes");
    assert_eq!(received, N, "byte count mismatch");

    std::thread::sleep(Duration::from_millis(10));
    println!("test_write_backpressure_integrity() PASS");
    std::thread::sleep(Duration::from_millis(10));
}

// Run `workers` concurrent backpressure exchanges, each looping `rounds`
// times, and return how many lost or corrupted data. The loss this guards
// against needs sys-io's single device task to fall behind so the send buffer
// still holds *un-transmitted* bytes when the client's close races the FIN;
// many concurrent flows starve that task the way the soak's mixed load does.
// Each (worker, round) uses a distinct port so a lingering socket from the
// previous round cannot collide on rebind. With `verbose`, every failure is
// printed (the standalone repro); otherwise the caller asserts on the count.
fn run_backpressure_concurrent(workers: usize, rounds: usize, n: usize, verbose: bool) -> usize {
    let failures = Arc::new(AtomicUsize::new(0));
    std::thread::scope(|s| {
        for w in 0..workers {
            let failures = &failures;
            s.spawn(move || {
                for r in 0..rounds {
                    let port = 20000 + (w * rounds + r) as u16;
                    let (received, ok) = run_write_backpressure_once(port, n);
                    if !ok {
                        if verbose {
                            println!("worker {w} round {r}: CORRUPTION received={received}");
                        }
                        failures.fetch_add(1, Ordering::Relaxed);
                    } else if received != n {
                        if verbose {
                            println!(
                                "worker {w} round {r}: LOSS received={received} of {n} (lost {})",
                                n - received
                            );
                        }
                        failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    failures.load(Ordering::Relaxed)
}

// Regression guard for shutdown(Write) dropping acknowledged send data: many
// concurrent slow-reader flows, each of which shuts down its write half while
// the send queue is backed up. Every accepted byte must reach the peer before
// FIN, so not one exchange may come up short.
fn test_write_backpressure_concurrent() {
    const N: usize = 512 * 1024;
    let failures = run_backpressure_concurrent(8, 4, N, false);
    assert_eq!(
        failures, 0,
        "shutdown(Write) lost data on {failures} exchange(s)"
    );
    std::thread::sleep(Duration::from_millis(10));
    println!("test_write_backpressure_concurrent() PASS");
    std::thread::sleep(Duration::from_millis(10));
}

// Heavier standalone repro (96 exchanges) for reproducing/observing the bug by
// hand: `systest test-tcp-shutdown-repro`. Prints each shortfall rather than
// asserting, so it reports the full loss distribution.
pub fn test_tcp_shutdown_repro() {
    const N: usize = 1024 * 1024;
    let total = 8 * 12;
    let failures = run_backpressure_concurrent(8, 12, N, true);
    println!("test_tcp_shutdown_repro DONE: {failures}/{total} exchanges lost data");
}

// Data arriving well before the deadline must complete a timed read
// immediately (the deadline rides the parker; the wake is the rx task's).
// The peer reads to EOF and returns, so it can never be stranded by a
// failed assertion in the client closure.
fn test_read_timeout_early_data() {
    let listener = std::net::TcpListener::bind("127.0.0.1:3336").unwrap();
    let elapsed = std::thread::scope(|s| {
        s.spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(100));
            let _ = std::io::Write::write_all(&mut conn, b"hello");
            // Block until the client closes, then return (no flag spin).
            let mut sink = [0_u8; 8];
            let _ = conn.read(&mut sink);
        });

        let mut client = std::net::TcpStream::connect("127.0.0.1:3336").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let start = std::time::Instant::now();
        let mut buf = [0_u8; 64];
        let n = client.read(&mut buf).unwrap();
        let elapsed = start.elapsed();
        assert_eq!(&buf[..n], b"hello");
        // Dropping the client closes it, releasing the peer's read.
        elapsed
    });

    assert!(elapsed < Duration::from_secs(4));
    std::thread::sleep(Duration::from_millis(10));
    println!("test_read_timeout_early_data() PASS");
    std::thread::sleep(Duration::from_millis(10));
}

// Two threads blocking-read one stream through dup'd FDs (try_clone).
// Every byte goes to exactly one reader, and at EOF BOTH must wake and
// see Ok(0) - the wake-all-and-recheck contract of the stream's waker
// list. A lost wake strands a reader forever (the watchdog would flag
// the hang).
fn test_concurrent_readers() {
    const N: usize = 1024 * 1024;
    let listener = std::net::TcpListener::bind("127.0.0.1:3337").unwrap();
    let done = AtomicBool::new(false);

    let bad = AtomicBool::new(false);
    let sum = std::thread::scope(|s| {
        let done_ref = &done;
        s.spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let buf = [0xa5_u8; 8192];
            let mut written = 0_usize;
            while written < N {
                let n = (N - written).min(buf.len());
                if std::io::Write::write_all(&mut conn, &buf[..n]).is_err() {
                    return;
                }
                written += n;
            }
            let _ = conn.shutdown(std::net::Shutdown::Write);
            // Hold the connection open until both readers hit EOF, then
            // return; never blocks on an assertion's outcome.
            while !done_ref.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(10));
            }
        });

        let client = std::net::TcpStream::connect("127.0.0.1:3337").unwrap();
        let client2 = client.try_clone().unwrap();

        let bad_ref = &bad;
        let reader = move |mut conn: std::net::TcpStream| {
            move || -> usize {
                let mut buf = [0_u8; 4096];
                let mut total = 0_usize;
                loop {
                    match conn.read(&mut buf) {
                        Ok(0) => return total,
                        Ok(n) => {
                            if !buf[..n].iter().all(|b| *b == 0xa5) {
                                bad_ref.store(true, Ordering::Release);
                            }
                            total += n;
                        }
                        Err(_) => {
                            bad_ref.store(true, Ordering::Release);
                            return total;
                        }
                    }
                }
            }
        };
        let r1 = s.spawn(reader(client));
        let r2 = s.spawn(reader(client2));
        let sum = r1.join().unwrap() + r2.join().unwrap();
        // Both readers reached EOF; release the writer thread.
        done.store(true, Ordering::Release);
        sum
    });

    assert!(
        !bad.load(Ordering::Acquire),
        "reader saw wrong bytes or errored"
    );
    assert_eq!(sum, N, "concurrent readers lost or duplicated bytes");
    std::thread::sleep(Duration::from_millis(10));
    println!("test_concurrent_readers() PASS");
    std::thread::sleep(Duration::from_millis(10));
}

// A timeout storm during a live transfer, aimed at TcpWriteFuture's subtlest
// rule-7 case: a write that commits partial progress to pending_tx and is then
// dropped when SO_SNDTIMEO fires. The peer drains stop-and-go, so the client's
// pipeline repeatedly fills during the stalls and its short-timeout writes are
// created and dropped mid-flight -- some surrendering partial progress (Ok(n)),
// some zero-progress (Err(TimedOut), retried). Every byte must still arrive
// exactly once and in order: a drop that lost or double-counted bytes trips the
// order check, and a lost backpressure wake would hang (the watchdog flags it).
fn test_timeout_storm_during_transfer() {
    const N: usize = 1024 * 1024;
    let listener = std::net::TcpListener::bind("127.0.0.1:3339").unwrap();
    let received = Arc::new(AtomicUsize::new(0));
    let ok = Arc::new(AtomicBool::new(true));

    std::thread::scope(|s| {
        let received_ref = &received;
        let ok_ref = &ok;
        s.spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = [0_u8; 4096];
            let mut total = 0_usize;
            while total < N {
                match conn.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        for (pos, b) in buf[..n].iter().enumerate() {
                            if *b != ((total + pos) & 255) as u8 {
                                ok_ref.store(false, Ordering::Release);
                            }
                        }
                        total += n;
                        // Stall longer than the client's write timeout so the
                        // pipeline fills and storms the client's write futures.
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => {
                        ok_ref.store(false, Ordering::Release);
                        break;
                    }
                }
            }
            received_ref.store(total, Ordering::Release);
        });

        let mut client = std::net::TcpStream::connect("127.0.0.1:3339").unwrap();
        client
            .set_write_timeout(Some(Duration::from_millis(2)))
            .unwrap();

        let mut chunk = [0_u8; 8192];
        let mut sent = 0_usize;
        let mut timeouts = 0_usize;
        while sent < N {
            for (pos, b) in chunk.iter_mut().enumerate() {
                *b = ((sent + pos) & 255) as u8;
            }
            let want = (N - sent).min(chunk.len());
            match std::io::Write::write(&mut client, &chunk[..want]) {
                Ok(n) => {
                    assert!(n > 0, "write returned Ok(0)");
                    sent += n;
                }
                Err(e) => {
                    assert_eq!(e.kind(), std::io::ErrorKind::TimedOut);
                    timeouts += 1;
                }
            }
        }
        client.shutdown(std::net::Shutdown::Write).unwrap();
        // The storm premise -- writer outpaces reader, so the send queue fills
        // and a 2ms write hits a zero-progress timeout -- only holds when the
        // writer runs at full speed. Under --under-load the writer is itself
        // starved of CPU, so the (deliberately slow) reader keeps the queue
        // drained and no write times out. That is a coverage assumption, not a
        // correctness property; the integrity checks below still run in both
        // modes. Require a timeout only when the writer isn't CPU-starved.
        assert!(
            timeouts > 0 || crate::under_load(),
            "the storm produced no zero-progress timeout"
        );
    });

    assert!(ok.load(Ordering::Acquire), "peer saw wrong bytes");
    assert_eq!(received.load(Ordering::Acquire), N, "byte count mismatch");
    std::thread::sleep(Duration::from_millis(10));
    println!("test_timeout_storm_during_transfer() PASS");
    std::thread::sleep(Duration::from_millis(10));
}

/// Every frame the virtio device delivered this boot passed the driver's RX
/// header validation and the netstack's checksum policy.
///
/// systest arrives over ssh, so by the time it runs the device has delivered
/// thousands of ordinary frames. The driver counts (and re-posts the buffer
/// of) every completion it rejects instead of delivering it, so a validation
/// rule that is wrong about what the host actually writes surfaces here as a
/// nonzero counter rather than as silently lost traffic.
///
/// The checksum counter is the same check for the per-frame verdict: the
/// netstack now verifies every frame the device did not vouch for, so a
/// verdict that is wrong about which frames carry a complete checksum shows up
/// here instead of as a connection that mysteriously stalls.
fn test_device_rx_validation() {
    let received = read_sys_io_metric("net.device.rx_packets");
    assert!(received > 0, "the virtio device delivered no frames");
    assert_eq!(
        read_sys_io_metric("net.device.rx_dropped"),
        0,
        "the virtio driver rejected receive completions ({received} frames delivered)"
    );
    assert_eq!(
        read_sys_io_metric("net.rx.csum_failed"),
        0,
        "the netstack dropped frames on checksum verification \
         ({received} frames delivered)"
    );

    println!("-- test_device_rx_validation() PASS");
}

/// Ordinary traffic never needs more neighbors than the cache holds.
///
/// An ARP request or a neighbor solicitation is unsolicited -- any peer on the
/// segment can send one -- so it may take a free slot or refresh a mapping but
/// may never displace one; without that rule a handful of forged requests
/// flushes every legitimate mapping, the gateway included. The counter is what
/// says the rule never fires on real traffic: systest arrives over ssh, so the
/// VM has already resolved and used its gateway by the time this runs.
fn test_neighbor_admission() {
    let received = read_sys_io_metric("net.device.rx_packets");
    assert!(received > 0, "the virtio device delivered no frames");
    assert_eq!(
        read_sys_io_metric("net.neighbor.admission_refused"),
        0,
        "the netstack refused neighbor mappings a full cache could not hold \
         ({received} frames delivered)"
    );

    println!("-- test_neighbor_admission() PASS");
}

/// sys-io accounts for every listening socket that is waiting on a peer to
/// finish the handshake, and resets connection requests no socket wants.
///
/// The gauge alone cannot be sampled from here. A peer that answers completes
/// the handshake in the poll after the one that took its SYN, so a socket is
/// half-open for a fraction of a round trip, while reading a metric is a
/// cross-thread round trip through sys-io's net runtime. `half_open_total` is
/// what makes the accounting observable -- every connection below passes
/// through the state exactly once -- and the gauge returning to its baseline is
/// what says the count falls again. The stalled handshake itself needs packet
/// injection and lives in the netstack's
/// `tcp_half_open_stalls_and_unmatched_syn_is_reset`.
///
/// The reset half is also the full-OS guard that a closed port stays a closed
/// port: a request for a listener that is merely out of sockets is dropped so
/// the peer retries, and doing that to a port nothing listens on would turn
/// `ECONNREFUSED` into a hang.
fn test_half_open_accounting() {
    use std::os::fd::AsRawFd;

    // Nothing listens on discard, and it is below the ephemeral range, so no
    // connect of ours can be handed this port and answer itself.
    const CLOSED_ADDR: &str = "127.0.0.1:9";
    const CONNECTIONS: u64 = 8;

    let half_open_before = read_sys_io_metric("net.tcp.half_open");
    let total_before = read_sys_io_metric("net.tcp.half_open_total");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut accepted = Vec::new();
    for _ in 0..CONNECTIONS {
        // The listening pool completes the handshake on its own; accept() only
        // hands over a connection sys-io has already established.
        let client = std::net::TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        // Leave no lingering socket behind: a late drop moves global gauges
        // under whatever runs next.
        moto_rt::net::set_linger(client.as_raw_fd(), Some(Duration::ZERO)).unwrap();
        moto_rt::net::set_linger(server.as_raw_fd(), Some(Duration::ZERO)).unwrap();
        accepted.push((client, server));
    }

    assert_eq!(
        read_sys_io_metric("net.tcp.half_open_total"),
        total_before + CONNECTIONS,
        "expected one half-open socket per connection"
    );
    // accept() returns after the accepting socket has left SYN-RECEIVED, so
    // every one of them has been accounted for by now.
    assert_eq!(
        read_sys_io_metric("net.tcp.half_open"),
        half_open_before,
        "half-open sockets outlived their handshakes"
    );

    drop(accepted);
    drop(listener);

    let rst_before = read_sys_io_metric("net.tcp.syn_rst_unmatched");
    // A connection request nobody wants. sys-io reports the reset as a timeout
    // rather than a refusal, which this test does not depend on -- but a
    // request that was dropped instead would retransmit forever, so the wait is
    // bounded and the counter below is what tells the two apart.
    let closed_addr: std::net::SocketAddr = CLOSED_ADDR.parse().unwrap();
    assert!(std::net::TcpStream::connect_timeout(&closed_addr, Duration::from_secs(10)).is_err());
    assert_eq!(
        read_sys_io_metric("net.tcp.syn_rst_unmatched"),
        rst_before + 1,
        "expected exactly one reset connection request"
    );

    println!("-- test_half_open_accounting() PASS");
}

/// A listening pool grows into the burst it cannot serve, loses none of it, and
/// gives the growth back once the burst is over.
///
/// `net.tcp.backlog_extra` is exactly what the growth measures: the listening
/// sockets demand added beyond what clients asked for at bind, which is what
/// `max_backlog_global` bounds. `net.tcp_listening_sockets` is the other half --
/// the accounting could be returned while the sockets themselves stayed
/// committed, which is the memory the sweep exists to give back. The listener is
/// still bound while the return is checked, because dropping it would hand the
/// growth back for reasons that have nothing to do with a sweep.
///
/// A pool cannot grow before the burst that shows it is too shallow. Against the
/// four-deep pool this binds, 24 at once used to lose 12 to 17 of them to a
/// reset, which is terminal for the peer; a request the pool cannot take is
/// dropped instead, so its peer retransmits into the deepened pool and every
/// connection arrives.
///
/// How many requests have to be dropped to get there is not fixed, and no
/// assertion here may rest on it: sys-io creates the burst's client sockets a
/// few at a time between its own polls, so a pool that doubles every time it
/// empties can stay ahead of the arrivals and take all 24 without losing one.
/// What holds either way is that nothing bound was answered with a reset.
fn test_backlog_growth_and_shrink() {
    use std::os::fd::AsRawFd;

    const BURST: usize = 24;
    // Retransmits carry the requests the burst's first poll could not take: one
    // second, then two. Generous, and only so that a lost connection fails this
    // test instead of hanging it.
    const CONNECT_DEADLINE: Duration = Duration::from_secs(20);
    // Two sweep windows and slack: the window a burst falls in returns nothing,
    // having seen the pool run out inside it.
    const RETURN_DEADLINE: Duration = Duration::from_secs(40);

    let baseline = read_sys_io_metric("net.tcp.backlog_extra");
    let dropped_before = read_sys_io_metric("net.tcp.syn_backlog_dropped");
    let reset_before = read_sys_io_metric("net.tcp.syn_rst_unmatched");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    // bind() returns with the pool created, so this is the base to come back to.
    let bound = read_sys_io_metric("net.tcp_listening_sockets");

    // Every connect issued before any is collected, which is the arrival shape
    // the pool is the backlog for. The default pool is four deep.
    let start = Arc::new(std::sync::Barrier::new(BURST));
    let mut threads = Vec::with_capacity(BURST);
    for _ in 0..BURST {
        let start = start.clone();
        threads.push(std::thread::spawn(move || {
            start.wait();
            std::net::TcpStream::connect_timeout(&addr, CONNECT_DEADLINE)
        }));
    }
    let mut connected = Vec::with_capacity(BURST);
    let mut failures = Vec::new();
    for thread in threads {
        match thread.join().unwrap() {
            Ok(stream) => connected.push(stream),
            Err(err) => failures.push(err),
        }
    }
    assert!(
        failures.is_empty(),
        "a burst of {BURST} lost {} connections, the first with {:?}",
        failures.len(),
        failures[0].kind()
    );

    // Whatever the four-deep pool could not take was dropped rather than reset,
    // which is what let it arrive at all; and the pool it ran out of deepened.
    let dropped = read_sys_io_metric("net.tcp.syn_backlog_dropped") - dropped_before;
    let grown = read_sys_io_metric("net.tcp.backlog_extra");
    assert_eq!(
        read_sys_io_metric("net.tcp.syn_rst_unmatched"),
        reset_before,
        "a burst of {BURST} against a four-deep pool was met with a reset \
         ({dropped} requests dropped, backlog_extra {grown})"
    );
    assert!(
        grown > baseline,
        "a burst of {BURST} against a four-deep pool added no listening sockets \
         ({dropped} requests dropped, backlog_extra {grown}, baseline {baseline})"
    );

    // Leave nothing draining behind: the sweep is the only thing that should
    // move the counter from here on.
    for client in &connected {
        moto_rt::net::set_linger(client.as_raw_fd(), Some(Duration::ZERO)).unwrap();
    }
    for _ in 0..connected.len() {
        let (server, _) = listener.accept().unwrap();
        moto_rt::net::set_linger(server.as_raw_fd(), Some(Duration::ZERO)).unwrap();
    }
    drop(connected);

    let deadline = std::time::Instant::now() + RETURN_DEADLINE;
    loop {
        let extra = read_sys_io_metric("net.tcp.backlog_extra");
        let listening = read_sys_io_metric("net.tcp_listening_sockets");
        if extra <= baseline && listening <= bound {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the listening pool kept {extra} grown sockets after the burst, \
             {listening} listening (baseline {baseline}, bound {bound}, peak {grown})"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    drop(listener);
    println!("-- test_backlog_growth_and_shrink() PASS");
}

// `O_NONBLOCK` and `SO_*TIMEO` belong to the open file description, so two FDs
// from one `try_clone` share them. That is why they live on the vdso's
// `RtTcpStream` -- the object the FD table shares between dups -- rather than
// on the native stream or per descriptor, and nothing else in the suite pins
// it. Each flag is both *read back* through the other FD and *acted on*
// through it, because the getter and the blocking path are separate readers
// and only the second one is the behavior.
//
// The accepted stream's inherited `O_NONBLOCK` is pinned here too. Motor's
// accept copies the listener's flag into the stream it returns, and mio's
// Motor shim depends on that: it marks only the listener, so a stream that did
// not inherit would block tokio's reactor. That copy moved into the vdso with
// the flag, which is what makes it this test's second claim.
fn test_tcp_dup_shares_posix_flags() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let s1 = std::net::TcpStream::connect(addr).unwrap();
    // Held so the reads below block on an idle connection rather than see EOF.
    let peer = listener.accept().unwrap().0;
    let s2 = s1.try_clone().unwrap();
    let buf = &mut [0_u8; 64];

    // The inherited flag is a copy, so both of its values have to be pinned.
    // This listener is blocking, so its accepted stream must be too: a stream
    // that came back nonblocking regardless of the listener would satisfy the
    // nonblocking half at the end of this test and still be wrong.
    peer.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    assert_eq!(
        (&peer).read(buf).err().unwrap().kind(),
        std::io::ErrorKind::TimedOut,
        "a stream accepted from a blocking listener was nonblocking"
    );

    assert!(s2.read_timeout().unwrap().is_none());
    assert!(s2.write_timeout().unwrap().is_none());

    let timo = Duration::from_millis(1);
    s1.set_read_timeout(Some(timo)).unwrap();
    s1.set_write_timeout(Some(timo)).unwrap();
    assert_eq!(timo, s2.read_timeout().unwrap().unwrap());
    assert_eq!(timo, s2.write_timeout().unwrap().unwrap());
    assert_eq!(
        (&s2).read(buf).err().unwrap().kind(),
        std::io::ErrorKind::TimedOut,
        "a receive timeout set on one FD did not bound a read on its dup"
    );

    s2.set_read_timeout(None).unwrap();
    assert!(s1.read_timeout().unwrap().is_none());

    // A deadline stays set here only so that an unshared `O_NONBLOCK` fails the
    // assertion below instead of hanging: the blocking path consults the flag
    // first, so a shared one returns WouldBlock at once and an unshared one
    // gets as far as parking and comes back TimedOut.
    s1.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s1.set_nonblocking(true).unwrap();
    assert_eq!(
        (&s2).read(buf).err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock,
        "O_NONBLOCK set on one FD did not reach its dup"
    );

    listener.set_nonblocking(true).unwrap();
    let client = std::net::TcpStream::connect(addr).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let accepted = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "a connected peer never became acceptable"
                );
                std::thread::yield_now();
            }
            Err(err) => panic!("accept failed: {err:?}"),
        }
    };
    // Bounded for the same reason as the dup above: without a deadline, a
    // stream that failed to inherit the flag parks forever and the regression
    // arrives as a harness timeout instead of an assertion.
    accepted
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    assert_eq!(
        (&accepted).read(buf).err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock,
        "an accepted stream did not inherit its listener's O_NONBLOCK"
    );
    drop(client);

    println!("test_tcp_dup_shares_posix_flags() PASS");
}

// A listener's only POSIX flag is `O_NONBLOCK`, and it belongs to the open file
// description just as the stream's do, so two FDs from one `try_clone` share
// it. That is why it lives on the vdso's `RtTcpListener` rather than on the
// native listener, and nothing else in the suite pins it. Both of its values
// are pinned, because a build that ignored the flag in one direction would
// still satisfy the other half.
//
// The flag is checked through what reads it rather than through a getter: the
// accept path, the stream it hands back, and `listen()`, which the ABI accepts
// only for a nonblocking descriptor.
fn test_tcp_listener_dup_shares_posix_flags() {
    use std::os::fd::AsRawFd;

    let l1 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l1.local_addr().unwrap();
    let l2 = l1.try_clone().unwrap();
    let buf = &mut [0_u8; 64];

    // Blocking, which is the state a fresh listener starts in: a stream
    // accepted through the dup must be blocking too. Deliberately first, while
    // no async accept is armed, so this accept answers from its own request.
    let client = std::net::TcpStream::connect(addr).unwrap();
    let accepted = l2.accept().unwrap().0;
    accepted
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    assert_eq!(
        (&accepted).read(buf).err().unwrap().kind(),
        std::io::ErrorKind::TimedOut,
        "a stream accepted from a blocking listener was nonblocking"
    );
    drop(accepted);
    drop(client);

    // Set through one FD, read through the other. `listen()` is checked first
    // because it is the one reader that answers without waiting: an unshared
    // flag fails it here, rather than parking the accept below on a listener
    // nothing is connecting to.
    l1.set_nonblocking(true).unwrap();
    assert_eq!(
        moto_rt::net::listen(l2.as_raw_fd(), 8),
        Ok(()),
        "O_NONBLOCK set on one listener FD did not reach its dup"
    );
    assert_eq!(
        l2.accept().err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock,
        "the accept path did not read the O_NONBLOCK its dup was told"
    );

    let client = std::net::TcpStream::connect(addr).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let accepted = loop {
        match l2.accept() {
            Ok((stream, _)) => break stream,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "a connected peer never became acceptable"
                );
                std::thread::yield_now();
            }
            Err(err) => panic!("accept failed: {err:?}"),
        }
    };
    // Bounded for the same reason the dup assertions above are: without a
    // deadline, a stream that failed to inherit the flag parks forever and the
    // regression arrives as a harness timeout instead of an assertion.
    accepted
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    assert_eq!(
        (&accepted).read(buf).err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock,
        "a stream accepted through a dup did not inherit O_NONBLOCK"
    );
    drop(client);

    // Clearing it reaches the dup too, which `listen()` states for the same
    // reason: a blocking descriptor has no accept queue for it to arm.
    l2.set_nonblocking(false).unwrap();
    assert_eq!(
        moto_rt::net::listen(l1.as_raw_fd(), 8),
        Err(moto_rt::Error::InvalidArgument),
        "O_NONBLOCK cleared on one listener FD did not reach its dup"
    );

    println!("test_tcp_listener_dup_shares_posix_flags() PASS");
}

// A blocking `accept()` must not be starved by an accept request the listener
// already had outstanding. sys-io answers the oldest request, which need not be
// the one this caller posted, so a caller keyed to its own request used to wait
// for a *second* connection that nothing was going to make. Callers should not
// mix the two modes on one listener, but the failure was a silent hang, so it
// is pinned rather than left to be rediscovered.
fn test_blocking_accept_is_not_starved() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    // Arms the async accept backlog and then puts the descriptor back to
    // blocking: the armed request outlives the flag that created it.
    listener.set_nonblocking(true).unwrap();
    listener.set_nonblocking(false).unwrap();

    // The accept runs on its own thread so that starvation fails this
    // assertion instead of hanging the suite until the harness times out.
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let accepting = std::thread::spawn(move || {
        let accepted = listener.accept();
        let _ = done_tx.send(());
        accepted
    });

    let client = std::net::TcpStream::connect(addr).unwrap();
    assert!(
        done_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
        "a blocking accept was starved by the listener's own outstanding accept"
    );
    let (accepted, peer) = accepting.join().unwrap().unwrap();
    assert_eq!(peer.ip(), client.local_addr().unwrap().ip());
    drop(accepted);
    drop(client);

    println!("test_blocking_accept_is_not_starved() PASS");
}

// A socket its client drops without ever writing a byte is reset, not closed
// gracefully. A reset cannot truncate a stream that carried nothing, and the
// peer must learn at once that nobody will read what it is still sending --
// otherwise the abandoned socket sits in FinWait2 absorbing that data into a
// buffer with no reader, for the whole `DEFAULT_LINGER_SECS`. That is what
// made mio's `tcp::test_write_error` take exactly 60 seconds.
//
// Bounded rather than open-ended: the failure this guards against is a stall,
// so an unfixed build must fail an assertion instead of parking the suite.
fn test_write_to_dropped_peer_fails_fast() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let (conn, _) = listener.accept().unwrap();
        drop(conn); // Never read a byte, never wrote one.
    });

    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    peer.join().unwrap();
    // Without this a blocking write parks inside the kernel once the send
    // buffer fills, and the stall arrives as a hang rather than as this
    // assertion.
    stream
        .set_write_timeout(Some(Duration::from_millis(200)))
        .unwrap();

    let buf = [0_u8; 4096];
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match stream.write(&buf) {
            Ok(_) => assert!(
                std::time::Instant::now() < deadline,
                "writing to a dropped peer kept succeeding: it was closed gracefully, not reset"
            ),
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                assert!(
                    std::time::Instant::now() < deadline,
                    "writing to a dropped peer never failed: its data was absorbed for the linger"
                );
            }
            Err(_) => break, // Reset: terminal and prompt, which is the point.
        }
    }

    println!("test_write_to_dropped_peer_fails_fast() PASS");
}

/// Writing to a peer that closed gracefully (FIN, not abort) is answered
/// with an RST: the peer's reader is gone for good, so the writer must see
/// a reset promptly, not a zero-window stall for the peer's linger. Covers
/// both orphaning paths: a full close and a shutdown(Both) that keeps the
/// fd alive.
fn test_write_after_peer_graceful_close_resets() {
    fn write_until_reset(stream: &mut std::net::TcpStream, context: &str) {
        // Without this a blocking write parks inside the kernel once the
        // send buffer fills, and a stall arrives as a hang rather than as
        // the assertions below.
        stream
            .set_write_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let buf = [0_u8; 4096];
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match stream.write(&buf) {
                Ok(_) => assert!(
                    std::time::Instant::now() < deadline,
                    "{context}: writes kept succeeding; data after FIN was absorbed"
                ),
                Err(err)
                    if err.kind() == std::io::ErrorKind::WouldBlock
                        || err.kind() == std::io::ErrorKind::TimedOut =>
                {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "{context}: writes never failed; data after FIN was absorbed"
                    );
                }
                Err(err) => {
                    // NotConnected is today's surface for any dead stream:
                    // moto-rt has no ConnectionReset code (recorded step 6
                    // decision). The claim here is promptness, not the kind.
                    assert!(
                        matches!(
                            err.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::BrokenPipe
                                | std::io::ErrorKind::NotConnected
                        ),
                        "{context}: unexpected error kind: {err:?}"
                    );
                    break;
                }
            }
        }
    }

    // A byte each way makes the close a graceful FIN rather than the
    // never-used-connection abort, with nothing left unread on the peer.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        conn.write_all(b"x").unwrap();
        let mut byte = [0_u8; 1];
        conn.read_exact(&mut byte).unwrap();
        drop(conn);
    });
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    let mut byte = [0_u8; 1];
    stream.read_exact(&mut byte).unwrap();
    stream.write_all(b"y").unwrap();
    peer.join().unwrap();
    // EOF first: the FIN is in, the peer socket is orphaned in FIN-WAIT.
    assert_eq!(stream.read(&mut byte).unwrap(), 0);
    write_until_reset(&mut stream, "close");

    // Same, via shutdown(Both) with the fd held open: only the shutdown
    // speaks for the reader being gone.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (hold_tx, hold_rx) = std::sync::mpsc::channel::<()>();
    let peer = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        conn.write_all(b"x").unwrap();
        let mut byte = [0_u8; 1];
        conn.read_exact(&mut byte).unwrap();
        conn.shutdown(std::net::Shutdown::Both).unwrap();
        let _ = hold_rx.recv();
        drop(conn);
    });
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    let mut byte = [0_u8; 1];
    stream.read_exact(&mut byte).unwrap();
    stream.write_all(b"y").unwrap();
    assert_eq!(stream.read(&mut byte).unwrap(), 0);
    write_until_reset(&mut stream, "shutdown(Both)");
    hold_tx.send(()).unwrap();
    peer.join().unwrap();

    println!("test_write_after_peer_graceful_close_resets() PASS");
}

/// Backlog saturation, staying within the API's guarantees: fill the ready
/// queue exactly to the backlog (the pump stops donating), drain part of
/// it, and prove donations resume -- later connects complete and every
/// accepted stream is live. Overflowing the backlog would be refused by
/// design, so this never does.
fn test_backlog_saturation_liveness() {
    use std::os::fd::AsRawFd;

    const BACKLOG: usize = 4;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    // listen() only accepts a nonblocking listener; the accepts below want
    // the blocking path back.
    listener.set_nonblocking(true).unwrap();
    moto_rt::net::listen(listener.as_raw_fd(), BACKLOG as u32).unwrap();
    listener.set_nonblocking(false).unwrap();
    let addr = listener.local_addr().unwrap();

    let connect = || std::thread::spawn(move || std::net::TcpStream::connect(addr).unwrap());

    // Saturate: all BACKLOG connects complete without a single accept().
    let first: Vec<_> = (0..BACKLOG).map(|_| connect()).collect();
    let mut clients: Vec<_> = first.into_iter().map(|t| t.join().unwrap()).collect();

    // Drain half, then two more connects must complete: the pump resumed.
    let mut accepted = Vec::new();
    for _ in 0..2 {
        accepted.push(listener.accept().unwrap());
    }
    let second: Vec<_> = (0..2).map(|_| connect()).collect();
    clients.extend(second.into_iter().map(|t| t.join().unwrap()));

    for _ in 0..(BACKLOG - 2 + 2) {
        accepted.push(listener.accept().unwrap());
    }
    assert_eq!(accepted.len(), BACKLOG + 2);
    drop((accepted, clients, listener));
    println!("test_backlog_saturation_liveness() PASS");
}

// The step-3 storm (networking plan): with the vDSO recheck ticks deleted,
// every park below is woken only by its real wake chain. Timeout storms on
// quiet and backpressured sockets run concurrently with live TCP and UDP
// traffic on other sockets: the storm's constant park/timeout/drop churn on
// the shared channel must not eat a live socket's wake (a lost wake now
// hangs this test instead of hiding behind a 500ms/5s recheck), and every
// short-timeout call must keep returning on time while the channel is busy.
fn test_timeout_storm_under_traffic() {
    const RUN: Duration = Duration::from_millis(2500);

    let stop = Arc::new(AtomicBool::new(false));
    // Separate release for the parking lot: its held sockets must outlive
    // the stormers, or the drop's RST turns a parked write's TimedOut into
    // ConnectionReset mid-join.
    let release = Arc::new(AtomicBool::new(false));

    // Quiet-socket parking lot: accepts and holds streams, reading nothing.
    let lot = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let lot_addr = lot.local_addr().unwrap();
    let held = {
        let release = release.clone();
        std::thread::spawn(move || {
            lot.set_nonblocking(true).unwrap();
            let mut held = Vec::new();
            while !release.load(Ordering::Acquire) {
                match lot.accept() {
                    Ok((s, _)) => held.push(s),
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
            held.len()
        })
    };

    // Live TCP: an echo pair on its own sockets, counting roundtrips.
    let echo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo.local_addr().unwrap();
    // EOF-driven, not stop-driven: it must keep serving through the
    // post-storm probe and exit only when the client drops.
    let echo_srv = std::thread::spawn(move || {
        let (mut conn, _) = echo.accept().unwrap();
        let mut buf = [0u8; 4096];
        loop {
            match conn.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => conn.write_all(&buf[..n]).unwrap(),
                Err(err) => panic!("echo server read failed: {err:?}"),
            }
        }
    });
    let tcp_live = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut conn = std::net::TcpStream::connect(echo_addr).unwrap();
            let out = [0x5au8; 4096];
            let mut back = [0u8; 4096];
            let mut roundtrips = 0usize;
            while !stop.load(Ordering::Acquire) {
                conn.write_all(&out).unwrap();
                conn.read_exact(&mut back).unwrap();
                assert_eq!(back[0], 0x5a);
                roundtrips += 1;
            }
            (conn, roundtrips)
        })
    };

    // Live UDP: a single-thread ping-pong pair; a rare drop is retried,
    // only completed roundtrips count.
    let udp_live = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let b_addr = b.local_addr().unwrap();
            b.set_read_timeout(Some(Duration::from_millis(250)))
                .unwrap();
            let mut buf = [0u8; 16];
            let mut roundtrips = 0usize;
            while !stop.load(Ordering::Acquire) {
                a.send_to(b"storm-ping", b_addr).unwrap();
                match b.recv_from(&mut buf) {
                    Ok((n, _)) => {
                        assert_eq!(&buf[..n], b"storm-ping");
                        roundtrips += 1;
                    }
                    Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::TimedOut),
                }
            }
            roundtrips
        })
    };

    // The storm: quiet-socket RCVTIMEO parks (TCP and UDP) and
    // never-drained SNDTIMEO writes, all short, looping until stop.
    let mut stormers = Vec::new();
    for timeout_ms in [1u64, 5, 20] {
        let stop = stop.clone();
        stormers.push(std::thread::spawn(move || {
            let mut conn = std::net::TcpStream::connect(lot_addr).unwrap();
            conn.set_read_timeout(Some(Duration::from_millis(timeout_ms)))
                .unwrap();
            let mut buf = [0u8; 64];
            let mut calls = 0usize;
            while !stop.load(Ordering::Acquire) {
                match conn.read(&mut buf) {
                    Ok(_) => panic!("read data from a quiet socket"),
                    Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::TimedOut),
                }
                calls += 1;
            }
            calls
        }));
    }
    {
        let stop = stop.clone();
        stormers.push(std::thread::spawn(move || {
            let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            sock.set_read_timeout(Some(Duration::from_millis(5)))
                .unwrap();
            let mut buf = [0u8; 64];
            let mut calls = 0usize;
            while !stop.load(Ordering::Acquire) {
                match sock.recv_from(&mut buf) {
                    Ok(_) => panic!("datagram on a quiet socket"),
                    Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::TimedOut),
                }
                calls += 1;
            }
            calls
        }));
    }
    for _ in 0..2 {
        let stop = stop.clone();
        stormers.push(std::thread::spawn(move || {
            let mut conn = std::net::TcpStream::connect(lot_addr).unwrap();
            conn.set_write_timeout(Some(Duration::from_millis(10)))
                .unwrap();
            let chunk = [7u8; 8192];
            let mut calls = 0usize;
            while !stop.load(Ordering::Acquire) {
                match conn.write(&chunk) {
                    Ok(n) => assert!(n > 0, "write returned Ok(0)"),
                    Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::TimedOut),
                }
                calls += 1;
            }
            calls
        }));
    }

    std::thread::sleep(RUN);
    stop.store(true, Ordering::Release);

    let mut storm_calls = Vec::new();
    for t in stormers {
        storm_calls.push(t.join().unwrap());
    }
    release.store(true, Ordering::Release);
    let _held_count = held.join().unwrap();
    let udp_roundtrips = udp_live.join().unwrap();
    let (mut conn, tcp_roundtrips) = tcp_live.join().unwrap();

    // Post-storm: the live socket still echoes -- no wake was stolen for
    // good. (This also lets the echo server exit on its next read.)
    conn.write_all(b"post-storm").unwrap();
    let mut tail = [0u8; 10];
    conn.read_exact(&mut tail).unwrap();
    assert_eq!(&tail, b"post-storm");
    drop(conn);
    echo_srv.join().unwrap();

    // Progress floors, far below the theoretical rates so scheduling noise
    // and --under-load starvation cannot trip them.
    assert!(tcp_roundtrips >= 5, "live TCP starved: {tcp_roundtrips}");
    assert!(udp_roundtrips >= 5, "live UDP starved: {udp_roundtrips}");
    for (i, calls) in storm_calls.iter().enumerate() {
        assert!(*calls >= 5, "storm thread {i} starved: {calls} calls");
    }

    println!("test_timeout_storm_under_traffic() PASS");
}

pub fn run_all_tests() {
    test_device_rx_validation();
    test_neighbor_admission();
    test_channel_teardown();
    test_backlog_saturation_liveness();
    // Runs while teardown leaves the ephemeral port space quiet.
    test_simultaneous_open();
    test_native_net_cancellation();
    test_connect_reset_is_not_a_timeout();
    test_tcp_socket_state_transitions();
    test_half_open_accounting();
    test_backlog_growth_and_shrink();
    test_tx_error_with_queued_rx();
    test_ipv6();
    test_zero_port_listen();
    test_tcp_loopback();
    test_tcp_dup_shares_posix_flags();
    test_tcp_listener_dup_shares_posix_flags();
    test_blocking_accept_is_not_starved();
    test_write_to_dropped_peer_fails_fast();
    test_write_after_peer_graceful_close_resets();
    test_tcp_listener_ttl();
    test_tcp_buffer_sizes();
    test_native_buffer_options();
    test_tcp_linger();
    test_peek();
    test_read_timeout_early_data();
    test_write_timeout();
    test_write_backpressure_integrity();
    test_write_backpressure_concurrent();
    test_timeout_storm_during_transfer();
    test_timeout_storm_under_traffic();
    test_concurrent_readers();
}

// pub fn test_wget() {
//     // let url = "1.1.1.1:80";
//     // let url = "10.0.2.10:10023";
//     let mut stream = std::net::TcpStream::connect(url).unwrap();
//     let request = "GET /\nHost: 1.1.1.1\nUser-Agent: *\nAccept: */*\n\n";
//     stream.write(request.as_bytes()).unwrap();

//     let mut rx = [0 as u8; 8];
//     match stream.read(&mut rx) {
//         Ok(_) => {
//             println!("test_wget(): got a response from {}", url);
//         }
//         Err(e) => {
//             println!("Failed to receive data: {}", e);
//             panic!()
//         }
//     }
// }
