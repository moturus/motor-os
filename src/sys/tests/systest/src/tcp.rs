#![allow(unused)]
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, atomic::*};
use std::task::{Context, Poll};
use std::time::Duration;

use moto_io::net::readiness::{NetEventListener, Readiness};
use moto_io::net::tcp::{TcpListener as NativeTcpListener, TcpStream as NativeTcpStream};

struct NoopNetEventListener;

impl NetEventListener for NoopNetEventListener {
    fn on_readiness(&self, _edges: Readiness) {}

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn read_sys_io_metric(name: &str) -> u64 {
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

fn wait_for_sys_io_metric(name: &str, predicate: impl Fn(u64) -> bool) -> u64 {
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

fn wait_for_cancelled_accept_cleanup(listener_addr: SocketAddr, client_addr: SocketAddr) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let sockets = read_tcp_socket_stats();
        let client_is_live = sockets.iter().any(|socket| {
            socket.local_addr() == Some(client_addr) && socket.remote_addr() == Some(listener_addr)
        });
        let abandoned_accept_is_live = sockets.iter().any(|socket| {
            socket.local_addr() == Some(listener_addr) && socket.remote_addr() == Some(client_addr)
        });
        if client_is_live && !abandoned_accept_is_live {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "cancelled accept was not reclaimed; matching sockets: {:?}",
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

fn wait_for_tcp_pair(listener_addr: SocketAddr, client_addr: SocketAddr) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let sockets = read_tcp_socket_stats();
        let client_is_live = sockets.iter().any(|socket| {
            socket.local_addr() == Some(client_addr) && socket.remote_addr() == Some(listener_addr)
        });
        let server_is_live = sockets.iter().any(|socket| {
            socket.local_addr() == Some(listener_addr) && socket.remote_addr() == Some(client_addr)
        });
        if client_is_live && server_is_live {
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

fn wait_for_cancelled_connect_cleanup(pairs: &[(SocketAddr, SocketAddr)]) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let sockets = read_tcp_socket_stats();
        let all_reclaimed = pairs.iter().all(|(listener_addr, client_addr)| {
            let server_is_live = sockets.iter().any(|socket| {
                socket.local_addr() == Some(*listener_addr)
                    && socket.remote_addr() == Some(*client_addr)
            });
            let abandoned_connect_is_live = sockets.iter().any(|socket| {
                socket.local_addr() == Some(*client_addr)
                    && socket.remote_addr() == Some(*listener_addr)
            });
            server_is_live && !abandoned_connect_is_live
        });
        if all_reclaimed {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "cancelled connect was not reclaimed; pairs: {pairs:?}, sockets: {sockets:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// A dropped native connect future must not strand the socket that sys-io
/// creates when the already-posted connect RPC later completes. The keeper
/// listener deliberately holds the native channel open after each future
/// releases its own reservation, reproducing the leak's required condition.
fn test_cancelled_native_connect_closes_socket() {
    use std::future::Future;

    const CONNECTIONS: usize = 4;

    let total_before = read_sys_io_metric("net.total_tcp_sockets");
    let keeper = NativeTcpListener::bind(
        &"127.0.0.1:0".parse().unwrap(),
        Arc::new(NoopNetEventListener),
    )
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listener_addr = listener.local_addr().unwrap();

    for _ in 0..CONNECTIONS {
        let mut connect = Box::pin(NativeTcpStream::connect(
            &listener_addr,
            None,
            Arc::new(NoopNetEventListener),
        ));
        let waker = futures::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        assert!(matches!(connect.as_mut().poll(&mut context), Poll::Pending));
        drop(connect);
    }

    let mut servers = Vec::with_capacity(CONNECTIONS);
    let mut pairs = Vec::with_capacity(CONNECTIONS);
    for _ in 0..CONNECTIONS {
        let (server, client_addr) = listener.accept().unwrap();
        pairs.push((listener_addr, client_addr));
        servers.push(server);
    }

    wait_for_sys_io_metric("net.total_tcp_sockets", |value| {
        value >= total_before + (CONNECTIONS as u64) * 2
    });
    wait_for_cancelled_connect_cleanup(&pairs);

    drop(servers);
    drop(listener);
    drop(keeper);
    println!("test_cancelled_native_connect_closes_socket() PASS");
}

/// A dropped native accept future must not strand the socket that sys-io
/// creates when its already-posted accept RPC later completes.
fn test_cancelled_native_accept_closes_socket() {
    use std::future::Future;

    let total_before = read_sys_io_metric("net.total_tcp_sockets");
    let listener = NativeTcpListener::bind(
        &"127.0.0.1:0".parse().unwrap(),
        Arc::new(NoopNetEventListener),
    )
    .unwrap();
    let make_listener = || Arc::new(NoopNetEventListener) as Arc<dyn NetEventListener>;

    // The first poll posts an accept RPC. Dropping while it is pending is the
    // cancellation being tested; the connection below completes that RPC.
    let mut accept = Box::pin(listener.accept(&make_listener));
    let waker = futures::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    assert!(matches!(accept.as_mut().poll(&mut context), Poll::Pending));
    drop(accept);

    let listener_addr = *listener.socket_addr();
    let client = std::net::TcpStream::connect(listener_addr).unwrap();
    let client_addr = client.local_addr().unwrap();

    // Both halves were allocated, so this cannot pass merely because the
    // connection never reached the accept response. Only the client half
    // should remain live after cancellation cleanup. Match the two loopback
    // endpoints directly so unrelated system socket churn cannot skew this.
    wait_for_sys_io_metric("net.total_tcp_sockets", |value| value >= total_before + 2);
    wait_for_cancelled_accept_cleanup(listener_addr, client_addr);

    drop(client);
    drop(listener);
    println!("test_cancelled_native_accept_closes_socket() PASS");
}

/// Cancellation after the accept response has reached the one-shot but before
/// the future consumes it must reclaim the accepted stream as well.
fn test_delivered_then_cancelled_native_accept_closes_socket() {
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

    let listener = NativeTcpListener::bind(
        &"127.0.0.1:0".parse().unwrap(),
        Arc::new(NoopNetEventListener),
    )
    .unwrap();
    let make_listener = || Arc::new(NoopNetEventListener) as Arc<dyn NetEventListener>;

    let mut accept = Box::pin(listener.accept(&make_listener));
    let wake_flag = Arc::new(WakeFlag(AtomicBool::new(false)));
    let waker = std::task::Waker::from(wake_flag.clone());
    let mut context = Context::from_waker(&waker);
    assert!(matches!(accept.as_mut().poll(&mut context), Poll::Pending));

    let listener_addr = *listener.socket_addr();
    let client = std::net::TcpStream::connect(listener_addr).unwrap();
    let client_addr = client.local_addr().unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !wake_flag.0.load(Ordering::Acquire) {
        assert!(
            std::time::Instant::now() < deadline,
            "accept response was not delivered to the waiting future"
        );
        std::thread::yield_now();
    }
    wait_for_tcp_pair(listener_addr, client_addr);

    // Do not poll the woken future: cancellation must drop and roll back the
    // successful PendingAccept stored in the one-shot channel.
    drop(accept);
    wait_for_cancelled_accept_cleanup(listener_addr, client_addr);

    drop(client);
    drop(listener);
    println!("test_delivered_then_cancelled_native_accept_closes_socket() PASS");
}

/// Releasing the final listener reference on its channel runtime must remain
/// nonblocking when the runtime's staging queue is full. The netdev hook makes
/// the otherwise narrow last-reference/backpressure race deterministic.
fn test_native_listener_drop_under_backpressure() {
    use std::future::Future;

    let listener = NativeTcpListener::bind(
        &"127.0.0.1:0".parse().unwrap(),
        Arc::new(NoopNetEventListener),
    )
    .unwrap();
    moto_io::net::channel::arm_listener_drop_backpressure_test(listener.handle());

    // Post an accept and cancel it. Its eventual response makes the channel
    // runtime temporarily upgrade the listener Weak to an Arc.
    let make_listener = || Arc::new(NoopNetEventListener) as Arc<dyn NetEventListener>;
    let mut accept = Box::pin(listener.accept(&make_listener));
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

    // The channel runtime now owns the only remaining listener Arc and its
    // send queue is full. Releasing the hook runs TcpListener::drop there.
    drop(listener);
    moto_io::net::channel::release_listener_drop_backpressure_test();

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !moto_io::net::channel::listener_drop_backpressure_test_is_done() {
        assert!(
            std::time::Instant::now() < deadline,
            "TcpListener::drop blocked its channel runtime on a full send queue"
        );
        std::thread::yield_now();
    }

    drop(client);
    println!("test_native_listener_drop_under_backpressure() PASS");
}

pub fn test_native_net_cancellation() {
    test_cancelled_native_connect_closes_socket();
    test_cancelled_native_accept_closes_socket();
    test_delivered_then_cancelled_native_accept_closes_socket();
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

    let stream = moto_async::LocalRuntime::new()
        .block_on(NativeTcpStream::connect(
            &listener_addr,
            None,
            Arc::new(NoopNetEventListener),
        ))
        .unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !stream.has_rx_bytes() {
        assert!(
            std::time::Instant::now() < deadline,
            "peer data did not reach the native stream"
        );
        std::thread::yield_now();
    }

    // sys-io returns the original id-zero TX message when it rejects an
    // asynchronous write (for example, because the peer has closed). Inject
    // that protocol result after real RX data to deterministically exercise
    // the same ordering seen under HTTP production traffic.
    let mut tx_error = moto_ipc::io_channel::Msg::new();
    tx_error.command = moto_sys_io::api_net::NetCmd::TcpStreamTx as u16;
    tx_error.handle = stream.handle();
    tx_error.status = moto_rt::E_NOT_CONNECTED;
    stream.process_incoming_msg(tx_error);

    drop(stream);
    release_peer.store(true, Ordering::Release);
    peer.join().unwrap();
    println!("test_tx_error_with_queued_rx() PASS");
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

fn test_ipv6() {
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
    assert_eq!(failures, 0, "shutdown(Write) lost data on {failures} exchange(s)");
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

    assert!(!bad.load(Ordering::Acquire), "reader saw wrong bytes or errored");
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

pub fn run_all_tests() {
    test_channel_teardown();
    test_native_net_cancellation();
    test_tx_error_with_queued_rx();
    test_ipv6();
    test_zero_port_listen();
    test_tcp_loopback();
    test_peek();
    test_read_timeout_early_data();
    test_write_timeout();
    test_write_backpressure_integrity();
    test_write_backpressure_concurrent();
    test_timeout_storm_during_transfer();
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
