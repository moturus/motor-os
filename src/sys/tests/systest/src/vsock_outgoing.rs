use core::future::Future;
use core::task::{Context, Poll};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Wake, Waker};
use std::time::{Duration, Instant};

use moto_io::net::vsock::{Shutdown, VsockAddr, VsockListener, VsockStream};
use moto_ipc::io_channel::{CHANNEL_PAGE_COUNT, PAGE_SIZE};
use moto_sys_io::api_net::IO_SUBCHANNELS;

use crate::net_harness::{bounded, host_channel};

const MAX_FRAME: usize = 64 * 1024;
const ROLE_DATA: &[u8] = b"role:data";
const ROLE_SYNC: &[u8] = b"role:sync";
const SEND_SHUTDOWN_DONE: &[u8] = b"shutdown:send";
const RECEIVE_SHUTDOWN_DONE: &[u8] = b"shutdown:receive";
const CONTINUE: &[u8] = b"continue";
const TRANSFER_DONE: &[u8] = b"transfer:done";
const CASE_DONE: &[u8] = b"case:done";
const FINAL_SLOT_ADMITTED: &[u8] = b"final-slot:admitted";
const CANCEL_READY: &[u8] = b"cancel:ready";
const ROLES_READY: &[u8] = b"roles:ready";
const STALLED_DATA_READY: &[u8] = b"stalled:data-ready";
const UNRELATED_PING: &[u8] = b"unrelated:ping";
const UNRELATED_PONG: &[u8] = b"unrelated:pong";
const DRAIN_STARTED: &[u8] = b"drain:started";
const LISTENER_READY: &[u8] = b"listener:ready";
const BACKLOG_READY: &[u8] = b"backlog:ready";
const LISTENER_DROPPED: &[u8] = b"listener:dropped";
const BACKLOG_CLEARED: &[u8] = b"backlog:cleared";
const LISTENER_REBOUND: &[u8] = b"listener:rebound";
const NATIVE_ACCEPT_READY: &[u8] = b"native-accept:ready";
const NATIVE_ACCEPT_EARLY: &[u8] = b"early";
const NATIVE_ACCEPT_EARLY_READY: &[u8] = b"native-accept:early-ready";
const NATIVE_ACCEPT_REPLY: &[u8] = b"accepted";
const NATIVE_ACCEPT_DROPPED: &[u8] = b"native-accept:dropped";
const NATIVE_ACCEPT_CLOSE_READY: &[u8] = b"native-accept:close-ready";
const NATIVE_ACCEPT_CLOSED: &[u8] = b"closed";
const NATIVE_ACCEPT_CLOSED_READY: &[u8] = b"native-accept:closed-ready";
const NATIVE_ACCEPT_CANCEL_READY: &[u8] = b"native-accept:cancel-ready";
const NATIVE_ACCEPT_CANCEL_CLOSED: &[u8] = b"native-accept:cancel-closed";
const NATIVE_ACCEPT_EXIT_READY: &[u8] = b"native-accept:exit-ready";
const NATIVE_ACCEPT_ANCHOR_HELD: &[u8] = b"native-accept:anchor-held";
const NATIVE_ACCEPT_CONNECT_READY: &[u8] = b"native-accept:connect-ready";
const NATIVE_ACCEPT_BOTH_HELD: &[u8] = b"native-accept:both-held";
const NATIVE_ACCEPT_EXITED: &[u8] = b"native-accept:exited";
const NATIVE_ACCEPT_EXIT_CLEANED: &[u8] = b"native-accept:exit-cleaned";
const NATIVE_ACCEPT_EXIT_REBOUND: &[u8] = b"native-accept:exit-rebound";
const COEXIST_READY: &[u8] = b"coexist:ready";
const COEXIST_START: &[u8] = b"coexist:start";
const COEXIST_PROGRESS: &[u8] = b"coexist:progress";
const COEXIST_CONTINUE: &[u8] = b"coexist:continue";
const COEXIST_PHASE_BYTES: usize = 256 * 1024;
const COEXIST_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const TAP_HOST: &str = "192.168.4.1";
const INCOMING_PORT: u32 = 70_001;
const NATIVE_ACCEPT_PORT: u32 = 70_002;
const NATIVE_ACCEPT_EXIT_PORT: u32 = 70_003;
const CAPACITY_READY: &[u8] = b"capacity:ready";
const CAPACITY_FULL: &[u8] = b"capacity:full";
const CAPACITY_PROGRESS: &[u8] = b"capacity:progress";
const CAPACITY_DROPPED: &[u8] = b"capacity:dropped";
const CAPACITY_CLEARED: &[u8] = b"capacity:cleared";
const CAPACITY_REBOUND: &[u8] = b"capacity:rebound";
const CAPACITY_REUSED: &[u8] = b"capacity:reused";
const CAPACITY_PORT_START: u32 = 70_010;
const CAPACITY_LISTENERS: usize = 8;
const GLOBAL_STREAM_LIMIT: usize = 64;
const CANCEL_POLLS: usize = 4;
const SMALL_ECHO_ROUNDTRIPS: usize = 128;
const PAGES_PER_SUBCHANNEL: usize = CHANNEL_PAGE_COUNT / IO_SUBCHANNELS as usize;

enum Action {
    Echo(usize),
    Duplex { send: usize, echo: usize },
    LocalSendShutdown { send: usize, receive: usize },
    LocalReceiveShutdown { receive: usize, send: usize },
    UnixPeerClose { receive: usize },
    CancelRead { receive: usize },
    CancelWrite { tail: usize },
    CancelBeforePollDrop,
    CancelQueuedConnect,
    StalledReader { total: usize },
    Coexistence,
    IncomingBacklog,
    IncomingOwnerDrop,
    NativeAccept,
    GlobalStreamCapacity,
}

#[derive(Clone, Copy)]
enum AbsentPeerBehavior {
    Refused,
    Silent,
}

impl AbsentPeerBehavior {
    fn parse(value: &str) -> Self {
        match value {
            "refused" => Self::Refused,
            "silent" => Self::Silent,
            _ => panic!("invalid absent-peer behavior '{value}'"),
        }
    }
}

impl Action {
    fn needs_sync(&self) -> bool {
        matches!(
            self,
            Self::LocalSendShutdown { .. }
                | Self::LocalReceiveShutdown { .. }
                | Self::UnixPeerClose { .. }
                | Self::CancelRead { .. }
                | Self::CancelWrite { .. }
                | Self::CancelQueuedConnect
                | Self::StalledReader { .. }
                | Self::Coexistence
        )
    }
}

fn parse_size(value: &str) -> usize {
    value
        .parse()
        .unwrap_or_else(|_| panic!("invalid vsock byte count '{value}'"))
}

fn parse_action(args: &[String]) -> Action {
    match args {
        [action, total] if action == "echo" => Action::Echo(parse_size(total)),
        [action, send, echo] if action == "duplex" => Action::Duplex {
            send: parse_size(send),
            echo: parse_size(echo),
        },
        [action, send, receive] if action == "local-send-shutdown" => Action::LocalSendShutdown {
            send: parse_size(send),
            receive: parse_size(receive),
        },
        [action, receive, send] if action == "local-receive-shutdown" => {
            Action::LocalReceiveShutdown {
                receive: parse_size(receive),
                send: parse_size(send),
            }
        }
        [action, receive] if action == "unix-peer-close" => Action::UnixPeerClose {
            receive: parse_size(receive),
        },
        [action, receive] if action == "cancel-read" => Action::CancelRead {
            receive: parse_size(receive),
        },
        [action, tail] if action == "cancel-write" => Action::CancelWrite {
            tail: parse_size(tail),
        },
        [action] if action == "cancel-before-poll-drop" => Action::CancelBeforePollDrop,
        [action] if action == "cancel-queued-connect" => Action::CancelQueuedConnect,
        [action, total] if action == "stalled-reader" => Action::StalledReader {
            total: parse_size(total),
        },
        [action] if action == "coexistence" => Action::Coexistence,
        [action] if action == "incoming-backlog" => Action::IncomingBacklog,
        [action] if action == "incoming-owner-drop" => Action::IncomingOwnerDrop,
        [action] if action == "native-accept" => Action::NativeAccept,
        [action] if action == "global-stream-capacity" => Action::GlobalStreamCapacity,
        _ => panic!(
            "expected echo N, duplex SEND_N ECHO_N, \
             local-send-shutdown SEND_N RECEIVE_N, \
             local-receive-shutdown RECEIVE_N SEND_N, unix-peer-close RECEIVE_N, \
             cancel-read RECEIVE_N, cancel-write TAIL_N, cancel-before-poll-drop, \
             cancel-queued-connect, stalled-reader TOTAL, coexistence, incoming-backlog, \
             incoming-owner-drop, native-accept, or global-stream-capacity"
        ),
    }
}

fn pattern_byte(offset: usize) -> u8 {
    (offset.wrapping_mul(37).wrapping_add(11) & 0xff) as u8
}

async fn write_all(stream: &VsockStream, bytes: &[u8]) {
    let mut written = 0;
    while written < bytes.len() {
        match stream.try_write(&[&bytes[written..]]) {
            Ok(0) => panic!("nonempty vsock write made no progress"),
            Ok(len) => written += len,
            Err(moto_rt::E_NOT_READY) => {
                let bufs = [&bytes[written..]];
                match stream.write_future(&bufs).await {
                    Ok(0) => panic!("nonempty vsock write future made no progress"),
                    Ok(len) => written += len,
                    Err(error) => panic!("vsock write future failed: {error:?}"),
                }
            }
            Err(error) => panic!("vsock write failed: {error:?}"),
        }
    }
}

async fn read_exact(stream: &VsockStream, bytes: &mut [u8]) {
    let mut read = 0;
    while read < bytes.len() {
        match stream.try_read(&mut [&mut bytes[read..]]) {
            Ok(0) => panic!(
                "vsock stream reached EOF with {} bytes missing",
                bytes.len() - read
            ),
            Ok(len) => read += len,
            Err(moto_rt::E_NOT_READY) => {
                let remaining = bytes.len() - read;
                let result = {
                    let mut bufs = [&mut bytes[read..]];
                    stream.read_future(&mut bufs).await
                };
                match result {
                    Ok(0) => panic!("vsock stream reached EOF with {remaining} bytes missing"),
                    Ok(len) => read += len,
                    Err(error) => panic!("vsock read future failed: {error:?}"),
                }
            }
            Err(error) => panic!("vsock read failed: {error:?}"),
        }
    }
}

async fn write_frame(stream: &VsockStream, payload: &[u8]) {
    assert!(payload.len() <= MAX_FRAME);
    let header = u32::try_from(payload.len()).unwrap().to_be_bytes();
    write_all(stream, &header).await;
    write_all(stream, payload).await;
}

async fn read_frame(stream: &VsockStream) -> Vec<u8> {
    let mut header = [0_u8; 4];
    read_exact(stream, &mut header).await;
    let len = u32::from_be_bytes(header) as usize;
    assert!(len <= MAX_FRAME, "host frame exceeds 64 KiB: {len}");
    let mut payload = vec![0_u8; len];
    read_exact(stream, &mut payload).await;
    payload
}

async fn expect_frame(stream: &VsockStream, expected: &[u8]) {
    assert_eq!(read_frame(stream).await, expected);
}

fn assert_read_eof(stream: &VsockStream) {
    let mut unexpected = [0_u8; 1];
    assert_eq!(stream.try_read(&mut [&mut unexpected]), Ok(0));
}

struct CountWake(AtomicUsize);

impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn poll_pending<F: Future>(future: F) -> Arc<CountWake> {
    let counter = Arc::new(CountWake(AtomicUsize::new(0)));
    let waker = Waker::from(counter.clone());
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    counter
}

fn assert_not_woken(counters: &[Arc<CountWake>]) {
    assert!(
        counters
            .iter()
            .all(|counter| counter.0.load(Ordering::Relaxed) == 0),
        "a canceled vsock future retained a waiter"
    );
}

fn expect_child_marker(reader: &mut impl BufRead, expected: &str) {
    let mut line = String::new();
    assert_ne!(
        reader.read_line(&mut line).unwrap(),
        0,
        "child exited early"
    );
    assert_eq!(line, format!("{expected}\n"));
}

fn pattern(start: usize, len: usize) -> Vec<u8> {
    (start..start + len).map(pattern_byte).collect()
}

fn print_throughput(label: &str, bytes: usize, elapsed: Duration) {
    let elapsed_ns = elapsed.as_nanos().max(1);
    let bytes_per_second = bytes as u128 * 1_000_000_000 / elapsed_ns;
    println!(
        "vsock measurement: {label} aggregate_vsock_payload_bytes={bytes} elapsed_us={} payload_bytes_per_second={bytes_per_second}",
        elapsed.as_micros()
    );
}

fn sys_io_memory_usage() -> u64 {
    crate::kernel_metric("memory_usage", moto_sys::stats::PID_SYS_IO)
}

fn fill_tx_without_yield(stream: &VsockStream) -> usize {
    let mut accepted = 0;
    for _ in 0..=PAGES_PER_SUBCHANNEL {
        let page = pattern(accepted, PAGE_SIZE);
        match stream.try_write(&[&page]) {
            Ok(PAGE_SIZE) => accepted += PAGE_SIZE,
            Ok(len) => panic!("full-page write accepted only {len} bytes"),
            Err(moto_rt::E_NOT_READY) => {
                assert_eq!(accepted, PAGES_PER_SUBCHANNEL * PAGE_SIZE);
                return accepted;
            }
            Err(error) => panic!("subchannel page fill failed: {error:?}"),
        }
    }
    panic!("vsock subchannel did not apply bounded page backpressure")
}

async fn write_raw_pattern(stream: &VsockStream, start: usize, len: usize) {
    let bytes = pattern(start, len);
    write_all(stream, &bytes).await;
}

async fn write_pattern(stream: &VsockStream, total: usize) {
    if total == 0 {
        write_frame(stream, &[]).await;
        return;
    }
    let mut offset = 0;
    while offset < total {
        let len = (total - offset).min(MAX_FRAME);
        let payload: Vec<_> = (offset..offset + len).map(pattern_byte).collect();
        write_frame(stream, &payload).await;
        offset += len;
    }
}

async fn read_pattern(stream: &VsockStream, total: usize) {
    if total == 0 {
        assert!(read_frame(stream).await.is_empty());
        return;
    }
    let mut offset = 0;
    while offset < total {
        let payload = read_frame(stream).await;
        assert!(!payload.is_empty(), "empty frame inside nonempty transfer");
        assert!(payload.len() <= total - offset, "host sent excess payload");
        for (index, byte) in payload.iter().enumerate() {
            assert_eq!(*byte, pattern_byte(offset + index));
        }
        offset += payload.len();
    }
}

async fn coexistence_vsock_phase(stream: &VsockStream, sync: &VsockStream, done: &[u8]) {
    futures::join!(
        write_pattern(stream, COEXIST_PHASE_BYTES),
        read_pattern(stream, COEXIST_PHASE_BYTES)
    );
    expect_frame(sync, done).await;
}

async fn coexistence_ports(sync: &VsockStream) -> (u16, u16) {
    let ports = read_frame(sync).await;
    assert_eq!(ports.len(), 4, "invalid coexistence endpoint frame");
    let tcp = u16::from_be_bytes([ports[0], ports[1]]);
    let udp = u16::from_be_bytes([ports[2], ports[3]]);
    assert_ne!(tcp, 0);
    assert_ne!(udp, 0);
    (tcp, udp)
}

fn coexistence_io(
    path: std::path::PathBuf,
    ports: (u16, u16),
    ready: moto_async::oneshot::Sender<()>,
    start: std::sync::mpsc::Receiver<()>,
    progress: moto_async::oneshot::Sender<()>,
    resume: std::sync::mpsc::Receiver<()>,
    done: moto_async::oneshot::Sender<()>,
) {
    use std::io::{Read, Seek, Write};
    use std::net::{TcpStream, UdpSocket};
    use std::os::fd::AsRawFd;

    const BLOCK_BYTES: usize = 64 * 1024;
    const TCP_BYTES: usize = 16 * 1024;
    const UDP_BYTES: usize = 256;
    let (tcp_port, udp_port) = ports;

    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let mut tcp = TcpStream::connect((TAP_HOST, tcp_port)).unwrap();
    tcp.set_read_timeout(Some(COEXIST_IO_TIMEOUT)).unwrap();
    tcp.set_write_timeout(Some(COEXIST_IO_TIMEOUT)).unwrap();
    let udp = UdpSocket::bind("0.0.0.0:0").unwrap();
    udp.set_read_timeout(Some(COEXIST_IO_TIMEOUT)).unwrap();
    udp.set_write_timeout(Some(COEXIST_IO_TIMEOUT)).unwrap();

    ready.send(()).unwrap();
    start.recv().unwrap();

    let block = vec![0x31; BLOCK_BYTES];
    let tcp_payload = vec![0x52; TCP_BYTES];
    let udp_payload = [0x73; UDP_BYTES];
    file.write_all(&block).unwrap();
    tcp.write_all(&tcp_payload).unwrap();
    assert_eq!(
        udp.send_to(&udp_payload, (TAP_HOST, udp_port)).unwrap(),
        UDP_BYTES
    );
    progress.send(()).unwrap();

    // The vsock phase must make progress before these pending operations are
    // completed, then both workloads resume from one causal barrier.
    resume.recv().unwrap();
    moto_rt::fs::flush(file.as_raw_fd()).unwrap();
    file.seek(std::io::SeekFrom::Start(0)).unwrap();
    let mut block_back = vec![0; BLOCK_BYTES];
    file.read_exact(&mut block_back).unwrap();
    assert_eq!(block_back, block);

    let mut tcp_back = vec![0; TCP_BYTES];
    tcp.read_exact(&mut tcp_back).unwrap();
    assert_eq!(tcp_back, tcp_payload);

    let mut udp_back = [0; UDP_BYTES];
    let (len, _) = udp.recv_from(&mut udp_back).unwrap();
    assert_eq!(&udp_back[..len], &udp_payload);

    drop(file);
    std::fs::remove_file(path).unwrap();
    done.send(()).unwrap();
}

async fn read_eof(stream: &VsockStream) {
    let mut unexpected = [0_u8; 1];
    loop {
        match stream.try_read(&mut [&mut unexpected]) {
            Ok(0) => return,
            Ok(len) => panic!("received {len} bytes after final framed payload"),
            Err(moto_rt::E_NOT_READY) => stream.readable().await,
            Err(error) => panic!("vsock EOF read failed: {error:?}"),
        }
    }
}

async fn connect(client: &moto_io::net::NetClient, peer: VsockAddr) -> Arc<VsockStream> {
    let stream = VsockStream::connect_reserved(client.try_reserve().unwrap(), peer)
        .await
        .expect("outgoing vsock connect failed");
    assert_eq!(stream.peer_addr(), Ok(peer));
    let local = stream
        .socket_addr()
        .expect("connected stream has no local address");
    assert_eq!(local.cid, 3);
    assert_ne!(local.port, 0);
    assert_ne!(local.port, u32::MAX);
    stream.writable().await;
    stream
}

async fn test_connect_errors(
    client: &moto_io::net::NetClient,
    peer: VsockAddr,
    absent_peer: AbsentPeerBehavior,
) {
    let baseline = client.reservations();
    let unsupported = VsockAddr {
        cid: 4,
        port: peer.port,
    };
    let result = VsockStream::connect_reserved(client.try_reserve().unwrap(), unsupported).await;
    assert_eq!(result.err(), Some(moto_rt::E_NOT_IMPLEMENTED));
    assert_eq!(client.reservations(), baseline);

    let absent = VsockAddr {
        cid: 2,
        // The peer fixture listens only on `peer.port` in a fresh per-run
        // socket directory.
        port: peer.port.checked_add(2).unwrap(),
    };
    let expected = match absent_peer {
        AbsentPeerBehavior::Refused => moto_rt::E_NOT_CONNECTED,
        AbsentPeerBehavior::Silent => moto_rt::E_TIMED_OUT,
    };
    let started = Instant::now();
    let result = VsockStream::connect_reserved(client.try_reserve().unwrap(), absent).await;
    assert_eq!(
        result.err(),
        Some(expected),
        "unexpected error for {absent:?}"
    );
    if matches!(absent_peer, AbsentPeerBehavior::Silent) {
        assert!(
            started.elapsed() >= Duration::from_secs(2),
            "silent peer completed before the connect deadline"
        );
    }
    assert_eq!(
        client.reservations(),
        baseline,
        "failed connect retained its reservation"
    );
    println!("vsock connect errors: PASS");
}

async fn run_incoming_backlog(stream: &VsockStream, drop_owner_channel: bool) {
    let listener = crate::net_driver::RawVsockListener::bind(INCOMING_PORT).await;
    write_frame(stream, LISTENER_READY).await;
    expect_frame(stream, BACKLOG_READY).await;
    listener.accept_early(INCOMING_PORT).await;

    if drop_owner_channel {
        // The peer acknowledges only after every queued child observes EOF,
        // ordering sys-io's channel cleanup before the rebind below.
        drop(listener);
    } else {
        listener.close().await;
    }
    write_frame(stream, LISTENER_DROPPED).await;
    expect_frame(stream, BACKLOG_CLEARED).await;

    crate::net_driver::RawVsockListener::bind(INCOMING_PORT)
        .await
        .close()
        .await;
    write_frame(stream, LISTENER_REBOUND).await;
}

async fn run_global_stream_capacity(stream: &VsockStream) {
    let control_only = sys_io_memory_usage();
    let mut listeners = Vec::with_capacity(CAPACITY_LISTENERS);
    for offset in 0..CAPACITY_LISTENERS {
        listeners.push(
            crate::net_driver::RawVsockListener::bind(CAPACITY_PORT_START + offset as u32).await,
        );
    }
    write_frame(stream, CAPACITY_READY).await;

    // The host has now admitted 63 incoming streams and observed strict
    // refusal of the next. This control stream is the 64th live stream.
    expect_frame(stream, CAPACITY_FULL).await;
    let capacity_full = sys_io_memory_usage();
    write_frame(stream, CAPACITY_PROGRESS).await;

    for listener in listeners {
        listener.close().await;
    }
    write_frame(stream, CAPACITY_DROPPED).await;
    expect_frame(stream, CAPACITY_CLEARED).await;
    let after_cleanup = sys_io_memory_usage();

    let admitted_streams = (GLOBAL_STREAM_LIMIT - 1) as i128;
    let full_delta = capacity_full as i128 - control_only as i128;
    let cleanup_delta = after_cleanup as i128 - control_only as i128;
    // These snapshots cover the whole sys-io process, not attributed vsock
    // allocations; the delta also includes listener and allocator retention.
    println!(
        "vsock measurement: global-stream-capacity sys_io_whole_process_bytes control_only={control_only} capacity_full={capacity_full} after_cleanup={after_cleanup} full_delta={full_delta} full_delta_per_admitted_stream={} cleanup_delta={cleanup_delta}",
        full_delta / admitted_streams
    );

    let rebound = crate::net_driver::RawVsockListener::bind(CAPACITY_PORT_START).await;
    write_frame(stream, CAPACITY_REBOUND).await;
    expect_frame(stream, CAPACITY_REUSED).await;
    rebound.close().await;
    write_frame(stream, CASE_DONE).await;
}

async fn run_native_accept(
    client: &moto_io::net::NetClient,
    control: &VsockStream,
) -> Vec<Arc<CountWake>> {
    let listener = VsockListener::bind_reserved(client.try_reserve().unwrap(), NATIVE_ACCEPT_PORT)
        .await
        .unwrap();
    assert_eq!(
        listener.socket_addr_async().await,
        Ok(VsockAddr {
            cid: 3,
            port: NATIVE_ACCEPT_PORT,
        })
    );

    // The listener belongs to the control channel; accepted streams are
    // deliberately donated by a separately driven channel in this process.
    let (accept_client, accept_driver) = crate::net_harness::host_channel_on_thread();
    let keeper = accept_client.try_reserve().unwrap();
    let unpolled = listener.accept_reserved(accept_client.try_reserve().unwrap());
    drop(unpolled);
    assert_eq!(accept_client.reservations(), 1);

    write_frame(control, NATIVE_ACCEPT_READY).await;
    // The host confirms its bytes were sent before this accept exists. They
    // must arrive only after the response installs the native stream route.
    expect_frame(control, NATIVE_ACCEPT_EARLY_READY).await;
    let accepted = listener
        .accept_reserved(accept_client.try_reserve().unwrap())
        .await
        .unwrap();
    assert_eq!(
        accepted.socket_addr(),
        Some(VsockAddr {
            cid: 3,
            port: NATIVE_ACCEPT_PORT,
        })
    );
    assert_eq!(accepted.peer_addr().unwrap().cid, 2);
    let mut early = [0_u8; NATIVE_ACCEPT_EARLY.len()];
    read_exact(&accepted, &mut early).await;
    assert_eq!(early, NATIVE_ACCEPT_EARLY);
    write_all(&accepted, NATIVE_ACCEPT_REPLY).await;
    drop(accepted);
    expect_frame(control, NATIVE_ACCEPT_DROPPED).await;
    // A later RPC on this channel follows its queued teardown record. Host
    // EOF alone does not prove the native driver released that record yet.
    moto_io::net::vsock::availability(&accept_client)
        .await
        .unwrap();
    assert_eq!(accept_client.reservations(), 1);

    // The host completes a full close before acknowledging this barrier and
    // before the accept future exists. Buffered bytes must remain drainable,
    // followed by the same terminal result as an ordinary Unix peer close.
    write_frame(control, NATIVE_ACCEPT_CLOSE_READY).await;
    expect_frame(control, NATIVE_ACCEPT_CLOSED_READY).await;
    let closed = listener
        .accept_reserved(accept_client.try_reserve().unwrap())
        .await
        .unwrap();
    let mut bytes = [0_u8; NATIVE_ACCEPT_CLOSED.len()];
    read_exact(&closed, &mut bytes).await;
    assert_eq!(bytes, NATIVE_ACCEPT_CLOSED);
    read_eof(&closed).await;
    assert_eq!(
        closed.try_write(&[b"after peer close"]),
        Err(moto_rt::E_NOT_CONNECTED)
    );
    drop(closed);
    moto_io::net::vsock::availability(&accept_client)
        .await
        .unwrap();
    assert_eq!(accept_client.reservations(), 1);

    // Polling once registers and queues an empty-listener accept. Dropping
    // the future releases its slot; the live keeper lets the weak waiter
    // close the later successful response on this same channel.
    let canceled = listener.accept_reserved(accept_client.try_reserve().unwrap());
    let counter = poll_pending(canceled);
    assert_eq!(accept_client.reservations(), 1);
    write_frame(control, NATIVE_ACCEPT_CANCEL_READY).await;
    expect_frame(control, NATIVE_ACCEPT_CANCEL_CLOSED).await;

    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("vsock-exit-accept-child")
        .arg(NATIVE_ACCEPT_EXIT_PORT.to_string())
        .arg(control.peer_addr().unwrap().port.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child_stdin = child.stdin.take().unwrap();
    let mut child_stdout = BufReader::new(child.stdout.take().unwrap());
    expect_child_marker(&mut child_stdout, "queued");
    write_frame(control, NATIVE_ACCEPT_EXIT_READY).await;
    expect_frame(control, NATIVE_ACCEPT_ANCHOR_HELD).await;
    expect_child_marker(&mut child_stdout, "accepted");
    expect_child_marker(&mut child_stdout, "armed");
    write_frame(control, NATIVE_ACCEPT_CONNECT_READY).await;
    expect_frame(control, NATIVE_ACCEPT_BOTH_HELD).await;
    child_stdin.write_all(b"exit\n").unwrap();
    child_stdin.flush().unwrap();
    drop(child_stdin);
    assert_eq!(child.wait().unwrap().code(), Some(0));
    write_frame(control, NATIVE_ACCEPT_EXITED).await;

    // Host EOF proves sys-io has processed child-channel teardown. Only that
    // causal token permits the different process to reclaim the same port.
    expect_frame(control, NATIVE_ACCEPT_EXIT_CLEANED).await;
    let rebound = crate::net_driver::RawVsockListener::bind(NATIVE_ACCEPT_EXIT_PORT).await;
    rebound.close().await;
    write_frame(control, NATIVE_ACCEPT_EXIT_REBOUND).await;

    drop(listener);
    drop(keeper);
    accept_driver.join().unwrap();
    assert_eq!(accept_client.reservations(), 0);
    write_frame(control, CASE_DONE).await;
    vec![counter]
}

async fn test_native_listener_bind_drop(client: &moto_io::net::NetClient) {
    const BIND_PORT: u32 = 80_001;
    const CANCEL_PORT: u32 = 80_002;
    const FAILED_PORT: u32 = 80_003;

    let baseline = client.reservations();

    crate::net_driver::test_raw_vsock_pending_accepts().await;

    let unpolled = VsockListener::bind_reserved(client.try_reserve().unwrap(), CANCEL_PORT);
    drop(unpolled);
    assert_eq!(client.reservations(), baseline);
    assert_eq!(
        VsockListener::bind_reserved(client.try_reserve().unwrap(), u32::MAX)
            .await
            .err(),
        Some(moto_rt::E_INVALID_ARGUMENT)
    );
    assert_eq!(client.reservations(), baseline);

    let listener = VsockListener::bind_reserved(client.try_reserve().unwrap(), BIND_PORT)
        .await
        .unwrap();
    assert_eq!(client.reservations(), baseline + 1);
    assert_eq!(
        listener.socket_addr_async().await,
        Ok(VsockAddr {
            cid: 3,
            port: BIND_PORT,
        })
    );
    drop(listener);
    crate::net_harness::wait_until("native vsock listener reservation release", || {
        client.reservations() == baseline
    })
    .await;

    // One poll queues the bind and transfers its reservation into PendingBind.
    // Cancellation keeps rollback armed; eventual response dispatch owns the
    // listener drop and reservation release.
    let mut bind = Box::pin(VsockListener::bind_reserved(
        client.try_reserve().unwrap(),
        CANCEL_PORT,
    ));
    let waker = futures::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    assert!(matches!(bind.as_mut().poll(&mut context), Poll::Pending));
    assert_eq!(client.reservations(), baseline + 1);
    drop(bind);
    crate::net_harness::wait_until("cancelled vsock listener reservation release", || {
        client.reservations() == baseline
    })
    .await;

    let (failed_client, failed_driver) = crate::net_harness::host_channel_on_thread();
    let listener = VsockListener::bind_reserved(failed_client.try_reserve().unwrap(), FAILED_PORT)
        .await
        .unwrap();
    failed_client.fail_for_test();
    assert_eq!(
        listener.socket_addr_async().await,
        Err(moto_rt::E_NOT_CONNECTED)
    );
    drop(listener);
    assert_eq!(failed_client.reservations(), 0);
    failed_driver.join().unwrap();
    drop(failed_client);
}

async fn run_action(
    client: &moto_io::net::NetClient,
    peer: VsockAddr,
    stream: &VsockStream,
    sync: Option<&VsockStream>,
    action: Action,
) -> Vec<Arc<CountWake>> {
    match action {
        Action::Echo(total) => {
            if total == 0 {
                assert_eq!(stream.try_write(&[&[]]), Ok(0));
                let mut empty = [];
                assert_eq!(stream.try_read(&mut [&mut empty]), Ok(0));
            }
            if total == 1 {
                let started = Instant::now();
                for _ in 0..SMALL_ECHO_ROUNDTRIPS {
                    // Keep the existing framed one-byte request and exact
                    // pattern validation; only repeat it on this same stream.
                    write_pattern(stream, total).await;
                    read_pattern(stream, total).await;
                }
                let aggregate_ns = started.elapsed().as_nanos();
                println!(
                    "vsock measurement: framed_echo_bytes=1 roundtrips={} \
                     aggregate_rtt_ns={aggregate_ns} mean_rtt_ns={}",
                    SMALL_ECHO_ROUNDTRIPS,
                    aggregate_ns / SMALL_ECHO_ROUNDTRIPS as u128,
                );
            } else {
                write_pattern(stream, total).await;
                read_pattern(stream, total).await;
            }
            read_eof(stream).await;
            Vec::new()
        }
        Action::Duplex { send, echo } => {
            let started = Instant::now();
            let writer = async {
                write_pattern(stream, echo).await;
            };
            let reader = async {
                read_pattern(stream, send).await;
                read_pattern(stream, echo).await;
            };
            futures::join!(writer, reader);
            let elapsed = started.elapsed();
            read_eof(stream).await;
            print_throughput("duplex", send + echo * 2, elapsed);
            Vec::new()
        }
        Action::LocalSendShutdown { send, receive } => {
            let sync = sync.unwrap();
            write_pattern(stream, send).await;
            stream.shutdown_async(Shutdown::Write).await.unwrap();
            assert_eq!(
                stream.try_write(&[b"after shutdown"]),
                Err(moto_rt::E_NOT_CONNECTED)
            );
            write_frame(sync, SEND_SHUTDOWN_DONE).await;
            read_pattern(stream, receive).await;
            expect_frame(sync, TRANSFER_DONE).await;
            write_frame(sync, CASE_DONE).await;
            Vec::new()
        }
        Action::LocalReceiveShutdown { receive, send } => {
            let sync = sync.unwrap();
            read_pattern(stream, receive).await;
            stream.shutdown_async(Shutdown::Read).await.unwrap();
            assert_read_eof(stream);
            write_frame(sync, RECEIVE_SHUTDOWN_DONE).await;
            expect_frame(sync, CONTINUE).await;
            assert_read_eof(stream);
            write_pattern(stream, send).await;
            stream.shutdown_async(Shutdown::Write).await.unwrap();
            assert_eq!(
                stream.try_write(&[b"after shutdown"]),
                Err(moto_rt::E_NOT_CONNECTED)
            );
            write_frame(sync, CASE_DONE).await;
            expect_frame(sync, TRANSFER_DONE).await;
            Vec::new()
        }
        Action::UnixPeerClose { receive } => {
            let sync = sync.unwrap();
            read_pattern(stream, receive).await;
            read_eof(stream).await;
            assert_eq!(
                stream.try_write(&[b"after peer close"]),
                Err(moto_rt::E_NOT_CONNECTED)
            );
            write_frame(sync, CASE_DONE).await;
            Vec::new()
        }
        Action::CancelRead { receive } => {
            let sync = sync.unwrap();
            let mut counters = Vec::new();
            for _ in 0..CANCEL_POLLS {
                counters.push(poll_pending(stream.readable()));
                let mut byte = [0_u8; 1];
                let mut bufs = [&mut byte[..]];
                counters.push(poll_pending(stream.read_future(&mut bufs)));
            }
            write_frame(sync, CANCEL_READY).await;
            read_pattern(stream, receive).await;
            // The selected UDS proxy maps host SHUT_WR to full stream close;
            // this challenges stale read waiters, not SEND-only semantics.
            read_eof(stream).await;
            expect_frame(sync, TRANSFER_DONE).await;
            write_frame(sync, CASE_DONE).await;
            counters
        }
        Action::CancelWrite { tail } => {
            let sync = sync.unwrap();
            // The host consumed both role frames. Its acknowledgement also
            // lets the driver return the data stream's framing page before
            // the exact per-subchannel capacity assertion below.
            expect_frame(sync, ROLES_READY).await;
            let accepted = fill_tx_without_yield(stream);
            let probe = [0x5a_u8; PAGE_SIZE];
            let mut counters = Vec::new();
            for _ in 0..CANCEL_POLLS {
                counters.push(poll_pending(stream.writable()));
                let bufs = [&probe[..]];
                counters.push(poll_pending(stream.write_future(&bufs)));
            }
            write_frame(sync, CANCEL_READY).await;
            write_raw_pattern(stream, accepted, tail).await;
            stream.shutdown_async(Shutdown::Write).await.unwrap();
            write_frame(sync, SEND_SHUTDOWN_DONE).await;
            expect_frame(sync, TRANSFER_DONE).await;
            write_frame(sync, CASE_DONE).await;
            counters
        }
        Action::CancelBeforePollDrop => {
            let accepted = fill_tx_without_yield(stream);
            assert_eq!(accepted, PAGES_PER_SUBCHANNEL * PAGE_SIZE);

            // Dropping an unpolled async function is deterministically before
            // RPC registration/publication and releases its reservation.
            let connect = VsockStream::connect_reserved(client.try_reserve().unwrap(), peer);
            drop(connect);
            assert_eq!(client.reservations(), 1);
            Vec::new()
        }
        Action::CancelQueuedConnect => {
            let sync = sync.unwrap();

            // The in-flight query, not the idle client, owns the second
            // channel after its final connect reservation is released.
            let (final_client, final_driver) = moto_io::net::connect()
                .await
                .expect("final-slot channel connect failed");
            let final_connect =
                VsockStream::connect_reserved(final_client.try_reserve().unwrap(), peer);
            let final_query_wake = Arc::new(CountWake(AtomicUsize::new(0)));
            let mut final_query = Box::pin(moto_io::net::vsock::availability(&final_client));
            {
                let waker = Waker::from(final_query_wake.clone());
                let mut context = Context::from_waker(&waker);
                assert!(matches!(
                    final_query.as_mut().poll(&mut context),
                    Poll::Pending
                ));
            }
            let final_counter = poll_pending(final_connect);
            assert_eq!(final_client.reservations(), 0);
            let final_driver_thread = std::thread::spawn(move || {
                moto_async::LocalRuntime::new().block_on(final_driver.run());
            });

            let connect = VsockStream::connect_reserved(client.try_reserve().unwrap(), peer);
            let counter = poll_pending(connect);

            // Both connects are admitted while the retained query keeps the
            // final-slot IPC mapping alive after its driver exits.
            expect_frame(sync, FINAL_SLOT_ADMITTED).await;
            assert_eq!(client.reservations(), 2);
            final_driver_thread.join().unwrap();
            assert!(final_query_wake.0.load(Ordering::Acquire) > 0);
            let waker = Waker::noop();
            let mut context = Context::from_waker(waker);
            assert_eq!(
                final_query.as_mut().poll(&mut context),
                Poll::Ready(Err(moto_rt::Error::NotConnected))
            );
            drop(final_query);
            assert_eq!(final_client.reservations(), 0);
            assert_eq!(
                moto_io::net::vsock::availability(&final_client).await,
                Err(moto_rt::Error::NotConnected)
            );
            assert_eq!(
                final_client.try_reserve().err(),
                Some(moto_io::net::ReserveError::ShuttingDown)
            );
            expect_frame(sync, TRANSFER_DONE).await;
            write_frame(sync, CASE_DONE).await;
            vec![final_counter, counter]
        }
        Action::StalledReader { total } => {
            let sync = sync.unwrap();
            expect_frame(sync, STALLED_DATA_READY).await;

            // Establish that data is held for this stream, but leave every
            // byte unread while an independent stream makes round-trip progress.
            stream.readable().await;
            write_frame(sync, UNRELATED_PING).await;
            expect_frame(sync, UNRELATED_PONG).await;

            write_frame(sync, DRAIN_STARTED).await;
            read_pattern(stream, total).await;
            expect_frame(sync, TRANSFER_DONE).await;
            write_frame(sync, CASE_DONE).await;
            Vec::new()
        }
        Action::Coexistence => {
            let sync = sync.unwrap();
            let path = crate::temp_path("systest-vsock-coexistence");
            let (tcp_port, udp_port) = coexistence_ports(sync).await;
            let (ready_tx, ready_rx) = moto_async::oneshot();
            let (progress_tx, progress_rx) = moto_async::oneshot();
            let (done_tx, done_rx) = moto_async::oneshot();
            let (start_tx, start_rx) = std::sync::mpsc::channel();
            let (resume_tx, resume_rx) = std::sync::mpsc::channel();
            let io_thread = std::thread::spawn(move || {
                coexistence_io(
                    path,
                    (tcp_port, udp_port),
                    ready_tx,
                    start_rx,
                    progress_tx,
                    resume_rx,
                    done_tx,
                )
            });

            expect_frame(sync, COEXIST_READY).await;
            ready_rx.await.unwrap();
            let started = Instant::now();
            start_tx.send(()).unwrap();
            write_frame(sync, COEXIST_START).await;
            let ((), io_progress) = futures::join!(
                coexistence_vsock_phase(stream, sync, COEXIST_PROGRESS),
                progress_rx
            );
            io_progress.unwrap();

            resume_tx.send(()).unwrap();
            write_frame(sync, COEXIST_CONTINUE).await;
            let ((), io_done) = futures::join!(
                coexistence_vsock_phase(stream, sync, TRANSFER_DONE),
                done_rx
            );
            io_done.unwrap();
            io_thread.join().unwrap();
            let elapsed = started.elapsed();
            print_throughput("coexistence", COEXIST_PHASE_BYTES * 2 * 2, elapsed);
            Vec::new()
        }
        Action::IncomingBacklog => {
            run_incoming_backlog(stream, false).await;
            Vec::new()
        }
        Action::IncomingOwnerDrop => {
            run_incoming_backlog(stream, true).await;
            Vec::new()
        }
        Action::NativeAccept => run_native_accept(client, stream).await,
        Action::GlobalStreamCapacity => {
            run_global_stream_capacity(stream).await;
            Vec::new()
        }
    }
}

pub fn run(args: &[String]) {
    assert!(
        args.len() >= 4,
        "expected CID PORT ABSENT_PEER_BEHAVIOR ACTION..."
    );
    let peer = VsockAddr {
        cid: args[0].parse().expect("invalid peer CID"),
        port: args[1].parse().expect("invalid peer port"),
    };
    let absent_peer = AbsentPeerBehavior::parse(&args[2]);
    let action = parse_action(&args[3..]);
    let test_listener_bind = matches!(&action, Action::Echo(0));
    let verdict = args[3..].join(" ");

    let completed = moto_async::LocalRuntime::new().block_on(async {
        let (client, driver_task) = host_channel().await;
        assert_eq!(moto_io::net::vsock::availability(&client).await, Ok(()));
        let stream = connect(&client, peer).await;
        let sync = if action.needs_sync() {
            // The selected UDS backends do not expose directional EOF. This
            // independent stream carries causal barriers after shutdown RPCs.
            let sync = connect(&client, peer).await;
            assert_ne!(stream.socket_addr(), sync.socket_addr());
            write_frame(&stream, ROLE_DATA).await;
            write_frame(&sync, ROLE_SYNC).await;
            Some(sync)
        } else {
            None
        };
        let counters = run_action(&client, peer, &stream, sync.as_deref(), action).await;
        if test_listener_bind {
            test_connect_errors(&client, peer, absent_peer).await;
            crate::net_driver::test_raw_vsock_listener_bind().await;
            test_native_listener_bind_drop(&client).await;
        }
        drop(sync);
        drop(stream);
        let completed = bounded(driver_task, 5).await && client.reservations() == 0;
        assert_not_woken(&counters);
        completed
    });
    assert!(
        completed,
        "vsock NetDriver did not drain after the stream dropped"
    );
    println!("vsock outgoing: {verdict} PASS");
}
