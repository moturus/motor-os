use core::future::Future;
use core::task::{Context, Poll};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Wake, Waker};

use moto_io::net::vsock::{Shutdown, VsockAddr, VsockStream};
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
const CANCEL_READY: &[u8] = b"cancel:ready";
const ROLES_READY: &[u8] = b"roles:ready";
const STALLED_DATA_READY: &[u8] = b"stalled:data-ready";
const UNRELATED_PING: &[u8] = b"unrelated:ping";
const UNRELATED_PONG: &[u8] = b"unrelated:pong";
const DRAIN_STARTED: &[u8] = b"drain:started";
const CANCEL_POLLS: usize = 4;
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
        _ => panic!(
            "expected echo N, duplex SEND_N ECHO_N, \
             local-send-shutdown SEND_N RECEIVE_N, \
             local-receive-shutdown RECEIVE_N SEND_N, unix-peer-close RECEIVE_N, \
             cancel-read RECEIVE_N, cancel-write TAIL_N, cancel-before-poll-drop, \
             cancel-queued-connect, or stalled-reader TOTAL"
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

fn pattern(start: usize, len: usize) -> Vec<u8> {
    (start..start + len).map(pattern_byte).collect()
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
            write_pattern(stream, total).await;
            read_pattern(stream, total).await;
            read_eof(stream).await;
            Vec::new()
        }
        Action::Duplex { send, echo } => {
            let writer = async {
                write_pattern(stream, echo).await;
            };
            let reader = async {
                read_pattern(stream, send).await;
                read_pattern(stream, echo).await;
                read_eof(stream).await;
            };
            futures::join!(writer, reader);
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
            let connect = VsockStream::connect_reserved(client.try_reserve().unwrap(), peer);
            let counter = poll_pending(connect);

            // The first poll queued the request locally but cannot run the
            // same-runtime driver. The host proves later success was closed.
            expect_frame(sync, TRANSFER_DONE).await;
            assert_eq!(client.reservations(), 2);
            write_frame(sync, CASE_DONE).await;
            vec![counter]
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
    }
}

pub fn run(args: &[String]) {
    assert!(args.len() >= 3, "expected CID PORT ACTION...");
    let peer = VsockAddr {
        cid: args[0].parse().expect("invalid peer CID"),
        port: args[1].parse().expect("invalid peer port"),
    };
    let action = parse_action(&args[2..]);
    let verdict = args[2..].join(" ");

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
