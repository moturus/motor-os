use std::sync::Arc;

use moto_io::net::vsock::{Shutdown, VsockAddr, VsockStream};

use crate::net_harness::{bounded, host_channel};

const MAX_FRAME: usize = 64 * 1024;
const ROLE_DATA: &[u8] = b"role:data";
const ROLE_SYNC: &[u8] = b"role:sync";
const SEND_SHUTDOWN_DONE: &[u8] = b"shutdown:send";
const RECEIVE_SHUTDOWN_DONE: &[u8] = b"shutdown:receive";
const CONTINUE: &[u8] = b"continue";
const TRANSFER_DONE: &[u8] = b"transfer:done";
const CASE_DONE: &[u8] = b"case:done";

enum Action {
    Echo(usize),
    Duplex { send: usize, echo: usize },
    LocalSendShutdown { send: usize, receive: usize },
    LocalReceiveShutdown { receive: usize, send: usize },
    UnixPeerClose { receive: usize },
}

impl Action {
    fn needs_sync(&self) -> bool {
        !matches!(self, Self::Echo(_) | Self::Duplex { .. })
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
        _ => panic!(
            "expected echo N, duplex SEND_N ECHO_N, \
             local-send-shutdown SEND_N RECEIVE_N, \
             local-receive-shutdown RECEIVE_N SEND_N, or unix-peer-close RECEIVE_N"
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

async fn run_action(stream: &VsockStream, sync: Option<&VsockStream>, action: Action) {
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
        run_action(&stream, sync.as_deref(), action).await;
        drop(sync);
        drop(stream);
        bounded(driver_task, 5).await && client.reservations() == 0
    });
    assert!(
        completed,
        "vsock NetDriver did not drain after the stream dropped"
    );
    println!("vsock outgoing: {verdict} PASS");
}
