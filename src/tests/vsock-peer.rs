use std::{
    env, fs,
    io::{self, ErrorKind, Read, Write},
    net::{Shutdown, TcpListener, UdpSocket},
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    process::ExitCode,
    thread,
    time::{Duration, Instant},
};

const PORT: u32 = 70_000;
const MAX_FRAME: usize = 64 * 1024;
const MAX_TRANSFER: usize = 16 * 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const ACCEPT_POLL: Duration = Duration::from_millis(10);
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
const RAW_SUBCHANNEL_BYTES: usize = 64 * 1024;
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
const NATIVE_ACCEPT_SIMULTANEOUS_READY: &[u8] = b"native-accept:simultaneous-ready";
const NATIVE_ACCEPT_SIMULTANEOUS_CONNECTED: &[u8] = b"native-accept:simultaneous-connected";
const NATIVE_ACCEPT_SIMULTANEOUS_STARTED: &[u8] = b"native-accept:simultaneous-started";
const NATIVE_ACCEPT_SIMULTANEOUS_CLOSED: &[u8] = b"native-accept:simultaneous-closed";
const NATIVE_ACCEPT_REUSE_CONNECTED: &[u8] = b"native-accept:reuse-connected";
const NATIVE_ACCEPT_REUSED: &[u8] = b"native-accept:reused";
const NATIVE_ACCEPT_REUSE_PAYLOAD: &[u8] = b"reuse";
const NATIVE_ACCEPT_REUSE_REPLY: &[u8] = b"reused";
const NATIVE_ACCEPT_CANCEL_READY: &[u8] = b"native-accept:cancel-ready";
const NATIVE_ACCEPT_CANCEL_CLOSED: &[u8] = b"native-accept:cancel-closed";
const NATIVE_ACCEPT_EXIT_READY: &[u8] = b"native-accept:exit-ready";
const NATIVE_ACCEPT_ANCHOR_HELD: &[u8] = b"native-accept:anchor-held";
const NATIVE_ACCEPT_CONNECT_READY: &[u8] = b"native-accept:connect-ready";
const NATIVE_ACCEPT_BOTH_HELD: &[u8] = b"native-accept:both-held";
const NATIVE_ACCEPT_EXITED: &[u8] = b"native-accept:exited";
const NATIVE_ACCEPT_EXIT_CLEANED: &[u8] = b"native-accept:exit-cleaned";
const NATIVE_ACCEPT_EXIT_REBOUND: &[u8] = b"native-accept:exit-rebound";
const ACCEPT_DISCONNECT_READY: &[u8] = b"accept-disconnect:ready";
const ACCEPT_DISCONNECT_HELD: &[u8] = b"accept-disconnect:held";
const ACCEPT_DISCONNECT_CLOSED: &[u8] = b"accept-disconnect:closed";
const ACCEPT_DISCONNECT_PORT: u32 = 70_004;
const ACCEPT_DISCONNECT_ROUNDS: usize = 16;
const COEXIST_READY: &[u8] = b"coexist:ready";
const COEXIST_START: &[u8] = b"coexist:start";
const COEXIST_PROGRESS: &[u8] = b"coexist:progress";
const COEXIST_CONTINUE: &[u8] = b"coexist:continue";
const COEXIST_PHASE_BYTES: usize = 256 * 1024;
const TAP_HOST: &str = "192.168.4.1";
const INCOMING_PORT: u32 = 70_001;
const NATIVE_ACCEPT_PORT: u32 = 70_002;
const NATIVE_ACCEPT_EXIT_PORT: u32 = 70_003;
const LISTENER_BACKLOG: usize = 8;
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
const SMALL_ECHO_ROUNDTRIPS: usize = 128;

struct SocketPath(PathBuf);

enum Action {
    Echo(usize),
    Send(usize),
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

impl Action {
    fn description(&self) -> String {
        match self {
            Self::Echo(total) => format!("echo {total}"),
            Self::Send(total) => format!("send {total}"),
            Self::Duplex { send, echo } => format!("duplex {send} {echo}"),
            Self::LocalSendShutdown { send, receive } => {
                format!("local-send-shutdown {send} {receive}")
            }
            Self::LocalReceiveShutdown { receive, send } => {
                format!("local-receive-shutdown {receive} {send}")
            }
            Self::UnixPeerClose { receive } => format!("unix-peer-close {receive}"),
            Self::CancelRead { receive } => format!("cancel-read {receive}"),
            Self::CancelWrite { tail } => format!("cancel-write {tail}"),
            Self::CancelBeforePollDrop => "cancel-before-poll-drop".into(),
            Self::CancelQueuedConnect => "cancel-queued-connect".into(),
            Self::StalledReader { total } => format!("stalled-reader {total}"),
            Self::Coexistence => "coexistence".into(),
            Self::IncomingBacklog => "incoming-backlog".into(),
            Self::IncomingOwnerDrop => "incoming-owner-drop".into(),
            Self::NativeAccept => "native-accept".into(),
            Self::GlobalStreamCapacity => "global-stream-capacity".into(),
        }
    }

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

impl Drop for SocketPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message.into())
}

fn parse_size(value: &str) -> io::Result<usize> {
    let size = value
        .parse::<usize>()
        .map_err(|_| invalid(format!("invalid byte count '{value}'")))?;
    if size > MAX_TRANSFER {
        return Err(invalid(format!("byte count {size} exceeds {MAX_TRANSFER}")));
    }
    Ok(size)
}

fn parse_pair(first: &str, second: &str) -> io::Result<(usize, usize)> {
    let first = parse_size(first)?;
    let second = parse_size(second)?;
    if first
        .checked_add(second)
        .is_none_or(|sum| sum > MAX_TRANSFER)
    {
        return Err(invalid(format!(
            "combined byte count exceeds {MAX_TRANSFER}"
        )));
    }
    Ok((first, second))
}

fn parse_action(name: &str, args: &[String]) -> io::Result<Action> {
    match (name, args) {
        ("echo", [total]) => Ok(Action::Echo(parse_size(total)?)),
        ("send", [total]) => Ok(Action::Send(parse_size(total)?)),
        ("duplex", [send, echo]) => {
            let (send, echo) = parse_pair(send, echo)?;
            Ok(Action::Duplex { send, echo })
        }
        ("local-send-shutdown", [send, receive]) => {
            let (send, receive) = parse_pair(send, receive)?;
            Ok(Action::LocalSendShutdown { send, receive })
        }
        ("local-receive-shutdown", [receive, send]) => {
            let (receive, send) = parse_pair(receive, send)?;
            Ok(Action::LocalReceiveShutdown { receive, send })
        }
        ("unix-peer-close", [receive]) => Ok(Action::UnixPeerClose {
            receive: parse_size(receive)?,
        }),
        ("cancel-read", [receive]) => Ok(Action::CancelRead {
            receive: parse_size(receive)?,
        }),
        ("cancel-write", [tail]) => Ok(Action::CancelWrite {
            tail: parse_size(tail)?,
        }),
        ("cancel-before-poll-drop", []) => Ok(Action::CancelBeforePollDrop),
        ("cancel-queued-connect", []) => Ok(Action::CancelQueuedConnect),
        ("stalled-reader", [total]) => Ok(Action::StalledReader {
            total: parse_size(total)?,
        }),
        ("coexistence", []) => Ok(Action::Coexistence),
        ("incoming-backlog", []) => Ok(Action::IncomingBacklog),
        ("incoming-owner-drop", []) => Ok(Action::IncomingOwnerDrop),
        ("native-accept", []) => Ok(Action::NativeAccept),
        ("global-stream-capacity", []) => Ok(Action::GlobalStreamCapacity),
        _ => Err(invalid(
            "actions: echo N | send N | duplex SEND_N ECHO_N | \
             local-send-shutdown SEND_N RECEIVE_N | \
             local-receive-shutdown RECEIVE_N SEND_N | unix-peer-close RECEIVE_N | \
             cancel-read RECEIVE_N | cancel-write TAIL_N | cancel-before-poll-drop | \
             cancel-queued-connect | stalled-reader TOTAL | coexistence | incoming-backlog | \
             incoming-owner-drop | native-accept | global-stream-capacity",
        )),
    }
}

fn read_frame(stream: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0_u8; 4];
    let first = stream.read(&mut header[..1])?;
    if first == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut header[1..])?;
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME {
        return Err(invalid(format!("frame length {len} exceeds {MAX_FRAME}")));
    }
    let mut payload = vec![0_u8; len];
    stream.read_exact(&mut payload)?;
    Ok(Some(payload))
}

fn write_frame(stream: &mut UnixStream, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len()).map_err(|_| invalid("frame length overflow"))?;
    if payload.len() > MAX_FRAME {
        return Err(invalid(format!(
            "frame length {} exceeds {MAX_FRAME}",
            payload.len()
        )));
    }
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(payload)
}

fn pattern_byte(offset: usize) -> u8 {
    (offset.wrapping_mul(37).wrapping_add(11) & 0xff) as u8
}

fn send_pattern(stream: &mut UnixStream, total: usize) -> io::Result<()> {
    if total == 0 {
        return write_frame(stream, &[]);
    }
    send_pattern_from(stream, 0, total)
}

fn send_pattern_from(stream: &mut UnixStream, start: usize, total: usize) -> io::Result<()> {
    let end = start
        .checked_add(total)
        .ok_or_else(|| invalid("pattern range overflow"))?;
    let mut offset = start;
    while offset < end {
        let len = (end - offset).min(MAX_FRAME);
        let payload: Vec<_> = (offset..offset + len).map(pattern_byte).collect();
        write_frame(stream, &payload)?;
        offset += len;
    }
    Ok(())
}

fn echo_exact(stream: &mut UnixStream, total: usize) -> io::Result<()> {
    if total == 0 {
        let payload = read_frame(stream)?.ok_or_else(|| invalid("EOF before zero frame"))?;
        if !payload.is_empty() {
            return Err(invalid("nonempty frame for zero-byte echo"));
        }
        return write_frame(stream, &payload);
    }

    let mut received = 0;
    while received < total {
        let payload = read_frame(stream)?.ok_or_else(|| invalid("EOF before echo completed"))?;
        if payload.is_empty() || payload.len() > total - received {
            return Err(invalid("echo frames do not match the requested byte count"));
        }
        received += payload.len();
        write_frame(stream, &payload)?;
    }
    Ok(())
}

fn receive_pattern(stream: &mut UnixStream, total: usize) -> io::Result<()> {
    if total == 0 {
        let payload = read_frame(stream)?.ok_or_else(|| invalid("EOF before zero frame"))?;
        return if payload.is_empty() {
            Ok(())
        } else {
            Err(invalid("nonempty frame for zero-byte receive"))
        };
    }

    let mut received = 0;
    while received < total {
        let payload = read_frame(stream)?.ok_or_else(|| invalid("EOF before receive completed"))?;
        if payload.is_empty() || payload.len() > total - received {
            return Err(invalid(
                "receive frames do not match the requested byte count",
            ));
        }
        for (index, byte) in payload.iter().enumerate() {
            if *byte != pattern_byte(received + index) {
                return Err(invalid(format!(
                    "received corrupt byte at offset {}",
                    received + index
                )));
            }
        }
        received += payload.len();
    }
    Ok(())
}

fn receive_raw_pattern(stream: &mut UnixStream, total: usize) -> io::Result<()> {
    let mut received = 0;
    let mut buf = [0_u8; 16 * 1024];
    while received < total {
        let capacity = (total - received).min(buf.len());
        let len = stream.read(&mut buf[..capacity])?;
        if len == 0 {
            return Err(invalid("EOF before raw pattern completed"));
        }
        for (index, byte) in buf[..len].iter().enumerate() {
            if *byte != pattern_byte(received + index) {
                return Err(invalid(format!(
                    "raw pattern corrupt at offset {}",
                    received + index
                )));
            }
        }
        received += len;
    }
    Ok(())
}

fn expect_frame(stream: &mut UnixStream, expected: &[u8]) -> io::Result<()> {
    let actual = read_frame(stream)?.ok_or_else(|| invalid("EOF before control frame"))?;
    if actual == expected {
        Ok(())
    } else {
        Err(invalid(format!("unexpected control frame: {actual:?}")))
    }
}

fn accept_before(listener: &UnixListener, deadline: Instant) -> io::Result<UnixStream> {
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error) if error.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(ACCEPT_POLL);
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                return Err(io::Error::new(
                    ErrorKind::TimedOut,
                    "accept deadline expired",
                ));
            }
            Err(error) => return Err(error),
        }
    }
}

fn configure_stream(stream: UnixStream) -> io::Result<UnixStream> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(stream)
}

fn connect_guest(base: &str, port: u32) -> io::Result<UnixStream> {
    let mut stream = configure_stream(UnixStream::connect(base)?)?;
    stream.write_all(format!("CONNECT {port}\n").as_bytes())?;
    let mut ack = [0_u8; 32];
    let mut len = 0;
    loop {
        if len == ack.len() {
            return Err(invalid("vsock CSM acknowledgement is too long"));
        }
        stream.read_exact(&mut ack[len..len + 1])?;
        len += 1;
        if ack[len - 1] == b'\n' {
            break;
        }
    }
    let ack = std::str::from_utf8(&ack[..len])
        .map_err(|_| invalid("vsock CSM acknowledgement is not UTF-8"))?;
    let port = ack
        .strip_prefix("OK ")
        .and_then(|ack| ack.strip_suffix('\n'))
        .filter(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| invalid(format!("invalid vsock CSM acknowledgement: {ack:?}")))?;
    port.parse::<u32>()
        .map_err(|_| invalid(format!("invalid vsock CSM port: {port:?}")))?;
    Ok(stream)
}

fn expect_eof(stream: &mut UnixStream) -> io::Result<()> {
    let mut byte = [0_u8; 1];
    match stream.read(&mut byte)? {
        0 => Ok(()),
        _ => Err(invalid("guest-initiated reset carried unexpected data")),
    }
}

fn expect_prefix_then_eof(stream: &mut UnixStream, expected: &[u8]) -> io::Result<()> {
    let mut received = 0;
    let mut buf = [0_u8; 16];
    loop {
        let len = stream.read(&mut buf)?;
        if len == 0 {
            return Ok(());
        }
        let end = received + len;
        if end > expected.len() || buf[..len] != expected[received..end] {
            return Err(invalid("process-exit TX was not an exact prefix"));
        }
        received = end;
    }
}

fn expect_guest_refusal(base: &str, port: u32) -> io::Result<()> {
    let mut stream = configure_stream(UnixStream::connect(base)?)?;
    stream.write_all(format!("CONNECT {port}\n").as_bytes())?;
    let mut byte = [0_u8; 1];
    match stream.read(&mut byte) {
        Ok(0) => Ok(()),
        Ok(_) => Err(invalid(
            "refused backlog connection received a CSM acknowledgement",
        )),
        Err(error) => Err(error),
    }
}

fn run_global_capacity_cycle(base: &str, control: &mut UnixStream) -> io::Result<()> {
    expect_frame(control, CAPACITY_READY)?;
    let mut connections = Vec::with_capacity(GLOBAL_STREAM_LIMIT - 1);
    for listener in 0..CAPACITY_LISTENERS {
        let count = if listener + 1 == CAPACITY_LISTENERS {
            LISTENER_BACKLOG - 1
        } else {
            LISTENER_BACKLOG
        };
        let port = CAPACITY_PORT_START + listener as u32;
        for _ in 0..count {
            connections.push(connect_guest(base, port)?);
        }
    }
    assert_eq!(connections.len(), GLOBAL_STREAM_LIMIT - 1);
    expect_guest_refusal(base, CAPACITY_PORT_START + CAPACITY_LISTENERS as u32 - 1)?;

    write_frame(control, CAPACITY_FULL)?;
    expect_frame(control, CAPACITY_PROGRESS)?;
    expect_frame(control, CAPACITY_DROPPED)?;
    for connection in &mut connections {
        expect_eof(connection)?;
    }
    write_frame(control, CAPACITY_CLEARED)
}

fn accept_pair(listener: &UnixListener, deadline: Instant) -> io::Result<(UnixStream, UnixStream)> {
    let mut first = configure_stream(accept_before(listener, deadline)?)?;
    let mut second = configure_stream(accept_before(listener, deadline)?)?;
    let first_role = read_frame(&mut first)?.ok_or_else(|| invalid("first role missing"))?;
    let second_role = read_frame(&mut second)?.ok_or_else(|| invalid("second role missing"))?;
    if first_role == ROLE_DATA && second_role == ROLE_SYNC {
        Ok((first, second))
    } else if first_role == ROLE_SYNC && second_role == ROLE_DATA {
        Ok((second, first))
    } else {
        Err(invalid(format!(
            "invalid stream roles: {first_role:?}, {second_role:?}"
        )))
    }
}

fn coexistence_network(
    listener: TcpListener,
    udp: UdpSocket,
    ready: std::sync::mpsc::Sender<()>,
    progress: std::sync::mpsc::Sender<()>,
    resume: std::sync::mpsc::Receiver<()>,
) -> io::Result<()> {
    const TCP_BYTES: usize = 16 * 1024;
    const UDP_BYTES: usize = 256;

    let (mut tcp, _) = listener.accept()?;
    tcp.set_read_timeout(Some(IO_TIMEOUT))?;
    tcp.set_write_timeout(Some(IO_TIMEOUT))?;
    udp.set_read_timeout(Some(IO_TIMEOUT))?;
    udp.set_write_timeout(Some(IO_TIMEOUT))?;
    ready
        .send(())
        .map_err(|_| invalid("coexistence owner dropped before network readiness"))?;

    let mut tcp_payload = vec![0; TCP_BYTES];
    tcp.read_exact(&mut tcp_payload)?;
    if tcp_payload != vec![0x52; TCP_BYTES] {
        return Err(invalid("corrupt coexistence TCP payload"));
    }
    let mut udp_payload = [0; UDP_BYTES];
    let (len, source) = udp.recv_from(&mut udp_payload)?;
    if len != UDP_BYTES || udp_payload != [0x73; UDP_BYTES] {
        return Err(invalid("corrupt coexistence UDP payload"));
    }
    progress
        .send(())
        .map_err(|_| invalid("coexistence owner dropped before network progress"))?;

    resume
        .recv_timeout(IO_TIMEOUT)
        .map_err(|_| invalid("coexistence network resume timed out"))?;
    tcp.write_all(&tcp_payload)?;
    if udp.send_to(&udp_payload, source)? != UDP_BYTES {
        return Err(invalid("short coexistence UDP echo"));
    }
    Ok(())
}

fn run() -> io::Result<()> {
    let args: Vec<_> = env::args().collect();
    let (base, action_name) = match args.as_slice() {
        [_, base, action, ..] => (base, action.as_str()),
        _ => return Err(invalid("usage: vsock-peer BASE ACTION BYTE-COUNTS...")),
    };
    let action = parse_action(action_name, &args[3..])?;
    let socket_path = PathBuf::from(format!("{base}_{PORT}"));
    let listener = UnixListener::bind(&socket_path)?;
    let _socket_path = SocketPath(socket_path.clone());
    listener.set_nonblocking(true)?;
    println!("READY {}", socket_path.display());
    io::stdout().flush()?;

    let completed_action = action.description();
    let deadline = Instant::now() + IO_TIMEOUT;
    if action.needs_sync() {
        let (mut data, mut sync) = accept_pair(&listener, deadline)?;
        match action {
            Action::LocalSendShutdown { send, receive } => {
                receive_pattern(&mut data, send)?;
                expect_frame(&mut sync, SEND_SHUTDOWN_DONE)?;
                send_pattern(&mut data, receive)?;
                write_frame(&mut sync, TRANSFER_DONE)?;
                expect_frame(&mut sync, CASE_DONE)?;
            }
            Action::LocalReceiveShutdown { receive, send } => {
                send_pattern(&mut data, receive)?;
                expect_frame(&mut sync, RECEIVE_SHUTDOWN_DONE)?;
                write_frame(&mut sync, CONTINUE)?;
                receive_pattern(&mut data, send)?;
                expect_frame(&mut sync, CASE_DONE)?;
                write_frame(&mut sync, TRANSFER_DONE)?;
            }
            Action::UnixPeerClose { receive } => {
                send_pattern(&mut data, receive)?;
                data.shutdown(Shutdown::Write)?;
                expect_frame(&mut sync, CASE_DONE)?;
            }
            Action::CancelRead { receive } => {
                expect_frame(&mut sync, CANCEL_READY)?;
                send_pattern(&mut data, receive)?;
                data.shutdown(Shutdown::Write)?;
                write_frame(&mut sync, TRANSFER_DONE)?;
                expect_frame(&mut sync, CASE_DONE)?;
            }
            Action::CancelWrite { tail } => {
                write_frame(&mut sync, ROLES_READY)?;
                expect_frame(&mut sync, CANCEL_READY)?;
                let total = RAW_SUBCHANNEL_BYTES
                    .checked_add(tail)
                    .filter(|total| *total <= MAX_TRANSFER)
                    .ok_or_else(|| invalid("cancel-write byte count exceeds fixture bound"))?;
                receive_raw_pattern(&mut data, total)?;
                expect_frame(&mut sync, SEND_SHUTDOWN_DONE)?;
                write_frame(&mut sync, TRANSFER_DONE)?;
                expect_frame(&mut sync, CASE_DONE)?;
            }
            Action::CancelQueuedConnect => {
                let mut canceled = Vec::with_capacity(2);
                for _ in 0..2 {
                    canceled.push(configure_stream(accept_before(&listener, deadline)?)?);
                }
                write_frame(&mut sync, FINAL_SLOT_ADMITTED)?;
                for mut canceled in canceled {
                    let mut unexpected = [0_u8; 1];
                    // Response rollback or whole-channel disconnect closes
                    // each entire late successful connection.
                    if canceled.read(&mut unexpected)? != 0 {
                        return Err(invalid("late canceled connection carried data"));
                    }
                }
                write_frame(&mut sync, TRANSFER_DONE)?;
                expect_frame(&mut sync, CASE_DONE)?;
            }
            Action::StalledReader { total } => {
                if total <= MAX_FRAME {
                    return Err(invalid("stalled-reader transfer must exceed one frame"));
                }
                send_pattern_from(&mut data, 0, MAX_FRAME)?;
                let writer = thread::spawn(move || {
                    send_pattern_from(&mut data, MAX_FRAME, total - MAX_FRAME)?;
                    Ok::<_, io::Error>(data)
                });

                write_frame(&mut sync, STALLED_DATA_READY)?;
                expect_frame(&mut sync, UNRELATED_PING)?;
                write_frame(&mut sync, UNRELATED_PONG)?;
                expect_frame(&mut sync, DRAIN_STARTED)?;

                let data = writer
                    .join()
                    .map_err(|_| invalid("stalled-reader writer panicked"))??;
                write_frame(&mut sync, TRANSFER_DONE)?;
                expect_frame(&mut sync, CASE_DONE)?;
                drop(data);
            }
            Action::Coexistence => {
                let tcp = TcpListener::bind((TAP_HOST, 0))?;
                let udp = UdpSocket::bind((TAP_HOST, 0))?;
                let tcp_port = tcp.local_addr()?.port().to_be_bytes();
                let udp_port = udp.local_addr()?.port().to_be_bytes();
                write_frame(
                    &mut sync,
                    &[tcp_port[0], tcp_port[1], udp_port[0], udp_port[1]],
                )?;

                let (network_ready_tx, network_ready_rx) = std::sync::mpsc::channel();
                let (network_progress_tx, network_progress_rx) = std::sync::mpsc::channel();
                let (network_resume_tx, network_resume_rx) = std::sync::mpsc::channel();
                let network = thread::spawn(move || {
                    coexistence_network(
                        tcp,
                        udp,
                        network_ready_tx,
                        network_progress_tx,
                        network_resume_rx,
                    )
                });
                network_ready_rx
                    .recv_timeout(IO_TIMEOUT)
                    .map_err(|_| invalid("coexistence network accept timed out"))?;
                write_frame(&mut sync, COEXIST_READY)?;
                expect_frame(&mut sync, COEXIST_START)?;
                send_pattern(&mut data, COEXIST_PHASE_BYTES)?;
                receive_pattern(&mut data, COEXIST_PHASE_BYTES)?;
                network_progress_rx
                    .recv_timeout(IO_TIMEOUT)
                    .map_err(|_| invalid("coexistence network progress timed out"))?;
                write_frame(&mut sync, COEXIST_PROGRESS)?;

                expect_frame(&mut sync, COEXIST_CONTINUE)?;
                network_resume_tx
                    .send(())
                    .map_err(|_| invalid("coexistence network worker exited before resume"))?;
                send_pattern(&mut data, COEXIST_PHASE_BYTES)?;
                receive_pattern(&mut data, COEXIST_PHASE_BYTES)?;
                network
                    .join()
                    .map_err(|_| invalid("coexistence network worker panicked"))??;
                write_frame(&mut sync, TRANSFER_DONE)?;
            }
            _ => unreachable!(),
        }
    } else {
        let mut stream = configure_stream(accept_before(&listener, deadline)?)?;
        match action {
            Action::Echo(total) => {
                let roundtrips = if total == 1 { SMALL_ECHO_ROUNDTRIPS } else { 1 };
                for _ in 0..roundtrips {
                    echo_exact(&mut stream, total)?;
                }
                stream.shutdown(Shutdown::Write)?;
            }
            Action::Send(total) => {
                send_pattern(&mut stream, total)?;
                stream.shutdown(Shutdown::Write)?;
            }
            Action::Duplex { send, echo } => {
                send_pattern(&mut stream, send)?;
                echo_exact(&mut stream, echo)?;
                stream.shutdown(Shutdown::Write)?;
            }
            Action::CancelBeforePollDrop => {
                receive_raw_pattern(&mut stream, RAW_SUBCHANNEL_BYTES)?;
                let mut unexpected = [0_u8; 1];
                // Guest Drop closes the whole stream after queued TX drains.
                if stream.read(&mut unexpected)? != 0 {
                    return Err(invalid("dropped stream carried excess data"));
                }
            }
            Action::IncomingBacklog | Action::IncomingOwnerDrop => {
                expect_frame(&mut stream, LISTENER_READY)?;
                let mut connections = Vec::with_capacity(LISTENER_BACKLOG);
                for _ in 0..LISTENER_BACKLOG {
                    connections.push(connect_guest(base, INCOMING_PORT)?);
                }
                expect_guest_refusal(base, INCOMING_PORT)?;
                for connection in &mut connections {
                    connection.write_all(b"early")?;
                }
                write_frame(&mut stream, BACKLOG_READY)?;

                expect_frame(&mut stream, LISTENER_DROPPED)?;
                for connection in &mut connections {
                    expect_eof(connection)?;
                }
                write_frame(&mut stream, BACKLOG_CLEARED)?;
                expect_frame(&mut stream, LISTENER_REBOUND)?;
            }
            Action::NativeAccept => {
                expect_frame(&mut stream, NATIVE_ACCEPT_READY)?;
                let mut accepted = connect_guest(base, NATIVE_ACCEPT_PORT)?;
                accepted.write_all(NATIVE_ACCEPT_EARLY)?;
                write_frame(&mut stream, NATIVE_ACCEPT_EARLY_READY)?;
                let mut reply = [0_u8; NATIVE_ACCEPT_REPLY.len()];
                accepted.read_exact(&mut reply)?;
                if reply != NATIVE_ACCEPT_REPLY {
                    return Err(invalid("native accepted stream reply mismatch"));
                }
                expect_eof(&mut accepted)?;
                write_frame(&mut stream, NATIVE_ACCEPT_DROPPED)?;

                expect_frame(&mut stream, NATIVE_ACCEPT_CLOSE_READY)?;
                let mut closed = connect_guest(base, NATIVE_ACCEPT_PORT)?;
                closed.write_all(NATIVE_ACCEPT_CLOSED)?;
                closed.shutdown(Shutdown::Both)?;
                drop(closed);
                write_frame(&mut stream, NATIVE_ACCEPT_CLOSED_READY)?;

                expect_frame(&mut stream, NATIVE_ACCEPT_SIMULTANEOUS_READY)?;
                let mut simultaneous = connect_guest(base, NATIVE_ACCEPT_PORT)?;
                write_frame(&mut stream, NATIVE_ACCEPT_SIMULTANEOUS_CONNECTED)?;
                expect_frame(&mut stream, NATIVE_ACCEPT_SIMULTANEOUS_STARTED)?;
                // This Unix write-close becomes full virtio peer shutdown in
                // the pinned UDS proxies while retaining the host read side.
                simultaneous.shutdown(Shutdown::Write)?;
                expect_eof(&mut simultaneous)?;
                expect_frame(&mut stream, NATIVE_ACCEPT_SIMULTANEOUS_CLOSED)?;

                let mut reused = connect_guest(base, NATIVE_ACCEPT_PORT)?;
                reused.write_all(NATIVE_ACCEPT_REUSE_PAYLOAD)?;
                write_frame(&mut stream, NATIVE_ACCEPT_REUSE_CONNECTED)?;
                let mut reply = [0_u8; NATIVE_ACCEPT_REUSE_REPLY.len()];
                reused.read_exact(&mut reply)?;
                if reply != NATIVE_ACCEPT_REUSE_REPLY {
                    return Err(invalid("native accepted reuse reply mismatch"));
                }
                expect_eof(&mut reused)?;
                expect_frame(&mut stream, NATIVE_ACCEPT_REUSED)?;

                expect_frame(&mut stream, NATIVE_ACCEPT_CANCEL_READY)?;
                let mut canceled = connect_guest(base, NATIVE_ACCEPT_PORT)?;
                expect_eof(&mut canceled)?;
                write_frame(&mut stream, NATIVE_ACCEPT_CANCEL_CLOSED)?;

                for _ in 0..2 {
                    expect_frame(&mut stream, NATIVE_ACCEPT_EXIT_READY)?;
                    let mut anchor = connect_guest(base, NATIVE_ACCEPT_EXIT_PORT)?;
                    anchor.write_all(b"r")?;
                    write_frame(&mut stream, NATIVE_ACCEPT_ANCHOR_HELD)?;
                    expect_frame(&mut stream, NATIVE_ACCEPT_CONNECT_READY)?;
                    let mut outgoing = configure_stream(accept_before(&listener, deadline)?)?;
                    write_frame(&mut stream, NATIVE_ACCEPT_BOTH_HELD)?;
                    expect_frame(&mut stream, NATIVE_ACCEPT_EXITED)?;
                    expect_prefix_then_eof(&mut anchor, b"t")?;
                    expect_eof(&mut outgoing)?;
                    write_frame(&mut stream, NATIVE_ACCEPT_EXIT_CLEANED)?;
                    expect_frame(&mut stream, NATIVE_ACCEPT_EXIT_REBOUND)?;
                }
                for _ in 0..ACCEPT_DISCONNECT_ROUNDS {
                    expect_frame(&mut stream, ACCEPT_DISCONNECT_READY)?;
                    let mut accepted = connect_guest(base, ACCEPT_DISCONNECT_PORT)?;
                    write_frame(&mut stream, ACCEPT_DISCONNECT_HELD)?;
                    expect_eof(&mut accepted)?;
                    write_frame(&mut stream, ACCEPT_DISCONNECT_CLOSED)?;
                }
                run_global_capacity_cycle(base, &mut stream)?;
                expect_frame(&mut stream, CASE_DONE)?;
            }
            Action::GlobalStreamCapacity => {
                run_global_capacity_cycle(base, &mut stream)?;
                run_global_capacity_cycle(base, &mut stream)?;

                expect_frame(&mut stream, CAPACITY_REBOUND)?;
                let mut rebound = connect_guest(base, CAPACITY_PORT_START)?;
                write_frame(&mut stream, CAPACITY_REUSED)?;
                expect_frame(&mut stream, CASE_DONE)?;
                expect_eof(&mut rebound)?;
            }
            _ => unreachable!(),
        }
    }

    println!("DONE {completed_action}");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vsock-peer: {error}");
            ExitCode::FAILURE
        }
    }
}
