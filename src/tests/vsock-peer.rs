use std::{
    env, fs,
    io::{self, ErrorKind, Read, Write},
    net::Shutdown,
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
const CANCEL_READY: &[u8] = b"cancel:ready";
const ROLES_READY: &[u8] = b"roles:ready";
const RAW_SUBCHANNEL_BYTES: usize = 64 * 1024;

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
        _ => Err(invalid(
            "actions: echo N | send N | duplex SEND_N ECHO_N | \
             local-send-shutdown SEND_N RECEIVE_N | \
             local-receive-shutdown RECEIVE_N SEND_N | unix-peer-close RECEIVE_N | \
             cancel-read RECEIVE_N | cancel-write TAIL_N",
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
    let mut offset = 0;
    while offset < total {
        let len = (total - offset).min(MAX_FRAME);
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
            _ => unreachable!(),
        }
    } else {
        let mut stream = configure_stream(accept_before(&listener, deadline)?)?;
        match action {
            Action::Echo(total) => {
                echo_exact(&mut stream, total)?;
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
