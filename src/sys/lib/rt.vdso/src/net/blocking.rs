//! The blocking POSIX layer over moto-io::net's async-first sockets.
//!
//! moto-io::net does the async work and copies in the polling context; this
//! is where a vdso caller thread parks — the spin, the park-with-recheck,
//! `SO_*TIMEO` and `O_NONBLOCK`. It mirrors how `rt_fs` blocks on
//! moto-io::fs. Keeping the blocking here rather than in moto-io is what lets
//! a native app drive the same sockets on its own executor with nothing
//! blocking baked in (design 5.4).

use core::future::Future;
use core::net::SocketAddr;
use core::time::Duration;
use moto_io::net::tcp::TcpStream;
use moto_io::net::udp::UdpSocket;
use moto_rt::time::Instant;
use moto_sys::ErrorCode;

/// Longest a bounded-recheck park sleeps before re-polling regardless of
/// wakes. The TX backpressure wake crosses the process boundary (sys-io
/// frees a page -> wakes the channel runtime -> the tx-waker list), and
/// that path is not race-free in practice — the old blocking write loop
/// carried an exponential sleep ladder (max 3s) for exactly this reason.
/// A miss now costs at most one tick of extra latency instead of a hang;
/// a healthy send never waits this long, so steady-state TX pays nothing.
/// Also the UDP send recheck.
const TX_PARK_RECHECK: Duration = Duration::from_millis(500);

/// Read-side recheck interval: the old blocking read loop woke every 5s
/// (its `DEBUG_TIMEOUT`) even without data, which masked any lost RX
/// wake; kept here as the same insurance. A blocked reader waiting for
/// data pays one wasted wakeup per interval, as it did before. Also the
/// UDP recv recheck.
const RX_PARK_RECHECK: Duration = Duration::from_secs(5);

/// A blocking write spins then yields this many times, re-checking for TX-page
/// room, before it commits to a park. Restores the pre-D4b ladder's cheap page
/// grab: a small write that briefly outruns sys-io's drain catches a freed page
/// here instead of paying a park+wake syscall per write (~30% of default-buffer
/// bulk TX, kill checkpoint 2). Uncontended writes and RR never reach the spin.
const TX_WRITE_SPINS: usize = 100;
const TX_WRITE_YIELDS: usize = 100;

/// Drive `fut` on the calling thread, capping each park at `recheck` so a
/// lost wake self-heals on the next tick. `deadline` is the real
/// `SO_*TIMEO` bound if any; `Err(fut)` is only returned once that real
/// deadline passes (never on a recheck tick), so the caller can extract
/// partial progress.
fn block_on_recheck<F: Future + Unpin>(
    mut fut: F,
    deadline: Option<Instant>,
    recheck: Duration,
) -> Result<F::Output, F> {
    loop {
        let now = Instant::now();
        if let Some(d) = deadline
            && now >= d
        {
            return Err(fut);
        }
        let tick = match deadline {
            Some(d) => d.min(now + recheck),
            None => now + recheck,
        };
        match moto_async::block_on_sync_deadline(fut, tick) {
            Ok(v) => return Ok(v),
            // Either the recheck tick or the real deadline fired; the loop
            // top distinguishes them and re-polls (self-healing a lost wake).
            Err(f) => fut = f,
        }
    }
}

/// An `SO_*TIMEO` nanosecond value turned into a park deadline.
fn deadline_from(timeout_ns: u64) -> Option<Instant> {
    if timeout_ns == u64::MAX {
        None
    } else {
        Some(Instant::now() + Duration::from_nanos(timeout_ns))
    }
}

/// Blocking TCP read or peek: the `O_NONBLOCK` fast return, then a park
/// bounded by `SO_RCVTIMEO` with the recheck insurance.
pub fn tcp_read(
    stream: &TcpStream,
    bufs: &mut [&mut [u8]],
    peek: bool,
) -> Result<usize, ErrorCode> {
    match stream.try_read(bufs, peek) {
        Ok(sz) => return Ok(sz),
        Err(err) => assert_eq!(err, moto_rt::E_NOT_READY),
    }

    if stream.is_nonblocking() {
        return Err(moto_rt::E_NOT_READY);
    }

    let deadline = deadline_from(stream.read_timeout());
    let fut = stream.read_future(bufs, peek);
    match block_on_recheck(fut, deadline, RX_PARK_RECHECK) {
        Ok(res) => res,
        Err(_fut) => Err(moto_rt::E_TIMED_OUT),
    }
}

/// Blocking TCP write. Writes what fits, then spins/yields for page room
/// before committing to a park (see `TX_WRITE_SPINS`). Committed bytes
/// survive a `SO_SNDTIMEO` timeout (design rule 7).
pub fn tcp_write(stream: &TcpStream, bufs: &[&[u8]]) -> Result<usize, ErrorCode> {
    if stream.is_nonblocking() {
        return stream.try_write(bufs);
    }

    // Fast path: try_write does the empty/closed checks plus a nonblocking
    // write. A return here means at least one byte moved (or nothing to do);
    // only a fully backpressured write falls to the spin then the future.
    match stream.try_write(bufs) {
        Ok(n) => return Ok(n),
        Err(err) if err != moto_rt::E_NOT_READY => return Err(err),
        Err(_) => {}
    }

    for i in 0..(TX_WRITE_SPINS + TX_WRITE_YIELDS) {
        if i < TX_WRITE_SPINS {
            core::hint::spin_loop();
        } else {
            moto_sys::SysCpu::sched_yield();
        }
        if !stream.can_write_now() {
            return Err(moto_rt::E_NOT_CONNECTED);
        }
        if stream.have_write_buffer_space() {
            match stream.try_write(bufs) {
                Ok(n) => return Ok(n),
                Err(err) if err != moto_rt::E_NOT_READY => return Err(err),
                Err(_) => {}
            }
        }
    }

    let deadline = deadline_from(stream.write_timeout());
    let fut = stream.write_future(bufs);
    match block_on_recheck(fut, deadline, TX_PARK_RECHECK) {
        Ok(res) => res,
        // Timed out: surrender partial progress (design rule 7).
        Err(fut) => {
            if fut.written > 0 {
                Ok(fut.written)
            } else {
                Err(moto_rt::E_TIMED_OUT)
            }
        }
    }
}

/// Blocking TCP peek: a read that leaves the bytes queued.
pub fn tcp_peek(stream: &TcpStream, buf: &mut [u8]) -> Result<usize, ErrorCode> {
    tcp_read(stream, &mut [buf], true)
}

/// Blocking UDP receive or peek: the `O_NONBLOCK` fast return, then a park
/// bounded by `SO_RCVTIMEO`.
pub fn udp_recv(
    socket: &UdpSocket,
    buf: &mut [u8],
    peek: bool,
) -> Result<(usize, SocketAddr), ErrorCode> {
    if socket.is_nonblocking() {
        return socket.try_recv_from(buf, peek);
    }

    let deadline = deadline_from(socket.read_timeout());
    let fut = socket.recv_from_future(buf, peek);
    match block_on_recheck(fut, deadline, RX_PARK_RECHECK) {
        Ok(res) => res,
        Err(_fut) => Err(moto_rt::E_TIMED_OUT),
    }
}

/// Blocking UDP send, bounded by `SO_SNDTIMEO`.
pub fn udp_send(socket: &UdpSocket, buf: &[u8], addr: &SocketAddr) -> Result<usize, ErrorCode> {
    if socket.is_nonblocking() {
        return socket.try_send_to(buf, addr);
    }

    if buf.len() > moto_rt::net::MAX_UDP_PAYLOAD {
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }

    let deadline = deadline_from(socket.write_timeout());
    let fut = socket.send_to_future(buf, addr);
    match block_on_recheck(fut, deadline, TX_PARK_RECHECK) {
        Ok(res) => res,
        Err(_fut) => Err(moto_rt::E_TIMED_OUT),
    }
}
