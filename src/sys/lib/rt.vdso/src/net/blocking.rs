//! The blocking POSIX layer over moto-io::net's async-first sockets.
//!
//! moto-io::net does the async work and copies in the polling context; this
//! is where a vdso caller thread parks — the spin, the park, `SO_*TIMEO`
//! and `O_NONBLOCK`. It mirrors how `rt_fs` blocks on moto-io::fs. Keeping
//! the blocking here rather than in moto-io is what lets a native app drive
//! the same sockets on its own executor with nothing blocking baked in
//! (design 5.4).

use crate::net::rt_tcp::RtTcpStream;
use crate::net::rt_udp::RtUdpSocket;
use core::future::Future;
use core::net::SocketAddr;
use core::time::Duration;
use moto_rt::time::Instant;
use moto_sys::ErrorCode;

/// A blocking write spins then yields this many times, re-checking for TX-page
/// room, before it commits to a park. Restores the old blocking write loop's
/// cheap page grab: a small write that briefly outruns sys-io's drain catches a
/// freed page here instead of paying a park+wake syscall per write (~30% of
/// default-buffer bulk TX, measured). Uncontended writes and RR never reach the
/// spin.
const TX_WRITE_SPINS: usize = 100;
const TX_WRITE_YIELDS: usize = 100;

/// Drive `fut` on the calling thread; `deadline` is the real `SO_*TIMEO`
/// bound if any. The park is wake-driven with no recheck tick: the wake
/// chain (rx task -> WaitSet, sys-io page-free -> tx-waker drain) is relied
/// on outright, so a lost wake hangs the caller instead of hiding behind a
/// periodic re-poll. `Err(fut)` means the deadline passed; the caller can
/// extract partial progress.
fn block_on_deadline<F: Future + Unpin>(fut: F, deadline: Option<Instant>) -> Result<F::Output, F> {
    match deadline {
        None => Ok(moto_async::block_on_sync(fut)),
        Some(d) => moto_async::block_on_sync_deadline(fut, d),
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
/// bounded by `SO_RCVTIMEO`. Both are read from the descriptor wrapper, which
/// is where POSIX state lives; the future comes from the native stream.
pub fn tcp_read(
    stream: &RtTcpStream,
    bufs: &mut [&mut [u8]],
    peek: bool,
) -> Result<usize, ErrorCode> {
    match stream.inner().try_read(bufs, peek) {
        Ok(sz) => return Ok(sz),
        Err(moto_rt::E_NOT_READY) => {}
        Err(err) => return Err(err),
    }

    if stream.is_nonblocking() {
        return Err(moto_rt::E_NOT_READY);
    }

    let deadline = deadline_from(stream.read_timeout());
    let fut = stream.inner().read_future(bufs, peek);
    match block_on_deadline(fut, deadline) {
        Ok(res) => res,
        Err(_fut) => Err(moto_rt::E_TIMED_OUT),
    }
}

/// Blocking TCP write. Writes what fits, then spins/yields for page room
/// before committing to a park (see `TX_WRITE_SPINS`). Committed bytes
/// survive a `SO_SNDTIMEO` timeout (design rule 7).
pub fn tcp_write(stream: &RtTcpStream, bufs: &[&[u8]]) -> Result<usize, ErrorCode> {
    if stream.is_nonblocking() {
        return stream.inner().try_write(bufs);
    }

    // Fast path: try_write does the empty/closed checks plus a nonblocking
    // write. A return here means at least one byte moved (or nothing to do);
    // only a fully backpressured write falls to the spin then the future.
    match stream.inner().try_write(bufs) {
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
        if !stream.inner().can_write_now() {
            return Err(stream.inner().dead_write_error());
        }
        if stream.inner().have_write_buffer_space() {
            match stream.inner().try_write(bufs) {
                Ok(n) => return Ok(n),
                Err(err) if err != moto_rt::E_NOT_READY => return Err(err),
                Err(_) => {}
            }
        }
    }

    let deadline = deadline_from(stream.write_timeout());
    let fut = stream.inner().write_future(bufs);
    match block_on_deadline(fut, deadline) {
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
pub fn tcp_peek(stream: &RtTcpStream, buf: &mut [u8]) -> Result<usize, ErrorCode> {
    tcp_read(stream, &mut [buf], true)
}

/// Blocking UDP receive or peek: the `O_NONBLOCK` fast return, then a park
/// bounded by `SO_RCVTIMEO`. Both are read from the descriptor wrapper, which
/// is where POSIX state lives; the future comes from the native socket.
pub fn udp_recv(
    socket: &RtUdpSocket,
    buf: &mut [u8],
    peek: bool,
) -> Result<(usize, SocketAddr), ErrorCode> {
    if socket.is_nonblocking() {
        return socket.inner().try_recv_from(buf, peek);
    }

    let deadline = deadline_from(socket.read_timeout());
    let fut = socket.inner().recv_from_future(buf, peek);
    match block_on_deadline(fut, deadline) {
        Ok(res) => res,
        Err(_fut) => Err(moto_rt::E_TIMED_OUT),
    }
}

/// Blocking UDP send, bounded by `SO_SNDTIMEO`.
pub fn udp_send(socket: &RtUdpSocket, buf: &[u8], addr: &SocketAddr) -> Result<usize, ErrorCode> {
    if socket.is_nonblocking() {
        return socket.inner().try_send_to(buf, addr);
    }

    if buf.len() > moto_rt::net::MAX_UDP_PAYLOAD {
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }

    let deadline = deadline_from(socket.write_timeout());
    let fut = socket.inner().send_to_future(buf, addr);
    match block_on_deadline(fut, deadline) {
        Ok(res) => res,
        Err(_fut) => Err(moto_rt::E_TIMED_OUT),
    }
}
