//! The vdso TCP veneer: the PosixFile impls the FD table dispatches through
//! and the poll-registry event synthesis, layered over the moto-io TCP state
//! machines. This is all that stays in the vdso after the Stage-F move; it
//! reads the moved sockets through their public API and emits through the
//! concrete `EventSourceManaged` the ABI shims installed as each socket's
//! listener.

use crate::posix::PosixFile;
use crate::posix::PosixKind;
use crate::runtime::EventSourceManaged;
use moto_io::net::readiness::NetEventListener;
use moto_io::net::tcp::TcpListener;
use moto_io::net::tcp::TcpStream;
use moto_rt::RtFd;
use moto_rt::poll::Interests;
use moto_rt::poll::Token;
use moto_sys::ErrorCode;
use moto_sys_io::api_net::TcpState;

impl PosixFile for TcpListener {
    fn kind(&self) -> PosixKind {
        PosixKind::TcpListener
    }

    fn close(&self, rt_fd: RtFd) -> Result<(), ErrorCode> {
        listener_event_source(self).on_closed_locally(rt_fd);
        Ok(())
    }

    fn poll_add(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        listener_event_source(self).add_interests(r_id, source_fd, token, interests)?;

        if (interests & moto_rt::poll::POLL_READABLE != 0) && self.has_async_accepts() {
            listener_event_source(self).on_event(moto_rt::poll::POLL_READABLE);
        }

        Ok(())
    }

    fn poll_set(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        listener_event_source(self).set_interests(r_id, source_fd, token, interests)?;

        if (interests & moto_rt::poll::POLL_READABLE != 0) && self.has_async_accepts() {
            listener_event_source(self).on_event(moto_rt::poll::POLL_READABLE);
        }

        Ok(())
    }

    fn poll_del(&self, r_id: u64, source_fd: RtFd) -> Result<(), ErrorCode> {
        listener_event_source(self).del_interests(r_id, source_fd)
    }
}

/// The veneer's poll-registry source for a listener, recovered from the
/// abstract listener the vdso installed. Sound because the vdso always
/// installs an `EventSourceManaged`; a native moto-io host that registered
/// no listener would never reach the poll-registration paths that call this.
fn listener_event_source(listener: &TcpListener) -> &EventSourceManaged {
    listener
        .event_listener()
        .as_any()
        .downcast_ref::<EventSourceManaged>()
        .expect("vdso net socket without an EventSourceManaged listener")
}

impl PosixFile for TcpStream {
    fn kind(&self) -> PosixKind {
        PosixKind::TcpStream
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        crate::net::blocking::tcp_read(self, &mut [buf], false)
    }

    unsafe fn read_vectored(&self, bufs: &mut [&mut [u8]]) -> Result<usize, ErrorCode> {
        crate::net::blocking::tcp_read(self, bufs, false)
    }

    fn write(&self, buf: &[u8]) -> Result<usize, ErrorCode> {
        crate::net::blocking::tcp_write(self, &[buf])
    }

    unsafe fn write_vectored(&self, bufs: &[&[u8]]) -> Result<usize, ErrorCode> {
        crate::net::blocking::tcp_write(self, bufs)
    }

    fn flush(&self) -> Result<(), ErrorCode> {
        Ok(())
    }

    fn close(&self, rt_fd: RtFd) -> Result<(), ErrorCode> {
        stream_event_source(self).on_closed_locally(rt_fd);
        Ok(())
    }

    fn poll_add(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        stream_event_source(self).add_interests(r_id, source_fd, token, interests)?;
        stream_maybe_raise_events(self, interests);
        Ok(())
    }

    fn poll_set(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        stream_event_source(self).set_interests(r_id, source_fd, token, interests)?;
        stream_maybe_raise_events(self, interests);
        Ok(())
    }

    fn poll_del(&self, r_id: u64, source_fd: RtFd) -> Result<(), ErrorCode> {
        stream_event_source(self).del_interests(r_id, source_fd)
    }
}

/// The veneer's poll-registry source for a stream (see the listener
/// counterpart `listener_event_source`).
fn stream_event_source(stream: &TcpStream) -> &EventSourceManaged {
    stream
        .event_listener()
        .as_any()
        .downcast_ref::<EventSourceManaged>()
        .expect("vdso net socket without an EventSourceManaged listener")
}

/// Synthesize the poll events a freshly-registered interest expects, based
/// on the stream's current state (mio semantics, somewhat ad-hoc). Called
/// from poll_add/poll_set only; a veneer concern (it emits through the
/// concrete `EventSourceManaged`), so it reads the moved state machine
/// through its public accessors.
fn stream_maybe_raise_events(stream: &TcpStream, interests: Interests) {
    let mut events = 0;

    let state = stream.tcp_state();
    if state == TcpState::Closed {
        // MIO TCP tests assume this.
        events = moto_rt::poll::POLL_WRITE_CLOSED
            | moto_rt::poll::POLL_READ_CLOSED
            | moto_rt::poll::POLL_READABLE
            | moto_rt::poll::POLL_WRITABLE;
        stream_event_source(stream).on_event(events);
        return;
    }

    match state {
        TcpState::Listening | TcpState::PendingAccept | TcpState::Connecting => return,
        _ => {}
    }

    if (interests & moto_rt::poll::POLL_WRITABLE != 0)
        && stream.have_write_buffer_space()
        && state.can_write()
    {
        events |= moto_rt::poll::POLL_WRITABLE;
    }

    if ((interests & moto_rt::poll::POLL_READABLE) != 0)
        && state.can_read()
        && stream.has_rx_bytes()
    {
        events |= moto_rt::poll::POLL_READABLE;
    }

    if !state.can_read() {
        events |= moto_rt::poll::POLL_READ_CLOSED;
    }

    if events != 0 {
        stream_event_source(stream).on_event(events);
    }
}
