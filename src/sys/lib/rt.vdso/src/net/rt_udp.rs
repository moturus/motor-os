//! The vdso UDP veneer: the PosixFile impl and poll-registry event synthesis
//! over the moto-io `UdpSocket` state machine (see the TCP veneer in rt_tcp).

use crate::posix::PosixFile;
use crate::posix::PosixKind;
use crate::runtime::EventSourceManaged;
use moto_io::net::readiness::NetEventListener;
use moto_io::net::udp::UdpSocket;
use moto_rt::poll::Interests;
use moto_rt::poll::Token;
use moto_rt::{ErrorCode, RtFd};

impl PosixFile for UdpSocket {
    fn kind(&self) -> PosixKind {
        PosixKind::UdpSocket
    }

    fn write(&self, buf: &[u8]) -> Result<usize, ErrorCode> {
        let Some(addr) = self.peer_addr() else {
            return Err(moto_rt::E_NOT_CONNECTED);
        };

        crate::net::blocking::udp_send(self, buf, &addr)
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        crate::net::blocking::udp_recv(self, buf, false).map(|(sz, _)| sz)
    }

    fn close(&self, rt_fd: RtFd) -> Result<(), ErrorCode> {
        event_source(self).on_closed_locally(rt_fd);
        Ok(())
    }

    fn poll_add(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        event_source(self).add_interests(r_id, source_fd, token, interests)?;
        maybe_raise_events(self, interests);
        Ok(())
    }

    fn poll_set(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        event_source(self).set_interests(r_id, source_fd, token, interests)?;
        maybe_raise_events(self, interests);
        Ok(())
    }

    fn poll_del(&self, r_id: u64, source_fd: RtFd) -> Result<(), ErrorCode> {
        event_source(self).del_interests(r_id, source_fd)
    }
}

/// The veneer's poll-registry source for a UDP socket (see the TCP
/// counterparts `stream_event_source` / `listener_event_source`).
fn event_source(socket: &UdpSocket) -> &EventSourceManaged {
    socket
        .event_listener()
        .as_any()
        .downcast_ref::<EventSourceManaged>()
        .expect("vdso net socket without an EventSourceManaged listener")
}

/// Synthesize the poll events a freshly-registered interest expects. Called
/// from poll_add/poll_set only; a veneer concern (it emits through the
/// concrete `EventSourceManaged`), reading the moved socket through its
/// public accessors.
fn maybe_raise_events(socket: &UdpSocket, interests: Interests) {
    let mut events = 0;

    if (interests & moto_rt::poll::POLL_WRITABLE != 0) && !socket.tx_queue_full() {
        events |= moto_rt::poll::POLL_WRITABLE;
    }

    if (interests & moto_rt::poll::POLL_READABLE) != 0 && socket.has_rx_datagram() {
        events |= moto_rt::poll::POLL_READABLE;
    }

    if events != 0 {
        event_source(socket).on_event(events);
    }
}
