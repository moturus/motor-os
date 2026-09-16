use std::io::Result as IoResult;

use super::credit::{CreditAdvertisement, CreditError, CreditState};
use super::rx_buffer::StreamBuffer;

const STREAM_RX_CAPACITY: usize = 128 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadOutcome {
    Copied(usize),
    Pending,
    Eof,
    ConnectionReset,
}

/// State retained for one established stream. Wire-operation dispatch,
/// connection lookup, and TX drain/shutdown sequencing remain with its owner.
/// After reset, that owner must stop dispatching further packet effects here.
pub(crate) struct EstablishedStream {
    receive: StreamBuffer,
    peer_send_shutdown: bool,
    peer_receive_shutdown: bool,
    reset: bool,
}

impl EstablishedStream {
    pub(crate) fn new() -> IoResult<Self> {
        Ok(Self {
            receive: StreamBuffer::new(STREAM_RX_CAPACITY)?,
            peer_send_shutdown: false,
            peer_receive_shutdown: false,
            reset: false,
        })
    }

    pub(crate) fn credit(&self) -> &CreditState {
        self.receive.credit()
    }

    pub(crate) fn charge_tx_after_publish(&mut self, len: u32) -> Result<(), CreditError> {
        self.receive.charge_tx_after_publish(len)
    }

    /// Apply a validated packet's credit before any packet-specific effect.
    /// Impossible forwarding permanently resets only this stream.
    pub(crate) fn update_peer_credit(
        &mut self,
        peer: CreditAdvertisement,
    ) -> Result<(), CreditError> {
        let result = self.receive.update_peer(peer);
        if result == Err(CreditError::PeerForwardedBeyondSent) {
            self.reset = true;
        }
        result
    }

    /// Apply credit and append one RW payload atomically. Capacity rejection
    /// remains a fallible boundary; the connection owner applies D22's reset.
    pub(crate) fn try_receive_packet(
        &mut self,
        peer: CreditAdvertisement,
        payload: &[u8],
    ) -> Result<(), CreditError> {
        if payload.len() > self.receive.credit().rx_allowance() {
            return Err(CreditError::ReceiveCapacityExceeded);
        }
        self.update_peer_credit(peer)?;
        self.receive.try_append_packet(payload)
    }

    /// SHUTDOWN bits are permanent hints. Passing neither bit is a no-op.
    pub(crate) fn peer_shutdown(&mut self, receive: bool, send: bool) {
        self.peer_receive_shutdown |= receive;
        self.peer_send_shutdown |= send;
    }

    /// An unexpected/error RST has no response action; orderly close remains
    /// in the owner's phase handling.
    pub(crate) fn peer_reset(&mut self) {
        self.reset = true;
    }

    /// Peer SEND shutdown leaves local writes open; peer RECEIVE and reset do not.
    pub(crate) fn accepts_new_writes(&self) -> bool {
        !self.peer_receive_shutdown && !self.reset
    }

    pub(crate) fn accepts_peer_data(&self) -> bool {
        !self.peer_send_shutdown && !self.reset
    }

    /// Copy into storage already reserved by IPC. Validated bytes are delivered
    /// before the retained reset cause or orderly EOF becomes visible.
    pub(crate) fn read_into_reserved(&mut self, dst: &mut [u8]) -> ReadOutcome {
        if dst.is_empty() {
            return ReadOutcome::Copied(0);
        }
        let copied = self.receive.copy_into_reserved(dst);
        if copied != 0 {
            ReadOutcome::Copied(copied)
        } else if self.reset {
            ReadOutcome::ConnectionReset
        } else if self.peer_send_shutdown {
            ReadOutcome::Eof
        } else {
            ReadOutcome::Pending
        }
    }
}
