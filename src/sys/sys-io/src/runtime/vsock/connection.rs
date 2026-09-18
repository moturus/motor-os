use std::io::{ErrorKind, Result as IoResult};

use super::credit::{CreditAdvertisement, CreditError, CreditState};
use super::rx_buffer::StreamBuffer;
use super::vsock_wire::{Operation, PacketHeader, SHUTDOWN_RECEIVE, SHUTDOWN_SEND};

const STREAM_RX_CAPACITY: usize = 128 * 1024;
const SHUTDOWN_BOTH: u32 = SHUTDOWN_RECEIVE | SHUTDOWN_SEND;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadOutcome {
    Copied(usize),
    Pending,
    Eof,
    ConnectionReset,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TerminalCause {
    Refused,
    ConnectionReset,
    TimedOut,
    OrderlyClosed,
    InternalError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConnectionPhase {
    Connecting,
    Established,
    Terminal(TerminalCause),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReceiveOutcome {
    None,
    Connected,
    SendCreditUpdate,
    SendReset,
}

/// Protocol state for one tuple. Client authority and tuple lookup stay with
/// the common socket owner. Inputs must already be decoded and tuple-matched.
pub(crate) struct Connection {
    phase: ConnectionPhase,
    receive: StreamBuffer,
    peer_shutdown: u32,
    shutdown_requested: u32,
    shutdown_queued: u32,
    shutdown_published: u32,
    cleanup_started: bool,
}

impl Connection {
    /// Allocate receive capacity before the owner publishes REQUEST.
    pub(crate) fn new_outgoing() -> IoResult<Self> {
        Ok(Self {
            phase: ConnectionPhase::Connecting,
            receive: StreamBuffer::new(STREAM_RX_CAPACITY)?,
            peer_shutdown: 0,
            shutdown_requested: 0,
            shutdown_queued: 0,
            shutdown_published: 0,
            cleanup_started: false,
        })
    }

    /// Allocate receive capacity and validate REQUEST credit before the owner
    /// publishes RESPONSE or makes the connection available for accept.
    pub(crate) fn new_incoming(request: &PacketHeader) -> IoResult<Self> {
        if request.operation != Operation::Request {
            return Err(ErrorKind::InvalidInput.into());
        }
        let mut connection = Self::new_outgoing()?;
        connection
            .receive
            .update_peer(advertisement(request))
            .map_err(|_| ErrorKind::InvalidData)?;
        connection.phase = ConnectionPhase::Established;
        Ok(connection)
    }

    pub(crate) fn phase(&self) -> ConnectionPhase {
        self.phase
    }

    pub(crate) fn credit(&self) -> &CreditState {
        self.receive.credit()
    }

    pub(crate) fn charge_tx_after_publish(&mut self, len: u32) -> Result<(), CreditError> {
        self.receive.charge_tx_after_publish(len)
    }

    pub(crate) fn accepts_new_writes(&self) -> bool {
        self.can_publish_accepted_tx() && self.shutdown_requested & SHUTDOWN_SEND == 0
    }

    /// Previously accepted bytes may drain after local SEND shutdown, but not
    /// after peer RECEIVE shutdown or terminalization.
    pub(crate) fn can_publish_accepted_tx(&self) -> bool {
        self.phase == ConnectionPhase::Established && self.peer_shutdown & SHUTDOWN_RECEIVE == 0
    }

    pub(crate) fn has_buffered_rx(&self) -> bool {
        !self.receive.is_empty()
    }

    pub(crate) fn local_write_closed(&self) -> bool {
        self.shutdown_requested & SHUTDOWN_SEND != 0
            || self.peer_shutdown & SHUTDOWN_RECEIVE != 0
            || matches!(self.phase, ConnectionPhase::Terminal(_))
    }

    pub(crate) fn local_read_closed(&self) -> bool {
        self.shutdown_requested & SHUTDOWN_RECEIVE != 0
            || self.receive.is_empty()
                && (self.peer_shutdown & SHUTDOWN_SEND != 0
                    || matches!(self.phase, ConnectionPhase::Terminal(_)))
    }

    pub(crate) fn local_receive_shutdown(&self) -> bool {
        self.shutdown_requested & SHUTDOWN_RECEIVE != 0
    }

    pub(crate) fn terminal_cause(&self) -> Option<TerminalCause> {
        let ConnectionPhase::Terminal(cause) = self.phase else {
            return None;
        };
        Some(cause)
    }

    /// Deliver validated RX before the retained reset cause or orderly EOF.
    pub(crate) fn read_into_reserved(&mut self, dst: &mut [u8]) -> ReadOutcome {
        if dst.is_empty() {
            return ReadOutcome::Copied(0);
        }
        let copied = self.receive.copy_into_reserved(dst);
        if copied != 0 {
            return ReadOutcome::Copied(copied);
        }
        match self.phase {
            ConnectionPhase::Terminal(TerminalCause::OrderlyClosed) => ReadOutcome::Eof,
            ConnectionPhase::Terminal(_) => ReadOutcome::ConnectionReset,
            _ if self.peer_shutdown & SHUTDOWN_SEND != 0 => ReadOutcome::Eof,
            _ => ReadOutcome::Pending,
        }
    }

    /// Request permanent local shutdown flags. SEND immediately closes new
    /// application-write admission, but is not ready until accepted TX drains.
    pub(crate) fn request_shutdown(&mut self, flags: u32) {
        assert_eq!(flags & !SHUTDOWN_BOTH, 0);
        self.shutdown_requested |= flags;
    }

    pub(crate) fn shutdown_ready(&self, tx_drained: bool) -> u32 {
        if self.phase != ConnectionPhase::Established || !tx_drained {
            return 0;
        }
        self.shutdown_requested & !self.shutdown_queued
    }

    /// Record flags only after their control record has been retained by the
    /// owner. The caller must have obtained them from `shutdown_ready`.
    pub(crate) fn record_shutdown_queued(&mut self, flags: u32) {
        assert_ne!(flags, 0);
        assert_eq!(flags & !self.shutdown_ready(true), 0);
        self.shutdown_queued |= flags;
    }

    /// Record flags only after successful virtqueue publication.
    pub(crate) fn record_shutdown_published(&mut self, flags: u32) {
        assert_ne!(flags, 0);
        assert_eq!(flags & !self.shutdown_queued, 0);
        assert_eq!(flags & self.shutdown_published, 0);
        self.shutdown_published |= flags;
    }

    pub(crate) fn shutdown_published(&self, flags: u32) -> bool {
        self.shutdown_published & flags == flags
    }

    /// Return true once when peer BOTH is observed and all validated RX has
    /// drained. The owner then sends the one orderly RST response.
    pub(crate) fn take_orderly_reset_if_ready(&mut self) -> bool {
        if matches!(self.phase, ConnectionPhase::Terminal(_))
            || self.peer_shutdown != SHUTDOWN_BOTH
            || !self.receive.is_empty()
        {
            return false;
        }
        self.phase = ConnectionPhase::Terminal(TerminalCause::OrderlyClosed);
        true
    }

    /// First call starts the owner's single eight-second cleanup budget.
    pub(crate) fn begin_cleanup(&mut self) -> bool {
        if self.cleanup_started || matches!(self.phase, ConnectionPhase::Terminal(_)) {
            return false;
        }
        self.cleanup_started = true;
        true
    }

    /// Expiry requests one forced RST. Tuple release remains owner-side.
    pub(crate) fn expire_cleanup(&mut self) -> bool {
        if !self.cleanup_started || matches!(self.phase, ConnectionPhase::Terminal(_)) {
            return false;
        }
        self.enter_terminal(TerminalCause::ConnectionReset);
        true
    }

    pub(crate) fn connect_timed_out(&mut self) -> bool {
        if self.phase != ConnectionPhase::Connecting {
            return false;
        }
        self.enter_terminal(TerminalCause::TimedOut)
    }

    /// Locally abandon a connection whose unread bytes have no remaining
    /// consumer. The owner still retains it until the required RST publishes.
    pub(crate) fn abandon_unread_rx(&mut self) -> bool {
        self.request_shutdown(SHUTDOWN_RECEIVE);
        self.enter_terminal(TerminalCause::ConnectionReset)
    }

    pub(crate) fn device_failed(&mut self) -> bool {
        let changed = self.phase != ConnectionPhase::Terminal(TerminalCause::InternalError)
            || self.has_buffered_rx();
        self.receive.clear();
        self.phase = ConnectionPhase::Terminal(TerminalCause::InternalError);
        changed
    }

    /// Apply one decoded packet for this connection. A rejected packet never
    /// contributes payload or credit, and terminal causes are never replaced.
    pub(crate) fn receive(&mut self, header: &PacketHeader, payload: &[u8]) -> ReceiveOutcome {
        if header.operation == Operation::Reset {
            self.receive_reset();
            return ReceiveOutcome::None;
        }
        if matches!(self.phase, ConnectionPhase::Terminal(_)) {
            return ReceiveOutcome::SendReset;
        }

        match header.operation {
            Operation::Response if self.phase == ConnectionPhase::Connecting => {
                if self.update_peer_credit(header) {
                    self.phase = ConnectionPhase::Established;
                    ReceiveOutcome::Connected
                } else {
                    ReceiveOutcome::SendReset
                }
            }
            Operation::ReadWrite if self.phase == ConnectionPhase::Established => {
                if !payload.is_empty() && self.peer_shutdown & SHUTDOWN_SEND != 0
                    || payload.len() > self.credit().rx_allowance()
                {
                    return self.reject();
                }
                if self.receive.update_peer(advertisement(header)).is_ok()
                    && self.receive.try_append_packet(payload).is_ok()
                {
                    ReceiveOutcome::None
                } else {
                    self.reject()
                }
            }
            Operation::CreditUpdate if self.phase == ConnectionPhase::Established => {
                if self.update_peer_credit(header) {
                    ReceiveOutcome::None
                } else {
                    ReceiveOutcome::SendReset
                }
            }
            Operation::CreditRequest if self.phase == ConnectionPhase::Established => {
                if self.update_peer_credit(header) {
                    ReceiveOutcome::SendCreditUpdate
                } else {
                    ReceiveOutcome::SendReset
                }
            }
            Operation::Shutdown if self.phase == ConnectionPhase::Established => {
                if !self.update_peer_credit(header) {
                    return ReceiveOutcome::SendReset;
                }
                self.peer_shutdown |= header.flags & SHUTDOWN_BOTH;
                ReceiveOutcome::None
            }
            _ => self.reject(),
        }
    }

    fn update_peer_credit(&mut self, header: &PacketHeader) -> bool {
        if self.receive.update_peer(advertisement(header)).is_ok() {
            true
        } else {
            self.reject();
            false
        }
    }

    fn receive_reset(&mut self) {
        let cause = if self.phase == ConnectionPhase::Connecting {
            TerminalCause::Refused
        } else if self.shutdown_published == SHUTDOWN_BOTH || self.peer_shutdown == SHUTDOWN_BOTH {
            TerminalCause::OrderlyClosed
        } else {
            TerminalCause::ConnectionReset
        };
        self.enter_terminal(cause);
    }

    fn reject(&mut self) -> ReceiveOutcome {
        let cause = if self.phase == ConnectionPhase::Connecting {
            TerminalCause::Refused
        } else {
            TerminalCause::ConnectionReset
        };
        self.enter_terminal(cause);
        ReceiveOutcome::SendReset
    }

    fn enter_terminal(&mut self, cause: TerminalCause) -> bool {
        if matches!(self.phase, ConnectionPhase::Terminal(_)) {
            return false;
        }
        self.phase = ConnectionPhase::Terminal(cause);
        true
    }
}

fn advertisement(header: &PacketHeader) -> CreditAdvertisement {
    CreditAdvertisement {
        buf_alloc: header.buf_alloc,
        fwd_cnt: header.fwd_cnt,
    }
}
