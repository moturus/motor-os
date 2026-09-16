use std::io::{ErrorKind, Result as IoResult};

use super::credit::{CreditAdvertisement, CreditError, CreditState};
use super::stream::{EstablishedStream, ReadOutcome};
use super::vsock_wire::{Operation, PacketHeader, SHUTDOWN_RECEIVE, SHUTDOWN_SEND};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TerminalCause {
    Refused,
    ConnectionReset,
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
    stream: EstablishedStream,
}

impl Connection {
    /// Allocate receive capacity before the owner publishes REQUEST.
    pub(crate) fn new_outgoing() -> IoResult<Self> {
        Ok(Self {
            phase: ConnectionPhase::Connecting,
            stream: EstablishedStream::new()?,
        })
    }

    /// Allocate receive capacity and validate REQUEST credit before the owner
    /// publishes RESPONSE or makes the connection available for accept.
    pub(crate) fn new_incoming(request: &PacketHeader) -> IoResult<Self> {
        if request.operation != Operation::Request {
            return Err(ErrorKind::InvalidInput.into());
        }
        let mut stream = EstablishedStream::new()?;
        stream
            .update_peer_credit(advertisement(request))
            .map_err(|_| ErrorKind::InvalidData)?;
        Ok(Self {
            phase: ConnectionPhase::Established,
            stream,
        })
    }

    pub(crate) fn phase(&self) -> ConnectionPhase {
        self.phase
    }

    pub(crate) fn credit(&self) -> &CreditState {
        self.stream.credit()
    }

    pub(crate) fn charge_tx_after_publish(&mut self, len: u32) -> Result<(), CreditError> {
        self.stream.charge_tx_after_publish(len)
    }

    pub(crate) fn accepts_new_writes(&self) -> bool {
        self.phase == ConnectionPhase::Established && self.stream.accepts_new_writes()
    }

    pub(crate) fn read_into_reserved(&mut self, dst: &mut [u8]) -> ReadOutcome {
        self.stream.read_into_reserved(dst)
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
                if !payload.is_empty() && !self.stream.accepts_peer_data() {
                    return self.reject();
                }
                if self
                    .stream
                    .try_receive_packet(advertisement(header), payload)
                    .is_ok()
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
                self.stream.peer_shutdown(
                    header.flags & SHUTDOWN_RECEIVE != 0,
                    header.flags & SHUTDOWN_SEND != 0,
                );
                ReceiveOutcome::None
            }
            _ => self.reject(),
        }
    }

    fn update_peer_credit(&mut self, header: &PacketHeader) -> bool {
        if self
            .stream
            .update_peer_credit(advertisement(header))
            .is_ok()
        {
            true
        } else {
            self.reject();
            false
        }
    }

    fn receive_reset(&mut self) {
        if matches!(self.phase, ConnectionPhase::Terminal(_)) {
            return;
        }
        let cause = if self.phase == ConnectionPhase::Connecting {
            TerminalCause::Refused
        } else {
            TerminalCause::ConnectionReset
        };
        self.stream.peer_reset();
        self.phase = ConnectionPhase::Terminal(cause);
    }

    fn reject(&mut self) -> ReceiveOutcome {
        self.receive_reset();
        ReceiveOutcome::SendReset
    }
}

fn advertisement(header: &PacketHeader) -> CreditAdvertisement {
    CreditAdvertisement {
        buf_alloc: header.buf_alloc,
        fwd_cnt: header.fwd_cnt,
    }
}
