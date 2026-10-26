//! Bounded, readiness-driven work shared by the host and Motor transports.
use std::net::SocketAddr;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use crate::config::{Config, Result};
use crate::crypto::{Action, BUFFER_SIZE, Crypto};

pub const TICK: Duration = Duration::from_millis(250);
pub const BATCH: usize = 32;

/// Pending operations register their waker. Only fatal transport failures
/// return errors; a bounded queue drop remains an ordinary packet loss.
pub trait Io {
    type Error;
    fn receive_outer(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<std::result::Result<(usize, SocketAddr), Self::Error>>;
    fn receive_inner(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<std::result::Result<usize, Self::Error>>;
    fn send_outer(
        &mut self,
        cx: &mut Context<'_>,
        packet: &[u8],
        destination: SocketAddr,
    ) -> Poll<std::result::Result<(), Self::Error>>;
    fn submit_inner(&mut self, packet: &[u8]) -> bool;
}

#[derive(Default, Debug)]
pub struct Counters {
    pub outer_dropped: u64,
    pub inner_dropped: u64,
    pub batches: u64,
    pub timer_ticks: u64,
    pub transport_failures: u64,
}

struct Pending {
    buffer: Box<[u8; BUFFER_SIZE]>,
    used: Option<(usize, SocketAddr)>,
}

pub struct Scheduler {
    pub crypto: Crypto,
    pub counters: Counters,
    // One extra receive byte distinguishes an oversized/truncated datagram.
    input: Box<[u8; BUFFER_SIZE + 1]>,
    output: Box<[u8; BUFFER_SIZE]>,
    pending: Pending,
    deadline: Instant,
    prefer_rx: bool,
    flush_cursor: usize,
}

pub(crate) fn buffer<const N: usize>() -> Result<Box<[u8; N]>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(N)
        .map_err(|_| "cannot reserve packet buffer")?;
    bytes.resize(N, 0);
    Ok(bytes.into_boxed_slice().try_into().ok().unwrap())
}

impl Scheduler {
    pub fn new(config: &Config, now: Instant) -> Result<Self> {
        Ok(Self {
            crypto: Crypto::new(config)?,
            counters: Counters::default(),
            input: buffer()?,
            output: buffer()?,
            pending: Pending {
                buffer: buffer()?,
                used: None,
            },
            deadline: now + TICK,
            prefer_rx: true,
            flush_cursor: 0,
        })
    }

    /// The caller also registers a timer for this absolute deadline.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    pub fn poll<I: Io>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut I,
        now: Instant,
    ) -> Poll<std::result::Result<(), I::Error>> {
        match self.work(cx, io, now) {
            Ok(()) => Poll::Pending,
            Err(error) => {
                self.counters.transport_failures += 1;
                self.pending.used = None;
                Poll::Ready(Err(error))
            }
        }
    }

    fn work<I: Io>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut I,
        now: Instant,
    ) -> std::result::Result<(), I::Error> {
        let mut operations = 0;
        if let Some((len, destination)) = self.pending.used
            && let Poll::Ready(result) = io.send_outer(cx, &self.pending.buffer[..len], destination)
        {
            result?;
            self.pending.used = None;
            operations += 1;
        }
        if now >= self.deadline {
            // Preserve the original cadence, without replaying missed ticks.
            let remainder = (now - self.deadline).as_nanos() % TICK.as_nanos();
            self.deadline = now + TICK - Duration::from_nanos(remainder as u64);
            self.crypto.begin_timer_tick();
            self.counters.timer_ticks += 1;
            for peer in 0..self.crypto.peer_count() {
                let action = self.crypto.timer(peer, &mut self.output);
                emit(cx, io, action, &mut self.pending, &mut self.counters)?;
                operations += 1;
            }
        }
        while operations < BATCH {
            let first_rx = self.prefer_rx;
            let mut progressed = false;
            for rx in [first_rx, !first_rx] {
                if self.packet(cx, io, rx)? {
                    operations += 1;
                    self.prefer_rx = !rx;
                    progressed = true;
                    break;
                }
            }
            if !progressed {
                return Ok(());
            }
        }
        self.counters.batches += 1;
        cx.waker().wake_by_ref();
        Ok(())
    }

    fn packet<I: Io>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut I,
        rx: bool,
    ) -> std::result::Result<bool, I::Error> {
        let action = if rx {
            let Poll::Ready(result) = io.receive_outer(cx, &mut self.input[..]) else {
                return Ok(false);
            };
            let (len, source) = result?;
            self.crypto
                .receive(source, &self.input[..len], &mut self.output)
        } else {
            if self.pending.used.is_some() {
                return Ok(false);
            }
            let peers = self.crypto.peer_count();
            let flush = (0..peers)
                .map(|offset| (self.flush_cursor + offset) % peers)
                .find(|peer| self.crypto.needs_flush(*peer));
            if let Some(peer) = flush {
                self.flush_cursor = (peer + 1) % peers;
                self.crypto.flush(peer, &mut self.output)
            } else {
                let Poll::Ready(result) = io.receive_inner(cx, &mut self.input[..]) else {
                    return Ok(false);
                };
                self.crypto
                    .encapsulate(&self.input[..result?], &mut self.output)
            }
        };
        emit(cx, io, action, &mut self.pending, &mut self.counters)?;
        Ok(true)
    }
}

#[cfg(test)]
#[path = "schedule_tests.rs"]
mod tests;

fn emit<I: Io>(
    cx: &mut Context<'_>,
    io: &mut I,
    action: Action<'_>,
    pending: &mut Pending,
    counters: &mut Counters,
) -> std::result::Result<(), I::Error> {
    match action {
        Action::None => {}
        Action::Tunnel(packet) => {
            if !io.submit_inner(packet) {
                counters.inner_dropped += 1;
            }
        }
        Action::Network {
            destination,
            packet,
        } => match io.send_outer(cx, packet, destination) {
            Poll::Ready(result) => result?,
            Poll::Pending if pending.used.is_none() => {
                pending.buffer[..packet.len()].copy_from_slice(packet);
                pending.used = Some((packet.len(), destination));
            }
            Poll::Pending => counters.outer_dropped += 1,
        },
    }
    Ok(())
}
