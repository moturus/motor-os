use crate::options::Options;
use crate::peer::{Action, BUFFER_SIZE, Peer};
use crate::stack::Stack;
use crate::transport::{Event, Transport};
use moto_netstack::time::Instant;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender};
use std::time::{Duration, Instant as Clock};

pub struct Server {
    stack: Stack,
    peer: Option<Peer>,
    plain_endpoint: Option<SocketAddr>,
    transport: Transport,
    last_ciphertext: Vec<u8>,
    waiting_handshake: bool,
    sequence: u16,
    outer_rx: u64,
    outer_tx: u64,
    inner_rx: u64,
    inner_tx: u64,
    dropped: u64,
}

impl Server {
    pub fn new(options: Options, sender: SyncSender<Event>) -> Result<Self, &'static str> {
        let stack = Stack::new(&options.addresses, Instant::ZERO)
            .map_err(|_| "cannot initialize stack entropy")?;
        let transport =
            Transport::bind(options.bind, sender).map_err(|_| "cannot bind transport")?;
        let peer = options
            .keys
            .map(|keys| Peer::new(keys.private, keys.peer, keys.psk, options.endpoint));
        Ok(Self {
            stack,
            peer,
            transport,
            plain_endpoint: options.endpoint,
            last_ciphertext: Vec::with_capacity(BUFFER_SIZE),
            waiting_handshake: false,
            sequence: 0,
            outer_rx: 0,
            outer_tx: 0,
            inner_rx: 0,
            inner_tx: 0,
            dropped: 0,
        })
    }

    fn deliver(&mut self, action: Action<'_>) -> Result<(), &'static str> {
        match action {
            Action::None => {}
            Action::Network(endpoint, packet) => {
                self.transport
                    .send(endpoint, packet)
                    .map_err(|_| "UDP send failed")?;
                self.outer_tx += 1;
                if packet.first() == Some(&4) {
                    self.last_ciphertext.clear();
                    self.last_ciphertext.extend_from_slice(packet);
                }
            }
            Action::Inner(packet) => {
                if self.stack.receive(packet) {
                    self.inner_rx += 1;
                } else {
                    self.dropped += 1;
                }
            }
        }
        Ok(())
    }

    fn receive(
        &mut self,
        source: SocketAddr,
        packet: &[u8],
        buffer: &mut [u8; BUFFER_SIZE],
    ) -> Result<(), &'static str> {
        self.outer_rx += 1;
        if let Some(peer) = &mut self.peer {
            let action = peer.receive(source, packet, buffer);
            let completed = packet.first() == Some(&2)
                && matches!(&action, Action::Network(_, reply) if reply.first() == Some(&4));
            self.deliver(action)?;
            if completed && self.waiting_handshake {
                self.waiting_handshake = false;
                println!("HANDSHAKE OK");
                io::stdout().flush().map_err(|_| "stdout closed")?;
            }
            Ok(())
        } else if Some(source) == self.plain_endpoint {
            self.deliver(Action::Inner(packet))
        } else {
            self.dropped += 1;
            Ok(())
        }
    }

    fn poll(&mut self, now: Instant, buffer: &mut [u8; BUFFER_SIZE]) -> Result<(), &'static str> {
        self.stack.poll(now);
        for _ in 0..32 {
            let Some(packet) = self.stack.take_packet() else {
                break;
            };
            self.inner_tx += 1;
            let action = if let Some(peer) = &mut self.peer {
                peer.send(&packet, buffer)
            } else {
                Action::Network(self.plain_endpoint.unwrap(), &packet)
            };
            self.deliver(action)?;
        }
        for _ in 0..32 {
            let Some(peer) = &mut self.peer else {
                break;
            };
            let action = peer.flush(buffer);
            if matches!(action, Action::None) {
                break;
            }
            self.deliver(action)?;
        }
        if let Some(success) = self.stack.poll_ping(now) {
            println!("PING {}", if success { "OK" } else { "TIMEOUT" });
            io::stdout().flush().map_err(|_| "stdout closed")?;
        }
        Ok(())
    }

    fn command(
        &mut self,
        line: &str,
        now: Instant,
        sender: &SyncSender<Event>,
        buffer: &mut [u8; BUFFER_SIZE],
    ) -> Result<bool, &'static str> {
        let args: Vec<_> = line.split_ascii_whitespace().collect();
        match args.as_slice() {
            ["quit"] => return Ok(true),
            ["endpoint", address] => {
                if self.peer.is_some() {
                    return Err("WireGuard learns endpoints through authentication");
                }
                let address: SocketAddr = address.parse().map_err(|_| "invalid endpoint")?;
                if address.port() == 0
                    || address.ip().is_unspecified()
                    || address.ip().is_multicast()
                {
                    return Err("endpoint must be unicast with a nonzero port");
                }
                self.plain_endpoint = Some(address);
                println!("ENDPOINT {address}");
            }
            ["ping", address] => {
                let address = address.parse().map_err(|_| "invalid probe address")?;
                self.sequence = self.sequence.wrapping_add(1);
                self.stack.start_ping(address, self.sequence, now)?;
                println!("PING-START {address}");
            }
            ["keepalive"] => {
                let peer = self.peer.as_mut().ok_or("plain mode has no keepalive")?;
                let action = peer.send(&[], buffer);
                self.deliver(action)?;
                println!("KEEPALIVE");
            }
            ["handshake"] => {
                let peer = self.peer.as_mut().ok_or("plain mode has no handshake")?;
                let action = peer.handshake(buffer);
                self.deliver(action)?;
                self.waiting_handshake = true;
                println!("HANDSHAKE");
            }
            ["padding", "on"] => {
                self.peer
                    .as_mut()
                    .ok_or("plain mode has no wire padding")?
                    .padding = true;
                println!("PADDING ON");
            }
            ["replay"] | ["tamper"] | ["malformed"] => {
                let endpoint = self
                    .peer
                    .as_ref()
                    .and_then(Peer::endpoint)
                    .ok_or("no peer endpoint")?;
                let mut packet = if args[0] == "malformed" {
                    vec![0; BUFFER_SIZE + 1]
                } else if self.last_ciphertext.is_empty() {
                    return Err("no ciphertext to repeat");
                } else {
                    self.last_ciphertext.clone()
                };
                if args[0] == "tamper" {
                    *packet.last_mut().unwrap() ^= 1;
                }
                self.transport
                    .send(endpoint, &packet)
                    .map_err(|_| "UDP send failed")?;
                self.outer_tx += 1;
                println!("SENT {}", args[0]);
            }
            ["roam", address] | ["roam", address, _] => {
                let peer = self.peer.as_mut().ok_or("roaming requires WireGuard")?;
                let address: SocketAddr = address.parse().map_err(|_| "invalid roaming bind")?;
                let endpoint = if let Some(endpoint) = args.get(2) {
                    endpoint.parse().map_err(|_| "invalid roaming endpoint")?
                } else {
                    peer.endpoint().ok_or("no peer endpoint")?
                };
                if address.is_ipv4() != endpoint.is_ipv4()
                    || endpoint.port() == 0
                    || endpoint.ip().is_unspecified()
                    || endpoint.ip().is_multicast()
                {
                    return Err("roaming endpoint must be unicast in the bound family");
                }
                let transport = Transport::bind(address, sender.clone())
                    .map_err(|_| "cannot bind roaming transport")?;
                // An operator-directed family change needs the peer's address
                // in that family; received packets still learn it only after auth.
                peer.configure_endpoint(endpoint);
                self.transport = transport;
                println!(
                    "ROAM {}",
                    self.transport
                        .local_addr()
                        .map_err(|_| "cannot read bound address")?
                );
            }
            ["stats"] => {
                println!(
                    "STATS outer_rx={} outer_tx={} inner_rx={} inner_tx={} rejected={} dropped={}",
                    self.outer_rx,
                    self.outer_tx,
                    self.inner_rx,
                    self.inner_tx,
                    self.peer.as_ref().map_or(0, |peer| peer.rejected),
                    self.dropped + self.transport.dropped()
                );
            }
            _ => return Err("unknown command"),
        }
        io::stdout().flush().map_err(|_| "stdout closed")?;
        Ok(false)
    }

    pub fn run(
        mut self,
        receiver: Receiver<Event>,
        sender: SyncSender<Event>,
    ) -> Result<(), &'static str> {
        println!(
            "READY {}",
            self.transport
                .local_addr()
                .map_err(|_| "cannot read bound address")?
        );
        io::stdout().flush().map_err(|_| "stdout closed")?;
        let start = Clock::now();
        let mut timer_deadline = start + Duration::from_millis(250);
        let mut buffer = [0; BUFFER_SIZE];
        loop {
            if !self.transport.running() {
                return Err("UDP receiver stopped");
            }
            let clock = Clock::now();
            let now = Instant::from_micros(clock.duration_since(start).as_micros() as i64);
            if clock >= timer_deadline {
                if let Some(peer) = &mut self.peer {
                    let action = peer.timer(&mut buffer);
                    self.deliver(action)?;
                }
                while timer_deadline <= clock {
                    timer_deadline += Duration::from_millis(250);
                }
            }
            self.poll(now, &mut buffer)?;
            let delay = Duration::from_micros(self.stack.poll_delay(now).total_micros())
                .min(timer_deadline.saturating_duration_since(Clock::now()));
            let event = match receiver.recv_timeout(delay) {
                Ok(event) => event,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return Ok(()),
            };
            // Limit receive work so even continuous UDP input cannot starve
            // the independent WireGuard timer or inner socket services.
            for event in std::iter::once(event).chain(receiver.try_iter().take(31)) {
                match event {
                    Event::Datagram(source, packet) => {
                        self.receive(source, &packet, &mut buffer)?
                    }
                    Event::Command(line) => match self.command(&line, now, &sender, &mut buffer) {
                        Ok(true) => return Ok(()),
                        Ok(false) => {}
                        Err(error) => println!("ERROR {error}"),
                    },
                }
            }
        }
    }
}
