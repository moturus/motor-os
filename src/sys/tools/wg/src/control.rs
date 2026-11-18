//! Redacted, bounded control messages. No configuration or secret type crosses IPC.
use crate::config::{MAX_ADDRESSES, MAX_PEERS, MAX_PREFIXES, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use ipnetwork::IpNetwork;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const VERSION: u16 = 1;
pub const GET_INTERFACE: u16 = 1;
pub const GET_PEER: u16 = 2;
pub const STOP: u16 = 3;
pub const HELLO: u16 = 10;
pub const READY: u16 = 11;
pub const COMMITTED: u16 = 12;
pub const START_ERROR: u16 = 13;
pub const PAYLOAD_BYTES: usize = 4096 - 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    Starting,
    Up,
    Stopping,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    pub path: String,
    pub public_key: [u8; 32],
    pub listen_port: u16,
    pub transport_addresses: Vec<IpAddr>,
    pub cidrs: Vec<IpNetwork>,
    pub state: State,
    pub uptime_ms: u64,
    pub age_ms: u64,
    pub peer_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub public_key: [u8; 32],
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpNetwork>,
    pub keepalive: u16,
    pub has_psk: bool,
    pub handshake_ms: Option<u64>,
    pub received: u64,
    pub sent: u64,
}

#[derive(Clone)]
pub struct Snapshot {
    pub interface: Interface,
    pub peers: Vec<Peer>,
    pub captured: std::time::Instant,
}

impl Snapshot {
    pub fn new(config: &crate::config::Config, path: &str) -> Self {
        Self {
            interface: Interface {
                name: config.name.clone(),
                path: path.into(),
                public_key: config.public_key(),
                listen_port: config.listen_port,
                transport_addresses: config.transport_addresses.clone(),
                cidrs: config.cidrs.clone(),
                state: State::Starting,
                uptime_ms: 0,
                age_ms: 0,
                peer_count: config.peers.len(),
            },
            peers: config
                .peers
                .iter()
                .map(|peer| Peer {
                    public_key: peer.public_key,
                    endpoint: peer.endpoint,
                    allowed_ips: peer.allowed_ips.clone(),
                    keepalive: peer.persistent_keepalive.unwrap_or(0),
                    has_psk: peer.preshared_key.is_some(),
                    handshake_ms: None,
                    received: 0,
                    sent: 0,
                })
                .collect(),
            captured: std::time::Instant::now(),
        }
    }

    pub fn refresh(&mut self, scheduler: &crate::schedule::Scheduler, started: std::time::Instant) {
        self.captured = std::time::Instant::now();
        self.interface.uptime_ms = millis(self.captured.duration_since(started));
        for (index, peer) in self.peers.iter_mut().enumerate() {
            peer.endpoint = scheduler.crypto.endpoint(index);
            let (handshake, sent, received) = scheduler.crypto.peer_stats(index);
            peer.handshake_ms = handshake.map(millis);
            peer.sent = sent;
            peer.received = received;
        }
    }
}

pub fn millis(duration: std::time::Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

struct Writer(Vec<u8>);
impl Writer {
    fn u8(&mut self, value: u8) {
        self.0.push(value);
    }
    fn u16(&mut self, value: u16) {
        self.0.extend(value.to_le_bytes());
    }
    fn u64(&mut self, value: u64) {
        self.0.extend(value.to_le_bytes());
    }
    fn text(&mut self, value: &str, max: usize) -> Result<()> {
        if value.len() > max {
            return Err("control string exceeds limit");
        }
        self.u16(value.len() as u16);
        self.0.extend(value.bytes());
        Ok(())
    }
    fn address(&mut self, ip: IpAddr, prefix: u8, port: u16) {
        self.u8(if ip.is_ipv4() { 4 } else { 6 });
        self.u8(prefix);
        self.u16(port);
        match ip {
            IpAddr::V4(ip) => {
                self.0.extend(ip.octets());
                self.0.extend([0; 12]);
            }
            IpAddr::V6(ip) => self.0.extend(ip.octets()),
        }
    }
    fn finish(self) -> Result<Vec<u8>> {
        if self.0.len() > PAYLOAD_BYTES {
            Err("control reply exceeds channel")
        } else {
            Ok(self.0)
        }
    }
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn bytes<const N: usize>(&mut self) -> Result<[u8; N]> {
        if self.0.len() < N {
            return Err("truncated control message");
        }
        let (value, rest) = self.0.split_at(N);
        self.0 = rest;
        Ok(value.try_into().unwrap())
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.bytes()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.bytes()?))
    }
    fn boolean(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err("invalid control flags"),
        }
    }
    fn count(&mut self, max: usize) -> Result<usize> {
        let count = self.u16()? as usize;
        if count <= max {
            Ok(count)
        } else {
            Err("control count exceeds limit")
        }
    }
    fn text(&mut self, max: usize) -> Result<String> {
        let count = self.count(max)?;
        if self.0.len() < count {
            return Err("truncated control string");
        }
        let (value, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(std::str::from_utf8(value)
            .map_err(|_| "control string is not UTF-8")?
            .to_owned())
    }
    fn address(&mut self) -> Result<(IpAddr, u8, u16)> {
        let family = self.u8()?;
        let prefix = self.u8()?;
        let port = self.u16()?;
        let bytes = self.bytes::<16>()?;
        let ip = match family {
            4 if prefix <= 32 && bytes[4..] == [0; 12] => {
                IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
            }
            6 if prefix <= 128 => IpAddr::V6(Ipv6Addr::from(bytes)),
            _ => return Err("invalid control address"),
        };
        Ok((ip, prefix, port))
    }
    fn finish(self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err("unexpected control payload")
        }
    }
}

impl Interface {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.peer_count > MAX_PEERS
            || self.cidrs.len() > MAX_ADDRESSES
            || self.transport_addresses.len() > 2
        {
            return Err("control count exceeds limit");
        }
        let mut out = Writer(Vec::new());
        out.text(&self.name, 31)?;
        out.text(&self.path, 1024)?;
        out.0.extend(self.public_key);
        out.u16(self.listen_port);
        out.u8(self.state as u8);
        out.u64(self.uptime_ms);
        out.u64(self.age_ms);
        out.u16(self.peer_count as u16);
        out.u16(self.transport_addresses.len() as u16);
        for ip in &self.transport_addresses {
            out.address(*ip, 0, 0);
        }
        out.u16(self.cidrs.len() as u16);
        for cidr in &self.cidrs {
            out.address(cidr.ip(), cidr.prefix(), 0);
        }
        out.finish()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Reader(bytes);
        let name = input.text(31)?;
        crate::config::validate_name(&name)?;
        let path = input.text(1024)?;
        if !path.starts_with('/') {
            return Err("control config path is not absolute");
        }
        let public_key = input.bytes()?;
        let listen_port = input.u16()?;
        if listen_port == 0 {
            return Err("invalid control listen port");
        }
        let state = match input.u8()? {
            0 => State::Starting,
            1 => State::Up,
            2 => State::Stopping,
            _ => return Err("invalid lifecycle state"),
        };
        let uptime_ms = input.u64()?;
        let age_ms = input.u64()?;
        let peer_count = input.count(MAX_PEERS)?;
        let mut transport_addresses = Vec::new();
        for _ in 0..input.count(2)? {
            let (ip, prefix, port) = input.address()?;
            if prefix != 0 || port != 0 || !crate::config::unicast(ip) {
                return Err("invalid control transport address");
            }
            transport_addresses.push(ip);
        }
        let mut cidrs = Vec::new();
        for _ in 0..input.count(MAX_ADDRESSES)? {
            let (ip, prefix, port) = input.address()?;
            if port != 0 || !crate::config::unicast(ip) {
                return Err("invalid control CIDR");
            }
            cidrs.push(IpNetwork::new(ip, prefix).map_err(|_| "invalid control CIDR")?);
        }
        if transport_addresses.is_empty() || cidrs.is_empty() {
            return Err("missing control addresses");
        }
        input.finish()?;
        Ok(Self {
            name,
            path,
            public_key,
            listen_port,
            state,
            uptime_ms,
            age_ms,
            peer_count,
            transport_addresses,
            cidrs,
        })
    }
}

impl Peer {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.allowed_ips.is_empty() || self.allowed_ips.len() > MAX_PREFIXES {
            return Err("invalid control prefix count");
        }
        let mut out = Writer(Vec::new());
        out.0.extend(self.public_key);
        out.u8(self.endpoint.is_some().into());
        if let Some(endpoint) = self.endpoint {
            out.address(endpoint.ip(), 0, endpoint.port());
        }
        out.u16(self.keepalive);
        out.u8(self.has_psk.into());
        out.u8(self.handshake_ms.is_some().into());
        if let Some(age) = self.handshake_ms {
            out.u64(age);
        }
        out.u64(self.received);
        out.u64(self.sent);
        out.u16(self.allowed_ips.len() as u16);
        for prefix in &self.allowed_ips {
            out.address(prefix.ip(), prefix.prefix(), 0);
        }
        out.finish()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Reader(bytes);
        let public_key = input.bytes()?;
        let endpoint = if input.boolean()? {
            let (ip, prefix, port) = input.address()?;
            if prefix != 0 || port == 0 || !crate::config::unicast(ip) {
                return Err("invalid control endpoint");
            }
            Some(SocketAddr::new(ip, port))
        } else {
            None
        };
        let keepalive = input.u16()?;
        let has_psk = input.boolean()?;
        let handshake_ms = if input.boolean()? {
            Some(input.u64()?)
        } else {
            None
        };
        let received = input.u64()?;
        let sent = input.u64()?;
        let mut allowed_ips = Vec::new();
        for _ in 0..input.count(MAX_PREFIXES)? {
            let (ip, prefix, port) = input.address()?;
            if port != 0 {
                return Err("invalid control prefix");
            }
            allowed_ips.push(IpNetwork::new(ip, prefix).map_err(|_| "invalid control prefix")?);
        }
        if allowed_ips.is_empty() {
            return Err("missing control prefixes");
        }
        input.finish()?;
        Ok(Self {
            public_key,
            endpoint,
            allowed_ips,
            keepalive,
            has_psk,
            handshake_ms,
            received,
            sent,
        })
    }
}

pub fn display(pid: u64, interface: &Interface, peers: &[Peer]) -> String {
    use std::fmt::Write;
    let mut text = format!(
        "interface: {}\n  state: {}\n  pid: {pid} (Interactive)\n  config: {}\n  public key: {}\n  listen port: {}\n",
        interface.name,
        match interface.state {
            State::Starting => "starting",
            State::Up => "up",
            State::Stopping => "stopping",
        },
        crate::tool::escaped(&interface.path),
        STANDARD.encode(interface.public_key),
        interface.listen_port
    );
    let join = |values: Vec<String>| values.join(", ");
    writeln!(text, "  transport addresses: {}\n  cidrs: {}\n  mtu: {}\n  uptime: {}s\n  snapshot age: {}ms\n  peers: {}",
        join(interface.transport_addresses.iter().map(ToString::to_string).collect()), join(interface.cidrs.iter().map(ToString::to_string).collect()), crate::crypto::MTU, interface.uptime_ms / 1000, interface.age_ms, interface.peer_count).unwrap();
    for peer in peers {
        writeln!(text, "  peer: {}\n    endpoint: {}\n    allowed ips: {}\n    persistent keepalive: {}s\n    preshared key: {}\n    handshake: {}\n    transfer: {} bytes received, {} bytes sent",
            STANDARD.encode(peer.public_key), peer.endpoint.map_or_else(|| "not learned".into(), |value| value.to_string()), join(peer.allowed_ips.iter().map(ToString::to_string).collect()), peer.keepalive,
            if peer.has_psk { "set" } else { "none" }, peer.handshake_ms.map_or_else(|| "none (no current session)".into(), |age| format!("{}s ago", age.saturating_add(interface.age_ms) / 1000)), peer.received, peer.sent).unwrap();
    }
    text
}
