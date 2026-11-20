//! One device's authenticated peer dispatch and inner-address ownership.
use boringtun::noise::{Packet, Tunn, TunnResult, handshake, rate_limiter::RateLimiter};
use boringtun::x25519::{PublicKey, StaticSecret};
use ipnetwork::IpNetwork;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::config::{Config, Result};

pub const MTU: usize = 1420;
pub const BUFFER_SIZE: usize = 2048;

#[derive(Default, Debug)]
pub struct Counters {
    pub malformed: u64,
    pub unauthenticated: u64,
    pub unknown_peer: u64,
    pub disallowed_source: u64,
    pub no_owner: u64,
    pub no_endpoint: u64,
    pub crypto_errors: u64,
}

pub enum Action<'a> {
    None,
    Network {
        destination: SocketAddr,
        packet: &'a [u8],
    },
    Tunnel(&'a [u8]),
}

struct Peer {
    key: [u8; 32],
    tunnel: Tunn,
    endpoint: Option<SocketAddr>,
    flush: bool,
}

pub struct Crypto {
    private_key: StaticSecret,
    public_key: PublicKey,
    limiter: Arc<RateLimiter>,
    peers: Vec<Peer>,
    owners: Vec<(IpNetwork, usize)>,
    pub counters: Counters,
}

impl Crypto {
    pub fn new(config: &Config) -> Result<Self> {
        let mut peers = Vec::new();
        peers
            .try_reserve_exact(config.peers.len())
            .map_err(|_| "cannot reserve peers")?;
        let mut owners = Vec::new();
        let count = config.peers.iter().map(|peer| peer.allowed_ips.len()).sum();
        owners
            .try_reserve_exact(count)
            .map_err(|_| "cannot reserve prefix owners")?;
        let private_key = StaticSecret::from(config.private_key);
        let public_key = PublicKey::from(&private_key);
        let limiter = Arc::new(RateLimiter::new(&public_key, 100));
        for (index, peer) in config.peers.iter().enumerate() {
            owners.extend(peer.allowed_ips.iter().map(|prefix| (*prefix, index)));
            peers.push(Peer {
                key: peer.public_key,
                tunnel: Tunn::new(
                    private_key.clone(),
                    PublicKey::from(peer.public_key),
                    peer.preshared_key,
                    peer.persistent_keepalive,
                    (index + 1) as u32,
                    Some(limiter.clone()),
                ),
                endpoint: peer.endpoint,
                flush: false,
            });
        }
        owners.sort_by_key(|(prefix, _)| std::cmp::Reverse(prefix.prefix()));
        Ok(Self {
            private_key,
            public_key,
            limiter,
            peers,
            owners,
            counters: Counters::default(),
        })
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn endpoint(&self, peer: usize) -> Option<SocketAddr> {
        self.peers[peer].endpoint
    }

    pub fn peer_stats(&self, peer: usize) -> (Option<std::time::Duration>, u64, u64) {
        let (handshake, sent, received, _, _) = self.peers[peer].tunnel.stats();
        (handshake, sent as u64, received as u64)
    }

    fn owner(&self, address: IpAddr) -> Option<usize> {
        self.owners
            .iter()
            .find(|(prefix, _)| prefix.contains(address))
            .map(|(_, owner)| *owner)
    }

    pub fn encapsulate<'a>(
        &mut self,
        packet: &[u8],
        output: &'a mut [u8; BUFFER_SIZE],
    ) -> Action<'a> {
        let Some((_, destination)) = crate::ip::addresses(packet).filter(|_| packet.len() <= MTU)
        else {
            self.counters.malformed += 1;
            return Action::None;
        };
        let Some(index) = self.owner(destination) else {
            self.counters.no_owner += 1;
            return Action::None;
        };
        let peer = &mut self.peers[index];
        let Some(destination) = peer.endpoint else {
            self.counters.no_endpoint += 1;
            return Action::None;
        };
        match peer.tunnel.encapsulate(packet, output) {
            TunnResult::WriteToNetwork(packet) => Action::Network {
                destination,
                packet,
            },
            TunnResult::Done => Action::None,
            _ => {
                self.counters.crypto_errors += 1;
                Action::None
            }
        }
    }

    pub fn receive<'a>(
        &mut self,
        source: SocketAddr,
        datagram: &[u8],
        output: &'a mut [u8; BUFFER_SIZE],
    ) -> Action<'a> {
        if datagram.len() > BUFFER_SIZE || source.port() == 0 {
            self.counters.malformed += 1;
            return Action::None;
        }
        let mut cookie = [0; 64];
        let packet = match self
            .limiter
            .verify_packet(Some(source.ip()), datagram, &mut cookie)
        {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(packet)) => {
                output[..packet.len()].copy_from_slice(packet);
                return Action::Network {
                    destination: source,
                    packet: &output[..packet.len()],
                };
            }
            Err(_) => {
                self.counters.unauthenticated += 1;
                return Action::None;
            }
        };
        let cookie_reply = matches!(packet, Packet::PacketCookieReply(_));
        let index = match &packet {
            Packet::HandshakeInit(init) => {
                match handshake::parse_handshake_anon(&self.private_key, &self.public_key, init) {
                    Ok(init) => self
                        .peers
                        .iter()
                        .position(|peer| peer.key == init.peer_static_public),
                    Err(_) => {
                        self.counters.unauthenticated += 1;
                        return Action::None;
                    }
                }
            }
            Packet::HandshakeResponse(response) => (response.receiver_idx >> 8)
                .checked_sub(1)
                .map(|idx| idx as usize),
            Packet::PacketCookieReply(cookie) => (cookie.receiver_idx >> 8)
                .checked_sub(1)
                .map(|idx| idx as usize),
            Packet::PacketData(data) => (data.receiver_idx >> 8)
                .checked_sub(1)
                .map(|idx| idx as usize),
        };
        let Some(index) = index.filter(|index| *index < self.peers.len()) else {
            self.counters.unknown_peer += 1;
            return Action::None;
        };
        let peer = &mut self.peers[index];
        let result = peer.tunnel.handle_verified_packet(packet, output);
        if matches!(result, TunnResult::Err(_)) {
            self.counters.unauthenticated += 1;
            return Action::None;
        }
        // Empty authenticated data and both handshake directions can roam.
        // A valid cookie reply proves nothing about a peer's outer endpoint.
        if !cookie_reply {
            peer.endpoint = Some(source);
        }
        match result {
            TunnResult::WriteToNetwork(packet) => {
                peer.flush = true;
                Action::Network {
                    destination: source,
                    packet,
                }
            }
            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                let Some((address, _)) =
                    crate::ip::addresses(packet).filter(|_| packet.len() <= MTU)
                else {
                    self.counters.malformed += 1;
                    return Action::None;
                };
                if self.owner(address) != Some(index) {
                    self.counters.disallowed_source += 1;
                    return Action::None;
                }
                Action::Tunnel(packet)
            }
            _ => Action::None,
        }
    }

    pub fn needs_flush(&self, peer: usize) -> bool {
        self.peers[peer].flush
    }

    pub fn flush<'a>(&mut self, index: usize, output: &'a mut [u8; BUFFER_SIZE]) -> Action<'a> {
        let peer = &mut self.peers[index];
        if !peer.flush {
            return Action::None;
        }
        let Some(destination) = peer.endpoint else {
            peer.flush = false;
            self.counters.no_endpoint += 1;
            return Action::None;
        };
        match peer.tunnel.decapsulate(None, &[], output) {
            TunnResult::WriteToNetwork(packet) => Action::Network {
                destination,
                packet,
            },
            result => {
                peer.flush = false;
                if matches!(result, TunnResult::Err(_)) {
                    self.counters.crypto_errors += 1;
                }
                Action::None
            }
        }
    }

    pub fn begin_timer_tick(&self) {
        self.limiter.reset_count();
    }

    pub fn timer<'a>(&mut self, index: usize, output: &'a mut [u8; BUFFER_SIZE]) -> Action<'a> {
        let peer = &mut self.peers[index];
        match peer.tunnel.update_timers(output) {
            TunnResult::WriteToNetwork(packet) => match peer.endpoint {
                Some(destination) => Action::Network {
                    destination,
                    packet,
                },
                None => {
                    self.counters.no_endpoint += 1;
                    Action::None
                }
            },
            TunnResult::Done => Action::None,
            _ => {
                self.counters.crypto_errors += 1;
                Action::None
            }
        }
    }
}
