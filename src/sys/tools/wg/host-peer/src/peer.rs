//! The independent test peer uses upstream's ordinary single-peer API.
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use std::net::SocketAddr;

pub const BUFFER_SIZE: usize = 2048;

pub enum Action<'a> {
    None,
    Network(SocketAddr, &'a [u8]),
    Inner(&'a [u8]),
}

pub struct Peer {
    tunnel: Tunn,
    endpoint: Option<SocketAddr>,
    flush: bool,
    pub padding: bool,
    pub rejected: u64,
}

impl Peer {
    pub fn new(
        private_key: [u8; 32],
        public_key: [u8; 32],
        preshared_key: Option<[u8; 32]>,
        endpoint: Option<SocketAddr>,
    ) -> Self {
        Self {
            tunnel: Tunn::new(
                StaticSecret::from(private_key),
                PublicKey::from(public_key),
                preshared_key,
                None,
                1,
                None,
            ),
            endpoint,
            flush: false,
            padding: false,
            rejected: 0,
        }
    }

    pub fn endpoint(&self) -> Option<SocketAddr> {
        self.endpoint
    }

    pub fn configure_endpoint(&mut self, endpoint: SocketAddr) {
        self.endpoint = Some(endpoint);
    }

    pub fn handshake<'a>(&mut self, output: &'a mut [u8; BUFFER_SIZE]) -> Action<'a> {
        match (
            self.endpoint,
            self.tunnel.format_handshake_initiation(output, true),
        ) {
            (Some(endpoint), TunnResult::WriteToNetwork(packet)) => {
                Action::Network(endpoint, packet)
            }
            _ => Action::None,
        }
    }

    pub fn receive<'a>(
        &mut self,
        source: SocketAddr,
        datagram: &[u8],
        output: &'a mut [u8; BUFFER_SIZE],
    ) -> Action<'a> {
        // Empty input means "flush" to boringtun, not a network datagram.
        if datagram.is_empty() || datagram.len() > BUFFER_SIZE {
            self.rejected += 1;
            return Action::None;
        }
        match self.tunnel.decapsulate(Some(source.ip()), datagram, output) {
            TunnResult::WriteToNetwork(packet) => {
                // A response or keepalive follows authentication. A cookie
                // challenge does not authenticate the sender or permit roaming.
                if matches!(packet.first(), Some(2 | 4)) {
                    self.endpoint = Some(source);
                }
                self.flush = true;
                Action::Network(source, packet)
            }
            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                self.endpoint = Some(source);
                Action::Inner(packet)
            }
            TunnResult::Done => {
                if datagram[0] == 4 {
                    self.endpoint = Some(source); // Authenticated empty keepalive.
                }
                Action::None
            }
            TunnResult::Err(_) => {
                self.rejected += 1;
                Action::None
            }
        }
    }

    pub fn send<'a>(&mut self, packet: &[u8], output: &'a mut [u8; BUFFER_SIZE]) -> Action<'a> {
        if packet.len() > crate::link::MTU {
            self.rejected += 1;
            return Action::None;
        }
        let Some(endpoint) = self.endpoint else {
            return Action::None;
        };
        // The fixture can exercise padded wire packets without changing the
        // upstream crate. The authenticated IP length still excludes padding.
        let mut padded = [0; crate::link::MTU.next_multiple_of(16)];
        let packet = if self.padding {
            padded[..packet.len()].copy_from_slice(packet);
            &padded[..packet.len().next_multiple_of(16)]
        } else {
            packet
        };
        match self.tunnel.encapsulate(packet, output) {
            TunnResult::WriteToNetwork(packet) => Action::Network(endpoint, packet),
            TunnResult::Done => Action::None,
            _ => {
                self.rejected += 1;
                Action::None
            }
        }
    }

    pub fn flush<'a>(&mut self, output: &'a mut [u8; BUFFER_SIZE]) -> Action<'a> {
        let Some(endpoint) = self.endpoint.filter(|_| self.flush) else {
            return Action::None;
        };
        match self.tunnel.decapsulate(None, &[], output) {
            TunnResult::WriteToNetwork(packet) => Action::Network(endpoint, packet),
            _ => {
                self.flush = false;
                Action::None
            }
        }
    }

    pub fn timer<'a>(&mut self, output: &'a mut [u8; BUFFER_SIZE]) -> Action<'a> {
        match (self.endpoint, self.tunnel.update_timers(output)) {
            (Some(endpoint), TunnResult::WriteToNetwork(packet)) => {
                Action::Network(endpoint, packet)
            }
            _ => Action::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network(action: Action<'_>) -> Vec<u8> {
        match action {
            Action::Network(_, packet) => packet.to_vec(),
            _ => panic!("expected network output"),
        }
    }

    #[test]
    fn handshake_replay_and_authenticated_roaming() {
        let a_addr: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let b_addr: SocketAddr = "127.0.0.1:2000".parse().unwrap();
        let moved: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let a_key = [11; 32];
        let b_key = [22; 32];
        let public = |key| *PublicKey::from(&StaticSecret::from(key)).as_bytes();
        let mut a = Peer::new(a_key, public(b_key), None, Some(b_addr));
        let mut b = Peer::new(b_key, public(a_key), None, None);
        let mut output = [0; BUFFER_SIZE];
        let init = network(a.send(&[], &mut output));
        let reply = network(b.receive(a_addr, &init, &mut output));
        assert_eq!(b.endpoint(), Some(a_addr));
        let keepalive = network(a.receive(b_addr, &reply, &mut output));
        assert!(matches!(
            b.receive(a_addr, &keepalive, &mut output),
            Action::None
        ));
        let keepalive = network(a.send(&[], &mut output));
        assert!(matches!(
            b.receive(moved, &keepalive, &mut output),
            Action::None
        ));
        assert_eq!(b.endpoint(), Some(moved));
        let rejected = b.rejected;
        b.receive(a_addr, &keepalive, &mut output); // Replay must not move it back.
        assert_eq!(b.rejected, rejected + 1);
        assert_eq!(b.endpoint(), Some(moved));
        for invalid in [&[][..], &[0; 4], &[0; BUFFER_SIZE + 1]] {
            b.receive(a_addr, invalid, &mut output);
        }
        assert_eq!(b.rejected, rejected + 4);
        assert_eq!(b.endpoint(), Some(moved));

        // A restarted responder has no session, even while its peer still
        // does. The fixture can force a fresh initiation without a timer wait.
        let mut restarted = Peer::new(b_key, public(a_key), None, None);
        let init = network(a.handshake(&mut output));
        // Initiation does not replace the old session. A probe sent before
        // the response still uses that session and is lost at the new peer.
        let premature = network(a.send(&[], &mut output));
        assert_eq!(premature[0], 4);
        restarted.receive(moved, &premature, &mut output);
        assert_eq!(restarted.rejected, 1);
        let reply = network(restarted.receive(moved, &init, &mut output));
        let keepalive = network(a.receive(b_addr, &reply, &mut output));
        assert!(matches!(
            restarted.receive(moved, &keepalive, &mut output),
            Action::None
        ));
        assert_eq!(restarted.endpoint(), Some(moved));
        assert_eq!(restarted.rejected, 1);
    }
}
