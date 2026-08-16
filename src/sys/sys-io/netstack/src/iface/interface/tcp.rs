use super::*;

use crate::socket::tcp::Socket;

impl InterfaceInner {
    /// The initial sequence number a connection between these two endpoints
    /// starts from. See [`tcp_isn`].
    pub(crate) fn tcp_isn(&self, local: IpEndpoint, remote: IpEndpoint) -> TcpSeqNumber {
        tcp_isn(&self.tcp_isn_key, self.now, local, remote)
    }

    pub(crate) fn process_tcp<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        handled_by_raw_socket: bool,
        ip_repr: IpRepr,
        ip_payload: &'frame [u8],
    ) -> Option<Packet<'frame>> {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let tcp_packet = check!(TcpPacket::new_checked(ip_payload));
        let checksum_caps = self.caps.checksum.rx_vouched(meta.l4_csum_vouched);
        let tcp_repr = match TcpRepr::parse(&tcp_packet, &src_addr, &dst_addr, &checksum_caps) {
            Ok(tcp_repr) => tcp_repr,
            Err(_) => {
                // Attribute the drop when a failed checksum is why. It is the
                // only parse failure worth counting separately: a corrupted or
                // spoofed segment is otherwise indistinguishable from silence.
                if checksum_caps.tcp.rx() && !tcp_packet.verify_checksum(&src_addr, &dst_addr) {
                    self.rx_csum_failed = self.rx_csum_failed.wrapping_add(1);
                }
                net_trace!("iface: malformed tcp packet");
                return None;
            }
        };

        // The exact tuple outranks everything: a segment matching a live
        // connection reaches that connection (RFC 5961 challenge handling),
        // never a listener sharing the port. The index is authoritative:
        // a miss means no socket holds this tuple.
        let local = IpEndpoint::new(ip_repr.dst_addr(), tcp_repr.dst_port);
        let remote = IpEndpoint::new(ip_repr.src_addr(), tcp_repr.src_port);
        let mut taker = sockets.tcp_tuple(local, remote);
        // What no connection claims may reach a listener -- but only what a
        // Listen socket would accept: nothing carrying an ACK and no RST.
        // The gate matters beyond SYNs: a bare FIN probe is *swallowed* by a
        // listening port today (Linux parity), and consulting the pool for
        // it keeps that -- `process` drops it -- where falling through would
        // leak the listener's existence through the reflector's reset.
        if taker.is_none() && tcp_repr.ack_number.is_none() && tcp_repr.control != TcpControl::Rst {
            taker = sockets.tcp_listener(local);
        }
        #[cfg(debug_assertions)]
        match taker {
            // A hit must accept the packet it was handed.
            Some(handle) => assert!(
                sockets
                    .get::<Socket>(handle)
                    .accepts(self, &ip_repr, &tcp_repr),
                "the demux index named a socket that refuses the packet"
            ),
            // A miss is authoritative: no socket at all may accept. The
            // retired linear scan survives as this debug-only oracle.
            None => {
                let acceptor = sockets.items().find(|item| {
                    Socket::downcast(&item.socket)
                        .is_some_and(|socket| socket.accepts(self, &ip_repr, &tcp_repr))
                });
                assert!(
                    acceptor.is_none(),
                    "socket {} accepts a packet the demux index missed",
                    acceptor.unwrap().meta.handle
                );
            }
        }
        // Find, then process: the accepting socket's identity can change
        // under `process()` (a listener taking a SYN, an RST emptying a
        // connection), so its recorded demux key is re-derived after.
        if let Some(handle) = taker {
            let reply = sockets
                .get_mut::<Socket>(handle)
                .process(self, &ip_repr, &tcp_repr);
            sockets.sync_demux(handle);
            return reply.map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)));
        }

        if tcp_repr.control == TcpControl::Rst
            || ip_repr.dst_addr().is_unspecified()
            || ip_repr.src_addr().is_unspecified()
            || handled_by_raw_socket
        {
            // Never reply to a TCP RST packet with another TCP RST packet.
            // Never send a TCP RST packet with unspecified addresses.
            // Never send a TCP RST when packet has been handled by raw socket.
            None
        } else {
            // A connection request no socket took: nothing is listening, or
            // every listening socket is already spoken for. The two answers
            // differ, and only the second is a backlog running out.
            let endpoint = IpEndpoint::new(ip_repr.dst_addr(), tcp_repr.dst_port);
            if tcp_repr.control == TcpControl::Syn && tcp_repr.ack_number.is_none() {
                // At the half-open cap the listener runs on SYN cookies: the
                // request is answered without a socket, and the completing
                // ACK will prove it came through here. The mode table
                // outranks the socket walk below -- under a long flood every
                // socket carrying the listen endpoint can expire, while the
                // table is owned by the listener's admission.
                if let Some(config) = self.syn_cookie_config(&endpoint) {
                    // Past the bucket's rate the request is dropped for the
                    // peer to retransmit -- the pre-cookie behavior, not the
                    // reset below, which would refuse a service that is
                    // merely flooded.
                    if !self.tcp_cookie_limiter.try_take(self.now) {
                        self.tcp_syn_cookies_suppressed =
                            self.tcp_syn_cookies_suppressed.wrapping_add(1);
                        return None;
                    }
                    self.tcp_syn_cookies_sent = self.tcp_syn_cookies_sent.wrapping_add(1);
                    let remote = IpEndpoint::new(ip_repr.src_addr(), tcp_repr.src_port);
                    let (ip, tcp) = self.cookie_syn_ack(config, endpoint, remote, &tcp_repr);
                    return Some(Packet::new(ip, IpPayload::Tcp(tcp)));
                }
                if listener_owns(sockets, &endpoint) {
                    // A reset is terminal -- the peer gets `ECONNREFUSED` for a
                    // service that is running and merely busy -- while a dropped
                    // SYN is retransmitted, by which time the pool it drained
                    // has been replenished and deepened. Recorded so the
                    // listener can be deepened rather than left to lose the
                    // next burst too.
                    self.tcp_syn_backlog_dropped = self.tcp_syn_backlog_dropped.wrapping_add(1);
                    if !self.tcp_backlog_endpoints.contains(&endpoint) {
                        let _ = self.tcp_backlog_endpoints.push(endpoint);
                    }
                    return None;
                }
                // Nothing is listening. `ECONNREFUSED` is the honest answer and
                // what applications expect from a closed port, so this one
                // keeps its reset.
                self.tcp_syn_rst_unmatched = self.tcp_syn_rst_unmatched.wrapping_add(1);
            } else if tcp_repr.ack_number.is_some()
                && tcp_repr.control != TcpControl::Syn
                && self.syn_cookie_verifies(&endpoint)
            {
                // Possibly the completing ACK of a stateless handshake. Only
                // endpoints that minted recently are checked, so a prober
                // cannot grind the cookie hash against an idle listener.
                if let Some(restore) = self.check_cookie_ack(&ip_repr, &tcp_repr) {
                    if self.tcp_cookie_restores.push(restore).is_err() {
                        // The peer retransmits into a drained queue later;
                        // a reset would kill its established connection.
                        self.tcp_cookie_restores_dropped =
                            self.tcp_cookie_restores_dropped.wrapping_add(1);
                    }
                    return None;
                }
                self.tcp_syn_cookies_rejected = self.tcp_syn_cookies_rejected.wrapping_add(1);
            }
            // The packet wasn't handled by a socket, send a TCP RST packet --
            // through the reflector's bucket, because each of these is one
            // reply per unsolicited segment and the segment's source address
            // is whatever its sender wrote.
            if !self.tcp_rst_limiter.try_take(self.now) {
                self.tcp_rst_suppressed = self.tcp_rst_suppressed.wrapping_add(1);
                return None;
            }
            let (ip, tcp) = tcp::Socket::rst_reply(&ip_repr, &tcp_repr);
            Some(Packet::new(ip, IpPayload::Tcp(tcp)))
        }
    }
}

/// Whether a listener still owns `endpoint`, even with no socket left in
/// `Listen` for it.
///
/// `listen_endpoint` is set by [`Socket::listen`] and survives into every state
/// a socket that took a SYN moves through; [`Socket::connect`] resets it, so an
/// outbound connection's local port never answers here. A socket whose listen
/// endpoint would have accepted this request is therefore proof that a listener
/// is there and out of sockets, which is the one case where a reset is the
/// wrong answer. Walked only for a request nothing took, never on the data path.
fn listener_owns(sockets: &SocketSet, endpoint: &IpEndpoint) -> bool {
    sockets
        .items()
        .filter_map(|i| Socket::downcast(&i.socket))
        .any(|socket| {
            let listen = socket.listen_endpoint();
            listen.port != 0
                && listen.port == endpoint.port
                && listen.addr.is_none_or(|addr| addr == endpoint.addr)
        })
}

/// The widest 4-tuple: two IPv6 addresses and two ports.
pub(super) const MAX_TUPLE_LEN: usize = 36;

/// RFC 6528's initial sequence number: `ISN = M + F(4-tuple, key)`.
///
/// `M` is a timer, so a connection that reuses a 4-tuple starts ahead of where
/// the last one did and a straggling segment from that one cannot be taken for
/// new data. `F` is a keyed hash, so what a peer learns from the sequence
/// numbers of its own connections is one point of a function it cannot invert,
/// rather than -- as with one generator per interface -- the state behind every
/// other connection's numbers too.
///
/// The key must be unpredictable and per-interface; `M` need not be either, and
/// is the interface's own clock rounded to the RFC's four microseconds.
fn tcp_isn(key: &SipHasher24, now: Instant, local: IpEndpoint, remote: IpEndpoint) -> TcpSeqNumber {
    let mut tuple = [0_u8; MAX_TUPLE_LEN];
    let len = write_tuple(&mut tuple, local, remote);

    // Arithmetic, not a logical, shift: `Instant` is signed, and flooring keeps
    // the timer monotone either side of its origin.
    let m = (now.total_micros() >> 2) as u32;
    TcpSeqNumber(m.wrapping_add(key.hash(&tuple[..len]) as u32) as i32)
}

/// Writes the 4-tuple into `out` -- both addresses in network order, then both
/// ports -- and returns how many bytes that took.
///
/// An IPv4 tuple is twelve bytes and an IPv6 one thirty-six. SipHash mixes the
/// message length in, so the two families cannot hash alike even where their
/// bytes agree.
pub(super) fn write_tuple(
    out: &mut [u8; MAX_TUPLE_LEN],
    local: IpEndpoint,
    remote: IpEndpoint,
) -> usize {
    let mut len = 0;

    for addr in [local.addr, remote.addr] {
        match addr {
            #[cfg(feature = "proto-ipv4")]
            IpAddress::Ipv4(addr) => {
                out[len..len + 4].copy_from_slice(&addr.octets());
                len += 4;
            }
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(addr) => {
                out[len..len + 16].copy_from_slice(&addr.octets());
                len += 16;
            }
        }
    }

    out[len..len + 2].copy_from_slice(&local.port.to_be_bytes());
    out[len + 2..len + 4].copy_from_slice(&remote.port.to_be_bytes());
    len + 4
}

#[cfg(all(test, feature = "proto-ipv4"))]
mod tests {
    use super::*;

    const KEY: SipHasher24 = SipHasher24::new([0x5a; 16]);
    const NOW: Instant = Instant::from_micros_const(1_000_000_000);

    fn endpoint(host: u8, port: u16) -> IpEndpoint {
        IpEndpoint::new(IpAddress::v4(192, 0, 2, host), port)
    }

    /// Two machines carrying the same connection do not issue the same number,
    /// which is what stops one of them from predicting the other's.
    #[test]
    fn the_key_changes_the_number() {
        let mut key = [0x5a; 16];
        key[15] ^= 1;
        let (local, remote) = (endpoint(1, 49152), endpoint(2, 80));

        assert_ne!(
            tcp_isn(&SipHasher24::new(key), NOW, local, remote),
            tcp_isn(&KEY, NOW, local, remote)
        );
    }

    /// Every field of the 4-tuple reaches the number, so the connections a peer
    /// is allowed to see say nothing about the ones it is not.
    #[test]
    fn every_tuple_field_changes_the_number() {
        let isn = tcp_isn(&KEY, NOW, endpoint(1, 49152), endpoint(2, 80));

        for (local, remote) in [
            (endpoint(3, 49152), endpoint(2, 80)),
            (endpoint(1, 49153), endpoint(2, 80)),
            (endpoint(1, 49152), endpoint(3, 80)),
            (endpoint(1, 49152), endpoint(2, 81)),
        ] {
            assert_ne!(tcp_isn(&KEY, NOW, local, remote), isn);
        }
    }

    /// The key an interface was configured with is the one it hands numbers
    /// out under, which is the half of this the caller supplies.
    #[test]
    #[cfg(feature = "medium-ip")]
    fn the_interface_uses_its_configured_key() {
        let mut device = crate::phy::Loopback::new(Medium::Ip);
        let mut config = Config::new(HardwareAddress::Ip);
        config.tcp_isn_key = [0x5a; 16];
        let iface = Interface::new(config, &mut device, NOW);

        let (local, remote) = (endpoint(1, 49152), endpoint(2, 80));
        assert_eq!(
            iface.inner.tcp_isn(local, remote),
            tcp_isn(&KEY, NOW, local, remote)
        );
    }

    /// A reconnection on the same 4-tuple starts ahead of where the last one
    /// did, by RFC 6528's one tick per four microseconds.
    #[test]
    fn the_same_tuple_advances_with_time() {
        let (local, remote) = (endpoint(1, 49152), endpoint(2, 80));
        let later = Instant::from_micros(NOW.total_micros() + 4_000_000);

        assert_eq!(
            tcp_isn(&KEY, later, local, remote) - tcp_isn(&KEY, NOW, local, remote),
            1_000_000
        );
    }
}
