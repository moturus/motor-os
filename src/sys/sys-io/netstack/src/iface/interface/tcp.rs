use super::*;

use crate::socket::tcp::Socket;

impl InterfaceInner {
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

        for tcp_socket in sockets
            .items_mut()
            .filter_map(|i| Socket::downcast_mut(&mut i.socket))
        {
            if tcp_socket.accepts(self, &ip_repr, &tcp_repr) {
                return tcp_socket
                    .process(self, &ip_repr, &tcp_repr)
                    .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)));
            }
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
            if tcp_repr.control == TcpControl::Syn && tcp_repr.ack_number.is_none() {
                let endpoint = IpEndpoint::new(ip_repr.dst_addr(), tcp_repr.dst_port);
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
            }
            // The packet wasn't handled by a socket, send a TCP RST packet.
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
