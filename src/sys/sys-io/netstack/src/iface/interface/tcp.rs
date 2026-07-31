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
            // The packet wasn't handled by a socket, send a TCP RST packet.
            let (ip, tcp) = tcp::Socket::rst_reply(&ip_repr, &tcp_repr);
            Some(Packet::new(ip, IpPayload::Tcp(tcp)))
        }
    }
}
