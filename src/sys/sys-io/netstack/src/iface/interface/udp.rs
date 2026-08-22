use super::*;

#[cfg(feature = "socket-dns")]
use crate::socket::dns::Socket as DnsSocket;

#[cfg(feature = "socket-udp")]
use crate::socket::udp::Socket as UdpSocket;

impl InterfaceInner {
    pub(super) fn process_udp<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        handled_by_raw_socket: bool,
        ip_repr: IpRepr,
        ip_payload: &'frame [u8],
    ) -> Option<Packet<'frame>> {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let udp_packet = check!(UdpPacket::new_checked(ip_payload));
        let checksum_caps = self.caps.checksum.rx_vouched(meta.l4_csum_vouched);
        let udp_repr = match UdpRepr::parse(&udp_packet, &src_addr, &dst_addr, &checksum_caps) {
            Ok(udp_repr) => udp_repr,
            Err(_) => {
                // As in process_tcp: separate a failed checksum from the other
                // ways a datagram can be malformed.
                if checksum_caps.udp.rx() && !udp_packet.verify_checksum(&src_addr, &dst_addr) {
                    self.rx_csum_failed = self.rx_csum_failed.wrapping_add(1);
                }
                net_trace!("iface: malformed udp packet");
                return None;
            }
        };

        // Demux by the bound endpoint: exact-address binding first, then the
        // wildcard; a broadcast or multicast destination may land on any
        // binding of its port. Authoritative -- a miss means no UDP socket,
        // and the DNS walk below is what remains.
        #[cfg(feature = "socket-udp")]
        {
            let local = IpEndpoint::new(dst_addr, udp_repr.dst_port);
            let promiscuous = self.is_broadcast(&dst_addr) || dst_addr.is_multicast();
            let taker = sockets.udp_socket(local, promiscuous);
            #[cfg(debug_assertions)]
            match taker {
                Some(handle) => assert!(
                    sockets
                        .get::<UdpSocket>(handle)
                        .accepts(self, &ip_repr, &udp_repr),
                    "the udp index named a socket that refuses the datagram"
                ),
                // The retired linear scan survives as this debug-only oracle.
                None => {
                    let acceptor = sockets.items().find(|item| {
                        UdpSocket::downcast(&item.socket)
                            .is_some_and(|socket| socket.accepts(self, &ip_repr, &udp_repr))
                    });
                    assert!(
                        acceptor.is_none(),
                        "socket {} accepts a datagram the udp index missed",
                        acceptor.unwrap().meta.handle
                    );
                }
            }
            if let Some(handle) = taker {
                sockets.get_mut::<UdpSocket>(handle).process(
                    self,
                    meta,
                    &ip_repr,
                    &udp_repr,
                    udp_packet.payload(),
                );
                return None;
            }
        }

        #[cfg(feature = "socket-dns")]
        for dns_socket in sockets
            .items_mut()
            .filter_map(|i| DnsSocket::downcast_mut(&mut i.socket))
        {
            if dns_socket.accepts(&ip_repr, &udp_repr) {
                dns_socket.process(self, &ip_repr, &udp_repr, udp_packet.payload());
                return None;
            }
        }

        // The packet wasn't handled by a socket, send an ICMP port unreachable packet.
        match ip_repr {
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(_) if handled_by_raw_socket => None,
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(_) if handled_by_raw_socket => None,
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(ipv4_repr) => {
                let payload_len =
                    icmp_reply_payload_len(ip_payload.len(), IPV4_MIN_MTU, ipv4_repr.buffer_len());
                let icmpv4_reply_repr = Icmpv4Repr::DstUnreachable {
                    reason: Icmpv4DstUnreachable::PortUnreachable,
                    next_hop_mtu: None,
                    header: ipv4_repr,
                    data: &ip_payload[0..payload_len],
                };
                self.icmpv4_reply(ipv4_repr, icmpv4_reply_repr)
            }
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(ipv6_repr) => {
                let payload_len =
                    icmp_reply_payload_len(ip_payload.len(), IPV6_MIN_MTU, ipv6_repr.buffer_len());
                let icmpv6_reply_repr = Icmpv6Repr::DstUnreachable {
                    reason: Icmpv6DstUnreachable::PortUnreachable,
                    header: ipv6_repr,
                    data: &ip_payload[0..payload_len],
                };
                self.icmpv6_reply(ipv6_repr, icmpv6_reply_repr)
            }
        }
    }
}
