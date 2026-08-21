#[cfg(feature = "proto-ipv4")]
use crate::wire::Ipv4Packet;
use crate::wire::{IpEndpoint, IpProtocol, TcpPacket, TcpSeqNumber, UdpPacket};
#[cfg(feature = "proto-ipv6")]
use crate::wire::{Ipv6ExtHeader, Ipv6FragmentHeader, Ipv6FragmentRepr, Ipv6Packet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Transport {
    Udp,
    Tcp { seq: TcpSeqNumber },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Quote {
    pub local: IpEndpoint,
    pub remote: IpEndpoint,
    pub packet_len: usize,
    pub transport: Transport,
}

fn parse_transport(
    protocol: IpProtocol,
    payload: &[u8],
    fragmented: bool,
) -> Option<(u16, u16, Transport)> {
    if payload.len() < 8 {
        return None;
    }

    match protocol {
        IpProtocol::Udp => {
            let packet = UdpPacket::new_unchecked(payload);
            (packet.len() as usize >= crate::wire::UDP_HEADER_LEN)
                .then(|| (packet.src_port(), packet.dst_port(), Transport::Udp))
        }
        IpProtocol::Tcp if !fragmented => {
            let packet = TcpPacket::new_unchecked(payload);
            Some((
                packet.src_port(),
                packet.dst_port(),
                Transport::Tcp {
                    seq: packet.seq_number(),
                },
            ))
        }
        _ => None,
    }
}

#[cfg(feature = "proto-ipv4")]
pub(super) fn parse_ipv4(data: &[u8]) -> Option<Quote> {
    let packet = Ipv4Packet::new_checked_header(data).ok()?;
    if packet.version() != 4 || !packet.verify_checksum() || packet.reserved() {
        return None;
    }

    let offset = packet.frag_offset();
    let more = packet.more_frags();
    let fragmented = offset != 0 || more;
    if offset != 0 || (more && packet.dont_frag()) {
        return None;
    }

    let header_len = packet.header_len() as usize;
    let packet_len = packet.total_len() as usize;
    let quoted_end = core::cmp::min(data.len(), packet_len);
    let (src_port, dst_port, transport) = parse_transport(
        packet.next_header(),
        &data[header_len..quoted_end],
        fragmented,
    )?;
    let local = IpEndpoint::new(packet.src_addr().into(), src_port);
    let remote = IpEndpoint::new(packet.dst_addr().into(), dst_port);
    if !remote.addr.is_unicast() {
        return None;
    }

    Some(Quote {
        local,
        remote,
        packet_len,
        transport,
    })
}

#[cfg(feature = "proto-ipv6")]
pub(super) fn parse_ipv6(data: &[u8]) -> Option<Quote> {
    let packet = Ipv6Packet::new_checked_header(data).ok()?;
    if packet.version() != 6 {
        return None;
    }

    let packet_len = packet.total_len();
    let quoted_end = core::cmp::min(data.len(), packet_len);
    let mut payload = &data[packet.header_len()..quoted_end];
    let mut protocol = packet.next_header();

    if protocol == IpProtocol::HopByHop {
        let header = Ipv6ExtHeader::new_checked(payload).ok()?;
        let header_len = 2 + header.payload().len();
        protocol = header.next_header();
        payload = &payload[header_len..];
    }

    let fragmented = protocol == IpProtocol::Ipv6Frag;
    if fragmented {
        let header = Ipv6FragmentHeader::new_checked(payload).ok()?;
        let repr = Ipv6FragmentRepr::parse(&header).ok()?;
        if repr.frag_offset != 0 || !repr.more_frags || repr.next_header != IpProtocol::Udp {
            return None;
        }
        protocol = repr.next_header;
        payload = &payload[repr.buffer_len()..];
    }

    let (src_port, dst_port, transport) = parse_transport(protocol, payload, fragmented)?;
    let local = IpEndpoint::new(packet.src_addr().into(), src_port);
    let remote = IpEndpoint::new(packet.dst_addr().into(), dst_port);
    if !remote.addr.is_unicast() {
        return None;
    }

    Some(Quote {
        local,
        remote,
        packet_len,
        transport,
    })
}

impl super::InterfaceInner {
    pub(super) fn update_pmtu_from_quote(
        &mut self,
        _sockets: &mut crate::iface::SocketSet,
        quote: Quote,
        advertised_mtu: usize,
    ) -> bool {
        if !self.has_ip_addr(quote.local.addr) {
            return false;
        }

        let associated = match quote.transport {
            Transport::Udp => {
                #[cfg(feature = "socket-udp")]
                {
                    let Some(handle) = _sockets.udp_socket(quote.local, false) else {
                        return false;
                    };
                    _sockets
                        .get_mut::<crate::socket::udp::Socket>(handle)
                        .has_recent_send(quote.local, quote.remote, self.now)
                }
                #[cfg(not(feature = "socket-udp"))]
                {
                    false
                }
            }
            Transport::Tcp { seq: _seq } => {
                #[cfg(feature = "socket-tcp")]
                {
                    let Some(handle) = _sockets.tcp_tuple(quote.local, quote.remote) else {
                        return false;
                    };
                    _sockets
                        .get::<crate::socket::tcp::Socket>(handle)
                        .has_outstanding_unsacked(_seq)
                }
                #[cfg(not(feature = "socket-tcp"))]
                {
                    false
                }
            }
        };
        if !associated {
            return false;
        }

        let interface_mtu = self.caps.ip_mtu();
        self.routes.update_pmtu(
            quote.remote.addr,
            advertised_mtu,
            quote.packet_len,
            interface_mtu,
            self.now,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phy::{ChecksumCapabilities, Medium};
    #[cfg(feature = "socket-tcp")]
    use crate::socket::tcp;
    #[cfg(feature = "socket-udp")]
    use crate::socket::udp;
    use crate::tests::setup;
    use crate::time::Instant;
    use crate::wire::IpAddress;
    #[cfg(feature = "proto-ipv4")]
    use crate::wire::{Ipv4Address, Ipv4Repr};
    #[cfg(feature = "proto-ipv6")]
    use crate::wire::{Ipv6Address, Ipv6Repr};

    const SRC_PORT: u16 = 49_152;
    const DST_PORT: u16 = 443;
    const SEQ: TcpSeqNumber = TcpSeqNumber(0x1234_5678);

    fn udp_prefix() -> [u8; 8] {
        let mut bytes = [0; 8];
        let mut packet = UdpPacket::new_unchecked(&mut bytes);
        packet.set_src_port(SRC_PORT);
        packet.set_dst_port(DST_PORT);
        packet.set_len(1_400);
        bytes
    }

    fn tcp_prefix() -> [u8; 8] {
        let mut bytes = [0; 8];
        let mut packet = TcpPacket::new_unchecked(&mut bytes);
        packet.set_src_port(SRC_PORT);
        packet.set_dst_port(DST_PORT);
        packet.set_seq_number(SEQ);
        bytes
    }

    #[cfg(feature = "proto-ipv4")]
    fn ipv4_quote(protocol: IpProtocol, payload_len: usize, prefix: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 20 + prefix.len()];
        Ipv4Repr {
            src_addr: Ipv4Address::new(192, 0, 2, 1),
            dst_addr: Ipv4Address::new(198, 51, 100, 2),
            next_header: protocol,
            payload_len,
            hop_limit: 64,
        }
        .emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        bytes[20..].copy_from_slice(prefix);
        bytes
    }

    #[cfg(feature = "proto-ipv4")]
    #[test]
    fn ipv4_quote_checks_transport_and_fragment_shape() {
        let udp = udp_prefix();
        let tcp = tcp_prefix();
        assert_eq!(
            parse_ipv4(&ipv4_quote(IpProtocol::Udp, 1_400, &udp))
                .unwrap()
                .packet_len,
            1_420
        );
        assert_eq!(
            parse_ipv4(&ipv4_quote(IpProtocol::Tcp, 1_400, &tcp))
                .unwrap()
                .transport,
            Transport::Tcp { seq: SEQ }
        );
        assert!(parse_ipv4(&ipv4_quote(IpProtocol::Udp, 1_400, &udp[..7])).is_none());

        let mut first = ipv4_quote(IpProtocol::Udp, 1_400, &udp);
        let mut packet = Ipv4Packet::new_unchecked(&mut first);
        packet.set_dont_frag(false);
        packet.set_more_frags(true);
        packet.fill_checksum();
        assert_eq!(
            parse_ipv4(packet.as_ref()).unwrap().transport,
            Transport::Udp
        );

        packet.set_frag_offset(8);
        packet.fill_checksum();
        assert!(parse_ipv4(packet.as_ref()).is_none());
        packet.set_frag_offset(0);
        packet.set_dont_frag(true);
        packet.fill_checksum();
        assert!(parse_ipv4(packet.as_ref()).is_none());

        let mut first_tcp = ipv4_quote(IpProtocol::Tcp, 1_400, &tcp);
        let mut packet = Ipv4Packet::new_unchecked(&mut first_tcp);
        packet.set_dont_frag(false);
        packet.set_more_frags(true);
        packet.fill_checksum();
        assert!(parse_ipv4(packet.as_ref()).is_none());
    }

    #[cfg(feature = "socket-udp")]
    fn udp_with_recent_send(
        iface: &mut crate::iface::Interface,
        local: IpEndpoint,
        remote: IpEndpoint,
    ) -> udp::Socket<'static> {
        let mut socket = udp::Socket::new(
            udp::PacketBuffer::new(vec![], vec![]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 64]),
        );
        socket.bind(local).unwrap();
        socket.send_slice(b"sent", remote).unwrap();
        socket
            .dispatch(iface.context(), |_, _, _| Ok::<_, ()>(()))
            .unwrap();
        socket
    }

    #[cfg(all(feature = "proto-ipv4", feature = "socket-udp"))]
    #[test]
    fn icmpv4_decrease_requires_a_recent_live_udp_flow() {
        let (mut iface, mut sockets, _) = setup(Medium::Ip);
        let local_addr = Ipv4Address::new(192, 168, 1, 1);
        let remote_addr = Ipv4Address::new(192, 168, 1, 2);
        let local = IpEndpoint::new(local_addr.into(), SRC_PORT);
        let remote = IpEndpoint::new(remote_addr.into(), DST_PORT);
        let quote_header = Ipv4Repr {
            src_addr: local_addr,
            dst_addr: remote_addr,
            next_header: IpProtocol::Udp,
            payload_len: 1_400,
            hop_limit: 64,
        };
        let icmp = crate::wire::Icmpv4Repr::DstUnreachable {
            reason: crate::wire::Icmpv4DstUnreachable::FragRequired,
            next_hop_mtu: Some(1_400),
            header: quote_header,
            data: &udp_prefix(),
        };
        let mut bytes = vec![0; icmp.buffer_len()];
        icmp.emit(
            &mut crate::wire::Icmpv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        let outer = Ipv4Repr {
            src_addr: Ipv4Address::new(192, 168, 1, 254),
            dst_addr: local_addr,
            next_header: IpProtocol::Icmp,
            payload_len: bytes.len(),
            hop_limit: 64,
        };

        iface.inner.process_icmpv4(&mut sockets, outer, &bytes);
        assert_eq!(
            iface
                .inner
                .routes
                .effective_pmtu(remote.addr, 1_500, Instant::ZERO),
            1_500
        );

        sockets.add(1, udp_with_recent_send(&mut iface, local, remote));
        iface.inner.process_icmpv4(&mut sockets, outer, &bytes);
        assert_eq!(
            iface
                .inner
                .routes
                .effective_pmtu(remote.addr, 1_500, Instant::ZERO),
            1_400
        );
    }

    #[cfg(all(feature = "proto-ipv4", feature = "socket-tcp"))]
    fn tcp_dispatch_sizes(max_tso_size: usize) -> (usize, u16) {
        let (mut iface, _, _) = setup(Medium::Ip);
        iface.inner.caps.max_tso_size = max_tso_size;
        let local = IpEndpoint::new(IpAddress::v4(192, 168, 1, 1), SRC_PORT);
        let remote = IpEndpoint::new(IpAddress::v4(192, 168, 1, 2), DST_PORT);
        let interface_mtu = iface.inner.ip_mtu();
        assert!(iface.inner.routes.update_pmtu(
            remote.addr,
            1_200,
            1_400,
            interface_mtu,
            Instant::ZERO,
        ));

        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 8_192]),
            tcp::SocketBuffer::new(vec![0; 8_192]),
        );
        socket
            .restore_from_cookie(
                iface.context(),
                &tcp::TcpCookieRestore {
                    local,
                    remote,
                    rcv_nxt: TcpSeqNumber(20_000),
                    snd_nxt: TcpSeqNumber(10_000),
                    remote_mss: 1_460,
                    remote_window: 8_192,
                    peer_wscale: None,
                    peer_sack: true,
                    peer_tsval: None,
                },
            )
            .unwrap();
        socket.send_slice(&vec![0xa5; 3_000]).unwrap();

        let mut observed = None;
        socket
            .dispatch(iface.context(), |_, meta, (_, tcp)| {
                observed = Some((tcp.payload.len(), meta.tso_seg_size));
                Ok::<_, ()>(())
            })
            .unwrap();
        observed.unwrap()
    }

    #[cfg(all(feature = "proto-ipv4", feature = "socket-tcp"))]
    #[test]
    fn cached_pmtu_limits_tcp_segments_and_tso_but_not_syn_mss() {
        assert_eq!(tcp_dispatch_sizes(0), (1_160, 0));
        assert_eq!(tcp_dispatch_sizes(4_096), (3_000, 1_160));

        let (mut iface, _, _) = setup(Medium::Ip);
        let local = IpEndpoint::new(IpAddress::v4(192, 168, 1, 1), SRC_PORT);
        let remote = IpEndpoint::new(IpAddress::v4(192, 168, 1, 2), DST_PORT);
        let interface_mtu = iface.inner.ip_mtu();
        assert!(iface.inner.routes.update_pmtu(
            remote.addr,
            1_200,
            1_400,
            interface_mtu,
            Instant::ZERO,
        ));
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 64]),
            tcp::SocketBuffer::new(vec![0; 64]),
        );
        socket.connect(iface.context(), remote, local).unwrap();
        socket
            .dispatch(iface.context(), |_, _, (_, tcp)| {
                assert_eq!(tcp.max_seg_size, Some(1_460));
                Ok::<_, ()>(())
            })
            .unwrap();
    }

    #[cfg(feature = "proto-ipv6")]
    fn ipv6_quote(next_header: IpProtocol, payload_len: usize, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 40 + payload.len()];
        Ipv6Repr {
            src_addr: Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            dst_addr: Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            next_header,
            payload_len,
            hop_limit: 64,
        }
        .emit(&mut Ipv6Packet::new_unchecked(&mut bytes));
        bytes[40..].copy_from_slice(payload);
        bytes
    }

    #[cfg(all(feature = "proto-ipv6", feature = "socket-udp"))]
    #[test]
    fn icmpv6_decrease_requires_a_recent_exact_udp_flow() {
        let (mut iface, mut sockets, _) = setup(Medium::Ip);
        let local_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 1);
        let remote_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2);
        let local = IpEndpoint::new(local_addr.into(), SRC_PORT);
        let remote = IpEndpoint::new(remote_addr.into(), DST_PORT);
        sockets.add(1, udp_with_recent_send(&mut iface, local, remote));

        let quote_header = Ipv6Repr {
            src_addr: local_addr,
            dst_addr: remote_addr,
            next_header: IpProtocol::Udp,
            payload_len: 1_400,
            hop_limit: 64,
        };
        let icmp = crate::wire::Icmpv6Repr::PktTooBig {
            mtu: 1_300,
            header: quote_header,
            data: &udp_prefix(),
        };
        let outer_src = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0xff);
        let outer_dst = local_addr;
        let mut bytes = vec![0; icmp.buffer_len()];
        icmp.emit(
            &outer_src,
            &outer_dst,
            &mut crate::wire::Icmpv6Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        let outer = Ipv6Repr {
            src_addr: outer_src,
            dst_addr: outer_dst,
            next_header: IpProtocol::Icmpv6,
            payload_len: bytes.len(),
            hop_limit: 64,
        };

        iface.inner.process_icmpv6(&mut sockets, outer, &bytes);
        assert_eq!(
            iface
                .inner
                .routes
                .effective_pmtu(remote.addr, 1_500, Instant::ZERO),
            1_300
        );
    }

    #[cfg(all(feature = "proto-ipv4", feature = "socket-tcp"))]
    #[test]
    fn tcp_decrease_requires_exact_tuple_and_outstanding_sequence() {
        let (mut iface, mut sockets, _) = setup(Medium::Ip);
        let local = IpEndpoint::new(IpAddress::v4(192, 168, 1, 1), SRC_PORT);
        let remote = IpEndpoint::new(IpAddress::v4(192, 168, 1, 2), DST_PORT);
        let snd_nxt = TcpSeqNumber(10_000);
        let handle = sockets.add(
            1,
            tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; 64]),
                tcp::SocketBuffer::new(vec![0; 64]),
            ),
        );
        sockets
            .tcp_restore_from_cookie(
                handle,
                iface.context(),
                &tcp::TcpCookieRestore {
                    local,
                    remote,
                    rcv_nxt: TcpSeqNumber(20_000),
                    snd_nxt,
                    remote_mss: 1_460,
                    remote_window: 64,
                    peer_wscale: None,
                    peer_sack: true,
                    peer_tsval: None,
                },
            )
            .unwrap();
        sockets
            .get_mut::<tcp::Socket>(handle)
            .send_slice(b"outbound")
            .unwrap();
        sockets
            .get_mut::<tcp::Socket>(handle)
            .dispatch(iface.context(), |_, _, _| Ok::<_, ()>(()))
            .unwrap();

        let quote = Quote {
            local,
            remote,
            packet_len: 1_420,
            transport: Transport::Tcp { seq: snd_nxt + 8 },
        };
        assert!(
            !iface
                .inner
                .update_pmtu_from_quote(&mut sockets, quote, 1_400)
        );
        assert_eq!(
            iface
                .inner
                .routes
                .effective_pmtu(remote.addr, 1_500, Instant::ZERO),
            1_500
        );

        assert!(iface.inner.update_pmtu_from_quote(
            &mut sockets,
            Quote {
                transport: Transport::Tcp { seq: snd_nxt },
                ..quote
            },
            1_400,
        ));
        assert_eq!(
            iface
                .inner
                .routes
                .effective_pmtu(remote.addr, 1_500, Instant::ZERO),
            1_400
        );
    }

    #[cfg(feature = "proto-ipv6")]
    #[test]
    fn ipv6_quote_checks_supported_chain_and_fragment_shape() {
        let tcp = tcp_prefix();
        assert_eq!(
            parse_ipv6(&ipv6_quote(IpProtocol::Tcp, 20, &tcp))
                .unwrap()
                .transport,
            Transport::Tcp { seq: SEQ }
        );
        assert!(parse_ipv6(&ipv6_quote(IpProtocol::Tcp, 20, &tcp[..7])).is_none());

        let mut fragment = [0; 16];
        Ipv6FragmentRepr {
            next_header: IpProtocol::Udp,
            frag_offset: 0,
            more_frags: true,
            ident: 7,
        }
        .emit(&mut Ipv6FragmentHeader::new_unchecked(&mut fragment));
        fragment[8..].copy_from_slice(&udp_prefix());
        assert_eq!(
            parse_ipv6(&ipv6_quote(IpProtocol::Ipv6Frag, 1_208, &fragment))
                .unwrap()
                .transport,
            Transport::Udp
        );

        fragment[3] &= !1;
        assert!(parse_ipv6(&ipv6_quote(IpProtocol::Ipv6Frag, 1_208, &fragment)).is_none());
        fragment[3] |= 1;
        fragment[2] = 0;
        fragment[3] |= 8;
        assert!(parse_ipv6(&ipv6_quote(IpProtocol::Ipv6Frag, 1_208, &fragment)).is_none());

        let mut hbh_fragment = vec![0; 8];
        hbh_fragment[0] = IpProtocol::Ipv6Frag.into();
        hbh_fragment.extend_from_slice(&fragment);
        hbh_fragment[8 + 2] = 0;
        hbh_fragment[8 + 3] = 1;
        assert!(parse_ipv6(&ipv6_quote(IpProtocol::HopByHop, 1_216, &hbh_fragment)).is_some());
    }
}
