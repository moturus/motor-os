#[cfg(feature = "proto-ipv4")]
use crate::wire::Ipv4Packet;
use crate::wire::{IpEndpoint, IpProtocol, TcpPacket, TcpSeqNumber, UdpPacket};
#[cfg(feature = "proto-ipv6")]
use crate::wire::{Ipv6ExtHeader, Ipv6FragmentHeader, Ipv6FragmentRepr, Ipv6Packet};

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Transport {
    Udp,
    Tcp { seq: TcpSeqNumber },
}

#[cfg_attr(not(test), allow(dead_code))]
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
#[cfg_attr(not(test), allow(dead_code))]
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
#[cfg_attr(not(test), allow(dead_code))]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phy::ChecksumCapabilities;
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
