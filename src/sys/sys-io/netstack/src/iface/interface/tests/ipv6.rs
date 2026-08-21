use super::*;

#[cfg(all(
    feature = "medium-ip",
    feature = "proto-ipv6-fragmentation",
    feature = "socket-udp"
))]
fn ipv6_atomic_udp_payload(
    payload: &[u8],
    corrupt: bool,
    hop_by_hop: bool,
    next_header: IpProtocol,
) -> Vec<u8> {
    let src_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2);
    let dst_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 1);
    let udp_repr = UdpRepr {
        src_port: 4242,
        dst_port: 49_506,
    };
    let hbh_len = if hop_by_hop { 8 } else { 0 };
    let ipv6_repr = Ipv6Repr {
        src_addr,
        dst_addr,
        next_header: if hop_by_hop {
            IpProtocol::HopByHop
        } else {
            IpProtocol::Ipv6Frag
        },
        payload_len: hbh_len + 8 + udp_repr.header_len() + payload.len(),
        hop_limit: 64,
    };
    let mut bytes = vec![0; ipv6_repr.buffer_len() + ipv6_repr.payload_len];
    ipv6_repr.emit(&mut Ipv6Packet::new_unchecked(&mut bytes));

    let mut offset = ipv6_repr.buffer_len();
    if hop_by_hop {
        bytes[offset..offset + 8].copy_from_slice(&[44, 0, 0, 0, 0, 0, 0, 0]);
        offset += 8;
    }
    Ipv6FragmentRepr {
        next_header,
        frag_offset: 0,
        more_frags: false,
        ident: 1,
    }
    .emit(&mut Ipv6FragmentHeader::new_unchecked(
        &mut bytes[offset..offset + 8],
    ));
    offset += 8;

    let mut packet = UdpPacket::new_unchecked(&mut bytes[offset..]);
    udp_repr.emit(
        &mut packet,
        &src_addr.into(),
        &dst_addr.into(),
        payload.len(),
        |buffer| buffer.copy_from_slice(payload),
        &ChecksumCapabilities::default(),
    );
    if corrupt {
        packet.set_checksum(packet.checksum() ^ 1);
    }
    bytes
}

#[cfg(all(
    feature = "medium-ip",
    feature = "proto-ipv6-fragmentation",
    feature = "socket-udp"
))]
fn ipv6_atomic_udp(corrupt: bool, hop_by_hop: bool, next_header: IpProtocol) -> Vec<u8> {
    ipv6_atomic_udp_payload(b"atomic", corrupt, hop_by_hop, next_header)
}

#[cfg(all(
    feature = "medium-ip",
    feature = "proto-ipv6-fragmentation",
    feature = "socket-udp"
))]
fn ipv6_fragment(
    fragmentable: &[u8],
    range: core::ops::Range<usize>,
    more_frags: bool,
    hop_by_hop: bool,
) -> Vec<u8> {
    let src_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2);
    let dst_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 1);
    let hbh_len = if hop_by_hop { 8 } else { 0 };
    let ipv6_repr = Ipv6Repr {
        src_addr,
        dst_addr,
        next_header: if hop_by_hop {
            IpProtocol::HopByHop
        } else {
            IpProtocol::Ipv6Frag
        },
        payload_len: hbh_len + 8 + range.len(),
        hop_limit: 64,
    };
    let mut bytes = vec![0; ipv6_repr.buffer_len() + ipv6_repr.payload_len];
    ipv6_repr.emit(&mut Ipv6Packet::new_unchecked(&mut bytes));

    let mut offset = ipv6_repr.buffer_len();
    if hop_by_hop {
        bytes[offset..offset + 8].copy_from_slice(&[44, 0, 0, 0, 0, 0, 0, 0]);
        offset += 8;
    }
    Ipv6FragmentRepr {
        next_header: IpProtocol::Udp,
        frag_offset: range.start as u16,
        more_frags,
        ident: 7,
    }
    .emit(&mut Ipv6FragmentHeader::new_unchecked(
        &mut bytes[offset..offset + 8],
    ));
    offset += 8;
    bytes[offset..].copy_from_slice(&fragmentable[range]);
    bytes
}

#[cfg(all(
    feature = "medium-ip",
    feature = "proto-ipv6-fragmentation",
    feature = "socket-udp"
))]
fn ipv6_fragment_header_mut(frame: &mut [u8], hop_by_hop: bool) -> Ipv6FragmentHeader<&mut [u8]> {
    let offset = IPV6_HEADER_LEN + if hop_by_hop { 8 } else { 0 };
    Ipv6FragmentHeader::new_unchecked(&mut frame[offset..offset + 8])
}

#[cfg(all(
    feature = "medium-ip",
    feature = "proto-ipv6-fragmentation",
    feature = "socket-udp"
))]
fn feed_ipv6_frames_all(frames: impl IntoIterator<Item = Vec<u8>>) -> (Vec<Vec<u8>>, u64) {
    use crate::socket::udp;

    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let mut socket = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 256]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 64]),
    );
    socket.bind(49_506).unwrap();
    let handle = sockets.add(0, socket);
    for frame in frames {
        device.push_rx_vouched(frame, true);
    }
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    let socket = sockets.get_mut::<udp::Socket>(handle);
    let mut received = Vec::new();
    while let Ok((payload, _)) = socket.recv() {
        received.push(payload.to_vec());
    }
    (received, iface.take_rx_csum_failed())
}

#[cfg(all(
    feature = "medium-ip",
    feature = "proto-ipv6-fragmentation",
    feature = "socket-udp"
))]
fn feed_ipv6_frames(frames: impl IntoIterator<Item = Vec<u8>>) -> (Option<Vec<u8>>, u64) {
    let (received, checksum_failures) = feed_ipv6_frames_all(frames);
    (received.into_iter().next(), checksum_failures)
}

#[test]
#[cfg(all(
    feature = "medium-ip",
    feature = "proto-ipv6-fragmentation",
    feature = "socket-udp"
))]
fn ipv6_atomic_fragments_accept_supported_header_positions() {
    for hop_by_hop in [false, true] {
        assert_eq!(
            feed_ipv6_frames([ipv6_atomic_udp(false, hop_by_hop, IpProtocol::Udp)]),
            (Some(b"atomic".to_vec()), 0)
        );
    }
}

#[test]
#[cfg(all(
    feature = "medium-ip",
    feature = "proto-ipv6-fragmentation",
    feature = "socket-udp"
))]
fn ipv6_atomic_fragments_verify_checksum_and_reject_nesting() {
    assert_eq!(
        feed_ipv6_frames([ipv6_atomic_udp(true, false, IpProtocol::Udp)]),
        (None, 1)
    );
    assert_eq!(
        feed_ipv6_frames([ipv6_atomic_udp(false, false, IpProtocol::Ipv6Frag)]),
        (None, 0)
    );
}

#[test]
#[cfg(all(
    feature = "medium-ip",
    feature = "proto-ipv6-fragmentation",
    feature = "socket-udp"
))]
fn ipv6_reassembly_completes_in_both_orders_and_header_positions() {
    let atomic = ipv6_atomic_udp(false, false, IpProtocol::Udp);
    let fragmentable = &atomic[IPV6_HEADER_LEN + 8..];

    for hop_by_hop in [false, true] {
        let first = ipv6_fragment(fragmentable, 0..8, true, hop_by_hop);
        let last = ipv6_fragment(fragmentable, 8..fragmentable.len(), false, hop_by_hop);
        assert_eq!(
            feed_ipv6_frames([first.clone(), last.clone()]),
            (Some(b"atomic".to_vec()), 0)
        );
        assert_eq!(
            feed_ipv6_frames([last, first]),
            (Some(b"atomic".to_vec()), 0)
        );
    }
}

#[test]
#[cfg(all(
    feature = "medium-ip",
    feature = "proto-ipv6-fragmentation",
    feature = "socket-udp"
))]
fn ipv6_reassembly_verifies_checksum_and_preserves_duplicate_bytes() {
    const LARGE: &[u8] = b"abcdefghijklmnopqrstuvwx";
    let corrupt = ipv6_atomic_udp_payload(LARGE, true, false, IpProtocol::Udp);
    let fragmentable = &corrupt[IPV6_HEADER_LEN + 8..];
    assert_eq!(
        feed_ipv6_frames([
            ipv6_fragment(fragmentable, 0..16, true, false),
            ipv6_fragment(fragmentable, 16..fragmentable.len(), false, false),
        ]),
        (None, 1)
    );

    let correct = ipv6_atomic_udp(false, false, IpProtocol::Udp);
    let fragmentable = &correct[IPV6_HEADER_LEN + 8..];
    let mut changed = fragmentable.to_vec();
    changed[0] ^= 1;
    assert_eq!(
        feed_ipv6_frames([
            ipv6_fragment(fragmentable, 0..8, true, false),
            ipv6_fragment(&changed, 0..8, true, false),
            ipv6_fragment(fragmentable, 8..fragmentable.len(), false, false),
        ]),
        (Some(b"atomic".to_vec()), 0)
    );
}

#[test]
#[cfg(all(
    feature = "medium-ip",
    feature = "proto-ipv6-fragmentation",
    feature = "socket-udp"
))]
fn ipv6_overlap_tombstones_but_atomic_fragment_bypasses_state() {
    const LARGE: &[u8] = b"abcdefghijklmnopqrstuvwx";
    let packet = ipv6_atomic_udp_payload(LARGE, false, false, IpProtocol::Udp);
    let fragmentable = &packet[IPV6_HEADER_LEN + 8..];
    assert_eq!(
        feed_ipv6_frames([
            ipv6_fragment(fragmentable, 0..16, true, false),
            ipv6_fragment(fragmentable, 8..24, true, false),
            ipv6_fragment(fragmentable, 16..fragmentable.len(), false, false),
        ]),
        (None, 0)
    );

    let first = ipv6_fragment(fragmentable, 0..16, true, false);
    let last = ipv6_fragment(fragmentable, 16..fragmentable.len(), false, false);
    let mut atomic = ipv6_atomic_udp(false, false, IpProtocol::Udp);
    ipv6_fragment_header_mut(&mut atomic, false).set_ident(7);
    assert_eq!(
        feed_ipv6_frames_all([first, atomic, last]),
        (vec![b"atomic".to_vec(), LARGE.to_vec()], 0)
    );
}

#[test]
#[cfg(all(
    feature = "medium-ip",
    feature = "proto-ipv6-fragmentation",
    feature = "socket-udp"
))]
fn invalid_ipv6_first_fragments_retain_no_state() {
    let packet = ipv6_atomic_udp(false, false, IpProtocol::Udp);
    let fragmentable = &packet[IPV6_HEADER_LEN + 8..];
    let first = ipv6_fragment(fragmentable, 0..8, true, false);
    let last = ipv6_fragment(fragmentable, 8..fragmentable.len(), false, false);

    let mut reserved = first.clone();
    reserved[IPV6_HEADER_LEN + 1] = 1;
    let mut nested = first.clone();
    ipv6_fragment_header_mut(&mut nested, false).set_next_header(IpProtocol::Ipv6Frag);
    let mut tiny_tcp = first.clone();
    ipv6_fragment_header_mut(&mut tiny_tcp, false).set_next_header(IpProtocol::Tcp);
    let mut too_large = first.clone();
    let mut header = ipv6_fragment_header_mut(&mut too_large, false);
    header.set_frag_offset(65_528);
    header.set_more_frags(false);

    for invalid in [
        ipv6_fragment(fragmentable, 0..0, true, false),
        ipv6_fragment(fragmentable, 0..9, true, false),
        reserved,
        nested,
        tiny_tcp,
        too_large,
    ] {
        assert_eq!(
            feed_ipv6_frames([invalid, first.clone(), last.clone()]),
            (Some(b"atomic".to_vec()), 0)
        );
    }
}

#[test]
#[cfg(all(
    feature = "medium-ip",
    feature = "proto-ipv6-fragmentation",
    feature = "socket-udp"
))]
fn ipv6_reassembly_context_mismatch_poisons_the_key() {
    let packet = ipv6_atomic_udp(false, false, IpProtocol::Udp);
    let fragmentable = &packet[IPV6_HEADER_LEN + 8..];
    let first = ipv6_fragment(fragmentable, 0..8, true, false);
    let last = ipv6_fragment(fragmentable, 8..fragmentable.len(), false, false);

    let hbh_last = ipv6_fragment(fragmentable, 8..fragmentable.len(), false, true);
    assert_eq!(
        feed_ipv6_frames([first.clone(), hbh_last, last.clone()]),
        (None, 0)
    );

    let mut tcp_last = last.clone();
    ipv6_fragment_header_mut(&mut tcp_last, false).set_next_header(IpProtocol::Tcp);
    assert_eq!(feed_ipv6_frames([first, tcp_last, last]), (None, 0));
}

#[test]
#[cfg(feature = "medium-ethernet")]
fn icmp_echo_reply_policy() {
    let data = [
        0x60, 0, 0, 0, 0, 8, 0x3a, 0x40, 0xfd, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        0xfd, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x80, 0, 0x84, 0x3c, 0, 0, 0, 0,
    ];
    let packet = Ipv6Packet::new_checked(&data[..]).unwrap();
    let ip_repr = Ipv6Repr::parse(&packet).unwrap();
    let (mut iface, mut sockets, _) = setup(Medium::Ethernet);

    assert!(
        iface
            .inner
            .process_icmpv6(&mut sockets, ip_repr, packet.payload())
            .is_some()
    );
    iface.inner.auto_icmp_echo_reply = false;
    assert_eq!(
        iface
            .inner
            .process_icmpv6(&mut sockets, ip_repr, packet.payload()),
        None
    );
}

fn parse_ipv6(data: &[u8]) -> crate::wire::Result<Packet<'_>> {
    let ipv6_header = Ipv6Packet::new_checked(data)?;
    let ipv6 = Ipv6Repr::parse(&ipv6_header)?;

    match ipv6.next_header {
        IpProtocol::HopByHop => todo!(),
        IpProtocol::Icmp => todo!(),
        IpProtocol::Igmp => todo!(),
        IpProtocol::Tcp => todo!(),
        IpProtocol::Udp => todo!(),
        IpProtocol::Ipv6Route => todo!(),
        IpProtocol::Ipv6Frag => todo!(),
        IpProtocol::IpSecEsp => todo!(),
        IpProtocol::IpSecAh => todo!(),
        IpProtocol::Icmpv6 => {
            let icmp = Icmpv6Repr::parse(
                &ipv6.src_addr,
                &ipv6.dst_addr,
                &Icmpv6Packet::new_checked(ipv6_header.payload())?,
                &Default::default(),
            )?;
            Ok(Packet::new_ipv6(ipv6, IpPayload::Icmpv6(icmp)))
        }
        IpProtocol::Ipv6NoNxt => todo!(),
        IpProtocol::Ipv6Opts => todo!(),
        IpProtocol::Unknown(_) => todo!(),
    }
}

#[rstest]
#[cfg_attr(feature = "medium-ip", case::ip(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case::ethernet(Medium::Ethernet))]
#[cfg_attr(feature = "medium-ieee802154", case::ieee802154(Medium::Ieee802154))]
fn any_ip(#[case] medium: Medium) {
    // An empty echo request with destination address fdbe::3, which is not part of the interface
    // address list.
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x8, 0x3a, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x3, 0x80, 0x0, 0x84, 0x3a, 0x0, 0x0, 0x0, 0x0,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0003),
                hop_limit: 64,
                next_header: IpProtocol::Icmpv6,
                payload_len: 8,
            },
            IpPayload::Icmpv6(Icmpv6Repr::EchoRequest {
                ident: 0,
                seq_no: 0,
                data: b"",
            })
        ))
    );

    let (mut iface, mut sockets, _device) = setup(medium);

    // Add a route to the interface, otherwise, we don't know if the packet is routed localy.
    iface.routes_mut().update(|routes| {
        routes.push(crate::iface::Route {
            cidr: IpCidr::Ipv6(Ipv6Cidr::new(
                Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0),
                64,
            )),
            via_router: IpAddress::Ipv6(Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001)),
            preferred_until: None,
            expires_at: None,
        });
    });

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            None,
        ),
        None
    );

    // Accept any IP:
    iface.set_any_ip(true);
    assert!(
        iface
            .inner
            .process_ipv6(
                &mut sockets,
                PacketMeta::default(),
                HardwareAddress::default(),
                &Ipv6Packet::new_checked(&data[..]).unwrap(),
                None,
            )
            .is_some()
    );
}

#[rstest]
#[cfg_attr(feature = "medium-ip", case::ip(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case::ethernet(Medium::Ethernet))]
#[cfg_attr(feature = "medium-ieee802154", case::ieee802154(Medium::Ieee802154))]
fn multicast_source_address(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x40, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1,
    ];

    let response = None;

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            None,
        ),
        response
    );
}

#[rstest]
#[cfg_attr(feature = "medium-ip", case::ip(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case::ethernet(Medium::Ethernet))]
#[cfg_attr(feature = "medium-ieee802154", case::ieee802154(Medium::Ieee802154))]
fn hop_by_hop_skip_with_icmp(#[case] medium: Medium) {
    // The following contains:
    // - IPv6 header
    // - Hop-by-hop, with options:
    //  - PADN (skipped)
    //  - Unknown option (skipped)
    // - ICMP echo request
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x1b, 0x0, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x3a, 0x0, 0x1, 0x0, 0xf, 0x0, 0x1, 0x0, 0x80, 0x0, 0x2c, 0x88,
        0x0, 0x2a, 0x1, 0xa4, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
    ];

    let response = Some(Packet::new_ipv6(
        Ipv6Repr {
            src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
            dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
            hop_limit: 64,
            next_header: IpProtocol::Icmpv6,
            payload_len: 19,
        },
        IpPayload::Icmpv6(Icmpv6Repr::EchoReply {
            ident: 42,
            seq_no: 420,
            data: b"Lorem Ipsum",
        }),
    ));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            None,
        ),
        response
    );
}

#[rstest]
#[cfg_attr(feature = "medium-ip", case::ip(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case::ethernet(Medium::Ethernet))]
#[cfg_attr(feature = "medium-ieee802154", case::ieee802154(Medium::Ieee802154))]
fn hop_by_hop_discard_with_icmp(#[case] medium: Medium) {
    // The following contains:
    // - IPv6 header
    // - Hop-by-hop, with options:
    //  - PADN (skipped)
    //  - Unknown option (discard)
    // - ICMP echo request
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x1b, 0x0, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x3a, 0x0, 0x1, 0x0, 0x40, 0x0, 0x1, 0x0, 0x80, 0x0, 0x2c, 0x88,
        0x0, 0x2a, 0x1, 0xa4, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
    ];

    let response = None;

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            None,
        ),
        response
    );
}

#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
fn hop_by_hop_discard_param_problem(#[case] medium: Medium) {
    // The following contains:
    // - IPv6 header
    // - Hop-by-hop, with options:
    //  - PADN (skipped)
    //  - Unknown option (discard + ParamProblem)
    // - ICMP echo request
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x1b, 0x0, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x3a, 0x0, 0xC0, 0x0, 0x40, 0x0, 0x1, 0x0, 0x80, 0x0, 0x2c, 0x88,
        0x0, 0x2a, 0x1, 0xa4, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
    ];

    let response = Some(Packet::new_ipv6(
        Ipv6Repr {
            src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 1),
            dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2),
            next_header: IpProtocol::Icmpv6,
            payload_len: 75,
            hop_limit: 64,
        },
        IpPayload::Icmpv6(Icmpv6Repr::ParamProblem {
            reason: Icmpv6ParamProblem::UnrecognizedOption,
            pointer: 40,
            header: Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 1),
                next_header: IpProtocol::HopByHop,
                payload_len: 27,
                hop_limit: 64,
            },
            data: &[
                0x3a, 0x0, 0xC0, 0x0, 0x40, 0x0, 0x1, 0x0, 0x80, 0x0, 0x2c, 0x88, 0x0, 0x2a, 0x1,
                0xa4, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
            ],
        }),
    ));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            None,
        ),
        response
    );
}

#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
fn hop_by_hop_discard_with_multicast(#[case] medium: Medium) {
    // The following contains:
    // - IPv6 header
    // - Hop-by-hop, with options:
    //  - PADN (skipped)
    //  - Unknown option (discard (0b11) + ParamProblem)
    // - ICMP echo request
    //
    // In this case, even if the destination address is a multicast address, an ICMPv6 ParamProblem
    // should be transmitted.
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x1b, 0x0, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xff, 0x02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x3a, 0x0, 0x80, 0x0, 0x40, 0x0, 0x1, 0x0, 0x80, 0x0, 0x2c, 0x88,
        0x0, 0x2a, 0x1, 0xa4, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
    ];

    let response = Some(Packet::new_ipv6(
        Ipv6Repr {
            src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 1),
            dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2),
            next_header: IpProtocol::Icmpv6,
            payload_len: 75,
            hop_limit: 64,
        },
        IpPayload::Icmpv6(Icmpv6Repr::ParamProblem {
            reason: Icmpv6ParamProblem::UnrecognizedOption,
            pointer: 40,
            header: Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2),
                dst_addr: Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
                next_header: IpProtocol::HopByHop,
                payload_len: 27,
                hop_limit: 64,
            },
            data: &[
                0x3a, 0x0, 0x80, 0x0, 0x40, 0x0, 0x1, 0x0, 0x80, 0x0, 0x2c, 0x88, 0x0, 0x2a, 0x1,
                0xa4, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
            ],
        }),
    ));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            None,
        ),
        response
    );
}

#[rstest]
#[cfg_attr(feature = "medium-ip", case::ip(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case::ethernet(Medium::Ethernet))]
#[cfg_attr(feature = "medium-ieee802154", case::ieee802154(Medium::Ieee802154))]
fn imcp_empty_echo_request(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x8, 0x3a, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x80, 0x0, 0x84, 0x3c, 0x0, 0x0, 0x0, 0x0,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 64,
                next_header: IpProtocol::Icmpv6,
                payload_len: 8,
            },
            IpPayload::Icmpv6(Icmpv6Repr::EchoRequest {
                ident: 0,
                seq_no: 0,
                data: b"",
            })
        ))
    );

    let response = Some(Packet::new_ipv6(
        Ipv6Repr {
            src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
            dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
            hop_limit: 64,
            next_header: IpProtocol::Icmpv6,
            payload_len: 8,
        },
        IpPayload::Icmpv6(Icmpv6Repr::EchoReply {
            ident: 0,
            seq_no: 0,
            data: b"",
        }),
    ));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            None,
        ),
        response
    );
}

#[rstest]
#[cfg_attr(feature = "medium-ip", case::ip(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case::ethernet(Medium::Ethernet))]
#[cfg_attr(feature = "medium-ieee802154", case::ieee802154(Medium::Ieee802154))]
fn icmp_echo_request(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x13, 0x3a, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x80, 0x0, 0x2c, 0x88, 0x0, 0x2a, 0x1, 0xa4, 0x4c, 0x6f, 0x72,
        0x65, 0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 64,
                next_header: IpProtocol::Icmpv6,
                payload_len: 19,
            },
            IpPayload::Icmpv6(Icmpv6Repr::EchoRequest {
                ident: 42,
                seq_no: 420,
                data: b"Lorem Ipsum",
            })
        ))
    );

    let response = Some(Packet::new_ipv6(
        Ipv6Repr {
            src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
            dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
            hop_limit: 64,
            next_header: IpProtocol::Icmpv6,
            payload_len: 19,
        },
        IpPayload::Icmpv6(Icmpv6Repr::EchoReply {
            ident: 42,
            seq_no: 420,
            data: b"Lorem Ipsum",
        }),
    ));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            None,
        ),
        response
    );
}

#[rstest]
#[cfg_attr(feature = "medium-ip", case::ip(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case::ethernet(Medium::Ethernet))]
#[cfg_attr(feature = "medium-ieee802154", case::ieee802154(Medium::Ieee802154))]
fn icmp_echo_reply_as_input(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x13, 0x3a, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x81, 0x0, 0x2d, 0x56, 0x0, 0x0, 0x0, 0x0, 0x4c, 0x6f, 0x72, 0x65,
        0x6d, 0x20, 0x49, 0x70, 0x73, 0x75, 0x6d,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 64,
                next_header: IpProtocol::Icmpv6,
                payload_len: 19,
            },
            IpPayload::Icmpv6(Icmpv6Repr::EchoReply {
                ident: 0,
                seq_no: 0,
                data: b"Lorem Ipsum",
            })
        ))
    );

    let response = None;

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            None,
        ),
        response
    );
}

#[rstest]
#[cfg_attr(feature = "medium-ip", case::ip(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case::ethernet(Medium::Ethernet))]
#[cfg_attr(feature = "medium-ieee802154", case::ieee802154(Medium::Ieee802154))]
fn unknown_proto_with_multicast_dst_address(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xff, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1,
    ];

    let response = Some(Packet::new_ipv6(
        Ipv6Repr {
            src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
            dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
            hop_limit: 64,
            next_header: IpProtocol::Icmpv6,
            payload_len: 48,
        },
        IpPayload::Icmpv6(Icmpv6Repr::ParamProblem {
            reason: Icmpv6ParamProblem::UnrecognizedNxtHdr,
            pointer: 40,
            header: Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 64,
                next_header: IpProtocol::Unknown(0x0c),
                payload_len: 0,
            },
            data: &[],
        }),
    ));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            None,
        ),
        response
    );
}

#[rstest]
#[cfg_attr(feature = "medium-ip", case::ip(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case::ethernet(Medium::Ethernet))]
#[cfg_attr(feature = "medium-ieee802154", case::ieee802154(Medium::Ieee802154))]
fn unknown_proto(#[case] medium: Medium) {
    // Since the destination address is multicast, we should answer with an ICMPv6 message.
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x40, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1,
    ];

    let response = Some(Packet::new_ipv6(
        Ipv6Repr {
            src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
            dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
            hop_limit: 64,
            next_header: IpProtocol::Icmpv6,
            payload_len: 48,
        },
        IpPayload::Icmpv6(Icmpv6Repr::ParamProblem {
            reason: Icmpv6ParamProblem::UnrecognizedNxtHdr,
            pointer: 40,
            header: Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 64,
                next_header: IpProtocol::Unknown(0x0c),
                payload_len: 0,
            },
            data: &[],
        }),
    ));

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            None,
        ),
        response
    );
}

#[rstest]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn ndisc_neighbor_advertisement_ethernet(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x20, 0x3a, 0xff, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x88, 0x0, 0x3b, 0x9f, 0x40, 0x0, 0x0, 0x0, 0xfe, 0x80, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x2, 0x1, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x1,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 255,
                next_header: IpProtocol::Icmpv6,
                payload_len: 32,
            },
            IpPayload::Icmpv6(Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
                flags: NdiscNeighborFlags::SOLICITED,
                target_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x0002),
                lladdr: Some(RawHardwareAddress::from_bytes(&[0, 0, 0, 0, 0, 1])),
            }))
        ))
    );

    let response = None;

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            None,
        ),
        response
    );

    assert_eq!(
        iface.inner.neighbor_cache.lookup(
            &IpAddress::Ipv6(Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002)),
            iface.inner.now,
        ),
        NeighborAnswer::Found(HardwareAddress::Ethernet(EthernetAddress::from_bytes(&[
            0, 0, 0, 0, 0, 1
        ]))),
    );
}

#[rstest]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn ndisc_neighbor_advertisement_ethernet_multicast_addr(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x20, 0x3a, 0xff, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x88, 0x0, 0x3b, 0xa0, 0x40, 0x0, 0x0, 0x0, 0xfe, 0x80, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x2, 0x1, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 255,
                next_header: IpProtocol::Icmpv6,
                payload_len: 32,
            },
            IpPayload::Icmpv6(Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
                flags: NdiscNeighborFlags::SOLICITED,
                target_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x0002),
                lladdr: Some(RawHardwareAddress::from_bytes(&[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff
                ])),
            }))
        ))
    );

    let response = None;

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            None,
        ),
        response
    );

    assert_eq!(
        iface.inner.neighbor_cache.lookup(
            &IpAddress::Ipv6(Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002)),
            iface.inner.now,
        ),
        NeighborAnswer::NotFound,
    );
}

#[rstest]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn ndisc_neighbor_advertisement_ieee802154(#[case] medium: Medium) {
    let data = [
        0x60, 0x0, 0x0, 0x0, 0x0, 0x28, 0x3a, 0xff, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd, 0xbe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x88, 0x0, 0x3b, 0x96, 0x40, 0x0, 0x0, 0x0, 0xfe, 0x80, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x2, 0x2, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ];

    assert_eq!(
        parse_ipv6(&data),
        Ok(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002),
                dst_addr: Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0001),
                hop_limit: 255,
                next_header: IpProtocol::Icmpv6,
                payload_len: 40,
            },
            IpPayload::Icmpv6(Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
                flags: NdiscNeighborFlags::SOLICITED,
                target_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x0002),
                lladdr: Some(RawHardwareAddress::from_bytes(&[0, 0, 0, 0, 0, 0, 0, 1])),
            }))
        ))
    );

    let response = None;

    let (mut iface, mut sockets, _device) = setup(medium);

    assert_eq!(
        iface.inner.process_ipv6(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &Ipv6Packet::new_checked(&data[..]).unwrap(),
            None,
        ),
        response
    );

    assert_eq!(
        iface.inner.neighbor_cache.lookup(
            &IpAddress::Ipv6(Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x0002)),
            iface.inner.now,
        ),
        NeighborAnswer::Found(HardwareAddress::Ieee802154(Ieee802154Address::from_bytes(
            &[0, 0, 0, 0, 0, 0, 0, 1]
        ))),
    );
}

#[rstest]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn test_handle_valid_ndisc_request(#[case] medium: Medium) {
    let (mut iface, mut sockets, _device) = setup(medium);

    let mut eth_bytes = vec![0u8; 86];

    let local_ip_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 1);
    let remote_ip_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 2);
    let local_hw_addr = EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
    let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

    let solicit = Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
        target_addr: local_ip_addr,
        lladdr: Some(remote_hw_addr.into()),
    });
    let ip_repr = IpRepr::Ipv6(Ipv6Repr {
        src_addr: remote_ip_addr,
        dst_addr: local_ip_addr.solicited_node(),
        next_header: IpProtocol::Icmpv6,
        hop_limit: 0xff,
        payload_len: solicit.buffer_len(),
    });

    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(EthernetAddress([0x33, 0x33, 0x00, 0x00, 0x00, 0x00]));
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Ipv6);
    ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
    solicit.emit(
        &remote_ip_addr,
        &local_ip_addr.solicited_node(),
        &mut Icmpv6Packet::new_unchecked(&mut frame.payload_mut()[ip_repr.header_len()..]),
        &ChecksumCapabilities::default(),
    );

    let icmpv6_expected = Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
        flags: NdiscNeighborFlags::SOLICITED,
        target_addr: local_ip_addr,
        lladdr: Some(local_hw_addr.into()),
    });

    let ipv6_expected = Ipv6Repr {
        src_addr: local_ip_addr,
        dst_addr: remote_ip_addr,
        next_header: IpProtocol::Icmpv6,
        hop_limit: 0xff,
        payload_len: icmpv6_expected.buffer_len(),
    };

    // Ensure an Neighbor Solicitation triggers a Neighbor Advertisement
    assert_eq!(
        iface.inner.process_ethernet(
            &mut sockets,
            PacketMeta::default(),
            frame.into_inner(),
            &mut iface.fragments
        ),
        Some(EthernetPacket::Ip(Packet::new_ipv6(
            ipv6_expected,
            IpPayload::Icmpv6(icmpv6_expected)
        )))
    );

    // Ensure the address of the requester was entered in the cache
    assert_eq!(
        iface.inner.lookup_hardware_addr(
            MockTxToken,
            &IpAddress::Ipv6(remote_ip_addr),
            &mut iface.fragmenter,
        ),
        Ok((HardwareAddress::Ethernet(remote_hw_addr), MockTxToken))
    );
}

/// A neighbor solicitation is the IPv6 counterpart of an ARP request, and is
/// held to the same admission rule: it may not displace a cached neighbor. The
/// advertisement it asks for is still owed, so it must still go out.
#[rstest]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn test_ndisc_solicitation_never_evicts(#[case] medium: Medium) {
    use crate::config::IFACE_NEIGHBOR_CACHE_COUNT;

    let (mut iface, mut sockets, _device) = setup(medium);

    let local_ip_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 1);
    let remote_ip_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0x99);
    let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x99]);

    // Fill the cache to capacity with distinct neighbors.
    let cached: Vec<(Ipv6Address, EthernetAddress)> = (0..IFACE_NEIGHBOR_CACHE_COUNT)
        .map(|n| {
            let n = 10 + n as u8;
            (
                Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, n as u16),
                EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, n]),
            )
        })
        .collect();
    for (ip_addr, hw_addr) in &cached {
        iface.inner.neighbor_cache.fill(
            IpAddress::Ipv6(*ip_addr),
            HardwareAddress::Ethernet(*hw_addr),
            iface.inner.now,
        );
    }

    let solicit = Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
        target_addr: local_ip_addr,
        lladdr: Some(remote_hw_addr.into()),
    });
    let ip_repr = IpRepr::Ipv6(Ipv6Repr {
        src_addr: remote_ip_addr,
        dst_addr: local_ip_addr.solicited_node(),
        next_header: IpProtocol::Icmpv6,
        hop_limit: 0xff,
        payload_len: solicit.buffer_len(),
    });

    let mut eth_bytes = vec![0u8; 86];
    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(EthernetAddress([0x33, 0x33, 0x00, 0x00, 0x00, 0x00]));
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Ipv6);
    ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
    solicit.emit(
        &remote_ip_addr,
        &local_ip_addr.solicited_node(),
        &mut Icmpv6Packet::new_unchecked(&mut frame.payload_mut()[ip_repr.header_len()..]),
        &ChecksumCapabilities::default(),
    );

    // The advertisement is still owed, and still goes out.
    assert!(
        iface
            .inner
            .process_ethernet(
                &mut sockets,
                PacketMeta::default(),
                frame.into_inner(),
                &mut iface.fragments
            )
            .is_some()
    );

    // Every cached mapping survived, and the solicitor was not learned.
    for (ip_addr, hw_addr) in &cached {
        assert_eq!(
            iface
                .inner
                .neighbor_cache
                .lookup(&IpAddress::Ipv6(*ip_addr), iface.inner.now),
            NeighborAnswer::Found(HardwareAddress::Ethernet(*hw_addr))
        );
    }
    assert!(
        !iface
            .inner
            .neighbor_cache
            .lookup(&IpAddress::Ipv6(remote_ip_addr), iface.inner.now)
            .found()
    );
    assert_eq!(iface.take_neighbor_admission_refused(), 1);
}

#[rstest]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn test_ndisc_advert_never_evicts_gateway(#[case] medium: Medium) {
    use crate::config::IFACE_NEIGHBOR_CACHE_COUNT;

    let (mut iface, mut sockets, _device) = setup(medium);

    let local_ip_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 1);
    let local_hw_addr = EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
    let gateway_ip_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, 0xfe);
    let gateway_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0xfe]);

    iface.routes_mut().add_default_ipv6_route(gateway_ip_addr);

    // The gateway is closest to expiry, so it is the entry an unprotected
    // eviction takes first. The rest fill the cache.
    iface.inner.neighbor_cache.fill(
        IpAddress::Ipv6(gateway_ip_addr),
        HardwareAddress::Ethernet(gateway_hw_addr),
        iface.inner.now,
    );
    for n in 1..IFACE_NEIGHBOR_CACHE_COUNT as u8 {
        iface.inner.neighbor_cache.fill(
            IpAddress::Ipv6(Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, (10 + n).into())),
            HardwareAddress::Ethernet(EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 10 + n])),
            iface.inner.now + Duration::from_millis(n.into()),
        );
    }

    // A stream of forged advertisements, each from an address of its own.
    for n in 0..IFACE_NEIGHBOR_CACHE_COUNT as u8 + 2 {
        let other_ip_addr = Ipv6Address::new(0xfdbe, 0, 0, 0, 0, 0, 0, (20 + n).into());
        let other_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x01, 20 + n]);

        let advert = Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
            flags: NdiscNeighborFlags::SOLICITED,
            target_addr: other_ip_addr,
            lladdr: Some(other_hw_addr.into()),
        });
        let ip_repr = IpRepr::Ipv6(Ipv6Repr {
            src_addr: other_ip_addr,
            dst_addr: local_ip_addr,
            next_header: IpProtocol::Icmpv6,
            hop_limit: 0xff,
            payload_len: advert.buffer_len(),
        });

        let mut eth_bytes = vec![0u8; 86];
        let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
        frame.set_dst_addr(local_hw_addr);
        frame.set_src_addr(other_hw_addr);
        frame.set_ethertype(EthernetProtocol::Ipv6);
        ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
        advert.emit(
            &other_ip_addr,
            &local_ip_addr,
            &mut Icmpv6Packet::new_unchecked(&mut frame.payload_mut()[ip_repr.header_len()..]),
            &ChecksumCapabilities::default(),
        );

        assert!(
            iface
                .inner
                .process_ethernet(
                    &mut sockets,
                    PacketMeta::default(),
                    frame.into_inner(),
                    &mut iface.fragments
                )
                .is_none()
        );
    }

    // The gateway is still cached, so egress through it still resolves.
    assert_eq!(
        iface
            .inner
            .neighbor_cache
            .lookup(&IpAddress::Ipv6(gateway_ip_addr), iface.inner.now),
        NeighborAnswer::Found(HardwareAddress::Ethernet(gateway_hw_addr))
    );
}

#[rstest]
#[case(Medium::Ethernet)]
#[cfg(feature = "proto-ipv6-slaac")]
fn test_router_advertisement(#[case] medium: Medium) {
    fn recv_icmpv6(
        device: &mut crate::tests::TestingDevice,
        timestamp: Instant,
    ) -> std::vec::Vec<Ipv6Packet<std::vec::Vec<u8>>> {
        let caps = device.capabilities();
        recv_all(device, timestamp)
            .iter()
            .filter_map(|frame| {
                let ipv6_packet = match caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => {
                        let eth_frame = EthernetFrame::new_checked(frame).ok()?;
                        Ipv6Packet::new_checked(eth_frame.payload()).ok()?
                    }
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => Ipv6Packet::new_checked(&frame[..]).ok()?,
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => todo!(),
                };
                let buf = ipv6_packet.into_inner().to_vec();
                Some(Ipv6Packet::new_unchecked(buf))
            })
            .collect::<std::vec::Vec<_>>()
    }
    let prefix_addr = Ipv6Address::new(0x2001, 0xdb8, 0x3, 0, 0, 0, 0, 0);

    let mut device = crate::tests::TestingDevice::new(medium);
    let caps = device.capabilities();
    let checksum_caps = &caps.checksum;

    let mut eth_bytes = vec![0u8; 102];

    // Create mac addresses with derived link local addresses
    let local_hw_addr = EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
    let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);
    let ll_prefix = Ipv6Cidr::new(Ipv6Cidr::LINK_LOCAL_PREFIX.address(), 64);
    let local_ip_addr =
        Ipv6Cidr::from_link_prefix(&ll_prefix, HardwareAddress::Ethernet(local_hw_addr)).unwrap();
    let remote_ip_addr =
        Ipv6Cidr::from_link_prefix(&ll_prefix, HardwareAddress::Ethernet(remote_hw_addr)).unwrap();

    // Create config with slaac enabled
    let mut config = Config::new(match medium {
        #[cfg(feature = "medium-ethernet")]
        Medium::Ethernet => HardwareAddress::Ethernet(local_hw_addr),
        _ => panic!("Not supported"),
    });
    config.slaac = true;

    // Set up interface with link local address
    let mut iface = Interface::new(config, &mut device, Instant::ZERO);
    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs.push(IpCidr::Ipv6(local_ip_addr));
    });

    let mut sockets = SocketSet::new();
    iface.poll(Instant::ZERO, &mut device, &mut sockets);

    let transmitted: std::vec::Vec<Ipv6Packet<std::vec::Vec<u8>>> =
        recv_icmpv6(&mut device, Instant::ZERO)
            .into_iter()
            .filter(|packet| {
                // Filter for router solicitations
                packet.dst_addr() == IPV6_LINK_LOCAL_ALL_ROUTERS
            })
            .collect();

    assert_eq!(transmitted.len(), 1);

    for ipv6_packet in transmitted.into_iter() {
        let buf = ipv6_packet.into_inner();
        let ipv6_packet = Ipv6Packet::new_unchecked(buf.as_slice());
        let ipv6_repr = Ipv6Repr::parse(&ipv6_packet).unwrap();
        if ipv6_repr.dst_addr == IPV6_LINK_LOCAL_ALL_MLDV2_ROUTERS {
            continue; // Skip MLD reports
        }
        let icmpv6_packet = Icmpv6Packet::new_checked(ipv6_packet.payload()).unwrap();
        let icmp_repr = Icmpv6Repr::parse(
            &ipv6_repr.src_addr,
            &ipv6_repr.dst_addr,
            &icmpv6_packet,
            checksum_caps,
        )
        .unwrap();

        assert_eq!(
            icmp_repr,
            Icmpv6Repr::Ndisc(NdiscRepr::RouterSolicit {
                lladdr: Some(local_hw_addr.into()),
            })
        );

        assert_eq!(ipv6_repr.dst_addr, IPV6_LINK_LOCAL_ALL_ROUTERS);
        println!("repr {:?}", icmp_repr);
    }

    // Craft the router advertisement
    let mut prefix_information = NdiscPrefixInformation {
        prefix: prefix_addr,
        prefix_len: 64,
        flags: NdiscPrefixInfoFlags::ADDRCONF,
        valid_lifetime: Duration::from_secs(600),
        preferred_lifetime: Duration::from_secs(300),
    };
    let mut advertisement = NdiscRepr::RouterAdvert {
        hop_limit: 255,
        flags: NdiscRouterFlags::empty(),
        router_lifetime: Duration::from_secs(600),
        reachable_time: Duration::from_secs(0),
        retrans_time: Duration::from_secs(0),
        lladdr: None,
        mtu: None,
        prefix_info: Some(prefix_information),
    };
    let ip_repr = IpRepr::Ipv6(Ipv6Repr {
        src_addr: remote_ip_addr.address(),
        dst_addr: local_ip_addr.address(),
        next_header: IpProtocol::Icmpv6,
        hop_limit: 255,
        payload_len: advertisement.buffer_len(),
    });
    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(local_hw_addr);
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Ipv6);
    ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
    Icmpv6Repr::Ndisc(advertisement).emit(
        &remote_ip_addr.address(),
        &local_ip_addr.address(),
        &mut Icmpv6Packet::new_unchecked(&mut frame.payload_mut()[ip_repr.header_len()..]),
        &ChecksumCapabilities::default(),
    );

    iface.inner.process_ethernet(
        &mut sockets,
        PacketMeta::default(),
        frame.into_inner(),
        &mut iface.fragments,
    );

    iface.poll(Instant::ZERO, &mut device, &mut sockets);

    // Expect to have these two addresses after the router advertisement
    let expected_addrs = [
        IpCidr::Ipv6(local_ip_addr),
        IpCidr::Ipv6(Ipv6Cidr::new(
            Ipv6Address::new(0x2001, 0xdb8, 0x3, 0x0, 0x2, 0x2ff, 0xfe02, 0x202),
            64,
        )),
    ];
    for (generated, expected) in iface.ip_addrs().iter().zip(expected_addrs.iter()) {
        assert_eq!(generated, expected);
    }
    // Verify the pushed route matches expected
    iface.routes_mut().update(|route| {
        assert_eq!(route.len(), 1);
        assert_eq!(
            route[0].cidr,
            IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 0), 0)
        );
        assert_eq!(
            route[0].via_router,
            IpAddress::Ipv6(remote_ip_addr.address())
        );
        assert_eq!(route[0].preferred_until, None);
        assert_eq!(route[0].expires_at, None);
    });

    // Craft a router advertisement with zero lifetime for the prefix
    // to remove the prefix, but retain the route
    prefix_information.valid_lifetime = Duration::ZERO;
    prefix_information.preferred_lifetime = Duration::ZERO;
    if let NdiscRepr::RouterAdvert {
        ref mut prefix_info,
        ..
    } = advertisement
    {
        *prefix_info = Some(prefix_information);
    }

    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(local_hw_addr);
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Ipv6);
    ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
    Icmpv6Repr::Ndisc(advertisement).emit(
        &remote_ip_addr.address(),
        &local_ip_addr.address(),
        &mut Icmpv6Packet::new_unchecked(&mut frame.payload_mut()[ip_repr.header_len()..]),
        &ChecksumCapabilities::default(),
    );

    iface.inner.process_ethernet(
        &mut sockets,
        PacketMeta::default(),
        frame.into_inner(),
        &mut iface.fragments,
    );

    let now = Instant::from_secs(10);

    iface.poll(now, &mut device, &mut sockets);
    assert_eq!(iface.ip_addrs().len(), 1);
    iface.routes_mut().update(|route| {
        assert_eq!(route.len(), 1);
    });

    // Craft router advertisement with zero router lifetime
    // to remove the route
    if let NdiscRepr::RouterAdvert {
        ref mut prefix_info,
        ref mut router_lifetime,
        ..
    } = advertisement
    {
        *prefix_info = None;
        *router_lifetime = Duration::ZERO;
    }

    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(local_hw_addr);
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Ipv6);
    ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
    Icmpv6Repr::Ndisc(advertisement).emit(
        &remote_ip_addr.address(),
        &local_ip_addr.address(),
        &mut Icmpv6Packet::new_unchecked(&mut frame.payload_mut()[ip_repr.header_len()..]),
        &ChecksumCapabilities::default(),
    );

    iface.inner.process_ethernet(
        &mut sockets,
        PacketMeta::default(),
        frame.into_inner(),
        &mut iface.fragments,
    );

    let now = Instant::from_secs(20);
    iface.poll(now, &mut device, &mut sockets);
    iface.routes_mut().update(|route| {
        assert_eq!(route.len(), 0);
    });
}

#[rstest]
#[cfg_attr(feature = "medium-ip", case(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case(Medium::Ethernet))]
#[cfg_attr(feature = "medium-ieee802154", case(Medium::Ieee802154))]
fn test_solicited_node_addrs(#[case] medium: Medium) {
    let (mut iface, _, _) = setup(medium);
    let mut new_addrs = vec![
        IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 1, 2, 0, 2), 64),
        IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 3, 4, 0, 0xffff), 64),
    ];
    iface.update_ip_addrs(|addrs| {
        new_addrs.extend(addrs.iter().copied());
        *addrs = new_addrs;
    });
    assert!(
        iface
            .inner
            .has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0x0002))
    );
    assert!(
        iface
            .inner
            .has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0xffff))
    );
    assert!(
        !iface
            .inner
            .has_solicited_node(Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0x0003))
    );
}

#[cfg(feature = "socket-udp")]
#[rstest]
#[cfg_attr(feature = "medium-ip", case(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case(Medium::Ethernet))]
#[cfg_attr(feature = "medium-ieee802154", case(Medium::Ieee802154))]
fn test_icmp_reply_size(#[case] medium: Medium) {
    use crate::wire::IPV6_MIN_MTU as MIN_MTU;
    use crate::wire::Icmpv6DstUnreachable;
    const MAX_PAYLOAD_LEN: usize = 1192;

    let (mut iface, mut sockets, _device) = setup(medium);

    let src_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let dst_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

    // UDP packet that if not tructated will cause a icmp port unreachable reply
    // to exceed the minimum mtu bytes in length.
    let udp_repr = UdpRepr {
        src_port: 67,
        dst_port: 68,
    };
    let mut bytes = vec![0xff; udp_repr.header_len() + MAX_PAYLOAD_LEN];
    let mut packet = UdpPacket::new_unchecked(&mut bytes[..]);
    udp_repr.emit(
        &mut packet,
        &src_addr.into(),
        &dst_addr.into(),
        MAX_PAYLOAD_LEN,
        |buf| fill_slice(buf, 0x2a),
        &ChecksumCapabilities::default(),
    );

    let ip_repr = Ipv6Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Udp,
        hop_limit: 64,
        payload_len: udp_repr.header_len() + MAX_PAYLOAD_LEN,
    };
    let payload = packet.into_inner();

    let expected_icmp_repr = Icmpv6Repr::DstUnreachable {
        reason: Icmpv6DstUnreachable::PortUnreachable,
        header: ip_repr,
        data: &payload[..MAX_PAYLOAD_LEN],
    };

    let expected_ip_repr = Ipv6Repr {
        src_addr: dst_addr,
        dst_addr: src_addr,
        next_header: IpProtocol::Icmpv6,
        hop_limit: 64,
        payload_len: expected_icmp_repr.buffer_len(),
    };

    assert_eq!(
        expected_ip_repr.buffer_len() + expected_icmp_repr.buffer_len(),
        MIN_MTU
    );

    assert_eq!(
        iface.inner.process_udp(
            &mut sockets,
            PacketMeta::default(),
            false,
            ip_repr.into(),
            payload,
        ),
        Some(Packet::new_ipv6(
            expected_ip_repr,
            IpPayload::Icmpv6(expected_icmp_repr)
        ))
    );
}

#[cfg(feature = "medium-ip")]
#[test]
fn get_source_address() {
    let (mut iface, _, _) = setup(Medium::Ip);

    const OWN_LINK_LOCAL_ADDR: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const OWN_UNIQUE_LOCAL_ADDR1: Ipv6Address = Ipv6Address::new(0xfd00, 0, 0, 201, 1, 1, 1, 2);
    const OWN_UNIQUE_LOCAL_ADDR2: Ipv6Address = Ipv6Address::new(0xfd01, 0, 0, 201, 1, 1, 1, 2);
    const OWN_GLOBAL_UNICAST_ADDR1: Ipv6Address =
        Ipv6Address::new(0x2001, 0x0db8, 0x0003, 0, 0, 0, 0, 1);

    // List of addresses of the interface:
    //   fe80::1/64
    //   fd00::201:1:1:1:2/64
    //   fd01::201:1:1:1:2/64
    //   2001:db8:3::1/64
    iface.update_ip_addrs(|addrs| {
        addrs.clear();

        addrs.push(IpCidr::Ipv6(Ipv6Cidr::new(OWN_LINK_LOCAL_ADDR, 64)));
        addrs.push(IpCidr::Ipv6(Ipv6Cidr::new(OWN_UNIQUE_LOCAL_ADDR1, 64)));
        addrs.push(IpCidr::Ipv6(Ipv6Cidr::new(OWN_UNIQUE_LOCAL_ADDR2, 64)));
        addrs.push(IpCidr::Ipv6(Ipv6Cidr::new(OWN_GLOBAL_UNICAST_ADDR1, 64)));
    });

    // List of addresses we test:
    //   ::1               -> ::1
    //   fe80::42          -> fe80::1
    //   fd00::201:1:1:1:1 -> fd00::201:1:1:1:2
    //   fd01::201:1:1:1:1 -> fd01::201:1:1:1:2
    //   fd02::201:1:1:1:1 -> fd00::201:1:1:1:2 (because first added in the list)
    //   fd01::201:1:1:1:3 -> fd01::201:1:1:1:2 (because in same subnet)
    //   ff02::1           -> fe80::1 (same scope)
    //   2001:db8:3::2     -> 2001:db8:3::1
    //   2001:db9:3::2     -> 2001:db8:3::1
    const LINK_LOCAL_ADDR: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 42);
    const UNIQUE_LOCAL_ADDR1: Ipv6Address = Ipv6Address::new(0xfd00, 0, 0, 201, 1, 1, 1, 1);
    const UNIQUE_LOCAL_ADDR2: Ipv6Address = Ipv6Address::new(0xfd01, 0, 0, 201, 1, 1, 1, 1);
    const UNIQUE_LOCAL_ADDR3: Ipv6Address = Ipv6Address::new(0xfd02, 0, 0, 201, 1, 1, 1, 1);
    const UNIQUE_LOCAL_ADDR4: Ipv6Address = Ipv6Address::new(0xfd01, 0, 0, 201, 1, 1, 1, 3);
    const GLOBAL_UNICAST_ADDR1: Ipv6Address =
        Ipv6Address::new(0x2001, 0x0db8, 0x0003, 0, 0, 0, 0, 2);
    const GLOBAL_UNICAST_ADDR2: Ipv6Address =
        Ipv6Address::new(0x2001, 0x0db9, 0x0003, 0, 0, 0, 0, 2);

    assert_eq!(
        iface.inner.get_source_address_ipv6(&Ipv6Address::LOCALHOST),
        Ipv6Address::LOCALHOST
    );

    assert_eq!(
        iface.inner.get_source_address_ipv6(&LINK_LOCAL_ADDR),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR1),
        OWN_UNIQUE_LOCAL_ADDR1
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR2),
        OWN_UNIQUE_LOCAL_ADDR2
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR3),
        OWN_UNIQUE_LOCAL_ADDR1
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR4),
        OWN_UNIQUE_LOCAL_ADDR2
    );
    assert_eq!(
        iface
            .inner
            .get_source_address_ipv6(&IPV6_LINK_LOCAL_ALL_NODES),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR1),
        OWN_GLOBAL_UNICAST_ADDR1
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR2),
        OWN_GLOBAL_UNICAST_ADDR1
    );

    assert_eq!(
        iface.get_source_address_ipv6(&LINK_LOCAL_ADDR),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR1),
        OWN_UNIQUE_LOCAL_ADDR1
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR2),
        OWN_UNIQUE_LOCAL_ADDR2
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR3),
        OWN_UNIQUE_LOCAL_ADDR1
    );
    assert_eq!(
        iface.get_source_address_ipv6(&IPV6_LINK_LOCAL_ALL_NODES),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR1),
        OWN_GLOBAL_UNICAST_ADDR1
    );
    assert_eq!(
        iface.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR2),
        OWN_GLOBAL_UNICAST_ADDR1
    );
}

#[cfg(feature = "medium-ip")]
#[test]
fn get_source_address_only_link_local() {
    let (mut iface, _, _) = setup(Medium::Ip);

    // List of addresses in the interface:
    //   fe80::1/64
    const OWN_LINK_LOCAL_ADDR: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    iface.update_ip_addrs(|ips| {
        ips.clear();
        ips.push(IpCidr::Ipv6(Ipv6Cidr::new(OWN_LINK_LOCAL_ADDR, 64)));
    });

    // List of addresses we test:
    //   ::1               -> ::1
    //   fe80::42          -> fe80::1
    //   fd00::201:1:1:1:1 -> fe80::1
    //   fd01::201:1:1:1:1 -> fe80::1
    //   fd02::201:1:1:1:1 -> fe80::1
    //   ff02::1           -> fe80::1
    //   2001:db8:3::2     -> fe80::1
    //   2001:db9:3::2     -> fe80::1
    const LINK_LOCAL_ADDR: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 42);
    const UNIQUE_LOCAL_ADDR1: Ipv6Address = Ipv6Address::new(0xfd00, 0, 0, 201, 1, 1, 1, 1);
    const UNIQUE_LOCAL_ADDR2: Ipv6Address = Ipv6Address::new(0xfd01, 0, 0, 201, 1, 1, 1, 1);
    const UNIQUE_LOCAL_ADDR3: Ipv6Address = Ipv6Address::new(0xfd02, 0, 0, 201, 1, 1, 1, 1);
    const GLOBAL_UNICAST_ADDR1: Ipv6Address =
        Ipv6Address::new(0x2001, 0x0db8, 0x0003, 0, 0, 0, 0, 2);
    const GLOBAL_UNICAST_ADDR2: Ipv6Address =
        Ipv6Address::new(0x2001, 0x0db9, 0x0003, 0, 0, 0, 0, 2);

    assert_eq!(
        iface.inner.get_source_address_ipv6(&Ipv6Address::LOCALHOST),
        Ipv6Address::LOCALHOST
    );

    assert_eq!(
        iface.inner.get_source_address_ipv6(&LINK_LOCAL_ADDR),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR1),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR2),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR3),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface
            .inner
            .get_source_address_ipv6(&IPV6_LINK_LOCAL_ALL_NODES),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR1),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR2),
        OWN_LINK_LOCAL_ADDR
    );

    assert_eq!(
        iface.get_source_address_ipv6(&LINK_LOCAL_ADDR),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR1),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR2),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR3),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&IPV6_LINK_LOCAL_ALL_NODES),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR1),
        OWN_LINK_LOCAL_ADDR
    );
    assert_eq!(
        iface.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR2),
        OWN_LINK_LOCAL_ADDR
    );
}

#[cfg(feature = "medium-ip")]
#[test]
fn get_source_address_empty_interface() {
    let (mut iface, _, _) = setup(Medium::Ip);

    iface.update_ip_addrs(|ips| ips.clear());

    // List of addresses we test:
    //   ::1               -> ::1
    //   fe80::42          -> ::1
    //   fd00::201:1:1:1:1 -> ::1
    //   fd01::201:1:1:1:1 -> ::1
    //   fd02::201:1:1:1:1 -> ::1
    //   ff02::1           -> ::1
    //   2001:db8:3::2     -> ::1
    //   2001:db9:3::2     -> ::1
    const LINK_LOCAL_ADDR: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 42);
    const UNIQUE_LOCAL_ADDR1: Ipv6Address = Ipv6Address::new(0xfd00, 0, 0, 201, 1, 1, 1, 1);
    const UNIQUE_LOCAL_ADDR2: Ipv6Address = Ipv6Address::new(0xfd01, 0, 0, 201, 1, 1, 1, 1);
    const UNIQUE_LOCAL_ADDR3: Ipv6Address = Ipv6Address::new(0xfd02, 0, 0, 201, 1, 1, 1, 1);
    const GLOBAL_UNICAST_ADDR1: Ipv6Address =
        Ipv6Address::new(0x2001, 0x0db8, 0x0003, 0, 0, 0, 0, 2);
    const GLOBAL_UNICAST_ADDR2: Ipv6Address =
        Ipv6Address::new(0x2001, 0x0db9, 0x0003, 0, 0, 0, 0, 2);

    assert_eq!(
        iface.inner.get_source_address_ipv6(&Ipv6Address::LOCALHOST),
        Ipv6Address::LOCALHOST
    );

    assert_eq!(
        iface.inner.get_source_address_ipv6(&LINK_LOCAL_ADDR),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR1),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR2),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR3),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface
            .inner
            .get_source_address_ipv6(&IPV6_LINK_LOCAL_ALL_NODES),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR1),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.inner.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR2),
        Ipv6Address::LOCALHOST
    );

    assert_eq!(
        iface.get_source_address_ipv6(&LINK_LOCAL_ADDR),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR1),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR2),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.get_source_address_ipv6(&UNIQUE_LOCAL_ADDR3),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.get_source_address_ipv6(&IPV6_LINK_LOCAL_ALL_NODES),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR1),
        Ipv6Address::LOCALHOST
    );
    assert_eq!(
        iface.get_source_address_ipv6(&GLOBAL_UNICAST_ADDR2),
        Ipv6Address::LOCALHOST
    );
}

#[cfg(feature = "multicast")]
#[rstest]
#[cfg_attr(feature = "medium-ip", case(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case(Medium::Ethernet))]
fn test_join_ipv6_multicast_group(#[case] medium: Medium) {
    fn recv_icmpv6(
        device: &mut crate::tests::TestingDevice,
        timestamp: Instant,
    ) -> std::vec::Vec<Ipv6Packet<std::vec::Vec<u8>>> {
        let caps = device.capabilities();
        recv_all(device, timestamp)
            .iter()
            .filter_map(|frame| {
                let ipv6_packet = match caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => {
                        let eth_frame = EthernetFrame::new_checked(frame).ok()?;
                        Ipv6Packet::new_checked(eth_frame.payload()).ok()?
                    }
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => Ipv6Packet::new_checked(&frame[..]).ok()?,
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => todo!(),
                };
                let buf = ipv6_packet.into_inner().to_vec();
                Some(Ipv6Packet::new_unchecked(buf))
            })
            .collect::<std::vec::Vec<_>>()
    }

    let (mut iface, mut sockets, mut device) = setup(medium);

    let groups = [
        Ipv6Address::new(0xff05, 0, 0, 0, 0, 0, 0, 0x00fb),
        Ipv6Address::new(0xff0e, 0, 0, 0, 0, 0, 0, 0x0017),
    ];

    let timestamp = Instant::from_millis(0);

    // Drain the unsolicited node multicast report from the device
    iface.poll(timestamp, &mut device, &mut sockets);
    let _ = recv_icmpv6(&mut device, timestamp);

    for &group in &groups {
        iface.join_multicast_group(group).unwrap();
        assert!(iface.has_multicast_group(group));
    }
    assert!(iface.has_multicast_group(IPV6_LINK_LOCAL_ALL_NODES));
    iface.poll(timestamp, &mut device, &mut sockets);
    assert!(iface.has_multicast_group(IPV6_LINK_LOCAL_ALL_NODES));

    let reports = recv_icmpv6(&mut device, timestamp);
    assert_eq!(reports.len(), 2);

    let caps = device.capabilities();
    let checksum_caps = &caps.checksum;
    for (&group_addr, ipv6_packet) in groups.iter().zip(reports) {
        let buf = ipv6_packet.into_inner();
        let ipv6_packet = Ipv6Packet::new_unchecked(buf.as_slice());

        let _ipv6_repr = Ipv6Repr::parse(&ipv6_packet).unwrap();
        let ip_payload = ipv6_packet.payload();

        // The first 2 octets of this payload hold the next-header indicator and the
        // Hop-by-Hop header length (in 8-octet words, minus 1). The remaining 6 octets
        // hold the Hop-by-Hop PadN and Router Alert options.
        let hbh_header = Ipv6HopByHopHeader::new_checked(&ip_payload[..8]).unwrap();
        let hbh_repr = Ipv6HopByHopRepr::parse(&hbh_header).unwrap();

        assert_eq!(hbh_repr.options.len(), 3);
        assert_eq!(
            hbh_repr.options[0],
            Ipv6OptionRepr::Unknown {
                type_: Ipv6OptionType::Unknown(IpProtocol::Icmpv6.into()),
                length: 0,
                data: &[],
            }
        );
        assert_eq!(
            hbh_repr.options[1],
            Ipv6OptionRepr::RouterAlert(Ipv6OptionRouterAlert::MulticastListenerDiscovery)
        );
        assert_eq!(hbh_repr.options[2], Ipv6OptionRepr::PadN(0));

        let icmpv6_packet =
            Icmpv6Packet::new_checked(&ip_payload[hbh_repr.buffer_len()..]).unwrap();
        let icmpv6_repr = Icmpv6Repr::parse(
            &ipv6_packet.src_addr(),
            &ipv6_packet.dst_addr(),
            &icmpv6_packet,
            checksum_caps,
        )
        .unwrap();

        let record_data = match icmpv6_repr {
            Icmpv6Repr::Mld(MldRepr::Report {
                nr_mcast_addr_rcrds,
                data,
            }) => {
                assert_eq!(nr_mcast_addr_rcrds, 1);
                data
            }
            other => panic!("unexpected icmpv6_repr: {:?}", other),
        };

        let record = MldAddressRecord::new_checked(record_data).unwrap();
        let record_repr = MldAddressRecordRepr::parse(&record).unwrap();

        assert_eq!(
            record_repr,
            MldAddressRecordRepr {
                num_srcs: 0,
                mcast_addr: group_addr,
                record_type: MldRecordType::ChangeToInclude,
                aux_data_len: 0,
                payload: &[],
            }
        );

        if !group_addr.is_solicited_node_multicast() {
            iface.leave_multicast_group(group_addr).unwrap();
            assert!(!iface.has_multicast_group(group_addr));
            iface.poll(timestamp, &mut device, &mut sockets);
            assert!(!iface.has_multicast_group(group_addr));
        }
    }
}

#[rstest]
#[case(Medium::Ethernet)]
#[cfg(all(feature = "multicast", feature = "medium-ethernet"))]
fn test_handle_valid_multicast_query(#[case] medium: Medium) {
    fn recv_icmpv6(
        device: &mut crate::tests::TestingDevice,
        timestamp: Instant,
    ) -> std::vec::Vec<Ipv6Packet<std::vec::Vec<u8>>> {
        let caps = device.capabilities();
        recv_all(device, timestamp)
            .iter()
            .filter_map(|frame| {
                let ipv6_packet = match caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => {
                        let eth_frame = EthernetFrame::new_checked(frame).ok()?;
                        Ipv6Packet::new_checked(eth_frame.payload()).ok()?
                    }
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => Ipv6Packet::new_checked(&frame[..]).ok()?,
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => todo!(),
                };
                let buf = ipv6_packet.into_inner().to_vec();
                Some(Ipv6Packet::new_unchecked(buf))
            })
            .collect::<std::vec::Vec<_>>()
    }

    let (mut iface, mut sockets, mut device) = setup(medium);

    let mut timestamp = Instant::ZERO;

    let mut eth_bytes = vec![0u8; 86];

    let local_ip_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let remote_ip_addr = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 100);
    let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);
    let query_ip_addr = Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 0x1234);

    iface.join_multicast_group(query_ip_addr).unwrap();

    iface.poll(timestamp, &mut device, &mut sockets);
    // flush multicast reports from the join_multicast_group calls
    recv_icmpv6(&mut device, timestamp);

    let queries = [
        // General query, expect both multicast addresses back
        (
            Ipv6Address::UNSPECIFIED,
            IPV6_LINK_LOCAL_ALL_NODES,
            vec![local_ip_addr.solicited_node(), query_ip_addr],
        ),
        // Address specific query, expect only the queried address back
        (query_ip_addr, query_ip_addr, vec![query_ip_addr]),
    ];

    for (mcast_query, address, _results) in queries.iter() {
        let query = Icmpv6Repr::Mld(MldRepr::Query {
            max_resp_code: 1000,
            mcast_addr: *mcast_query,
            s_flag: false,
            qrv: 1,
            qqic: 60,
            num_srcs: 0,
            data: &[0, 0, 0, 0],
        });

        let ip_repr = IpRepr::Ipv6(Ipv6Repr {
            src_addr: remote_ip_addr,
            dst_addr: *address,
            next_header: IpProtocol::Icmpv6,
            hop_limit: 1,
            payload_len: query.buffer_len(),
        });

        let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
        frame.set_dst_addr(EthernetAddress([0x33, 0x33, 0x00, 0x00, 0x00, 0x00]));
        frame.set_src_addr(remote_hw_addr);
        frame.set_ethertype(EthernetProtocol::Ipv6);
        ip_repr.emit(frame.payload_mut(), &ChecksumCapabilities::default());
        query.emit(
            &remote_ip_addr,
            address,
            &mut Icmpv6Packet::new_unchecked(&mut frame.payload_mut()[ip_repr.header_len()..]),
            &ChecksumCapabilities::default(),
        );

        iface.inner.process_ethernet(
            &mut sockets,
            PacketMeta::default(),
            frame.into_inner(),
            &mut iface.fragments,
        );

        timestamp += crate::time::Duration::from_millis(1000);
        iface.poll(timestamp, &mut device, &mut sockets);
    }

    let reports = recv_icmpv6(&mut device, timestamp);
    assert_eq!(reports.len(), queries.len());

    let caps = device.capabilities();
    let checksum_caps = &caps.checksum;
    for ((_mcast_query, _address, results), ipv6_packet) in queries.iter().zip(reports) {
        let buf = ipv6_packet.into_inner();
        let ipv6_packet = Ipv6Packet::new_unchecked(buf.as_slice());

        let ipv6_repr = Ipv6Repr::parse(&ipv6_packet).unwrap();
        let ip_payload = ipv6_packet.payload();
        assert_eq!(ipv6_repr.dst_addr, IPV6_LINK_LOCAL_ALL_MLDV2_ROUTERS);

        // The first 2 octets of this payload hold the next-header indicator and the
        // Hop-by-Hop header length (in 8-octet words, minus 1). The remaining 6 octets
        // hold the Hop-by-Hop PadN and Router Alert options.
        let hbh_header = Ipv6HopByHopHeader::new_checked(&ip_payload[..8]).unwrap();
        let hbh_repr = Ipv6HopByHopRepr::parse(&hbh_header).unwrap();

        assert_eq!(hbh_repr.options.len(), 3);
        assert_eq!(
            hbh_repr.options[0],
            Ipv6OptionRepr::Unknown {
                type_: Ipv6OptionType::Unknown(IpProtocol::Icmpv6.into()),
                length: 0,
                data: &[],
            }
        );
        assert_eq!(
            hbh_repr.options[1],
            Ipv6OptionRepr::RouterAlert(Ipv6OptionRouterAlert::MulticastListenerDiscovery)
        );
        assert_eq!(hbh_repr.options[2], Ipv6OptionRepr::PadN(0));

        let icmpv6_packet =
            Icmpv6Packet::new_checked(&ip_payload[hbh_repr.buffer_len()..]).unwrap();
        let icmpv6_repr = Icmpv6Repr::parse(
            &ipv6_packet.src_addr(),
            &ipv6_packet.dst_addr(),
            &icmpv6_packet,
            checksum_caps,
        )
        .unwrap();

        let record_data = match icmpv6_repr {
            Icmpv6Repr::Mld(MldRepr::Report {
                nr_mcast_addr_rcrds,
                data,
            }) => {
                assert_eq!(nr_mcast_addr_rcrds, results.len() as u16);
                data
            }
            other => panic!("unexpected icmpv6_repr: {:?}", other),
        };

        let mut record_reprs = Vec::new();
        let mut payload = record_data;

        // FIXME: parsing multiple address records should be done by the MLD code
        while !payload.is_empty() {
            let record = MldAddressRecord::new_checked(payload).unwrap();
            let mut record_repr = MldAddressRecordRepr::parse(&record).unwrap();
            payload = record_repr.payload;
            record_repr.payload = &[];
            record_reprs.push(record_repr);
        }

        let expected_records = results
            .iter()
            .map(|addr| MldAddressRecordRepr {
                num_srcs: 0,
                mcast_addr: *addr,
                record_type: MldRecordType::ModeIsExclude,
                aux_data_len: 0,
                payload: &[],
            })
            .collect::<Vec<_>>();

        assert_eq!(record_reprs, expected_records);
    }
}

#[rstest]
#[case(Medium::Ethernet)]
#[cfg(all(feature = "multicast", feature = "medium-ethernet"))]
fn test_solicited_node_multicast_autojoin(#[case] medium: Medium) {
    let (mut iface, _, _) = setup(medium);

    let addr1 = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let addr2 = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs.clear();
        ip_addrs.push(IpCidr::new(addr1.into(), 64));
    });
    assert!(iface.has_multicast_group(addr1.solicited_node()));
    assert!(!iface.has_multicast_group(addr2.solicited_node()));

    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs.clear();
        ip_addrs.push(IpCidr::new(addr2.into(), 64));
    });
    assert!(!iface.has_multicast_group(addr1.solicited_node()));
    assert!(iface.has_multicast_group(addr2.solicited_node()));

    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs.clear();
        ip_addrs.push(IpCidr::new(addr1.into(), 64));
        ip_addrs.push(IpCidr::new(addr2.into(), 64));
    });
    assert!(iface.has_multicast_group(addr1.solicited_node()));
    assert!(iface.has_multicast_group(addr2.solicited_node()));

    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs.clear();
    });
    assert!(!iface.has_multicast_group(addr1.solicited_node()));
    assert!(!iface.has_multicast_group(addr2.solicited_node()));
}

#[test]
#[cfg(all(
    feature = "medium-ip",
    feature = "proto-ipv6-fragmentation",
    feature = "socket-udp"
))]
fn ipv6_source_fragments_a_maximum_udp_datagram() {
    const MAX_UDP_PAYLOAD: usize = 65_507;

    struct CaptureTxToken<'a>(&'a mut Vec<Vec<u8>>);

    impl TxToken for CaptureTxToken<'_> {
        fn consume<R, F>(self, len: usize, f: F) -> R
        where
            F: FnOnce(&mut [u8]) -> R,
        {
            let mut packet = vec![0; len];
            let result = f(&mut packet);
            self.0.push(packet);
            result
        }
    }

    let (mut iface, _sockets, mut device) = setup(Medium::Ip);
    let mtu = device.capabilities().ip_mtu();
    let src_addr = Ipv6Address::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1);
    let dst_addr = Ipv6Address::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 1);
    let udp_repr = UdpRepr {
        src_port: 49_500,
        dst_port: 49_501,
    };
    let payload: Vec<u8> = (0..MAX_UDP_PAYLOAD).map(|index| index as u8).collect();
    let ip_repr = Ipv6Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Udp,
        payload_len: UDP_HEADER_LEN + payload.len(),
        hop_limit: 37,
    };
    let mut fragments = Vec::new();

    assert_eq!(
        iface.inner.dispatch_ip(
            CaptureTxToken(&mut fragments),
            PacketMeta::default(),
            Packet::new_ipv6(ip_repr, IpPayload::Udp(udp_repr, &payload)),
            &mut iface.fragmenter,
        ),
        Ok(())
    );
    while !iface.fragmenter.finished() {
        iface
            .inner
            .dispatch_ipv6_frag(CaptureTxToken(&mut fragments), &mut iface.fragmenter);
    }

    let fragment_header_len = 8;
    let fragment_payload_size = (mtu - IPV6_HEADER_LEN - fragment_header_len) / 8 * 8;
    let mut reassembled = Vec::new();
    let mut expected_offset = 0;
    let mut ident = None;
    for (index, bytes) in fragments.iter().enumerate() {
        let packet = Ipv6Packet::new_checked(&bytes[..]).unwrap();
        let final_fragment = index + 1 == fragments.len();
        assert!(bytes.len() <= mtu);
        assert_eq!(packet.payload_len() as usize, bytes.len() - IPV6_HEADER_LEN);
        assert_eq!(packet.src_addr(), src_addr);
        assert_eq!(packet.dst_addr(), dst_addr);
        assert_eq!(packet.next_header(), IpProtocol::Ipv6Frag);
        assert_eq!(packet.hop_limit(), 37);

        let header = Ipv6FragmentHeader::new_checked(packet.payload()).unwrap();
        let repr = Ipv6FragmentRepr::parse(&header).unwrap();
        let fragment_payload = &packet.payload()[repr.buffer_len()..];
        assert_eq!(repr.next_header, IpProtocol::Udp);
        assert_eq!(repr.frag_offset as usize, expected_offset);
        assert_eq!(repr.more_frags, !final_fragment);
        assert_eq!(*ident.get_or_insert(repr.ident), repr.ident);
        assert_ne!(repr.ident, 0);
        if !final_fragment {
            assert_eq!(fragment_payload.len(), fragment_payload_size);
        }
        expected_offset += fragment_payload.len();
        reassembled.extend_from_slice(fragment_payload);
    }

    assert_eq!(expected_offset, UDP_HEADER_LEN + MAX_UDP_PAYLOAD);
    let udp_packet = UdpPacket::new_checked(&reassembled[..]).unwrap();
    UdpRepr::parse(
        &udp_packet,
        &src_addr.into(),
        &dst_addr.into(),
        &ChecksumCapabilities::default(),
    )
    .unwrap();
    assert_eq!(udp_packet.payload(), &payload);

    iface.fragmenter.reset();
    let next_payload = vec![0xa5; mtu];
    let next_repr = Ipv6Repr {
        payload_len: UDP_HEADER_LEN + next_payload.len(),
        ..ip_repr
    };
    let mut next_fragments = Vec::new();
    assert_eq!(
        iface.inner.dispatch_ip(
            CaptureTxToken(&mut next_fragments),
            PacketMeta::default(),
            Packet::new_ipv6(next_repr, IpPayload::Udp(udp_repr, &next_payload)),
            &mut iface.fragmenter,
        ),
        Ok(())
    );
    let packet = Ipv6Packet::new_checked(&next_fragments[0][..]).unwrap();
    let header = Ipv6FragmentHeader::new_checked(packet.payload()).unwrap();
    let staged_ident = Ipv6FragmentRepr::parse(&header).unwrap().ident;
    assert_ne!(staged_ident, ident.unwrap());

    let interface_mtu = iface.inner.ip_mtu();
    assert!(iface.inner.routes.update_pmtu(
        dst_addr.into(),
        1_200,
        next_repr.buffer_len() + next_repr.payload_len,
        interface_mtu,
        Instant::ZERO,
    ));
    assert!(iface.ipv6_egress(&mut device));
    let restarted = Ipv6Packet::new_checked(device.tx_queue.back().unwrap()).unwrap();
    assert!(restarted.total_len() <= 1_280);
    let header = Ipv6FragmentHeader::new_checked(restarted.payload()).unwrap();
    let repr = Ipv6FragmentRepr::parse(&header).unwrap();
    assert_eq!(repr.frag_offset, 0);
    assert_ne!(repr.ident, staged_ident);
}
