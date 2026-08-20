use super::*;

/// What the L4 checksum field of a received frame holds.
#[cfg(all(
    feature = "medium-ip",
    any(feature = "socket-tcp", feature = "socket-udp")
))]
#[derive(Clone, Copy)]
enum RxCsum {
    /// Correct for the frame, as an ordinary peer computes it.
    Correct,
    /// Corrupted in flight, or forged.
    Corrupt,
    /// Only the pseudo-header sum, which is what a frame flagged
    /// VIRTIO_NET_HDR_F_NEEDS_CSUM carries: whoever completes it still owes
    /// the payload sum, so verifying it here would reject a valid frame.
    PseudoHeader,
}

#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp"))]
fn tcp_connect_processes_syn_ack_and_fin_in_one_poll() {
    use crate::socket::tcp;

    const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const LOCAL_PORT: u16 = 49_500;
    const REMOTE_PORT: u16 = 80;

    fn packet(control: TcpControl, seq_number: TcpSeqNumber, ack_number: TcpSeqNumber) -> Vec<u8> {
        let tcp_repr = TcpRepr {
            src_port: REMOTE_PORT,
            dst_port: LOCAL_PORT,
            control,
            seq_number,
            ack_number: Some(ack_number),
            window_len: 64,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let ipv4_repr = Ipv4Repr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        };
        let mut bytes = vec![0; ipv4_repr.buffer_len() + tcp_repr.buffer_len()];
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        tcp_repr.emit(
            &mut TcpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
            &REMOTE_ADDR.into(),
            &LOCAL_ADDR.into(),
            &ChecksumCapabilities::default(),
        );
        bytes
    }

    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 64]),
        tcp::SocketBuffer::new(vec![0; 64]),
    );
    let handle = sockets.add(0, socket);
    sockets
        .get_mut::<tcp::Socket>(handle)
        .connect(
            iface.context(),
            (IpAddress::Ipv4(REMOTE_ADDR), REMOTE_PORT),
            LOCAL_PORT,
        )
        .unwrap();

    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    let syn_bytes = device.tx_queue.pop_front().unwrap();
    let syn_ip = Ipv4Packet::new_checked(&syn_bytes).unwrap();
    let syn = TcpPacket::new_checked(syn_ip.payload()).unwrap();
    assert!(syn.syn());

    let remote_seq = TcpSeqNumber(20_000);
    device.push_rx(packet(TcpControl::Syn, remote_seq, syn.seq_number() + 1));
    device.push_rx(packet(
        TcpControl::Fin,
        remote_seq + 1,
        syn.seq_number() + 1,
    ));

    // Interface::poll drains both queued packets before the executor can run.
    iface.poll(Instant::from_millis(1), &mut device, &mut sockets);
    assert_eq!(
        sockets.get::<tcp::Socket>(handle).state(),
        tcp::State::CloseWait
    );
}

/// Receive verification is on for every frame, and the device's per-frame
/// verdict is the only thing that waives it. Every frame Motor's virtio device
/// delivers in practice arrives vouched, so these tests are the only coverage
/// the verifying path gets.
#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp"))]
fn tcp_rx_checksum_honors_the_device_verdict() {
    use crate::socket::tcp;
    use crate::wire::ip::checksum;

    const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const LOCAL_PORT: u16 = 49_501;
    const REMOTE_PORT: u16 = 80;

    fn syn(csum: RxCsum) -> Vec<u8> {
        let tcp_repr = TcpRepr {
            src_port: REMOTE_PORT,
            dst_port: LOCAL_PORT,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(20_000),
            ack_number: None,
            window_len: 64,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let ipv4_repr = Ipv4Repr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        };
        let mut bytes = vec![0; ipv4_repr.buffer_len() + tcp_repr.buffer_len()];
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        let mut packet = TcpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]);
        tcp_repr.emit(
            &mut packet,
            &REMOTE_ADDR.into(),
            &LOCAL_ADDR.into(),
            &ChecksumCapabilities::default(),
        );
        match csum {
            RxCsum::Correct => (),
            RxCsum::Corrupt => packet.set_checksum(packet.checksum() ^ 1),
            RxCsum::PseudoHeader => packet.set_checksum(!checksum::pseudo_header_v4(
                &REMOTE_ADDR,
                &LOCAL_ADDR,
                IpProtocol::Tcp,
                tcp_repr.buffer_len() as u32,
            )),
        }
        bytes
    }

    /// Delivers one SYN to a listening socket and reports what the stack made
    /// of it: the socket's state, the frames dropped by verification, and the
    /// number of replies emitted.
    fn feed(frame: Vec<u8>, vouched: bool) -> (tcp::State, u64, usize) {
        let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 64]),
            tcp::SocketBuffer::new(vec![0; 64]),
        );
        socket.listen(LOCAL_PORT).unwrap();
        let handle = sockets.add(0, socket);

        device.push_rx_vouched(frame, vouched);
        iface.poll(Instant::ZERO, &mut device, &mut sockets);
        (
            sockets.get::<tcp::Socket>(handle).state(),
            iface.take_rx_csum_failed(),
            device.tx_queue.len(),
        )
    }

    // Nobody vouched, so the stack verifies: a corrupt segment is dropped and
    // counted, and draws no reply at all -- not even the RST an unmatched
    // segment would get.
    assert_eq!(
        feed(syn(RxCsum::Corrupt), false),
        (tcp::State::Listen, 1, 0)
    );
    // The same segment with its real checksum is accepted, which is what makes
    // the drop above attributable to the checksum and nothing else.
    assert_eq!(
        feed(syn(RxCsum::Correct), false),
        (tcp::State::SynReceived, 0, 1)
    );
    // DATA_VALID or NEEDS_CSUM: the device vouched for this one frame, so the
    // field is not examined and both are delivered.
    assert_eq!(
        feed(syn(RxCsum::Corrupt), true),
        (tcp::State::SynReceived, 0, 1)
    );
    assert_eq!(
        feed(syn(RxCsum::PseudoHeader), true),
        (tcp::State::SynReceived, 0, 1)
    );
    // A pseudo-header sum nobody vouched for is just a wrong checksum.
    assert_eq!(
        feed(syn(RxCsum::PseudoHeader), false),
        (tcp::State::Listen, 1, 0)
    );
}

/// The UDP half of [`tcp_rx_checksum_honors_the_device_verdict`].
#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-udp"))]
fn udp_rx_checksum_honors_the_device_verdict() {
    use crate::socket::udp;
    use crate::wire::ip::checksum;

    const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const LOCAL_PORT: u16 = 49_502;
    const REMOTE_PORT: u16 = 4242;
    static PAYLOAD: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

    fn datagram(csum: RxCsum) -> Vec<u8> {
        let udp_repr = UdpRepr {
            src_port: REMOTE_PORT,
            dst_port: LOCAL_PORT,
        };
        let udp_len = udp_repr.header_len() + PAYLOAD.len();
        let ipv4_repr = Ipv4Repr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Udp,
            payload_len: udp_len,
            hop_limit: 64,
        };
        let mut bytes = vec![0; ipv4_repr.buffer_len() + udp_len];
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        let mut packet = UdpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]);
        udp_repr.emit(
            &mut packet,
            &REMOTE_ADDR.into(),
            &LOCAL_ADDR.into(),
            PAYLOAD.len(),
            |buf| buf.copy_from_slice(&PAYLOAD),
            &ChecksumCapabilities::default(),
        );
        match csum {
            RxCsum::Correct => (),
            // A zero field means "no checksum computed", which is a legitimate
            // datagram rather than a corrupt one, so the flip must not reach it.
            RxCsum::Corrupt => {
                let corrupt = packet.checksum() ^ 1;
                assert_ne!(corrupt, 0);
                packet.set_checksum(corrupt);
            }
            RxCsum::PseudoHeader => packet.set_checksum(!checksum::pseudo_header_v4(
                &REMOTE_ADDR,
                &LOCAL_ADDR,
                IpProtocol::Udp,
                udp_len as u32,
            )),
        }
        bytes
    }

    /// Delivers one datagram to a bound socket and reports what the socket
    /// received and how many frames verification dropped.
    fn feed(frame: Vec<u8>, vouched: bool) -> (Option<Vec<u8>>, u64) {
        let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
        let mut socket = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 64]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 64]),
        );
        socket.bind(LOCAL_PORT).unwrap();
        let handle = sockets.add(0, socket);

        device.push_rx_vouched(frame, vouched);
        iface.poll(Instant::ZERO, &mut device, &mut sockets);
        let received = sockets
            .get_mut::<udp::Socket>(handle)
            .recv()
            .ok()
            .map(|(payload, _)| payload.to_vec());
        (received, iface.take_rx_csum_failed())
    }

    // The same five cases as the TCP half, in the same order and for the same
    // reasons.
    let delivered = || (Some(PAYLOAD.to_vec()), 0);
    assert_eq!(feed(datagram(RxCsum::Corrupt), false), (None, 1));
    assert_eq!(feed(datagram(RxCsum::Correct), false), delivered());
    assert_eq!(feed(datagram(RxCsum::Corrupt), true), delivered());
    assert_eq!(feed(datagram(RxCsum::PseudoHeader), true), delivered());
    assert_eq!(feed(datagram(RxCsum::PseudoHeader), false), (None, 1));
}

/// A 127/8 address means "this machine", so ingress refuses one on an interface
/// that is not [`Config::loopback`] and counts the frame. sys-io leans on this:
/// it keeps lowest-free ephemeral ports on loopback because loopback has no
/// off-path attacker, and this is what makes that premise true.
#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-udp"))]
fn loopback_addresses_are_refused_off_loopback() {
    use crate::socket::udp;

    const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const LOOPBACK_ADDR: Ipv4Address = Ipv4Address::new(127, 0, 0, 1);
    const LOOPBACK_PEER: Ipv4Address = Ipv4Address::new(127, 0, 0, 2);
    const LOCAL_PORT: u16 = 49_503;
    const REMOTE_PORT: u16 = 4242;
    static PAYLOAD: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

    fn datagram(src_addr: Ipv4Address, dst_addr: Ipv4Address) -> Vec<u8> {
        let udp_repr = UdpRepr {
            src_port: REMOTE_PORT,
            dst_port: LOCAL_PORT,
        };
        let udp_len = udp_repr.header_len() + PAYLOAD.len();
        let ipv4_repr = Ipv4Repr {
            src_addr,
            dst_addr,
            next_header: IpProtocol::Udp,
            payload_len: udp_len,
            hop_limit: 64,
        };
        let mut bytes = vec![0; ipv4_repr.buffer_len() + udp_len];
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        udp_repr.emit(
            &mut UdpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
            &src_addr.into(),
            &dst_addr.into(),
            PAYLOAD.len(),
            |buf| buf.copy_from_slice(&PAYLOAD),
            &ChecksumCapabilities::default(),
        );
        bytes
    }

    /// Delivers one datagram to a socket bound on every address the interface
    /// holds, and reports what arrived and how many frames the check dropped.
    /// The interface owns 127.0.0.1 either way, so a dropped frame is dropped
    /// by the check rather than for being addressed to nobody.
    fn feed(loopback: bool, frame: Vec<u8>) -> (Option<Vec<u8>>, u64) {
        let mut device = crate::tests::TestingDevice::new(Medium::Ip);
        let mut config = Config::new(HardwareAddress::Ip);
        config.loopback = loopback;
        let mut iface = Interface::new(config, &mut device, Instant::ZERO);
        iface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(LOCAL_ADDR.into(), 24));
            addrs.push(IpCidr::new(LOOPBACK_ADDR.into(), 8));
        });

        let mut socket = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 64]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 64]),
        );
        socket.bind(LOCAL_PORT).unwrap();
        let mut sockets = SocketSet::new();
        let handle = sockets.add(0, socket);

        device.push_rx(frame);
        iface.poll(Instant::ZERO, &mut device, &mut sockets);
        let received = sockets
            .get_mut::<udp::Socket>(handle)
            .recv()
            .ok()
            .map(|(payload, _)| payload.to_vec());
        (received, iface.take_rx_loopback_dropped())
    }

    let delivered = || (Some(PAYLOAD.to_vec()), 0);
    // The dangerous one: a source no peer off this machine may hold, which
    // every check before this one lets through.
    assert_eq!(feed(false, datagram(LOOPBACK_PEER, LOCAL_ADDR)), (None, 1));
    // The same datagram from an ordinary peer, which is what makes the drop
    // above attributable to the address and nothing else.
    assert_eq!(feed(false, datagram(REMOTE_ADDR, LOCAL_ADDR)), delivered());
    // A loopback destination is refused too, so the count covers both halves.
    assert_eq!(feed(false, datagram(REMOTE_ADDR, LOOPBACK_ADDR)), (None, 1));
    // On a loopback interface all of it is ordinary local traffic.
    assert_eq!(
        feed(true, datagram(LOOPBACK_PEER, LOOPBACK_ADDR)),
        delivered()
    );
}

/// A connection request no socket took is dropped when a listener owns the
/// endpoint and reset when nothing does, and every dropped one names the
/// listener it was for so that listener's pool can be deepened.
///
/// Dropping is what makes a burst survivable: a reset is terminal for the peer
/// -- `ECONNREFUSED` from a service that is running and merely busy -- while a
/// dropped SYN is retransmitted, and by then the pool has been replenished.
/// The count alone cannot say which listener ran out, and the accept backlog
/// cannot infer it: sockets leave `Listen` inside a poll, while whatever
/// watches them runs after it, interleaved with the replacements it spawns. A
/// request nobody could take is the unambiguous evidence, and this is where it
/// is produced.
#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp"))]
fn unmatched_syn_for_a_full_backlog_is_dropped() {
    use crate::iface::interface::MAX_BACKLOG_ENDPOINTS;
    use crate::socket::tcp;

    const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const LOCAL_PORT: u16 = 49_505;
    const CLOSED_PORT: u16 = 49_506;

    fn syn(src_port: u16, dst_port: u16) -> Vec<u8> {
        let tcp_repr = TcpRepr {
            src_port,
            dst_port,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(20_000),
            ack_number: None,
            window_len: 64,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let ipv4_repr = Ipv4Repr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        };
        let mut bytes = vec![0; ipv4_repr.buffer_len() + tcp_repr.buffer_len()];
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        tcp_repr.emit(
            &mut TcpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
            &REMOTE_ADDR.into(),
            &LOCAL_ADDR.into(),
            &ChecksumCapabilities::default(),
        );
        bytes
    }

    fn listening_socket(port: u16) -> tcp::Socket<'static> {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 64]),
            tcp::SocketBuffer::new(vec![0; 64]),
        );
        socket.listen(port).unwrap();
        socket
    }

    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    sockets.add(0, listening_socket(LOCAL_PORT));

    // One listening socket meets three requests in one poll: it takes the
    // first, and the two it cannot take are dropped rather than reset, so
    // their peers retransmit instead of failing. The endpoint is reported once
    // however many requests it lost.
    for src_port in [1000, 1001, 1002] {
        device.push_rx(syn(src_port, LOCAL_PORT));
    }
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(iface.take_tcp_syn_backlog_dropped(), 2);
    assert_eq!(iface.take_tcp_syn_rst_unmatched(), 0);
    assert_eq!(
        device.tx_queue.len(),
        1,
        "the two dropped requests were answered; only the SYN|ACK should go out"
    );
    let endpoints = iface.take_tcp_backlog_endpoints();
    assert_eq!(
        endpoints.as_slice(),
        [IpEndpoint::new(LOCAL_ADDR.into(), LOCAL_PORT)]
    );

    // Reading them clears them: a later poll that loses nothing reports
    // nothing, or every poll would keep growing the same pool.
    assert!(iface.take_tcp_backlog_endpoints().is_empty());
    iface.poll(Instant::from_millis(1), &mut device, &mut sockets);
    assert!(iface.take_tcp_backlog_endpoints().is_empty());

    // A port no listener owns keeps its reset. `ECONNREFUSED` is what an
    // application expects from a closed port, and a request that names no
    // listener also cannot crowd the bounded list below.
    device.tx_queue.clear();
    device.push_rx(syn(1003, CLOSED_PORT));
    iface.poll(Instant::from_millis(2), &mut device, &mut sockets);
    assert_eq!(iface.take_tcp_syn_rst_unmatched(), 1);
    assert_eq!(iface.take_tcp_syn_backlog_dropped(), 0);
    assert_eq!(device.tx_queue.len(), 1, "the closed port drew no reset");
    assert!(iface.take_tcp_backlog_endpoints().is_empty());

    // The list is bounded: one poll costs a fixed number of entries however
    // many listeners lose a request in it. The count is exact regardless.
    let listeners = MAX_BACKLOG_ENDPOINTS + 3;
    for i in 0..listeners {
        sockets.add(1 + i as u64, listening_socket(30_000 + i as u16));
    }
    for i in 0..listeners {
        // Two requests each: the first is taken, the second is lost.
        device.push_rx(syn(2000 + i as u16, 30_000 + i as u16));
        device.push_rx(syn(2100 + i as u16, 30_000 + i as u16));
    }
    iface.poll(Instant::from_millis(3), &mut device, &mut sockets);
    assert_eq!(iface.take_tcp_syn_backlog_dropped(), listeners as u64);
    assert_eq!(
        iface.take_tcp_backlog_endpoints().len(),
        MAX_BACKLOG_ENDPOINTS
    );
}

/// A SYN the full backlog would drop is answered statelessly when its
/// endpoint is in SYN-cookie mode: the SYN|ACK's sequence number verifies as
/// a cookie, its options mirror what a backlog socket would have advertised,
/// its TSval carries the peer's own offer home -- and nothing about the
/// exchange builds or changes a socket.
#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp"))]
fn syn_cookie_answers_what_the_full_backlog_would_drop() {
    use super::super::syn_cookies;
    use crate::iface::TcpSynCookieConfig;
    use crate::siphash::SipHasher24;
    use crate::socket::tcp;

    const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const LOCAL_PORT: u16 = 49_507;
    const PEER_TSVAL: u32 = 0x1234_5678;

    fn ts_clock() -> u32 {
        5_000_000
    }

    fn syn(src_port: u16, timestamp: Option<TcpTimestampRepr>) -> Vec<u8> {
        let tcp_repr = TcpRepr {
            src_port,
            dst_port: LOCAL_PORT,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(20_000),
            ack_number: None,
            window_len: 64,
            window_scale: Some(7),
            max_seg_size: Some(1400),
            sack_permitted: true,
            sack_ranges: [None; 3],
            timestamp,
            payload: &[],
        };
        let ipv4_repr = Ipv4Repr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        };
        let mut bytes = vec![0; ipv4_repr.buffer_len() + tcp_repr.buffer_len()];
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        tcp_repr.emit(
            &mut TcpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
            &REMOTE_ADDR.into(),
            &LOCAL_ADDR.into(),
            &ChecksumCapabilities::default(),
        );
        bytes
    }

    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let endpoint = IpEndpoint::new(LOCAL_ADDR.into(), LOCAL_PORT);
    iface.set_tsval_generator(Some(ts_clock));
    assert!(iface.engage_tcp_syn_cookies(
        endpoint,
        TcpSynCookieConfig {
            window_len: 16_384,
            wscale: 3,
        }
    ));

    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 64]),
        tcp::SocketBuffer::new(vec![0; 64]),
    );
    socket.listen(LOCAL_PORT).unwrap();
    let handle = sockets.add(0, socket);

    // The first request occupies the pool's one socket; the second is what a
    // full backlog would have dropped.
    device.push_rx(syn(1000, Some(TcpTimestampRepr::new(PEER_TSVAL, 0))));
    iface.poll(Instant::from_secs(700), &mut device, &mut sockets);
    device.tx_queue.clear();
    // 50 ms on: the same cookie counter period, and no retransmit timer has
    // fired to crowd the transmit queue.
    device.push_rx(syn(1001, Some(TcpTimestampRepr::new(PEER_TSVAL, 0))));
    iface.poll(Instant::from_millis(700_050), &mut device, &mut sockets);

    let bytes = device.tx_queue.pop_front().unwrap();
    assert!(device.tx_queue.is_empty());
    let ip = Ipv4Packet::new_checked(&bytes).unwrap();
    let reply = TcpRepr::parse(
        &TcpPacket::new_checked(ip.payload()).unwrap(),
        &LOCAL_ADDR.into(),
        &REMOTE_ADDR.into(),
        &ChecksumCapabilities::ignored(),
    )
    .unwrap();

    assert_eq!(reply.control, TcpControl::Syn);
    assert_eq!(reply.dst_port, 1001);
    assert_eq!(reply.ack_number, Some(TcpSeqNumber(20_001)));
    assert_eq!(reply.window_len, 16_384);
    assert_eq!(reply.window_scale, Some(3));
    assert!(reply.sack_permitted);
    let ip_mtu = iface.context().ip_mtu();
    assert_eq!(reply.max_seg_size, Some((ip_mtu - 40) as u16));

    // The timestamp: our clock's value carrying the peer's wscale and SACK
    // offer in the six low bits, echoing the peer's TSval.
    let ts = reply.timestamp.unwrap();
    assert_eq!(ts.tsecr, PEER_TSVAL);
    assert_eq!(ts.tsval >> 6, ts_clock() >> 6);
    assert_eq!(ts.tsval & 0x3f, 7 << 2 | 1 << 1);
    assert_eq!(
        syn_cookies::validate_tsecr(ts.tsval, ts_clock()),
        Some(syn_cookies::TsEcho {
            peer_wscale: Some(7),
            peer_sack: true
        })
    );

    // The sequence number is a cookie under the configured key, recording
    // the peer's 1400 rounded down to canonical 1220.
    let remote = IpEndpoint::new(REMOTE_ADDR.into(), 1001);
    assert_eq!(
        syn_cookies::verify(
            &SipHasher24::new([0; 16]),
            endpoint,
            remote,
            syn_cookies::counter(Instant::from_millis(700_050)),
            reply.seq_number,
        ),
        Some(1220)
    );

    // Stateless means stateless: the pool socket kept its own handshake, no
    // socket was added, and the drop accounting saw nothing.
    assert_eq!(iface.take_tcp_syn_cookies_sent(), 1);
    assert_eq!(iface.take_tcp_syn_backlog_dropped(), 0);
    assert!(iface.take_tcp_backlog_endpoints().is_empty());
    assert_eq!(sockets.iter().count(), 1);
    assert_eq!(
        sockets.get::<tcp::Socket>(handle).state(),
        tcp::State::SynReceived
    );
}

/// The cookie reply degrades exactly as far as the SYN does: options the peer
/// did not offer are not advertised, no timestamp clock means no timestamp,
/// disengaging restores the drop path, and the mode table is bounded.
#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp"))]
fn syn_cookie_reply_degrades_and_disengages() {
    use super::super::syn_cookies;
    use crate::iface::TcpSynCookieConfig;
    use crate::iface::interface::MAX_SYN_COOKIE_LISTENERS;
    use crate::siphash::SipHasher24;
    use crate::socket::tcp;

    const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const LOCAL_PORT: u16 = 49_508;

    fn bare_syn(src_port: u16, timestamp: Option<TcpTimestampRepr>) -> Vec<u8> {
        let tcp_repr = TcpRepr {
            src_port,
            dst_port: LOCAL_PORT,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(20_000),
            ack_number: None,
            window_len: 64,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp,
            payload: &[],
        };
        let ipv4_repr = Ipv4Repr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        };
        let mut bytes = vec![0; ipv4_repr.buffer_len() + tcp_repr.buffer_len()];
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        tcp_repr.emit(
            &mut TcpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
            &REMOTE_ADDR.into(),
            &LOCAL_ADDR.into(),
            &ChecksumCapabilities::default(),
        );
        bytes
    }

    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let endpoint = IpEndpoint::new(LOCAL_ADDR.into(), LOCAL_PORT);
    let config = TcpSynCookieConfig {
        window_len: 16_384,
        wscale: 3,
    };
    // No timestamp clock is installed on this interface.
    assert!(iface.engage_tcp_syn_cookies(endpoint, config));

    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 64]),
        tcp::SocketBuffer::new(vec![0; 64]),
    );
    socket.listen(LOCAL_PORT).unwrap();
    sockets.add(0, socket);

    device.push_rx(bare_syn(1000, None));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    device.tx_queue.clear();

    // A SYN offering nothing gets a cookie advertising nothing back; one
    // offering a timestamp still gets none, since we have no clock for it.
    device.push_rx(bare_syn(1001, None));
    device.push_rx(bare_syn(1002, Some(TcpTimestampRepr::new(7, 0))));
    iface.poll(Instant::from_millis(1), &mut device, &mut sockets);
    assert_eq!(device.tx_queue.len(), 2);
    for _ in 0..2 {
        let bytes = device.tx_queue.pop_front().unwrap();
        let ip = Ipv4Packet::new_checked(&bytes).unwrap();
        let reply = TcpRepr::parse(
            &TcpPacket::new_checked(ip.payload()).unwrap(),
            &LOCAL_ADDR.into(),
            &REMOTE_ADDR.into(),
            &ChecksumCapabilities::ignored(),
        )
        .unwrap();

        assert_eq!(reply.control, TcpControl::Syn);
        assert_eq!(reply.window_scale, None);
        assert!(!reply.sack_permitted);
        assert_eq!(reply.timestamp, None);
        // No MSS option on the SYN means the protocol default in the cookie.
        let remote = IpEndpoint::new(REMOTE_ADDR.into(), reply.dst_port);
        assert_eq!(
            syn_cookies::verify(
                &SipHasher24::new([0; 16]),
                endpoint,
                remote,
                syn_cookies::counter(Instant::ZERO),
                reply.seq_number,
            ),
            Some(536)
        );
    }
    assert_eq!(iface.take_tcp_syn_cookies_sent(), 2);

    // Disengaged, the endpoint is back to dropping what it cannot take.
    iface.disengage_tcp_syn_cookies(endpoint);
    device.push_rx(bare_syn(1003, None));
    iface.poll(Instant::from_millis(2), &mut device, &mut sockets);
    assert!(device.tx_queue.is_empty());
    assert_eq!(iface.take_tcp_syn_cookies_sent(), 0);
    assert_eq!(iface.take_tcp_syn_backlog_dropped(), 1);

    // The mode table is bounded, and re-engaging holds its slot rather than
    // taking another. The disengaged first endpoint is draining -- still
    // verifying -- so it keeps its slot against a newcomer.
    for i in 0..MAX_SYN_COOKIE_LISTENERS - 1 {
        let ep = IpEndpoint::new(LOCAL_ADDR.into(), 40_000 + i as u16);
        assert!(iface.engage_tcp_syn_cookies(ep, config));
        assert!(iface.engage_tcp_syn_cookies(ep, config));
    }
    let one_more = IpEndpoint::new(LOCAL_ADDR.into(), 41_000);
    assert!(!iface.engage_tcp_syn_cookies(one_more, config));

    // Re-engaging revives the draining entry in place; once disengaged and
    // past its drain window (a poll advances the clock), its slot is
    // reclaimed by the next engagement.
    assert!(iface.engage_tcp_syn_cookies(endpoint, config));
    iface.disengage_tcp_syn_cookies(endpoint);
    assert!(!iface.engage_tcp_syn_cookies(one_more, config));
    iface.poll(Instant::from_secs(200), &mut device, &mut sockets);
    assert!(iface.engage_tcp_syn_cookies(one_more, config));
}

/// The reflector's resets ride [`Config::tcp_rst_rate_limit`]'s token
/// bucket: a spray of segments no socket owns -- SYNs at a closed port and
/// stray ACKs alike, since both share the reset path -- draws at most the
/// configured burst of resets, the surplus is dropped unanswered and
/// counted, and the bucket refills continuously.
#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp"))]
fn unmatched_resets_are_rate_limited() {
    const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const CLOSED_PORT: u16 = 49_510;

    fn segment(src_port: u16, control: TcpControl, ack_number: Option<TcpSeqNumber>) -> Vec<u8> {
        let tcp_repr = TcpRepr {
            src_port,
            dst_port: CLOSED_PORT,
            control,
            seq_number: TcpSeqNumber(20_000),
            ack_number,
            window_len: 64,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let ipv4_repr = Ipv4Repr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        };
        let mut bytes = vec![0; ipv4_repr.buffer_len() + tcp_repr.buffer_len()];
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        tcp_repr.emit(
            &mut TcpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
            &REMOTE_ADDR.into(),
            &LOCAL_ADDR.into(),
            &ChecksumCapabilities::default(),
        );
        bytes
    }

    let mut device = crate::tests::TestingDevice::new(Medium::Ip);
    let mut config = Config::new(HardwareAddress::Ip);
    config.tcp_rst_rate_limit = 2;
    let mut iface = Interface::new(config, &mut device, Instant::ZERO);
    iface.update_ip_addrs(|addrs| {
        addrs.push(IpCidr::new(IpAddress::v4(192, 168, 1, 1), 24));
    });
    let mut sockets = SocketSet::new();

    // Five requests meet a two-deep bucket: two resets, three silences. The
    // unmatched count keeps counting requests, sent or suppressed.
    for src_port in 1000..1005 {
        device.push_rx(segment(src_port, TcpControl::Syn, None));
    }
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(device.tx_queue.len(), 2);
    assert_eq!(iface.take_tcp_rst_suppressed(), 3);
    assert_eq!(iface.take_tcp_syn_rst_unmatched(), 5);
    for bytes in device.tx_queue.drain(..) {
        let ip = Ipv4Packet::new_checked(&bytes).unwrap();
        let reply = TcpRepr::parse(
            &TcpPacket::new_checked(ip.payload()).unwrap(),
            &LOCAL_ADDR.into(),
            &REMOTE_ADDR.into(),
            &ChecksumCapabilities::ignored(),
        )
        .unwrap();
        assert_eq!(reply.control, TcpControl::Rst);
    }

    // At two per second the next token exists at 500 ms, not 499.
    device.push_rx(segment(1005, TcpControl::Syn, None));
    iface.poll(Instant::from_millis(499), &mut device, &mut sockets);
    assert!(device.tx_queue.is_empty());
    assert_eq!(iface.take_tcp_rst_suppressed(), 1);
    device.push_rx(segment(1006, TcpControl::Syn, None));
    iface.poll(Instant::from_millis(500), &mut device, &mut sockets);
    assert_eq!(device.tx_queue.len(), 1);
    assert_eq!(iface.take_tcp_rst_suppressed(), 0);
    device.tx_queue.clear();

    // Stray ACKs draw from the same bucket, refilled to its two-deep burst
    // by the elapsed second.
    for src_port in 1007..1010 {
        device.push_rx(segment(src_port, TcpControl::None, Some(TcpSeqNumber(1))));
    }
    iface.poll(Instant::from_millis(1_500), &mut device, &mut sockets);
    assert_eq!(device.tx_queue.len(), 2);
    assert_eq!(iface.take_tcp_rst_suppressed(), 1);
}

/// A reset is never answered with a reset: a stray RST at a port nobody
/// holds -- TCP's CLOSED state -- is dropped before the reflector, not
/// spent from its bucket. RFC 9293 3.10.7.1; two stacks answering each
/// other's resets would otherwise ping-pong forever.
#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp"))]
fn unmatched_rst_draws_silence() {
    const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const CLOSED_PORT: u16 = 49_512;

    fn segment(src_port: u16, control: TcpControl, ack_number: Option<TcpSeqNumber>) -> Vec<u8> {
        let tcp_repr = TcpRepr {
            src_port,
            dst_port: CLOSED_PORT,
            control,
            seq_number: TcpSeqNumber(20_000),
            ack_number,
            window_len: 64,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let ipv4_repr = Ipv4Repr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        };
        let mut bytes = vec![0; ipv4_repr.buffer_len() + tcp_repr.buffer_len()];
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        tcp_repr.emit(
            &mut TcpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
            &REMOTE_ADDR.into(),
            &LOCAL_ADDR.into(),
            &ChecksumCapabilities::default(),
        );
        bytes
    }

    let mut device = crate::tests::TestingDevice::new(Medium::Ip);
    let mut config = Config::new(HardwareAddress::Ip);
    config.tcp_rst_rate_limit = 2;
    let mut iface = Interface::new(config, &mut device, Instant::ZERO);
    iface.update_ip_addrs(|addrs| {
        addrs.push(IpCidr::new(IpAddress::v4(192, 168, 1, 1), 24));
    });
    let mut sockets = SocketSet::new();

    // Both reset shapes -- bare and carrying an ACK -- draw nothing.
    device.push_rx(segment(1000, TcpControl::Rst, None));
    device.push_rx(segment(1001, TcpControl::Rst, Some(TcpSeqNumber(1))));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert!(device.tx_queue.is_empty());
    // The silence is the drop rule, not the bucket having run dry.
    assert_eq!(iface.take_tcp_rst_suppressed(), 0);

    // And the bucket really was untouched: a stray ACK still draws its reset.
    device.push_rx(segment(1002, TcpControl::None, Some(TcpSeqNumber(1))));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(device.tx_queue.len(), 1);
}

/// Cookie SYN|ACKs ride [`Config::tcp_cookie_rate_limit`]'s own bucket: past
/// its rate the request is dropped for the peer to retransmit -- not passed
/// on to the reset path, however full the reset bucket may be.
#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp"))]
fn cookie_syn_acks_are_rate_limited() {
    use crate::iface::TcpSynCookieConfig;

    const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const LOCAL_PORT: u16 = 49_511;

    fn syn(src_port: u16) -> Vec<u8> {
        let tcp_repr = TcpRepr {
            src_port,
            dst_port: LOCAL_PORT,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(20_000),
            ack_number: None,
            window_len: 64,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let ipv4_repr = Ipv4Repr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        };
        let mut bytes = vec![0; ipv4_repr.buffer_len() + tcp_repr.buffer_len()];
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        tcp_repr.emit(
            &mut TcpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
            &REMOTE_ADDR.into(),
            &LOCAL_ADDR.into(),
            &ChecksumCapabilities::default(),
        );
        bytes
    }

    let mut device = crate::tests::TestingDevice::new(Medium::Ip);
    let mut config = Config::new(HardwareAddress::Ip);
    // Resets deliberately unlimited: a suppressed cookie that leaked through
    // to the reset path would show up below as a reset, not as silence.
    config.tcp_cookie_rate_limit = 1;
    let mut iface = Interface::new(config, &mut device, Instant::ZERO);
    iface.update_ip_addrs(|addrs| {
        addrs.push(IpCidr::new(IpAddress::v4(192, 168, 1, 1), 24));
    });
    let mut sockets = SocketSet::new();

    let endpoint = IpEndpoint::new(LOCAL_ADDR.into(), LOCAL_PORT);
    assert!(iface.engage_tcp_syn_cookies(
        endpoint,
        TcpSynCookieConfig {
            window_len: 16_384,
            wscale: 3,
        }
    ));

    // Three requests, a one-deep bucket: one cookie, two silences.
    for src_port in 1000..1003 {
        device.push_rx(syn(src_port));
    }
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(device.tx_queue.len(), 1);
    let bytes = device.tx_queue.pop_front().unwrap();
    let ip = Ipv4Packet::new_checked(&bytes).unwrap();
    let reply = TcpRepr::parse(
        &TcpPacket::new_checked(ip.payload()).unwrap(),
        &LOCAL_ADDR.into(),
        &REMOTE_ADDR.into(),
        &ChecksumCapabilities::ignored(),
    )
    .unwrap();
    assert_eq!(reply.control, TcpControl::Syn);
    assert!(reply.ack_number.is_some());

    assert_eq!(iface.take_tcp_syn_cookies_sent(), 1);
    assert_eq!(iface.take_tcp_syn_cookies_suppressed(), 2);
    assert_eq!(iface.take_tcp_rst_suppressed(), 0);
    assert_eq!(iface.take_tcp_syn_rst_unmatched(), 0);
    assert_eq!(iface.take_tcp_syn_backlog_dropped(), 0);

    // A second later the bucket holds one token again.
    device.push_rx(syn(1003));
    iface.poll(Instant::from_secs(1), &mut device, &mut sockets);
    assert_eq!(device.tx_queue.len(), 1);
    assert_eq!(iface.take_tcp_syn_cookies_sent(), 1);
    assert_eq!(iface.take_tcp_syn_cookies_suppressed(), 0);
}

/// The whole stateless handshake: a cookie SYN|ACK's completing ACK is
/// consumed without a reply, everything restoration needs comes off in the
/// take, and a socket restored from it exchanges data through the interface
/// as an ordinary established connection.
#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp"))]
fn syn_cookie_ack_restores_the_connection() {
    use crate::iface::TcpSynCookieConfig;
    use crate::socket::tcp;

    const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const LOCAL_PORT: u16 = 49_509;
    const PEER_TSVAL: u32 = 0x0bad_cafe;

    fn ts_clock() -> u32 {
        5_000_000
    }

    fn segment(tcp_repr: TcpRepr) -> Vec<u8> {
        let ipv4_repr = Ipv4Repr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        };
        let mut bytes = vec![0; ipv4_repr.buffer_len() + tcp_repr.buffer_len()];
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        tcp_repr.emit(
            &mut TcpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
            &REMOTE_ADDR.into(),
            &LOCAL_ADDR.into(),
            &ChecksumCapabilities::default(),
        );
        bytes
    }

    const SYN_TEMPL: TcpRepr<'static> = TcpRepr {
        src_port: 0,
        dst_port: LOCAL_PORT,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(20_000),
        ack_number: None,
        window_len: 64,
        window_scale: Some(7),
        max_seg_size: Some(1400),
        sack_permitted: true,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    };

    fn pop_tcp(device: &mut crate::tests::TestingDevice) -> TcpRepr<'static> {
        let bytes = device.tx_queue.pop_front().unwrap();
        let ip = Ipv4Packet::new_checked(&bytes).unwrap();
        let repr = TcpRepr::parse(
            &TcpPacket::new_checked(ip.payload()).unwrap(),
            &LOCAL_ADDR.into(),
            &REMOTE_ADDR.into(),
            &ChecksumCapabilities::ignored(),
        )
        .unwrap();
        assert!(repr.payload.is_empty());
        TcpRepr {
            payload: &[],
            ..repr
        }
    }

    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let endpoint = IpEndpoint::new(LOCAL_ADDR.into(), LOCAL_PORT);
    iface.set_tsval_generator(Some(ts_clock));
    assert!(iface.engage_tcp_syn_cookies(
        endpoint,
        TcpSynCookieConfig {
            window_len: 16_384,
            wscale: 3,
        }
    ));

    let mut listener = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 64]),
        tcp::SocketBuffer::new(vec![0; 64]),
    );
    listener.listen(LOCAL_PORT).unwrap();
    sockets.add(0, listener);

    // Occupy the pool's one socket, then draw a cookie SYN|ACK.
    device.push_rx(segment(TcpRepr {
        src_port: 1000,
        timestamp: Some(TcpTimestampRepr::new(PEER_TSVAL, 0)),
        ..SYN_TEMPL
    }));
    iface.poll(Instant::from_secs(700), &mut device, &mut sockets);
    device.tx_queue.clear();

    device.push_rx(segment(TcpRepr {
        src_port: 1001,
        timestamp: Some(TcpTimestampRepr::new(PEER_TSVAL, 0)),
        ..SYN_TEMPL
    }));
    iface.poll(Instant::from_millis(700_050), &mut device, &mut sockets);
    let syn_ack = pop_tcp(&mut device);
    assert_eq!(syn_ack.control, TcpControl::Syn);
    let cookie = syn_ack.seq_number;
    let our_tsval = syn_ack.timestamp.unwrap().tsval;

    // The completing ACK: consumed without a reply, and the restoration
    // record carries everything the stateless handshake preserved.
    let completing_ack = segment(TcpRepr {
        src_port: 1001,
        control: TcpControl::None,
        seq_number: TcpSeqNumber(20_001),
        ack_number: Some(cookie + 1),
        window_len: 500,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        timestamp: Some(TcpTimestampRepr::new(PEER_TSVAL + 1, our_tsval)),
        ..SYN_TEMPL
    });
    device.push_rx(completing_ack.clone());
    device.push_rx(completing_ack);
    iface.poll(Instant::from_millis(700_100), &mut device, &mut sockets);
    assert!(device.tx_queue.is_empty());
    assert_eq!(iface.take_tcp_syn_cookies_rejected(), 0);
    assert_eq!(iface.take_tcp_cookie_restores_dropped(), 0);

    let restores = iface.take_tcp_cookie_restores();
    assert_eq!(restores.len(), 1);
    let restore = restores[0];
    assert_eq!(restore.local, endpoint);
    assert_eq!(restore.remote, IpEndpoint::new(REMOTE_ADDR.into(), 1001));
    assert_eq!(restore.rcv_nxt, TcpSeqNumber(20_001));
    assert_eq!(restore.snd_nxt, cookie + 1);
    assert_eq!(restore.remote_mss, 1220);
    assert_eq!(restore.remote_window, 500);
    assert_eq!(restore.peer_wscale, Some(7));
    assert!(restore.peer_sack);
    assert_eq!(restore.peer_tsval, Some(PEER_TSVAL + 1));
    assert!(iface.take_tcp_cookie_restores().is_empty());

    // A peer whose SYN and ACK offered nothing restores degraded.
    device.push_rx(segment(TcpRepr {
        src_port: 1002,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        ..SYN_TEMPL
    }));
    iface.poll(Instant::from_millis(700_150), &mut device, &mut sockets);
    let bare_cookie = pop_tcp(&mut device).seq_number;
    device.push_rx(segment(TcpRepr {
        src_port: 1002,
        control: TcpControl::None,
        seq_number: TcpSeqNumber(20_001),
        ack_number: Some(bare_cookie + 1),
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        ..SYN_TEMPL
    }));
    iface.poll(Instant::from_millis(700_200), &mut device, &mut sockets);
    let degraded = iface.take_tcp_cookie_restores()[0];
    assert_eq!(degraded.remote_mss, 536);
    assert_eq!(degraded.peer_wscale, None);
    assert!(!degraded.peer_sack);
    assert_eq!(degraded.peer_tsval, None);

    // A socket restored from the record joins the interface as an ordinary
    // established connection: the peer's data reaches it and is
    // acknowledged.
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 4096]),
        tcp::SocketBuffer::new(vec![0; 4096]),
    );
    socket.set_ack_delay(None);
    socket.set_tsval_generator(Some(ts_clock));
    socket
        .restore_from_cookie(iface.context(), &restore)
        .unwrap();
    let handle = sockets.add(1, socket);

    device.push_rx(segment(TcpRepr {
        src_port: 1001,
        control: TcpControl::None,
        seq_number: TcpSeqNumber(20_001),
        ack_number: Some(cookie + 1),
        window_len: 500,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        timestamp: Some(TcpTimestampRepr::new(PEER_TSVAL + 2, our_tsval)),
        payload: b"hello",
        ..SYN_TEMPL
    }));
    iface.poll(Instant::from_millis(700_250), &mut device, &mut sockets);

    let socket = sockets.get_mut::<tcp::Socket>(handle);
    assert_eq!(socket.state(), tcp::State::Established);
    let mut buf = [0; 8];
    assert_eq!(socket.recv_slice(&mut buf), Ok(5));
    assert_eq!(&buf[..5], b"hello");
    let ack = pop_tcp(&mut device);
    assert_eq!(ack.dst_port, 1001);
    assert_eq!(ack.ack_number, Some(TcpSeqNumber(20_006)));
}

/// What the verification path refuses, and how it is bounded: a forged or
/// expired cookie is reset and counted, a bad timestamp echo refuses a valid
/// hash (the second factor), an endpoint that never minted offers no
/// verification surface at all, a full restore queue drops rather than
/// resets, and a disengaged endpoint keeps verifying through its drain
/// window.
#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp"))]
fn syn_cookie_ack_rejections_are_reset_and_bounded() {
    use super::super::syn_cookies;
    use crate::iface::TcpSynCookieConfig;
    use crate::iface::interface::MAX_COOKIE_RESTORES;
    use crate::siphash::SipHasher24;
    use crate::socket::tcp;

    const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const LOCAL_PORT: u16 = 49_510;
    const UNGATED_PORT: u16 = 49_511;
    const KEY: SipHasher24 = SipHasher24::new([0; 16]);

    fn ts_clock() -> u32 {
        5_000_000
    }

    fn ack(
        src_port: u16,
        dst_port: u16,
        ack: TcpSeqNumber,
        timestamp: Option<TcpTimestampRepr>,
    ) -> Vec<u8> {
        let tcp_repr = TcpRepr {
            src_port,
            dst_port,
            control: TcpControl::None,
            seq_number: TcpSeqNumber(20_001),
            ack_number: Some(ack),
            window_len: 64,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp,
            payload: &[],
        };
        let ipv4_repr = Ipv4Repr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        };
        let mut bytes = vec![0; ipv4_repr.buffer_len() + tcp_repr.buffer_len()];
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        tcp_repr.emit(
            &mut TcpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
            &REMOTE_ADDR.into(),
            &LOCAL_ADDR.into(),
            &ChecksumCapabilities::default(),
        );
        bytes
    }

    fn mint(dst_port: u16, src_port: u16, at: Instant) -> TcpSeqNumber {
        syn_cookies::mint(
            &KEY,
            IpEndpoint::new(LOCAL_ADDR.into(), dst_port),
            IpEndpoint::new(REMOTE_ADDR.into(), src_port),
            syn_cookies::counter(at),
            None,
        )
    }

    fn only_rst(device: &mut crate::tests::TestingDevice) {
        assert_eq!(device.tx_queue.len(), 1);
        let bytes = device.tx_queue.pop_front().unwrap();
        let ip = Ipv4Packet::new_checked(&bytes).unwrap();
        assert!(TcpPacket::new_checked(ip.payload()).unwrap().rst());
    }

    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let endpoint = IpEndpoint::new(LOCAL_ADDR.into(), LOCAL_PORT);
    iface.set_tsval_generator(Some(ts_clock));
    assert!(iface.engage_tcp_syn_cookies(
        endpoint,
        TcpSynCookieConfig {
            window_len: 16_384,
            wscale: 3,
        }
    ));

    // Baseline: a valid TS-less ACK restores.
    let cookie_at_zero = mint(LOCAL_PORT, 2000, Instant::ZERO);
    device.push_rx(ack(2000, LOCAL_PORT, cookie_at_zero + 1, None));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert!(device.tx_queue.is_empty());
    assert_eq!(iface.take_tcp_cookie_restores().len(), 1);
    assert_eq!(iface.take_tcp_syn_cookies_rejected(), 0);

    // A forged acknowledgment number is reset and counted.
    device.push_rx(ack(2001, LOCAL_PORT, cookie_at_zero + 100, None));
    iface.poll(Instant::from_millis(1), &mut device, &mut sockets);
    only_rst(&mut device);
    assert_eq!(iface.take_tcp_syn_cookies_rejected(), 1);

    // The second factor: a valid hash whose timestamp echo has the spare
    // bit set is refused all the same.
    let cookie = mint(LOCAL_PORT, 2002, Instant::from_millis(2));
    device.push_rx(ack(
        2002,
        LOCAL_PORT,
        cookie + 1,
        Some(TcpTimestampRepr::new(7, (ts_clock() & !0x3f) | 1)),
    ));
    iface.poll(Instant::from_millis(2), &mut device, &mut sockets);
    only_rst(&mut device);
    assert_eq!(iface.take_tcp_syn_cookies_rejected(), 1);
    assert!(iface.take_tcp_cookie_restores().is_empty());

    // An endpoint that never minted is not checked at all, listener or not:
    // the reset is the generic one and the rejection count stays put.
    let mut listener = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 64]),
        tcp::SocketBuffer::new(vec![0; 64]),
    );
    listener.listen(UNGATED_PORT).unwrap();
    sockets.add(0, listener);
    let ungated = mint(UNGATED_PORT, 2003, Instant::from_millis(3));
    device.push_rx(ack(2003, UNGATED_PORT, ungated + 1, None));
    iface.poll(Instant::from_millis(3), &mut device, &mut sockets);
    only_rst(&mut device);
    assert_eq!(iface.take_tcp_syn_cookies_rejected(), 0);

    // A cookie outlives nothing: two counter periods on, the baseline
    // cookie is an expired one.
    device.push_rx(ack(2004, LOCAL_PORT, cookie_at_zero + 1, None));
    iface.poll(Instant::from_secs(200), &mut device, &mut sockets);
    only_rst(&mut device);
    assert_eq!(iface.take_tcp_syn_cookies_rejected(), 1);

    // The restore queue is bounded; the surplus is dropped, not reset --
    // those peers retransmit into a drained queue.
    let at = Instant::from_millis(200_050);
    for i in 0..(MAX_COOKIE_RESTORES + 2) as u16 {
        let cookie = mint(LOCAL_PORT, 3000 + i, at);
        device.push_rx(ack(3000 + i, LOCAL_PORT, cookie + 1, None));
    }
    iface.poll(at, &mut device, &mut sockets);
    assert!(device.tx_queue.is_empty());
    assert_eq!(iface.take_tcp_cookie_restores().len(), MAX_COOKIE_RESTORES);
    assert_eq!(iface.take_tcp_cookie_restores_dropped(), 2);
    assert_eq!(iface.take_tcp_syn_cookies_rejected(), 0);

    // Disengaged, the endpoint still verifies through its drain window: the
    // handshakes its cookies started must be allowed to land.
    iface.disengage_tcp_syn_cookies(endpoint);
    let cookie = mint(LOCAL_PORT, 4000, Instant::from_millis(200_100));
    device.push_rx(ack(4000, LOCAL_PORT, cookie + 1, None));
    iface.poll(Instant::from_millis(200_100), &mut device, &mut sockets);
    assert!(device.tx_queue.is_empty());
    assert_eq!(iface.take_tcp_cookie_restores().len(), 1);
}

/// A peer that sends a SYN and then says nothing leaves the listening socket
/// half-open indefinitely, and a SYN no socket wants is reset and counted.
///
/// This is the deliberately stalled handshake sys-io's `net.tcp.half_open`
/// gauge measures. It cannot be built in the full-OS suite -- withholding the
/// final ACK needs packet injection, and every peer that answers completes the
/// handshake within the next poll -- so the stall itself is proven here, at
/// the only layer that can construct one.
#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp"))]
fn tcp_half_open_stalls_and_unmatched_syn_is_reset() {
    use crate::socket::tcp;

    const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const LOCAL_PORT: u16 = 49_503;
    const CLOSED_PORT: u16 = 49_504;
    const REMOTE_PORT: u16 = 80;

    fn packet(dst_port: u16, control: TcpControl, ack_number: Option<TcpSeqNumber>) -> Vec<u8> {
        let tcp_repr = TcpRepr {
            src_port: REMOTE_PORT,
            dst_port,
            control,
            seq_number: TcpSeqNumber(20_000),
            ack_number,
            window_len: 64,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let ipv4_repr = Ipv4Repr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        };
        let mut bytes = vec![0; ipv4_repr.buffer_len() + tcp_repr.buffer_len()];
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        tcp_repr.emit(
            &mut TcpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
            &REMOTE_ADDR.into(),
            &LOCAL_ADDR.into(),
            &ChecksumCapabilities::default(),
        );
        bytes
    }

    let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 64]),
        tcp::SocketBuffer::new(vec![0; 64]),
    );
    socket.listen(LOCAL_PORT).unwrap();
    let handle = sockets.add(0, socket);

    device.push_rx(packet(LOCAL_PORT, TcpControl::Syn, None));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(
        sockets.get::<tcp::Socket>(handle).state(),
        tcp::State::SynReceived
    );
    assert_eq!(iface.take_tcp_syn_rst_unmatched(), 0);

    // The peer never acknowledges. Nothing but the socket's own timeout, which
    // this socket does not have, ends the wait: the rings stay committed while
    // the stack keeps retransmitting the SYN|ACK.
    device.tx_queue.clear();
    for ms in [10, 1_000, 10_000] {
        iface.poll(Instant::from_millis(ms), &mut device, &mut sockets);
        assert_eq!(
            sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::SynReceived
        );
    }
    assert!(!device.tx_queue.is_empty(), "no SYN|ACK was retransmitted");

    // A SYN for a port no listener owns: nothing is listening, so a reset is
    // the honest answer. A listener that is merely out of sockets is the other
    // case, and is dropped instead -- see
    // `unmatched_syn_for_a_full_backlog_is_dropped`.
    device.tx_queue.clear();
    device.push_rx(packet(CLOSED_PORT, TcpControl::Syn, None));
    iface.poll(Instant::from_millis(10_001), &mut device, &mut sockets);
    assert_eq!(iface.take_tcp_syn_rst_unmatched(), 1);
    assert_eq!(device.tx_queue.len(), 1, "the unmatched SYN drew no reset");

    // Only connection requests count. An unmatched segment carrying an ACK is
    // reset the same way, but it is a stale connection, not a pending one.
    device.tx_queue.clear();
    device.push_rx(packet(
        CLOSED_PORT,
        TcpControl::None,
        Some(TcpSeqNumber(30_000)),
    ));
    iface.poll(Instant::from_millis(10_002), &mut device, &mut sockets);
    assert_eq!(iface.take_tcp_syn_rst_unmatched(), 0);
    assert_eq!(device.tx_queue.len(), 1, "the unmatched ACK drew no reset");
}

#[test]
#[cfg(feature = "medium-ethernet")]
fn icmp_echo_reply_policy() {
    let (mut iface, mut sockets, _) = setup(Medium::Ethernet);
    let ip_repr = Ipv4Repr {
        src_addr: Ipv4Address::new(192, 168, 1, 2),
        dst_addr: Ipv4Address::new(192, 168, 1, 1),
        next_header: IpProtocol::Icmp,
        payload_len: 8,
        hop_limit: 64,
    };
    let mut bytes = [0; 8];
    Icmpv4Repr::EchoRequest {
        ident: 1,
        seq_no: 2,
        data: &[],
    }
    .emit(
        &mut Icmpv4Packet::new_unchecked(&mut bytes),
        &ChecksumCapabilities::default(),
    );

    assert!(
        iface
            .inner
            .process_icmpv4(&mut sockets, ip_repr, &bytes)
            .is_some()
    );
    iface.inner.auto_icmp_echo_reply = false;
    assert_eq!(
        iface.inner.process_icmpv4(&mut sockets, ip_repr, &bytes),
        None
    );
}

#[rstest]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn test_any_ip_accept_arp(#[case] medium: Medium) {
    let mut buffer = [0u8; 64];
    #[allow(non_snake_case)]
    fn ETHERNET_FRAME_ARP(buffer: &mut [u8]) -> &[u8] {
        let ethernet_repr = EthernetRepr {
            src_addr: EthernetAddress::from_bytes(&[0x02, 0x02, 0x02, 0x02, 0x02, 0x03]),
            dst_addr: EthernetAddress::from_bytes(&[0x02, 0x02, 0x02, 0x02, 0x02, 0x02]),
            ethertype: EthernetProtocol::Arp,
        };
        let frame_repr = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: EthernetAddress::from_bytes(&[
                0x02, 0x02, 0x02, 0x02, 0x02, 0x03,
            ]),
            source_protocol_addr: Ipv4Address::from_octets([192, 168, 1, 2]),
            target_hardware_addr: EthernetAddress::from_bytes(&[
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            ]),
            target_protocol_addr: Ipv4Address::from_octets([192, 168, 1, 3]),
        };
        let mut frame = EthernetFrame::new_unchecked(&mut buffer[..]);
        ethernet_repr.emit(&mut frame);

        let mut frame = ArpPacket::new_unchecked(&mut buffer[ethernet_repr.buffer_len()..]);
        frame_repr.emit(&mut frame);

        &buffer[..ethernet_repr.buffer_len() + frame_repr.buffer_len()]
    }

    let (mut iface, mut sockets, _) = setup(medium);

    assert!(
        iface
            .inner
            .process_ethernet(
                &mut sockets,
                PacketMeta::default(),
                ETHERNET_FRAME_ARP(buffer.as_mut()),
                &mut iface.fragments,
            )
            .is_none()
    );

    // Accept any IP address
    iface.set_any_ip(true);

    assert!(
        iface
            .inner
            .process_ethernet(
                &mut sockets,
                PacketMeta::default(),
                ETHERNET_FRAME_ARP(buffer.as_mut()),
                &mut iface.fragments,
            )
            .is_some()
    );
}

#[rstest]
#[cfg_attr(feature = "medium-ip", case(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case(Medium::Ethernet))]
fn test_no_icmp_no_unicast(#[case] medium: Medium) {
    let (mut iface, mut sockets, _) = setup(medium);

    // Unknown Ipv4 Protocol
    //
    // Because the destination is the broadcast address
    // this should not trigger and Destination Unreachable
    // response. See RFC 1122 § 3.2.2.
    let repr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x01),
        dst_addr: Ipv4Address::BROADCAST,
        next_header: IpProtocol::Unknown(0x0c),
        payload_len: 0,
        hop_limit: 0x40,
    });

    let mut bytes = vec![0u8; 54];
    repr.emit(&mut bytes, &ChecksumCapabilities::default());
    let frame = Ipv4Packet::new_unchecked(&bytes[..]);

    // Ensure that the unknown protocol frame does not trigger an
    // ICMP error response when the destination address is a
    // broadcast address

    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &frame,
            &mut iface.fragments
        ),
        None
    );
}

#[rstest]
#[cfg_attr(feature = "medium-ip", case(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case(Medium::Ethernet))]
fn test_icmp_error_no_payload(#[case] medium: Medium) {
    static NO_BYTES: [u8; 0] = [];
    let (mut iface, mut sockets, _device) = setup(medium);

    // Unknown Ipv4 Protocol with no payload
    let repr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x02),
        dst_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x01),
        next_header: IpProtocol::Unknown(0x0c),
        payload_len: 0,
        hop_limit: 0x40,
    });

    let mut bytes = vec![0u8; 34];
    repr.emit(&mut bytes, &ChecksumCapabilities::default());
    let frame = Ipv4Packet::new_unchecked(&bytes[..]);

    // The expected Destination Unreachable response due to the
    // unknown protocol
    let icmp_repr = Icmpv4Repr::DstUnreachable {
        reason: Icmpv4DstUnreachable::ProtoUnreachable,
        next_hop_mtu: None,
        header: Ipv4Repr {
            src_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x02),
            dst_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x01),
            next_header: IpProtocol::Unknown(12),
            payload_len: 0,
            hop_limit: 64,
        },
        data: &NO_BYTES,
    };

    let expected_repr = Packet::new_ipv4(
        Ipv4Repr {
            src_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x01),
            dst_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x02),
            next_header: IpProtocol::Icmp,
            payload_len: icmp_repr.buffer_len(),
            hop_limit: 64,
        },
        IpPayload::Icmpv4(icmp_repr),
    );

    // Ensure that the unknown protocol triggers an error response.
    // And we correctly handle no payload.

    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &frame,
            &mut iface.fragments
        ),
        Some(expected_repr)
    );
}

#[rstest]
#[cfg_attr(feature = "medium-ip", case(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case(Medium::Ethernet))]
fn test_local_subnet_broadcasts(#[case] medium: Medium) {
    let (mut iface, _, _device) = setup(medium);
    iface.update_ip_addrs(|addrs| {
        addrs.iter_mut().next().map(|addr| {
            *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(192, 168, 1, 23), 24));
        });
    });

    assert!(
        iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(255, 255, 255, 255))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(255, 255, 255, 254))
    );
    assert!(
        iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 168, 1, 255))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 168, 1, 254))
    );

    iface.update_ip_addrs(|addrs| {
        addrs.iter_mut().next().map(|addr| {
            *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(192, 168, 23, 24), 16));
        });
    });
    assert!(
        iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(255, 255, 255, 255))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(255, 255, 255, 254))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 168, 23, 255))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 168, 23, 254))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 168, 255, 254))
    );
    assert!(
        iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 168, 255, 255))
    );

    iface.update_ip_addrs(|addrs| {
        addrs.iter_mut().next().map(|addr| {
            *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(192, 168, 23, 24), 8));
        });
    });
    assert!(
        iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(255, 255, 255, 255))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(255, 255, 255, 254))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 23, 1, 255))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 23, 1, 254))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 255, 255, 254))
    );
    assert!(
        iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 255, 255, 255))
    );
}

#[cfg(feature = "socket-udp")]
#[rstest]
#[cfg_attr(feature = "medium-ip", case(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case(Medium::Ethernet))]
fn test_icmp_error_port_unreachable(#[case] medium: Medium) {
    static UDP_PAYLOAD: [u8; 12] = [
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57, 0x6f, 0x6c, 0x64, 0x21,
    ];
    let (mut iface, mut sockets, _device) = setup(medium);

    let mut udp_bytes_unicast = vec![0u8; 20];
    let mut udp_bytes_broadcast = vec![0u8; 20];
    let mut packet_unicast = UdpPacket::new_unchecked(&mut udp_bytes_unicast);
    let mut packet_broadcast = UdpPacket::new_unchecked(&mut udp_bytes_broadcast);

    let udp_repr = UdpRepr {
        src_port: 67,
        dst_port: 68,
    };

    let ip_repr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x02),
        dst_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x01),
        next_header: IpProtocol::Udp,
        payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
        hop_limit: 64,
    });

    // Emit the representations to a packet
    udp_repr.emit(
        &mut packet_unicast,
        &ip_repr.src_addr(),
        &ip_repr.dst_addr(),
        UDP_PAYLOAD.len(),
        |buf| buf.copy_from_slice(&UDP_PAYLOAD),
        &ChecksumCapabilities::default(),
    );

    let data = packet_unicast.into_inner();

    // The expected Destination Unreachable ICMPv4 error response due
    // to no sockets listening on the destination port.
    let icmp_repr = Icmpv4Repr::DstUnreachable {
        reason: Icmpv4DstUnreachable::PortUnreachable,
        next_hop_mtu: None,
        header: Ipv4Repr {
            src_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x02),
            dst_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x01),
            next_header: IpProtocol::Udp,
            payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
            hop_limit: 64,
        },
        data,
    };
    let expected_repr = Packet::new_ipv4(
        Ipv4Repr {
            src_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x01),
            dst_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x02),
            next_header: IpProtocol::Icmp,
            payload_len: icmp_repr.buffer_len(),
            hop_limit: 64,
        },
        IpPayload::Icmpv4(icmp_repr),
    );

    // Ensure that the unknown protocol triggers an error response.
    // And we correctly handle no payload.
    assert_eq!(
        iface
            .inner
            .process_udp(&mut sockets, PacketMeta::default(), false, ip_repr, data),
        Some(expected_repr)
    );

    let ip_repr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x02),
        dst_addr: Ipv4Address::BROADCAST,
        next_header: IpProtocol::Udp,
        payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
        hop_limit: 64,
    });

    // Emit the representations to a packet
    udp_repr.emit(
        &mut packet_broadcast,
        &ip_repr.src_addr(),
        &IpAddress::Ipv4(Ipv4Address::BROADCAST),
        UDP_PAYLOAD.len(),
        |buf| buf.copy_from_slice(&UDP_PAYLOAD),
        &ChecksumCapabilities::default(),
    );

    // Ensure that the port unreachable error does not trigger an
    // ICMP error response when the destination address is a
    // broadcast address and no socket is bound to the port.
    assert_eq!(
        iface.inner.process_udp(
            &mut sockets,
            PacketMeta::default(),
            false,
            ip_repr,
            packet_broadcast.into_inner(),
        ),
        None
    );
}

#[rstest]
#[cfg_attr(feature = "medium-ip", case(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case(Medium::Ethernet))]
fn test_handle_ipv4_broadcast(#[case] medium: Medium) {
    use crate::wire::{Icmpv4Packet, Icmpv4Repr};

    let (mut iface, mut sockets, _device) = setup(medium);

    let our_ipv4_addr = iface.ipv4_addr().unwrap();
    let src_ipv4_addr = Ipv4Address::new(127, 0, 0, 2);

    // ICMPv4 echo request
    let icmpv4_data: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];
    let icmpv4_repr = Icmpv4Repr::EchoRequest {
        ident: 0x1234,
        seq_no: 0xabcd,
        data: &icmpv4_data,
    };

    // Send to IPv4 broadcast address
    let ipv4_repr = Ipv4Repr {
        src_addr: src_ipv4_addr,
        dst_addr: Ipv4Address::BROADCAST,
        next_header: IpProtocol::Icmp,
        hop_limit: 64,
        payload_len: icmpv4_repr.buffer_len(),
    };

    // Emit to ip frame
    let mut bytes = vec![0u8; ipv4_repr.buffer_len() + icmpv4_repr.buffer_len()];
    let frame = {
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes[..]),
            &ChecksumCapabilities::default(),
        );
        icmpv4_repr.emit(
            &mut Icmpv4Packet::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
            &ChecksumCapabilities::default(),
        );
        Ipv4Packet::new_unchecked(&bytes[..])
    };

    // Expected ICMPv4 echo reply
    let expected_icmpv4_repr = Icmpv4Repr::EchoReply {
        ident: 0x1234,
        seq_no: 0xabcd,
        data: &icmpv4_data,
    };
    let expected_ipv4_repr = Ipv4Repr {
        src_addr: our_ipv4_addr,
        dst_addr: src_ipv4_addr,
        next_header: IpProtocol::Icmp,
        hop_limit: 64,
        payload_len: expected_icmpv4_repr.buffer_len(),
    };
    let expected_packet =
        Packet::new_ipv4(expected_ipv4_repr, IpPayload::Icmpv4(expected_icmpv4_repr));

    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &frame,
            &mut iface.fragments
        ),
        Some(expected_packet)
    );
}

#[rstest]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn test_handle_valid_arp_request(#[case] medium: Medium) {
    let (mut iface, mut sockets, _device) = setup(medium);

    let mut eth_bytes = vec![0u8; 42];

    let local_ip_addr = Ipv4Address::new(0x7f, 0x00, 0x00, 0x01);
    let remote_ip_addr = Ipv4Address::new(0x7f, 0x00, 0x00, 0x02);
    let local_hw_addr = EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
    let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

    let repr = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr: remote_hw_addr,
        source_protocol_addr: remote_ip_addr,
        target_hardware_addr: EthernetAddress::default(),
        target_protocol_addr: local_ip_addr,
    };

    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(EthernetAddress::BROADCAST);
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Arp);
    let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
    repr.emit(&mut packet);

    // Ensure an ARP Request for us triggers an ARP Reply
    assert_eq!(
        iface.inner.process_ethernet(
            &mut sockets,
            PacketMeta::default(),
            frame.into_inner(),
            &mut iface.fragments
        ),
        Some(EthernetPacket::Arp(ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Reply,
            source_hardware_addr: local_hw_addr,
            source_protocol_addr: local_ip_addr,
            target_hardware_addr: remote_hw_addr,
            target_protocol_addr: remote_ip_addr
        }))
    );

    // Ensure the address of the requester was entered in the cache
    assert_eq!(
        iface.inner.lookup_hardware_addr(
            MockTxToken,
            &IpAddress::Ipv4(remote_ip_addr),
            &mut iface.fragmenter,
        ),
        Ok((HardwareAddress::Ethernet(remote_hw_addr), MockTxToken))
    );
}

#[rstest]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn test_handle_other_arp_request(#[case] medium: Medium) {
    let (mut iface, mut sockets, _device) = setup(medium);

    let mut eth_bytes = vec![0u8; 42];

    let remote_ip_addr = Ipv4Address::new(0x7f, 0x00, 0x00, 0x02);
    let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

    let repr = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr: remote_hw_addr,
        source_protocol_addr: remote_ip_addr,
        target_hardware_addr: EthernetAddress::default(),
        target_protocol_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x03),
    };

    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(EthernetAddress::BROADCAST);
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Arp);
    let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
    repr.emit(&mut packet);

    // Ensure an ARP Request for someone else does not trigger an ARP Reply
    assert_eq!(
        iface.inner.process_ethernet(
            &mut sockets,
            PacketMeta::default(),
            frame.into_inner(),
            &mut iface.fragments
        ),
        None
    );

    // Ensure the address of the requester was NOT entered in the cache
    assert_eq!(
        iface.inner.lookup_hardware_addr(
            MockTxToken,
            &IpAddress::Ipv4(remote_ip_addr),
            &mut iface.fragmenter,
        ),
        Err(DispatchError::NeighborPending)
    );
}

/// An ARP request may not displace a cached neighbor.
///
/// Filling from a request is deliberate: whoever asks for our address is
/// probably about to talk to us. Evicting for one is not -- a request is
/// unsolicited, so with the cache full a handful of forged ones would flush
/// every legitimate mapping, the gateway included. The reply is still owed
/// either way, so it must still go out.
#[rstest]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn test_arp_request_never_evicts(#[case] medium: Medium) {
    use crate::config::IFACE_NEIGHBOR_CACHE_COUNT;

    let (mut iface, mut sockets, _device) = setup(medium);

    let local_ip_addr = Ipv4Address::new(192, 168, 1, 1);
    let local_hw_addr = EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);

    // Fill the cache to capacity with distinct same-subnet neighbors.
    let cached: Vec<(Ipv4Address, EthernetAddress)> = (0..IFACE_NEIGHBOR_CACHE_COUNT)
        .map(|n| {
            let n = 10 + n as u8;
            (
                Ipv4Address::new(192, 168, 1, n),
                EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, n]),
            )
        })
        .collect();
    for (ip_addr, hw_addr) in &cached {
        iface.inner.neighbor_cache.fill(
            IpAddress::Ipv4(*ip_addr),
            HardwareAddress::Ethernet(*hw_addr),
            iface.inner.now,
        );
    }

    let other_ip_addr = Ipv4Address::new(192, 168, 1, 99);
    let other_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x99]);

    let repr = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr: other_hw_addr,
        source_protocol_addr: other_ip_addr,
        target_hardware_addr: EthernetAddress::default(),
        target_protocol_addr: local_ip_addr,
    };

    let mut eth_bytes = vec![0u8; 42];
    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(EthernetAddress::BROADCAST);
    frame.set_src_addr(other_hw_addr);
    frame.set_ethertype(EthernetProtocol::Arp);
    let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
    repr.emit(&mut packet);

    // The reply is still owed, and still goes out.
    assert_eq!(
        iface.inner.process_ethernet(
            &mut sockets,
            PacketMeta::default(),
            frame.into_inner(),
            &mut iface.fragments
        ),
        Some(EthernetPacket::Arp(ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Reply,
            source_hardware_addr: local_hw_addr,
            source_protocol_addr: local_ip_addr,
            target_hardware_addr: other_hw_addr,
            target_protocol_addr: other_ip_addr
        }))
    );

    // Every cached mapping survived, and the requester was not learned.
    for (ip_addr, hw_addr) in &cached {
        assert_eq!(
            iface
                .inner
                .neighbor_cache
                .lookup(&IpAddress::Ipv4(*ip_addr), iface.inner.now),
            NeighborAnswer::Found(HardwareAddress::Ethernet(*hw_addr))
        );
    }
    assert!(
        !iface
            .inner
            .neighbor_cache
            .lookup(&IpAddress::Ipv4(other_ip_addr), iface.inner.now)
            .found()
    );
    assert_eq!(iface.take_neighbor_admission_refused(), 1);
}

#[rstest]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn test_arp_reply_never_evicts_gateway(#[case] medium: Medium) {
    use crate::config::IFACE_NEIGHBOR_CACHE_COUNT;

    let (mut iface, mut sockets, _device) = setup(medium);

    let local_ip_addr = Ipv4Address::new(192, 168, 1, 1);
    let local_hw_addr = EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
    let gateway_ip_addr = Ipv4Address::new(192, 168, 1, 254);
    let gateway_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0xfe]);

    iface.routes_mut().add_default_ipv4_route(gateway_ip_addr);

    // The gateway is closest to expiry, so it is the entry an unprotected
    // eviction takes first. The rest fill the cache.
    iface.inner.neighbor_cache.fill(
        IpAddress::Ipv4(gateway_ip_addr),
        HardwareAddress::Ethernet(gateway_hw_addr),
        iface.inner.now,
    );
    for n in 1..IFACE_NEIGHBOR_CACHE_COUNT as u8 {
        iface.inner.neighbor_cache.fill(
            IpAddress::Ipv4(Ipv4Address::new(192, 168, 1, 10 + n)),
            HardwareAddress::Ethernet(EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 10 + n])),
            iface.inner.now + Duration::from_millis(n.into()),
        );
    }

    // A stream of forged replies, each from an address of its own.
    for n in 0..IFACE_NEIGHBOR_CACHE_COUNT as u8 + 2 {
        let other_ip_addr = Ipv4Address::new(192, 168, 1, 20 + n);
        let other_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x01, 20 + n]);

        let repr = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Reply,
            source_hardware_addr: other_hw_addr,
            source_protocol_addr: other_ip_addr,
            target_hardware_addr: local_hw_addr,
            target_protocol_addr: local_ip_addr,
        };

        let mut eth_bytes = vec![0u8; 42];
        let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
        frame.set_dst_addr(local_hw_addr);
        frame.set_src_addr(other_hw_addr);
        frame.set_ethertype(EthernetProtocol::Arp);
        repr.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()));

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
            .lookup(&IpAddress::Ipv4(gateway_ip_addr), iface.inner.now),
        NeighborAnswer::Found(HardwareAddress::Ethernet(gateway_hw_addr))
    );
    let (hardware_addr, _) = iface
        .inner
        .lookup_hardware_addr(
            MockTxToken,
            &IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)),
            &mut iface.fragmenter,
        )
        .unwrap();
    assert_eq!(
        hardware_addr,
        HardwareAddress::Ethernet(gateway_hw_addr),
        "egress through the gateway must not need re-resolution"
    );
}

#[rstest]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn test_discovery_silence_is_per_destination(#[case] medium: Medium) {
    /// Whom the interface has sent an ARP request for since the last call.
    fn requested(device: &mut crate::tests::TestingDevice) -> Vec<Ipv4Address> {
        device
            .tx_queue
            .drain(..)
            .filter_map(|buffer| {
                let frame = EthernetFrame::new_checked(&buffer[..]).ok()?;
                let packet = ArpPacket::new_checked(frame.payload()).ok()?;
                match ArpRepr::parse(&packet).ok()? {
                    ArpRepr::EthernetIpv4 {
                        operation: ArpOperation::Request,
                        target_protocol_addr,
                        ..
                    } => Some(target_protocol_addr),
                    _ => None,
                }
            })
            .collect()
    }

    let (mut iface, mut sockets, mut device) = setup(medium);
    let now = iface.inner.now;

    let local_ip_addr = Ipv4Address::new(192, 168, 1, 1);
    let local_hw_addr = EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
    let black_hole = Ipv4Address::new(192, 168, 1, 20);
    let answering = Ipv4Address::new(192, 168, 1, 30);
    let answering_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x30]);

    // A destination nobody answers for: the request goes out, and the packet
    // that wanted it waits on the neighbor.
    assert_eq!(
        iface
            .inner
            .lookup_hardware_addr(
                device.transmit(now).unwrap(),
                &IpAddress::Ipv4(black_hole),
                &mut iface.fragmenter,
            )
            .map(|(hardware_addr, _)| hardware_addr),
        Err(DispatchError::NeighborPending)
    );
    assert_eq!(requested(&mut device), vec![black_hole]);

    // Asking again within the silent interval costs the segment nothing.
    assert_eq!(
        iface
            .inner
            .lookup_hardware_addr(
                device.transmit(now).unwrap(),
                &IpAddress::Ipv4(black_hole),
                &mut iface.fragmenter,
            )
            .map(|(hardware_addr, _)| hardware_addr),
        Err(DispatchError::NeighborPending)
    );
    assert_eq!(requested(&mut device), Vec::<Ipv4Address>::new());

    // A second destination, still inside that interval: its own request goes
    // out, because the silence belongs to the black hole alone.
    assert_eq!(
        iface
            .inner
            .lookup_hardware_addr(
                device.transmit(now).unwrap(),
                &IpAddress::Ipv4(answering),
                &mut iface.fragmenter,
            )
            .map(|(hardware_addr, _)| hardware_addr),
        Err(DispatchError::NeighborPending)
    );
    assert_eq!(requested(&mut device), vec![answering]);

    let repr = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Reply,
        source_hardware_addr: answering_hw_addr,
        source_protocol_addr: answering,
        target_hardware_addr: local_hw_addr,
        target_protocol_addr: local_ip_addr,
    };
    let mut eth_bytes = vec![0u8; 42];
    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(local_hw_addr);
    frame.set_src_addr(answering_hw_addr);
    frame.set_ethertype(EthernetProtocol::Arp);
    repr.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()));

    assert_eq!(
        iface.inner.process_ethernet(
            &mut sockets,
            PacketMeta::default(),
            frame.into_inner(),
            &mut iface.fragments
        ),
        None
    );

    // So the second destination resolves within one silent interval of the
    // first going unanswered, and needs no further request.
    assert_eq!(
        iface
            .inner
            .lookup_hardware_addr(
                device.transmit(now).unwrap(),
                &IpAddress::Ipv4(answering),
                &mut iface.fragmenter,
            )
            .map(|(hardware_addr, _)| hardware_addr),
        Ok(HardwareAddress::Ethernet(answering_hw_addr))
    );
    assert_eq!(requested(&mut device), Vec::<Ipv4Address>::new());
}

#[rstest]
#[case(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
fn test_arp_flush_after_update_ip(#[case] medium: Medium) {
    let (mut iface, mut sockets, _device) = setup(medium);

    let mut eth_bytes = vec![0u8; 42];

    let local_ip_addr = Ipv4Address::new(0x7f, 0x00, 0x00, 0x01);
    let remote_ip_addr = Ipv4Address::new(0x7f, 0x00, 0x00, 0x02);
    let local_hw_addr = EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
    let remote_hw_addr = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);

    let repr = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr: remote_hw_addr,
        source_protocol_addr: remote_ip_addr,
        target_hardware_addr: EthernetAddress::default(),
        target_protocol_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x01),
    };

    let mut frame = EthernetFrame::new_unchecked(&mut eth_bytes);
    frame.set_dst_addr(EthernetAddress::BROADCAST);
    frame.set_src_addr(remote_hw_addr);
    frame.set_ethertype(EthernetProtocol::Arp);
    {
        let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
        repr.emit(&mut packet);
    }

    // Ensure an ARP Request for us triggers an ARP Reply
    assert_eq!(
        iface.inner.process_ethernet(
            &mut sockets,
            PacketMeta::default(),
            frame.into_inner(),
            &mut iface.fragments
        ),
        Some(EthernetPacket::Arp(ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Reply,
            source_hardware_addr: local_hw_addr,
            source_protocol_addr: local_ip_addr,
            target_hardware_addr: remote_hw_addr,
            target_protocol_addr: remote_ip_addr
        }))
    );

    // Ensure the address of the requester was entered in the cache
    assert_eq!(
        iface.inner.lookup_hardware_addr(
            MockTxToken,
            &IpAddress::Ipv4(remote_ip_addr),
            &mut iface.fragmenter,
        ),
        Ok((HardwareAddress::Ethernet(remote_hw_addr), MockTxToken))
    );

    // Update IP addrs to trigger ARP cache flush
    let local_ip_addr_new = Ipv4Address::new(0x7f, 0x00, 0x00, 0x01);
    iface.update_ip_addrs(|addrs| {
        addrs.iter_mut().next().map(|addr| {
            *addr = IpCidr::Ipv4(Ipv4Cidr::new(local_ip_addr_new, 24));
        });
    });

    // ARP cache flush after address change
    assert!(!iface.inner.has_neighbor(&IpAddress::Ipv4(remote_ip_addr)));
}

#[cfg(feature = "socket-icmp")]
#[rstest]
#[cfg_attr(feature = "medium-ip", case(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case(Medium::Ethernet))]
fn test_icmpv4_socket(#[case] medium: Medium) {
    use crate::wire::Icmpv4Packet;

    let (mut iface, mut sockets, _device) = setup(medium);

    let rx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 24]);
    let tx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 24]);

    let icmpv4_socket = icmp::Socket::new(rx_buffer, tx_buffer);

    let socket_handle = sockets.add(0, icmpv4_socket);

    let ident = 0x1234;
    let seq_no = 0x5432;
    let echo_data = &[0xff; 16];

    let socket = sockets.get_mut::<icmp::Socket>(socket_handle);
    // Bind to the ID 0x1234
    assert_eq!(socket.bind(icmp::Endpoint::Ident(ident)), Ok(()));

    // Ensure the ident we bound to and the ident of the packet are the same.
    let mut bytes = [0xff; 24];
    let mut packet = Icmpv4Packet::new_unchecked(&mut bytes[..]);
    let echo_repr = Icmpv4Repr::EchoRequest {
        ident,
        seq_no,
        data: echo_data,
    };
    echo_repr.emit(&mut packet, &ChecksumCapabilities::default());
    let icmp_data = &*packet.into_inner();

    let ipv4_repr = Ipv4Repr {
        src_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x02),
        dst_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x01),
        next_header: IpProtocol::Icmp,
        payload_len: 24,
        hop_limit: 64,
    };

    // Open a socket and ensure the packet is handled due to the listening
    // socket.
    assert!(!sockets.get_mut::<icmp::Socket>(socket_handle).can_recv());

    // Confirm we still get EchoReply from `moto-netstack` even with the ICMP socket listening
    let echo_reply = Icmpv4Repr::EchoReply {
        ident,
        seq_no,
        data: echo_data,
    };
    let ipv4_reply = Ipv4Repr {
        src_addr: ipv4_repr.dst_addr,
        dst_addr: ipv4_repr.src_addr,
        ..ipv4_repr
    };
    assert_eq!(
        iface
            .inner
            .process_icmpv4(&mut sockets, ipv4_repr, icmp_data),
        Some(Packet::new_ipv4(ipv4_reply, IpPayload::Icmpv4(echo_reply)))
    );
    let socket = sockets.get_mut::<icmp::Socket>(socket_handle);
    assert!(socket.can_recv());
    assert_eq!(
        socket.recv(),
        Ok((
            icmp_data,
            IpAddress::Ipv4(Ipv4Address::new(0x7f, 0x00, 0x00, 0x02))
        ))
    );
}

#[cfg(feature = "multicast")]
#[rstest]
#[cfg_attr(feature = "medium-ip", case(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case(Medium::Ethernet))]
fn test_handle_igmp(#[case] medium: Medium) {
    fn recv_igmp(
        device: &mut crate::tests::TestingDevice,
        timestamp: Instant,
    ) -> Vec<(Ipv4Repr, IgmpRepr)> {
        let caps = device.capabilities();
        let checksum_caps = &caps.checksum;
        recv_all(device, timestamp)
            .iter()
            .filter_map(|frame| {
                let ipv4_packet = match caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => {
                        let eth_frame = EthernetFrame::new_checked(frame).ok()?;
                        Ipv4Packet::new_checked(eth_frame.payload()).ok()?
                    }
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => Ipv4Packet::new_checked(&frame[..]).ok()?,
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => todo!(),
                };
                let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, checksum_caps).ok()?;
                let ip_payload = ipv4_packet.payload();
                let igmp_packet = IgmpPacket::new_checked(ip_payload).ok()?;
                let igmp_repr = IgmpRepr::parse(&igmp_packet).ok()?;
                Some((ipv4_repr, igmp_repr))
            })
            .collect::<Vec<_>>()
    }

    let groups = [
        Ipv4Address::new(224, 0, 0, 22),
        Ipv4Address::new(224, 0, 0, 56),
    ];

    let (mut iface, mut sockets, mut device) = setup(medium);

    // Join multicast groups
    let timestamp = Instant::ZERO;
    for group in &groups {
        iface.join_multicast_group(*group).unwrap();
    }
    iface.poll(timestamp, &mut device, &mut sockets);

    let reports = recv_igmp(&mut device, timestamp);
    assert_eq!(reports.len(), 2);
    for (i, group_addr) in groups.iter().enumerate() {
        assert_eq!(reports[i].0.next_header, IpProtocol::Igmp);
        assert_eq!(reports[i].0.dst_addr, *group_addr);
        assert_eq!(
            reports[i].1,
            IgmpRepr::MembershipReport {
                group_addr: *group_addr,
                version: IgmpVersion::Version2,
            }
        );
    }

    // General query
    const GENERAL_QUERY_BYTES: &[u8] = &[
        0x46, 0xc0, 0x00, 0x24, 0xed, 0xb4, 0x00, 0x00, 0x01, 0x02, 0x47, 0x43, 0xac, 0x16, 0x63,
        0x04, 0xe0, 0x00, 0x00, 0x01, 0x94, 0x04, 0x00, 0x00, 0x11, 0x64, 0xec, 0x8f, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    device.push_rx(GENERAL_QUERY_BYTES.to_vec());

    // Trigger processing until all packets received through the
    // loopback have been processed, including responses to
    // GENERAL_QUERY_BYTES. Therefore `recv_all()` would return 0
    // pkts that could be checked.
    iface.socket_ingress(&mut device, &mut sockets);

    // Leave multicast groups
    let timestamp = Instant::ZERO;
    for group in &groups {
        iface.leave_multicast_group(*group).unwrap();
    }
    iface.poll(timestamp, &mut device, &mut sockets);

    let leaves = recv_igmp(&mut device, timestamp);
    assert_eq!(leaves.len(), 2);
    for (i, group_addr) in groups.iter().cloned().enumerate() {
        assert_eq!(leaves[i].0.next_header, IpProtocol::Igmp);
        assert_eq!(leaves[i].0.dst_addr, IPV4_MULTICAST_ALL_ROUTERS);
        assert_eq!(leaves[i].1, IgmpRepr::LeaveGroup { group_addr });
    }
}

#[cfg(feature = "proto-ipv4-fragmentation")]
#[rstest]
#[cfg_attr(feature = "medium-ip", case(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case(Medium::Ethernet))]
fn test_packet_len(#[case] medium: Medium) {
    use crate::config::FRAGMENTATION_BUFFER_SIZE;

    let (mut iface, _, _) = setup(medium);

    struct TestTxToken {
        max_transmission_unit: usize,
    }

    impl TxToken for TestTxToken {
        fn consume<R, F>(self, len: usize, f: F) -> R
        where
            F: FnOnce(&mut [u8]) -> R,
        {
            net_debug!("TxToken get len: {}", len);
            assert!(len <= self.max_transmission_unit);
            let mut junk = [0; 1536];
            f(&mut junk[..len])
        }
    }

    iface.inner.neighbor_cache.fill(
        IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)),
        HardwareAddress::Ethernet(EthernetAddress::from_bytes(&[
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        ])),
        Instant::ZERO,
    );

    for ip_packet_len in [
        100,
        iface.inner.ip_mtu(),
        iface.inner.ip_mtu() + 1,
        FRAGMENTATION_BUFFER_SIZE,
    ] {
        net_debug!("ip_packet_len: {}", ip_packet_len);

        let mut ip_repr = Ipv4Repr {
            src_addr: Ipv4Address::new(127, 0, 0, 1),
            dst_addr: Ipv4Address::new(127, 0, 0, 1),
            next_header: IpProtocol::Udp,
            payload_len: 0,
            hop_limit: 64,
        };
        let udp_repr = UdpRepr {
            src_port: 12345,
            dst_port: 54321,
        };

        let ip_packet_payload_len = ip_packet_len - ip_repr.buffer_len();
        let udp_packet_payload_len = ip_packet_payload_len - udp_repr.header_len();
        ip_repr.payload_len = ip_packet_payload_len;

        let udp_packet_payload = vec![1; udp_packet_payload_len];
        let ip_payload = IpPayload::Udp(udp_repr, &udp_packet_payload);
        let ip_packet = Packet::new_ipv4(ip_repr, ip_payload);

        assert_eq!(
            iface.inner.dispatch_ip(
                TestTxToken {
                    max_transmission_unit: iface.inner.caps.max_transmission_unit
                },
                PacketMeta::default(),
                ip_packet,
                &mut iface.fragmenter,
            ),
            Ok(())
        );
    }
}

/// Check no reply is emitted when using a raw socket
#[cfg(feature = "socket-raw")]
fn check_no_reply_raw_socket(medium: Medium, frame: &crate::wire::ipv4::Packet<&[u8]>) {
    let (mut iface, mut sockets, _) = setup(medium);

    let packets = 1;
    let rx_buffer =
        raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY; packets], vec![0; 48 * 1]);
    let tx_buffer = raw::PacketBuffer::new(
        vec![raw::PacketMetadata::EMPTY; packets],
        vec![0; 48 * packets],
    );
    let raw_socket = raw::Socket::new(Some(IpVersion::Ipv4), None, rx_buffer, tx_buffer);
    sockets.add(0, raw_socket);

    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            frame,
            &mut iface.fragments
        ),
        None
    );
}

#[cfg(feature = "socket-raw")]
#[rstest]
#[cfg_attr(feature = "medium-ip", case(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case(Medium::Ethernet))]
/// Test no reply to received UDP when using raw socket which accepts all protocols
fn test_raw_socket_no_reply_udp(#[case] medium: Medium) {
    use crate::wire::{UdpPacket, UdpRepr};

    let src_addr = Ipv4Address::new(127, 0, 0, 2);
    let dst_addr = Ipv4Address::new(127, 0, 0, 1);

    const PAYLOAD_LEN: usize = 10;

    let udp_repr = UdpRepr {
        src_port: 67,
        dst_port: 68,
    };
    let ipv4_repr = Ipv4Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Udp,
        hop_limit: 64,
        payload_len: udp_repr.header_len() + PAYLOAD_LEN,
    };

    // Emit to frame
    let mut bytes = vec![0u8; ipv4_repr.buffer_len() + udp_repr.header_len() + PAYLOAD_LEN];
    let frame = {
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        udp_repr.emit(
            &mut UdpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
            &src_addr.into(),
            &dst_addr.into(),
            PAYLOAD_LEN,
            |buf| fill_slice(buf, 0x2a),
            &ChecksumCapabilities::default(),
        );
        Ipv4Packet::new_unchecked(&bytes[..])
    };

    check_no_reply_raw_socket(medium, &frame);
}

#[cfg(feature = "socket-raw")]
#[rstest]
#[cfg_attr(feature = "medium-ip", case(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case(Medium::Ethernet))]
/// Test no reply to received TCP when using raw socket which accepts all protocols
fn test_raw_socket_no_reply_tcp(#[case] medium: Medium) {
    use crate::wire::{TcpPacket, TcpRepr};

    let src_addr = Ipv4Address::new(127, 0, 0, 2);
    let dst_addr = Ipv4Address::new(127, 0, 0, 1);

    const PAYLOAD_LEN: usize = 10;
    const PAYLOAD: [u8; PAYLOAD_LEN] = [0x2a; PAYLOAD_LEN];

    let tcp_repr = TcpRepr {
        src_port: 67,
        dst_port: 68,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(1),
        ack_number: None,
        window_len: 10,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &PAYLOAD,
    };
    let ipv4_repr = Ipv4Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Tcp,
        hop_limit: 64,
        payload_len: tcp_repr.header_len() + PAYLOAD_LEN,
    };

    // Emit to frame
    let mut bytes = vec![0u8; ipv4_repr.buffer_len() + tcp_repr.header_len() + PAYLOAD_LEN];
    let frame = {
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        tcp_repr.emit(
            &mut TcpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
            &src_addr.into(),
            &dst_addr.into(),
            &ChecksumCapabilities::default(),
        );
        Ipv4Packet::new_unchecked(&bytes[..])
    };

    check_no_reply_raw_socket(medium, &frame);
}

#[cfg(all(feature = "socket-raw", feature = "socket-udp"))]
#[rstest]
#[cfg_attr(feature = "medium-ip", case(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case(Medium::Ethernet))]
fn test_raw_socket_with_udp_socket(#[case] medium: Medium) {
    use crate::socket::udp;
    use crate::wire::{IpEndpoint, IpVersion, UdpPacket, UdpRepr};

    static UDP_PAYLOAD: [u8; 5] = [0x48, 0x65, 0x6c, 0x6c, 0x6f];

    let (mut iface, mut sockets, _) = setup(medium);

    let udp_rx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 15]);
    let udp_tx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 15]);
    let udp_socket = udp::Socket::new(udp_rx_buffer, udp_tx_buffer);
    let udp_socket_handle = sockets.add(0, udp_socket);

    // Bind the socket to port 68
    assert_eq!(sockets.udp_bind(udp_socket_handle, 68), Ok(()));
    let socket = sockets.get_mut::<udp::Socket>(udp_socket_handle);
    assert!(!socket.can_recv());
    assert!(socket.can_send());

    let packets = 1;
    let raw_rx_buffer =
        raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY; packets], vec![0; 48 * 1]);
    let raw_tx_buffer = raw::PacketBuffer::new(
        vec![raw::PacketMetadata::EMPTY; packets],
        vec![0; 48 * packets],
    );
    let raw_socket = raw::Socket::new(
        Some(IpVersion::Ipv4),
        Some(IpProtocol::Udp),
        raw_rx_buffer,
        raw_tx_buffer,
    );
    sockets.add(1, raw_socket);

    let src_addr = Ipv4Address::new(127, 0, 0, 2);
    let dst_addr = Ipv4Address::new(127, 0, 0, 1);

    let udp_repr = UdpRepr {
        src_port: 67,
        dst_port: 68,
    };
    let mut bytes = vec![0xff; udp_repr.header_len() + UDP_PAYLOAD.len()];
    let mut packet = UdpPacket::new_unchecked(&mut bytes[..]);
    udp_repr.emit(
        &mut packet,
        &src_addr.into(),
        &dst_addr.into(),
        UDP_PAYLOAD.len(),
        |buf| buf.copy_from_slice(&UDP_PAYLOAD),
        &ChecksumCapabilities::default(),
    );
    let ipv4_repr = Ipv4Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Udp,
        hop_limit: 64,
        payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
    };

    // Emit to frame
    let mut bytes = vec![0u8; ipv4_repr.buffer_len() + udp_repr.header_len() + UDP_PAYLOAD.len()];
    let frame = {
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        udp_repr.emit(
            &mut UdpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
            &src_addr.into(),
            &dst_addr.into(),
            UDP_PAYLOAD.len(),
            |buf| buf.copy_from_slice(&UDP_PAYLOAD),
            &ChecksumCapabilities::default(),
        );
        Ipv4Packet::new_unchecked(&bytes[..])
    };

    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &frame,
            &mut iface.fragments
        ),
        None
    );

    // Make sure the UDP socket can still receive in presence of a Raw socket that handles UDP
    let socket = sockets.get_mut::<udp::Socket>(udp_socket_handle);
    assert!(socket.can_recv());
    assert_eq!(
        socket.recv(),
        Ok((
            &UDP_PAYLOAD[..],
            udp::UdpMetadata {
                local_address: Some(dst_addr.into()),
                ..IpEndpoint::new(src_addr.into(), 67).into()
            }
        ))
    );
}

#[cfg(feature = "proto-ipv4-fragmentation")]
use crate::phy::IPV4_FRAGMENT_PAYLOAD_ALIGNMENT;
#[cfg(all(feature = "socket-raw", feature = "proto-ipv4-fragmentation"))]
#[rstest]
#[cfg_attr(feature = "medium-ip", case(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case(Medium::Ethernet))]
fn test_raw_socket_tx_fragmentation(#[case] medium: Medium) {
    use std::panic::AssertUnwindSafe;

    let (mut iface, mut sockets, device) = setup(medium);
    let mtu = device.capabilities().max_transmission_unit;
    let unaligned_length = mtu - IPV4_HEADER_LEN;
    // This check ensures a valid test in which we actually do adjust for alignment.
    let mtu = if unaligned_length.is_multiple_of(IPV4_FRAGMENT_PAYLOAD_ALIGNMENT) {
        mtu + IPV4_FRAGMENT_PAYLOAD_ALIGNMENT / 2
    } else {
        mtu
    };

    let packets = 5;
    let rx_buffer = raw::PacketBuffer::new(
        vec![raw::PacketMetadata::EMPTY; packets],
        vec![0; mtu * packets],
    );
    let tx_buffer = raw::PacketBuffer::new(
        vec![raw::PacketMetadata::EMPTY; packets],
        vec![0; mtu * packets],
    );
    let socket = raw::Socket::new(
        Some(IpVersion::Ipv4),
        Some(IpProtocol::Udp),
        rx_buffer,
        tx_buffer,
    );
    let _handle = sockets.add(0, socket);

    let tx_packet_sizes = vec![
        mtu * 3 / 4, // Smaller than MTU
        mtu * 5 / 4, // Larger than MTU, requires fragmentation
        mtu * 9 / 4, // Much larger, requires two fragments
    ];

    // Define test token for capturing the fragments.
    struct TestFragmentTxToken {}

    impl TxToken for TestFragmentTxToken {
        fn consume<R, F>(self, len: usize, f: F) -> R
        where
            F: FnOnce(&mut [u8]) -> R,
        {
            // Buffer is something arbitrarily large.
            // We cannot capture the dynamic packet_size calculation here.
            let mut buffer = [0; 2048];
            let result = f(&mut buffer[..len]);
            // Verify the payload size is aligned.
            let payload_size = len - IPV4_HEADER_LEN;
            assert!(payload_size.is_multiple_of(IPV4_FRAGMENT_PAYLOAD_ALIGNMENT));
            result
        }
    }

    for packet_size in tx_packet_sizes {
        let payload_len = packet_size - IPV4_HEADER_LEN;
        let payload = vec![0u8; payload_len];

        let ip_repr = Ipv4Repr {
            src_addr: Ipv4Address::new(192, 168, 1, 3),
            dst_addr: Ipv4Address::BROADCAST,
            next_header: IpProtocol::Unknown(92),
            hop_limit: 64,
            payload_len,
        };
        let ip_payload = IpPayload::Raw(&payload);
        let packet = Packet::new_ipv4(ip_repr, ip_payload);

        // This should not panic for any payload size
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            if packet_size > mtu && medium == Medium::Ip {
                iface.inner.dispatch_ip(
                    TestFragmentTxToken {},
                    PacketMeta::default(),
                    packet,
                    &mut iface.fragmenter,
                )
            } else {
                iface.inner.dispatch_ip(
                    MockTxToken {},
                    PacketMeta::default(),
                    packet,
                    &mut iface.fragmenter,
                )
            }
        }));

        // All transmissions should succeed without panicking
        assert!(result.is_ok(), "Failed for packet size: {}", packet_size,);

        // Perform payload size checks if fragmentation is required.
        // It is sufficient to test only the simpler IP test case.
        if packet_size <= mtu || medium != Medium::Ip {
            continue;
        }

        // Verify that the fragment offset is correct.
        let unaligned_length = mtu - IPV4_HEADER_LEN;
        let remainder = unaligned_length % IPV4_FRAGMENT_PAYLOAD_ALIGNMENT;
        let expected_fragment_offset = mtu - IPV4_HEADER_LEN - remainder;
        let frag_offset = iface.fragmenter.ipv4.frag_offset;
        assert_eq!(frag_offset as usize, expected_fragment_offset);

        // Check subsequent fragment sizes if applicable.
        if packet_size / mtu == 2 {
            // Two fragments are left. The intermediate fragment must be aligned.
            iface
                .inner
                .dispatch_ipv4_frag(TestFragmentTxToken {}, &mut iface.fragmenter);
        }
        // Process the final fragment. It is the remainder of the data and does not have to be aligned.
        iface
            .inner
            .dispatch_ipv4_frag(MockTxToken {}, &mut iface.fragmenter);

        // The fragment offset should be the complete payload length once transmission is complete.
        let frag_offset = iface.fragmenter.ipv4.frag_offset;
        assert_eq!(frag_offset as usize, payload_len);
    }
}

#[cfg(all(feature = "medium-ip", feature = "proto-ipv4-fragmentation"))]
struct Ipv4FragmentSpec {
    dst_addr: Ipv4Address,
    protocol: IpProtocol,
    ident: u16,
    offset: u16,
    more_frags: bool,
    dont_frag: bool,
    reserved: bool,
    payload_len: usize,
}

#[cfg(all(feature = "medium-ip", feature = "proto-ipv4-fragmentation"))]
fn ipv4_fragment_bytes(spec: Ipv4FragmentSpec) -> Vec<u8> {
    let Ipv4FragmentSpec {
        dst_addr,
        protocol,
        ident,
        offset,
        more_frags,
        dont_frag,
        reserved,
        payload_len,
    } = spec;
    let repr = Ipv4Repr {
        src_addr: Ipv4Address::new(192, 168, 1, 2),
        dst_addr,
        next_header: protocol,
        payload_len,
        hop_limit: 64,
    };
    let mut bytes = vec![0; repr.buffer_len() + payload_len];
    let mut packet = Ipv4Packet::new_unchecked(&mut bytes);
    repr.emit(&mut packet, &ChecksumCapabilities::default());
    packet.set_ident(ident);
    packet.set_more_frags(more_frags);
    packet.set_dont_frag(dont_frag);
    packet.set_frag_offset(offset);
    packet.fill_checksum();
    if reserved {
        bytes[6] |= 0x80;
        Ipv4Packet::new_unchecked(&mut bytes).fill_checksum();
    }
    bytes
}

#[cfg(all(feature = "medium-ip", feature = "proto-ipv4-fragmentation"))]
fn customize_ipv4_fragment(bytes: &mut [u8], hop_limit: u8, payload_byte: u8) {
    let header_len = Ipv4Packet::new_unchecked(&*bytes).header_len() as usize;
    bytes[header_len..].fill(payload_byte);
    let mut packet = Ipv4Packet::new_unchecked(bytes);
    packet.set_hop_limit(hop_limit);
    packet.fill_checksum();
}

#[cfg(all(feature = "medium-ip", feature = "proto-ipv4-fragmentation"))]
fn ipv4_two_fragment_payload(
    protocol: IpProtocol,
    ident: u16,
    payload: &[u8],
    split: usize,
) -> [Vec<u8>; 2] {
    assert!(split > 0 && split < payload.len() && split.is_multiple_of(8));
    let dst_addr = Ipv4Address::new(192, 168, 1, 1);
    let mut first = ipv4_fragment_bytes(Ipv4FragmentSpec {
        dst_addr,
        protocol,
        ident,
        offset: 0,
        more_frags: true,
        dont_frag: false,
        reserved: false,
        payload_len: split,
    });
    let mut last = ipv4_fragment_bytes(Ipv4FragmentSpec {
        dst_addr,
        protocol,
        ident,
        offset: split as u16,
        more_frags: false,
        dont_frag: false,
        reserved: false,
        payload_len: payload.len() - split,
    });
    first[IPV4_HEADER_LEN..].copy_from_slice(&payload[..split]);
    last[IPV4_HEADER_LEN..].copy_from_slice(&payload[split..]);
    [first, last]
}

#[cfg(all(feature = "medium-ip", feature = "proto-ipv4-fragmentation"))]
fn assert_ipv4_fragment_reply(reply: Option<Packet<'_>>, hop_limit: u8, payload: &[u8]) {
    let reply = reply.expect("complete reassembly should produce an ICMP reply");
    match reply.payload() {
        IpPayload::Icmpv4(Icmpv4Repr::DstUnreachable { header, data, .. }) => {
            assert_eq!(header.hop_limit, hop_limit);
            assert_eq!(*data, payload);
        }
        other => panic!("unexpected reassembly reply: {other:?}"),
    }
}

#[test]
#[cfg(all(feature = "medium-ip", feature = "proto-ipv4-fragmentation"))]
fn ipv4_reassembly_uses_offset_zero_header_in_any_order() {
    let dst_addr = Ipv4Address::new(192, 168, 1, 1);
    for last_first in [false, true] {
        let (mut iface, mut sockets, _device) = setup(Medium::Ip);
        let mut first = ipv4_fragment_bytes(Ipv4FragmentSpec {
            dst_addr,
            protocol: IpProtocol::Unknown(99),
            ident: 1,
            offset: 0,
            more_frags: true,
            dont_frag: false,
            reserved: false,
            payload_len: 8,
        });
        let mut last = ipv4_fragment_bytes(Ipv4FragmentSpec {
            dst_addr,
            protocol: IpProtocol::Unknown(99),
            ident: 1,
            offset: 8,
            more_frags: false,
            dont_frag: false,
            reserved: false,
            payload_len: 8,
        });
        customize_ipv4_fragment(&mut first, 64, 0xaa);
        customize_ipv4_fragment(&mut last, 7, 0xbb);
        let first = Ipv4Packet::new_checked(&first[..]).unwrap();
        let last = Ipv4Packet::new_checked(&last[..]).unwrap();

        let reply = if last_first {
            assert!(
                iface
                    .inner
                    .process_ipv4(
                        &mut sockets,
                        PacketMeta::default(),
                        HardwareAddress::Ip,
                        &last,
                        &mut iface.fragments,
                    )
                    .is_none()
            );
            iface.inner.process_ipv4(
                &mut sockets,
                PacketMeta::default(),
                HardwareAddress::Ip,
                &first,
                &mut iface.fragments,
            )
        } else {
            assert!(
                iface
                    .inner
                    .process_ipv4(
                        &mut sockets,
                        PacketMeta::default(),
                        HardwareAddress::Ip,
                        &first,
                        &mut iface.fragments,
                    )
                    .is_none()
            );
            iface.inner.process_ipv4(
                &mut sockets,
                PacketMeta::default(),
                HardwareAddress::Ip,
                &last,
                &mut iface.fragments,
            )
        };
        assert_ipv4_fragment_reply(
            reply,
            64,
            &[
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb,
            ],
        );
    }
}

#[test]
#[cfg(all(feature = "medium-ip", feature = "proto-ipv4-fragmentation"))]
fn ipv4_reassembly_duplicate_preserves_first_bytes() {
    let (mut iface, mut sockets, _device) = setup(Medium::Ip);
    let dst_addr = Ipv4Address::new(192, 168, 1, 1);
    let spec = |offset, more_frags| Ipv4FragmentSpec {
        dst_addr,
        protocol: IpProtocol::Unknown(99),
        ident: 1,
        offset,
        more_frags,
        dont_frag: false,
        reserved: false,
        payload_len: 8,
    };
    let mut first = ipv4_fragment_bytes(spec(0, true));
    let mut duplicate = ipv4_fragment_bytes(spec(0, true));
    let mut last = ipv4_fragment_bytes(spec(8, false));
    customize_ipv4_fragment(&mut first, 64, 0xaa);
    customize_ipv4_fragment(&mut duplicate, 7, 0xcc);
    customize_ipv4_fragment(&mut last, 7, 0xbb);

    for bytes in [&first, &duplicate] {
        let packet = Ipv4Packet::new_checked(&bytes[..]).unwrap();
        assert!(
            iface
                .inner
                .process_ipv4(
                    &mut sockets,
                    PacketMeta::default(),
                    HardwareAddress::Ip,
                    &packet,
                    &mut iface.fragments,
                )
                .is_none()
        );
    }
    let last = Ipv4Packet::new_checked(&last[..]).unwrap();
    let reply = iface.inner.process_ipv4(
        &mut sockets,
        PacketMeta::default(),
        HardwareAddress::Ip,
        &last,
        &mut iface.fragments,
    );
    assert_ipv4_fragment_reply(
        reply,
        64,
        &[
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
            0xbb, 0xbb,
        ],
    );
}

#[test]
#[cfg(all(feature = "medium-ip", feature = "proto-ipv4-fragmentation"))]
fn ipv4_reassembly_completes_three_fragment_permutations() {
    const ORDERS: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let dst_addr = Ipv4Address::new(192, 168, 1, 1);

    for order in ORDERS {
        let (mut iface, mut sockets, _device) = setup(Medium::Ip);
        let mut fragments = [
            ipv4_fragment_bytes(Ipv4FragmentSpec {
                dst_addr,
                protocol: IpProtocol::Unknown(99),
                ident: 1,
                offset: 0,
                more_frags: true,
                dont_frag: false,
                reserved: false,
                payload_len: 8,
            }),
            ipv4_fragment_bytes(Ipv4FragmentSpec {
                dst_addr,
                protocol: IpProtocol::Unknown(99),
                ident: 1,
                offset: 8,
                more_frags: true,
                dont_frag: false,
                reserved: false,
                payload_len: 8,
            }),
            ipv4_fragment_bytes(Ipv4FragmentSpec {
                dst_addr,
                protocol: IpProtocol::Unknown(99),
                ident: 1,
                offset: 16,
                more_frags: false,
                dont_frag: false,
                reserved: false,
                payload_len: 8,
            }),
        ];
        for (index, fragment) in fragments.iter_mut().enumerate() {
            customize_ipv4_fragment(fragment, 64, 0xaa + index as u8);
        }

        for (position, index) in order.into_iter().enumerate() {
            let packet = Ipv4Packet::new_checked(&fragments[index][..]).unwrap();
            let reply = iface.inner.process_ipv4(
                &mut sockets,
                PacketMeta::default(),
                HardwareAddress::Ip,
                &packet,
                &mut iface.fragments,
            );
            if position == 2 {
                assert_ipv4_fragment_reply(
                    reply,
                    64,
                    &[
                        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xab, 0xab, 0xab, 0xab,
                        0xab, 0xab, 0xab, 0xab, 0xac, 0xac, 0xac, 0xac, 0xac, 0xac, 0xac, 0xac,
                    ],
                );
            } else {
                assert!(reply.is_none());
            }
        }
    }
}

#[test]
#[cfg(all(feature = "medium-ip", feature = "proto-ipv4-fragmentation"))]
fn ipv4_partial_overlap_after_final_fragment_tombstones_key() {
    let (mut iface, mut sockets, _device) = setup(Medium::Ip);
    let dst_addr = Ipv4Address::new(192, 168, 1, 1);
    let spec = |offset, more_frags, payload_len| Ipv4FragmentSpec {
        dst_addr,
        protocol: IpProtocol::Unknown(99),
        ident: 1,
        offset,
        more_frags,
        dont_frag: false,
        reserved: false,
        payload_len,
    };
    let final_fragment = ipv4_fragment_bytes(spec(16, false, 8));
    let overlapping = ipv4_fragment_bytes(spec(8, true, 16));
    let first = ipv4_fragment_bytes(spec(0, true, 8));
    let key = FragKey::Ipv4(Ipv4Packet::new_unchecked(&final_fragment[..]).get_key());

    for bytes in [&final_fragment, &overlapping, &first] {
        let packet = Ipv4Packet::new_checked(&bytes[..]).unwrap();
        assert!(
            iface
                .inner
                .process_ipv4(
                    &mut sockets,
                    PacketMeta::default(),
                    HardwareAddress::Ip,
                    &packet,
                    &mut iface.fragments,
                )
                .is_none()
        );
    }
    let assembler = iface.fragments.assembler.get(&key, Instant::ZERO).unwrap();
    assert_eq!(assembler.add(b"valid", 0), Err(AssemblerError::Poisoned));
}

#[test]
#[cfg(all(feature = "medium-ip", feature = "proto-ipv4-fragmentation"))]
fn ipv4_conflicting_final_size_poisons_existing_state() {
    let dst_addr = Ipv4Address::new(192, 168, 1, 1);
    let cases = [
        ((16, false, 8), (8, false, 8)),
        ((8, false, 8), (16, true, 8)),
    ];

    for (ident, (first_spec, conflict_spec)) in cases.into_iter().enumerate() {
        let (mut iface, mut sockets, _device) = setup(Medium::Ip);
        let build = |(offset, more_frags, payload_len)| {
            ipv4_fragment_bytes(Ipv4FragmentSpec {
                dst_addr,
                protocol: IpProtocol::Unknown(99),
                ident: ident as u16 + 1,
                offset,
                more_frags,
                dont_frag: false,
                reserved: false,
                payload_len,
            })
        };
        let first = build(first_spec);
        let conflict = build(conflict_spec);
        let key = FragKey::Ipv4(Ipv4Packet::new_unchecked(&first[..]).get_key());

        for bytes in [&first, &conflict] {
            let packet = Ipv4Packet::new_checked(&bytes[..]).unwrap();
            assert!(
                iface
                    .inner
                    .process_ipv4(
                        &mut sockets,
                        PacketMeta::default(),
                        HardwareAddress::Ip,
                        &packet,
                        &mut iface.fragments,
                    )
                    .is_none()
            );
        }
        let assembler = iface.fragments.assembler.get(&key, Instant::ZERO).unwrap();
        assert_eq!(assembler.add(b"valid", 0), Err(AssemblerError::Poisoned));
    }
}

#[test]
#[cfg(all(
    feature = "medium-ip",
    feature = "proto-ipv4-fragmentation",
    feature = "socket-udp"
))]
fn ipv4_reassembly_verifies_vouched_udp_checksum() {
    use crate::socket::udp;

    const LOCAL_PORT: u16 = 49_504;
    const REMOTE_PORT: u16 = 4242;
    const PAYLOAD: [u8; 8] = [0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4];

    fn fragments(corrupt: bool) -> [Vec<u8>; 2] {
        let src_addr = Ipv4Address::new(192, 168, 1, 2);
        let dst_addr = Ipv4Address::new(192, 168, 1, 1);
        let repr = UdpRepr {
            src_port: REMOTE_PORT,
            dst_port: LOCAL_PORT,
        };
        let mut bytes = vec![0; repr.header_len() + PAYLOAD.len()];
        let mut packet = UdpPacket::new_unchecked(&mut bytes);
        repr.emit(
            &mut packet,
            &src_addr.into(),
            &dst_addr.into(),
            PAYLOAD.len(),
            |buffer| buffer.copy_from_slice(&PAYLOAD),
            &ChecksumCapabilities::default(),
        );
        if corrupt {
            let checksum = packet.checksum() ^ 1;
            assert_ne!(checksum, 0);
            packet.set_checksum(checksum);
        }
        ipv4_two_fragment_payload(IpProtocol::Udp, 1, &bytes, UDP_HEADER_LEN)
    }

    fn feed(corrupt: bool) -> (Option<Vec<u8>>, u64) {
        let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
        let mut socket = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 64]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 64]),
        );
        socket.bind(LOCAL_PORT).unwrap();
        let handle = sockets.add(0, socket);

        for fragment in fragments(corrupt) {
            device.push_rx_vouched(fragment, true);
        }
        iface.poll(Instant::ZERO, &mut device, &mut sockets);
        let received = sockets
            .get_mut::<udp::Socket>(handle)
            .recv()
            .ok()
            .map(|(payload, _)| payload.to_vec());
        (received, iface.take_rx_csum_failed())
    }

    assert_eq!(feed(false), (Some(PAYLOAD.to_vec()), 0));
    assert_eq!(feed(true), (None, 1));
}

#[test]
#[cfg(all(
    feature = "medium-ip",
    feature = "proto-ipv4-fragmentation",
    feature = "socket-tcp"
))]
fn ipv4_reassembly_verifies_vouched_tcp_checksum() {
    use crate::socket::tcp;

    const LOCAL_PORT: u16 = 49_505;
    const REMOTE_PORT: u16 = 80;
    const PAYLOAD: [u8; 8] = [0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4];

    fn fragments(corrupt: bool) -> [Vec<u8>; 2] {
        let src_addr = Ipv4Address::new(192, 168, 1, 2);
        let dst_addr = Ipv4Address::new(192, 168, 1, 1);
        let repr = TcpRepr {
            src_port: REMOTE_PORT,
            dst_port: LOCAL_PORT,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(20_000),
            ack_number: None,
            window_len: 64,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &PAYLOAD,
        };
        let mut bytes = vec![0; repr.buffer_len()];
        let mut packet = TcpPacket::new_unchecked(&mut bytes);
        repr.emit(
            &mut packet,
            &src_addr.into(),
            &dst_addr.into(),
            &ChecksumCapabilities::default(),
        );
        if corrupt {
            packet.set_checksum(packet.checksum() ^ 1);
        }
        ipv4_two_fragment_payload(IpProtocol::Tcp, 1, &bytes, 24)
    }

    fn feed(corrupt: bool) -> (tcp::State, u64, usize) {
        let (mut iface, mut sockets, mut device) = setup(Medium::Ip);
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 64]),
            tcp::SocketBuffer::new(vec![0; 64]),
        );
        socket.listen(LOCAL_PORT).unwrap();
        let handle = sockets.add(0, socket);

        for fragment in fragments(corrupt) {
            device.push_rx_vouched(fragment, true);
        }
        iface.poll(Instant::ZERO, &mut device, &mut sockets);
        (
            sockets.get::<tcp::Socket>(handle).state(),
            iface.take_rx_csum_failed(),
            device.tx_queue.len(),
        )
    }

    assert_eq!(feed(false), (tcp::State::SynReceived, 0, 1));
    assert_eq!(feed(true), (tcp::State::Listen, 1, 0));
}

#[test]
#[cfg(all(feature = "medium-ip", feature = "proto-ipv4-fragmentation"))]
fn ipv4_reassembly_keys_do_not_mix() {
    let dst_addr = Ipv4Address::new(192, 168, 1, 1);

    for changed_field in 0..4 {
        let (mut iface, mut sockets, _device) = setup(Medium::Ip);
        let spec = |offset, more_frags| Ipv4FragmentSpec {
            dst_addr,
            protocol: IpProtocol::Unknown(99),
            ident: 1,
            offset,
            more_frags,
            dont_frag: false,
            reserved: false,
            payload_len: 8,
        };
        let mut first = ipv4_fragment_bytes(spec(0, true));
        let mut foreign_last = ipv4_fragment_bytes(spec(8, false));
        let mut matching_last = foreign_last.clone();
        customize_ipv4_fragment(&mut first, 64, 0xaa);
        customize_ipv4_fragment(&mut foreign_last, 64, 0xcc);
        customize_ipv4_fragment(&mut matching_last, 64, 0xbb);

        {
            let mut packet = Ipv4Packet::new_unchecked(&mut foreign_last);
            match changed_field {
                0 => packet.set_src_addr(Ipv4Address::new(192, 168, 1, 3)),
                1 => packet.set_dst_addr(Ipv4Address::BROADCAST),
                2 => packet.set_next_header(IpProtocol::Unknown(98)),
                3 => packet.set_ident(2),
                _ => unreachable!(),
            }
            packet.fill_checksum();
        }

        for bytes in [&first, &foreign_last] {
            let packet = Ipv4Packet::new_checked(&bytes[..]).unwrap();
            assert!(
                iface
                    .inner
                    .process_ipv4(
                        &mut sockets,
                        PacketMeta::default(),
                        HardwareAddress::Ip,
                        &packet,
                        &mut iface.fragments,
                    )
                    .is_none()
            );
        }
        let matching_last = Ipv4Packet::new_checked(&matching_last[..]).unwrap();
        let reply = iface.inner.process_ipv4(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::Ip,
            &matching_last,
            &mut iface.fragments,
        );
        assert_ipv4_fragment_reply(
            reply,
            64,
            &[
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb,
            ],
        );
    }
}

#[test]
#[cfg(all(feature = "medium-ip", feature = "proto-ipv4-fragmentation"))]
fn ipv4_invalid_first_fragments_allocate_no_state() {
    let (mut iface, mut sockets, _device) = setup(Medium::Ip);
    let dst_addr = Ipv4Address::new(192, 168, 1, 1);
    let cases = [
        (IpProtocol::Unknown(99), 0, true, false, false, 0),
        (IpProtocol::Unknown(99), 0, true, false, false, 9),
        (IpProtocol::Unknown(99), 0, true, true, false, 8),
        (IpProtocol::Unknown(99), 0, false, false, true, 8),
        (IpProtocol::Tcp, 0, true, false, false, 16),
        (IpProtocol::Unknown(99), 65_528, false, false, false, 8),
    ];

    for (index, (protocol, offset, more, df, reserved, payload_len)) in
        cases.into_iter().enumerate()
    {
        let bytes = ipv4_fragment_bytes(Ipv4FragmentSpec {
            dst_addr,
            protocol,
            ident: index as u16 + 1,
            offset,
            more_frags: more,
            dont_frag: df,
            reserved,
            payload_len,
        });
        let packet = Ipv4Packet::new_checked(&bytes[..]).unwrap();
        let key = FragKey::Ipv4(packet.get_key());
        assert!(
            iface
                .inner
                .process_ipv4(
                    &mut sockets,
                    PacketMeta::default(),
                    HardwareAddress::Ip,
                    &packet,
                    &mut iface.fragments,
                )
                .is_none()
        );
        assert!(!iface.fragments.assembler.contains_key(&key));
    }
}

#[test]
#[cfg(all(feature = "medium-ip", feature = "proto-ipv4-fragmentation"))]
fn ipv4_fragments_check_destination_before_allocating_state() {
    let (mut iface, mut sockets, _device) = setup(Medium::Ip);
    let bytes = ipv4_fragment_bytes(Ipv4FragmentSpec {
        dst_addr: Ipv4Address::new(192, 0, 2, 1),
        protocol: IpProtocol::Unknown(99),
        ident: 1,
        offset: 0,
        more_frags: true,
        dont_frag: false,
        reserved: false,
        payload_len: 8,
    });
    let packet = Ipv4Packet::new_checked(&bytes[..]).unwrap();
    let key = FragKey::Ipv4(packet.get_key());

    assert!(
        iface
            .inner
            .process_ipv4(
                &mut sockets,
                PacketMeta::default(),
                HardwareAddress::Ip,
                &packet,
                &mut iface.fragments,
            )
            .is_none()
    );
    assert!(!iface.fragments.assembler.contains_key(&key));
}

#[test]
#[cfg(all(feature = "medium-ip", feature = "proto-ipv4-fragmentation"))]
fn ipv4_invalid_fragment_poisons_existing_state() {
    let (mut iface, mut sockets, _device) = setup(Medium::Ip);
    let dst_addr = Ipv4Address::new(192, 168, 1, 1);
    let first = ipv4_fragment_bytes(Ipv4FragmentSpec {
        dst_addr,
        protocol: IpProtocol::Unknown(99),
        ident: 1,
        offset: 0,
        more_frags: true,
        dont_frag: false,
        reserved: false,
        payload_len: 8,
    });
    let invalid = ipv4_fragment_bytes(Ipv4FragmentSpec {
        dst_addr,
        protocol: IpProtocol::Unknown(99),
        ident: 1,
        offset: 8,
        more_frags: true,
        dont_frag: false,
        reserved: false,
        payload_len: 9,
    });

    for bytes in [&first, &invalid] {
        let packet = Ipv4Packet::new_checked(&bytes[..]).unwrap();
        assert!(
            iface
                .inner
                .process_ipv4(
                    &mut sockets,
                    PacketMeta::default(),
                    HardwareAddress::Ip,
                    &packet,
                    &mut iface.fragments,
                )
                .is_none()
        );
    }

    let key = FragKey::Ipv4(Ipv4Packet::new_unchecked(&first[..]).get_key());
    let assembler = iface.fragments.assembler.get(&key, Instant::ZERO).unwrap();
    assert_eq!(assembler.add(b"valid", 8), Err(AssemblerError::Poisoned));
}

#[cfg(all(feature = "socket-raw", feature = "proto-ipv4-fragmentation"))]
#[rstest]
#[cfg_attr(feature = "medium-ip", case(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case(Medium::Ethernet))]
fn test_raw_socket_rx_fragmentation(#[case] medium: Medium) {
    use crate::wire::{IpProtocol, IpVersion, Ipv4Address, Ipv4Packet, Ipv4Repr};

    let (mut iface, mut sockets, _device) = setup(medium);

    // Raw socket bound to IPv4 and a custom protocol.
    let packets = 1;
    let rx_buffer = raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY; packets], vec![0; 64]);
    let tx_buffer = raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY; packets], vec![0; 64]);
    let raw_socket = raw::Socket::new(
        Some(IpVersion::Ipv4),
        Some(IpProtocol::Unknown(99)),
        rx_buffer,
        tx_buffer,
    );
    let handle = sockets.add(0, raw_socket);

    // Build two IPv4 fragments that together form one packet.
    let src_addr = Ipv4Address::new(127, 0, 0, 2);
    let dst_addr = Ipv4Address::new(127, 0, 0, 1);
    let proto = IpProtocol::Unknown(99);
    let ident: u16 = 0x1234;

    let total_payload_len = 30usize;
    let first_payload_len = 24usize; // must be a multiple of 8
    let last_payload_len = total_payload_len - first_payload_len;

    // Helper to build one fragment as on-the-wire bytes
    let build_fragment = |payload_len: usize,
                          more_frags: bool,
                          frag_offset_octets: u16,
                          payload_byte: u8|
     -> Vec<u8> {
        let repr = Ipv4Repr {
            src_addr,
            dst_addr,
            next_header: proto,
            hop_limit: 64,
            payload_len,
        };
        let header_len = repr.buffer_len();
        let mut bytes = vec![0u8; header_len + payload_len];
        {
            let mut pkt = Ipv4Packet::new_unchecked(&mut bytes[..]);
            repr.emit(&mut pkt, &ChecksumCapabilities::default());
            pkt.set_ident(ident);
            pkt.set_dont_frag(false);
            pkt.set_more_frags(more_frags);
            pkt.set_frag_offset(frag_offset_octets);
            // Recompute checksum after changing fragmentation fields.
            pkt.fill_checksum();
        }
        // Fill payload with a simple pattern for validation
        for b in &mut bytes[header_len..] {
            *b = payload_byte;
        }
        bytes
    };

    let frag1_bytes = build_fragment(first_payload_len, true, 0, 0xAA);
    let frag2_bytes = build_fragment(last_payload_len, false, first_payload_len as u16, 0xBB);

    let frag1 = Ipv4Packet::new_unchecked(&frag1_bytes[..]);
    let frag2 = Ipv4Packet::new_unchecked(&frag2_bytes[..]);

    // First fragment alone should not be delivered to the raw socket.
    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &frag1,
            &mut iface.fragments
        ),
        None
    );
    {
        let socket = sockets.get_mut::<raw::Socket>(handle);
        assert!(!socket.can_recv());
    }

    // After the last fragment, the reassembled packet should be delivered.
    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &frag2,
            &mut iface.fragments
        ),
        None
    );

    // Validate the raw socket received one defragmented packet with correct payload.
    let socket = sockets.get_mut::<raw::Socket>(handle);
    assert!(socket.can_recv());
    let data = socket.recv().expect("raw socket should have a packet");
    let packet = Ipv4Packet::new_unchecked(data);
    let repr = Ipv4Repr::parse(&packet, &ChecksumCapabilities::default()).unwrap();
    assert_eq!(repr.src_addr, src_addr);
    assert_eq!(repr.dst_addr, dst_addr);
    assert_eq!(repr.next_header, proto);
    assert_eq!(repr.payload_len, total_payload_len);

    let payload = packet.payload();
    assert_eq!(payload.len(), total_payload_len);
    assert!(payload[..first_payload_len].iter().all(|&b| b == 0xAA));
    assert!(payload[first_payload_len..].iter().all(|&b| b == 0xBB));
}

#[cfg(feature = "socket-udp")]
#[rstest]
#[cfg_attr(feature = "medium-ip", case(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case(Medium::Ethernet))]
fn test_icmp_reply_size(#[case] medium: Medium) {
    use crate::wire::IPV4_MIN_MTU as MIN_MTU;
    const MAX_PAYLOAD_LEN: usize = 528;

    let (mut iface, mut sockets, _device) = setup(medium);

    let src_addr = Ipv4Address::new(192, 168, 1, 1);
    let dst_addr = Ipv4Address::new(192, 168, 1, 2);

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

    let ip_repr = Ipv4Repr {
        src_addr,
        dst_addr,
        next_header: IpProtocol::Udp,
        hop_limit: 64,
        payload_len: udp_repr.header_len() + MAX_PAYLOAD_LEN,
    };
    let payload = packet.into_inner();

    let expected_icmp_repr = Icmpv4Repr::DstUnreachable {
        reason: Icmpv4DstUnreachable::PortUnreachable,
        next_hop_mtu: None,
        header: ip_repr,
        data: &payload[..MAX_PAYLOAD_LEN],
    };

    let expected_ip_repr = Ipv4Repr {
        src_addr: dst_addr,
        dst_addr: src_addr,
        next_header: IpProtocol::Icmp,
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
        Some(Packet::new_ipv4(
            expected_ip_repr,
            IpPayload::Icmpv4(expected_icmp_repr)
        ))
    );
}

#[rstest]
#[cfg_attr(feature = "medium-ip", case(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case(Medium::Ethernet))]
fn get_source_address(#[case] medium: Medium) {
    let (mut iface, _, _) = setup(medium);

    const OWN_UNIQUE_LOCAL_ADDR1: Ipv4Address = Ipv4Address::new(172, 18, 1, 2);
    const OWN_UNIQUE_LOCAL_ADDR2: Ipv4Address = Ipv4Address::new(172, 24, 24, 14);

    // List of addresses of the interface:
    //   172.18.1.2/24
    //   172.24.24.14/24
    iface.update_ip_addrs(|addrs| {
        addrs.clear();

        addrs.push(IpCidr::Ipv4(Ipv4Cidr::new(OWN_UNIQUE_LOCAL_ADDR1, 24)));
        addrs.push(IpCidr::Ipv4(Ipv4Cidr::new(OWN_UNIQUE_LOCAL_ADDR2, 24)));
    });

    // List of addresses we test:
    //   172.18.1.254 -> 172.18.1.2
    //   172.24.24.12 -> 172.24.24.14
    //   172.24.23.254 -> 172.18.1.2
    const UNIQUE_LOCAL_ADDR1: Ipv4Address = Ipv4Address::new(172, 18, 1, 254);
    const UNIQUE_LOCAL_ADDR2: Ipv4Address = Ipv4Address::new(172, 24, 24, 12);
    const UNIQUE_LOCAL_ADDR3: Ipv4Address = Ipv4Address::new(172, 24, 23, 254);

    assert_eq!(
        iface.inner.get_source_address_ipv4(&UNIQUE_LOCAL_ADDR1),
        Some(OWN_UNIQUE_LOCAL_ADDR1)
    );

    assert_eq!(
        iface.inner.get_source_address_ipv4(&UNIQUE_LOCAL_ADDR2),
        Some(OWN_UNIQUE_LOCAL_ADDR2)
    );
    assert_eq!(
        iface.inner.get_source_address_ipv4(&UNIQUE_LOCAL_ADDR3),
        Some(OWN_UNIQUE_LOCAL_ADDR1)
    );
}

#[rstest]
#[cfg_attr(feature = "medium-ip", case(Medium::Ip))]
#[cfg_attr(feature = "medium-ethernet", case(Medium::Ethernet))]
fn get_source_address_empty_interface(#[case] medium: Medium) {
    let (mut iface, _, _) = setup(medium);

    iface.update_ip_addrs(|ips| ips.clear());

    // List of addresses we test:
    //   172.18.1.254 -> None
    //   172.24.24.12 -> None
    //   172.24.23.254 -> None
    const UNIQUE_LOCAL_ADDR1: Ipv4Address = Ipv4Address::new(172, 18, 1, 254);
    const UNIQUE_LOCAL_ADDR2: Ipv4Address = Ipv4Address::new(172, 24, 24, 12);
    const UNIQUE_LOCAL_ADDR3: Ipv4Address = Ipv4Address::new(172, 24, 23, 254);

    assert_eq!(
        iface.inner.get_source_address_ipv4(&UNIQUE_LOCAL_ADDR1),
        None
    );
    assert_eq!(
        iface.inner.get_source_address_ipv4(&UNIQUE_LOCAL_ADDR2),
        None
    );
    assert_eq!(
        iface.inner.get_source_address_ipv4(&UNIQUE_LOCAL_ADDR3),
        None
    );
}

#[cfg(all(feature = "medium-ip", feature = "proto-ipv4-fragmentation"))]
use crate::wire::ipv4::HEADER_LEN;
#[rstest]
#[cfg(all(feature = "medium-ip", feature = "proto-ipv4-fragmentation",))]
fn test_ipv4_fragment_size() {
    let (_, _, device) = setup(Medium::Ip);
    let caps = device.capabilities();
    for i in 0..IPV4_FRAGMENT_PAYLOAD_ALIGNMENT {
        assert!(
            caps.max_ipv4_fragment_size(HEADER_LEN + i)
                .is_multiple_of(IPV4_FRAGMENT_PAYLOAD_ALIGNMENT)
        );
    }
}

/// `Meta::demux_key` tracks the socket's identity through every class of
/// transition in the catalog: the set-mediated operations, the transitions a
/// peer drives inside `process()`, and the ones timers drive inside
/// `dispatch()`. This record is the invariant the demux maps are maintained
/// from.
#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp"))]
fn the_demux_key_tracks_every_transition() {
    use crate::iface::SocketHandle;
    use crate::socket::DemuxKey;
    use crate::socket::tcp;
    use crate::socket::tcp::TcpCookieRestore;
    use crate::wire::IpListenEndpoint;

    const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);

    fn segment(
        local_port: u16,
        remote_port: u16,
        control: TcpControl,
        seq: TcpSeqNumber,
        ack: Option<TcpSeqNumber>,
    ) -> Vec<u8> {
        let tcp_repr = TcpRepr {
            src_port: remote_port,
            dst_port: local_port,
            control,
            seq_number: seq,
            ack_number: ack,
            window_len: 4096,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let ipv4_repr = Ipv4Repr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        };
        let mut bytes = vec![0; ipv4_repr.buffer_len() + tcp_repr.buffer_len()];
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        tcp_repr.emit(
            &mut TcpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
            &REMOTE_ADDR.into(),
            &LOCAL_ADDR.into(),
            &ChecksumCapabilities::default(),
        );
        bytes
    }

    fn assert_coherent(sockets: &SocketSet<'_>) {
        for item in sockets.items() {
            assert_eq!(
                item.meta.demux_key,
                item.socket.demux_key(),
                "socket {} carries a stale demux key",
                item.meta.handle
            );
            if let Some(DemuxKey::TcpTuple { local, remote }) = item.meta.demux_key {
                assert_eq!(
                    sockets.tcp_tuple(local, remote),
                    Some(item.meta.handle),
                    "socket {} is missing from the tuple index",
                    item.meta.handle
                );
            }
        }
    }

    fn key_of(sockets: &SocketSet<'_>, handle: SocketHandle) -> Option<DemuxKey> {
        sockets
            .items()
            .find(|item| item.meta.handle == handle)
            .unwrap()
            .meta
            .demux_key
    }

    fn socket() -> tcp::Socket<'static> {
        tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 4096]),
            tcp::SocketBuffer::new(vec![0; 4096]),
        )
    }

    let mut device = crate::tests::TestingDevice::new(Medium::Ip);
    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, Instant::ZERO);
    iface.update_ip_addrs(|addrs| {
        addrs.push(IpCidr::new(IpAddress::v4(192, 168, 1, 1), 24));
    });
    let mut sockets = SocketSet::new();

    // An unconfigured socket has no identity.
    const LISTEN_PORT: u16 = 49_600;
    let listen_key = DemuxKey::TcpListen(IpListenEndpoint {
        addr: None,
        port: LISTEN_PORT,
    });
    let listener = sockets.add(0, socket());
    assert_coherent(&sockets);
    assert_eq!(key_of(&sockets, listener), None);

    // listen() through the set: the listening identity, at the call.
    sockets.tcp_listen(listener, LISTEN_PORT).unwrap();
    assert_coherent(&sockets);
    assert_eq!(key_of(&sockets, listener), Some(listen_key));

    // A SYN inside process(): the listener acquires its tuple.
    device.push_rx(segment(
        LISTEN_PORT,
        1000,
        TcpControl::Syn,
        TcpSeqNumber(20_000),
        None,
    ));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_coherent(&sockets);
    assert_eq!(
        key_of(&sockets, listener),
        Some(DemuxKey::TcpTuple {
            local: IpEndpoint::new(LOCAL_ADDR.into(), LISTEN_PORT),
            remote: IpEndpoint::new(REMOTE_ADDR.into(), 1000),
        })
    );

    // An RST in SYN-RECEIVED inside process(): back to the listening
    // identity -- connected to listening with no removal in between.
    device.push_rx(segment(
        LISTEN_PORT,
        1000,
        TcpControl::Rst,
        TcpSeqNumber(20_001),
        None,
    ));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_coherent(&sockets);
    assert_eq!(key_of(&sockets, listener), Some(listen_key));

    // close() on a listening socket changes identity at the call, and a
    // closed socket may listen again: reuse under the same handle.
    sockets.tcp_close(listener);
    assert_coherent(&sockets);
    assert_eq!(key_of(&sockets, listener), None);
    sockets.tcp_listen(listener, LISTEN_PORT).unwrap();
    assert_eq!(key_of(&sockets, listener), Some(listen_key));
    sockets.tcp_abort(listener);
    assert_coherent(&sockets);
    assert_eq!(key_of(&sockets, listener), None);

    // connect() claims the tuple at the call, in SYN-SENT.
    let client = sockets.add(1, socket());
    sockets
        .tcp_connect(
            client,
            iface.context(),
            (IpAddress::from(REMOTE_ADDR), 80),
            49_700,
        )
        .unwrap();
    assert_coherent(&sockets);
    assert_eq!(
        key_of(&sockets, client),
        Some(DemuxKey::TcpTuple {
            local: IpEndpoint::new(LOCAL_ADDR.into(), 49_700),
            remote: IpEndpoint::new(REMOTE_ADDR.into(), 80),
        })
    );

    // abort(): accepts() refuses from the call on, while the tuple field
    // lingers until dispatch emits the RST -- no identity either side.
    sockets.tcp_abort(client);
    assert_coherent(&sockets);
    assert_eq!(key_of(&sockets, client), None);
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_coherent(&sockets);
    assert_eq!(key_of(&sockets, client), None);

    // Cookie restore: an established connection appears with no listener.
    let restored = sockets.add(2, socket());
    sockets
        .tcp_restore_from_cookie(
            restored,
            iface.context(),
            &TcpCookieRestore {
                local: IpEndpoint::new(LOCAL_ADDR.into(), 49_800),
                remote: IpEndpoint::new(REMOTE_ADDR.into(), 2000),
                rcv_nxt: TcpSeqNumber(30_001),
                snd_nxt: TcpSeqNumber(40_001),
                remote_mss: 1460,
                remote_window: 4096,
                peer_wscale: Some(0),
                peer_sack: false,
                peer_tsval: None,
            },
        )
        .unwrap();
    assert_coherent(&sockets);
    let restored_key = DemuxKey::TcpTuple {
        local: IpEndpoint::new(LOCAL_ADDR.into(), 49_800),
        remote: IpEndpoint::new(REMOTE_ADDR.into(), 2000),
    };
    assert_eq!(key_of(&sockets, restored), Some(restored_key));

    // Passive close: the peer's FIN, our close, and the final ACK of our FIN
    // inside process() -- LAST-ACK to CLOSED with no API call at the end.
    device.push_rx(segment(
        49_800,
        2000,
        TcpControl::Fin,
        TcpSeqNumber(30_001),
        Some(TcpSeqNumber(40_001)),
    ));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_coherent(&sockets);
    assert_eq!(key_of(&sockets, restored), Some(restored_key));
    sockets.tcp_close(restored);
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(key_of(&sockets, restored), Some(restored_key));
    device.push_rx(segment(
        49_800,
        2000,
        TcpControl::None,
        TcpSeqNumber(30_002),
        Some(TcpSeqNumber(40_002)),
    ));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_coherent(&sockets);
    assert_eq!(key_of(&sockets, restored), None);

    // Active close: the identity survives FIN-WAIT and TIME-WAIT -- a stray
    // segment must still find the socket -- and ends when the TIME-WAIT
    // timer expires inside dispatch().
    let waiter = sockets.add(3, socket());
    sockets
        .tcp_restore_from_cookie(
            waiter,
            iface.context(),
            &TcpCookieRestore {
                local: IpEndpoint::new(LOCAL_ADDR.into(), 49_801),
                remote: IpEndpoint::new(REMOTE_ADDR.into(), 2001),
                rcv_nxt: TcpSeqNumber(31_001),
                snd_nxt: TcpSeqNumber(41_001),
                remote_mss: 1460,
                remote_window: 4096,
                peer_wscale: Some(0),
                peer_sack: false,
                peer_tsval: None,
            },
        )
        .unwrap();
    let waiter_key = DemuxKey::TcpTuple {
        local: IpEndpoint::new(LOCAL_ADDR.into(), 49_801),
        remote: IpEndpoint::new(REMOTE_ADDR.into(), 2001),
    };
    sockets.tcp_close(waiter);
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_coherent(&sockets);
    assert_eq!(key_of(&sockets, waiter), Some(waiter_key));
    device.push_rx(segment(
        49_801,
        2001,
        TcpControl::None,
        TcpSeqNumber(31_001),
        Some(TcpSeqNumber(41_002)),
    ));
    device.push_rx(segment(
        49_801,
        2001,
        TcpControl::Fin,
        TcpSeqNumber(31_001),
        Some(TcpSeqNumber(41_002)),
    ));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_coherent(&sockets);
    assert_eq!(key_of(&sockets, waiter), Some(waiter_key));
    iface.poll(Instant::from_secs(30), &mut device, &mut sockets);
    assert_coherent(&sockets);
    assert_eq!(key_of(&sockets, waiter), None);
}

/// The tuple index is the demux for open connections: delivery among many
/// sockets, exact-tuple-beats-listener (RFC 5961), purge on removal, and a
/// reclaimed tuple all resolve through it.
#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp"))]
fn the_tuple_index_is_the_demux() {
    use crate::socket::tcp;
    use crate::socket::tcp::TcpCookieRestore;

    const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);

    fn segment(
        local_port: u16,
        remote_port: u16,
        control: TcpControl,
        seq: TcpSeqNumber,
        ack: Option<TcpSeqNumber>,
        payload: &'static [u8],
    ) -> Vec<u8> {
        let tcp_repr = TcpRepr {
            src_port: remote_port,
            dst_port: local_port,
            control,
            seq_number: seq,
            ack_number: ack,
            window_len: 4096,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload,
        };
        let ipv4_repr = Ipv4Repr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        };
        let mut bytes = vec![0; ipv4_repr.buffer_len() + tcp_repr.buffer_len()];
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        tcp_repr.emit(
            &mut TcpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
            &REMOTE_ADDR.into(),
            &LOCAL_ADDR.into(),
            &ChecksumCapabilities::default(),
        );
        bytes
    }

    fn reply(device: &mut crate::tests::TestingDevice) -> TcpRepr<'static> {
        let bytes = device.tx_queue.pop_back().unwrap();
        let ip = Ipv4Packet::new_checked(&bytes).unwrap();
        let parsed = TcpRepr::parse(
            &TcpPacket::new_checked(ip.payload()).unwrap(),
            &LOCAL_ADDR.into(),
            &REMOTE_ADDR.into(),
            &ChecksumCapabilities::ignored(),
        )
        .unwrap();
        TcpRepr {
            payload: &[],
            ..parsed
        }
    }

    fn socket() -> tcp::Socket<'static> {
        tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 4096]),
            tcp::SocketBuffer::new(vec![0; 4096]),
        )
    }

    fn restore(local_port: u16, remote_port: u16) -> TcpCookieRestore {
        TcpCookieRestore {
            local: IpEndpoint::new(LOCAL_ADDR.into(), local_port),
            remote: IpEndpoint::new(REMOTE_ADDR.into(), remote_port),
            rcv_nxt: TcpSeqNumber(30_001),
            snd_nxt: TcpSeqNumber(40_001),
            remote_mss: 1460,
            remote_window: 4096,
            peer_wscale: Some(0),
            peer_sack: false,
            peer_tsval: None,
        }
    }

    let mut device = crate::tests::TestingDevice::new(Medium::Ip);
    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, Instant::ZERO);
    iface.update_ip_addrs(|addrs| {
        addrs.push(IpCidr::new(IpAddress::v4(192, 168, 1, 1), 24));
    });
    let mut sockets = SocketSet::new();

    // Ten listeners and ten open connections; a data segment lands on
    // exactly the connection whose tuple it names.
    for i in 0..10u64 {
        let listener = sockets.add(i, socket());
        sockets.tcp_listen(listener, 48_000 + i as u16).unwrap();
    }
    let mut connections = Vec::new();
    for i in 0..10u64 {
        let conn = sockets.add(10 + i, socket());
        sockets
            .tcp_restore_from_cookie(conn, iface.context(), &restore(49_000, 3000 + i as u16))
            .unwrap();
        connections.push(conn);
    }
    device.push_rx(segment(
        49_000,
        3_007,
        TcpControl::None,
        TcpSeqNumber(30_001),
        Some(TcpSeqNumber(40_001)),
        b"hello",
    ));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    for (i, conn) in connections.iter().enumerate() {
        let expected = if i == 7 { 5 } else { 0 };
        assert_eq!(
            sockets.get::<tcp::Socket>(*conn).recv_queue(),
            expected,
            "connection {i}"
        );
    }

    // A SYN naming a live connection's exact tuple reaches that connection
    // -- the RFC 5961 challenge ACK -- not the listener on the same port.
    let listener = sockets.add(20, socket());
    sockets.tcp_listen(listener, 49_000).unwrap();
    device.tx_queue.clear();
    device.push_rx(segment(
        49_000,
        3_000,
        TcpControl::Syn,
        TcpSeqNumber(50_000),
        None,
        &[],
    ));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    let challenge = reply(&mut device);
    assert_eq!(
        challenge.control,
        TcpControl::None,
        "a challenge ACK, not a SYN|ACK"
    );
    assert!(
        sockets.get::<tcp::Socket>(listener).is_listening(),
        "the listener must not have taken a SYN owned by a live connection"
    );

    // Removal purges: the departed connection's tuple draws the reflector's
    // reset, never a stale index hit.
    let departed = connections[3];
    sockets.remove(departed);
    assert!(
        sockets
            .tcp_tuple(
                IpEndpoint::new(LOCAL_ADDR.into(), 49_000),
                IpEndpoint::new(REMOTE_ADDR.into(), 3_003),
            )
            .is_none()
    );
    device.tx_queue.clear();
    device.push_rx(segment(
        49_000,
        3_003,
        TcpControl::None,
        TcpSeqNumber(30_001),
        Some(TcpSeqNumber(40_001)),
        &[],
    ));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(reply(&mut device).control, TcpControl::Rst);

    // A tuple its holder lost (peer reset) is reclaimable: the next holder
    // owns the index entry, while the dead socket sits in the set refused.
    let victim = connections[5];
    device.push_rx(segment(
        49_000,
        3_005,
        TcpControl::Rst,
        TcpSeqNumber(30_001),
        Some(TcpSeqNumber(40_001)),
        &[],
    ));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    let heir = sockets.add(21, socket());
    sockets
        .tcp_restore_from_cookie(heir, iface.context(), &restore(49_000, 3_005))
        .unwrap();
    let duplicate = sockets.add(22, socket());
    assert_eq!(
        sockets.tcp_restore_from_cookie(duplicate, iface.context(), &restore(49_000, 3_005)),
        Err(tcp::ListenError::InvalidState)
    );
    assert_eq!(
        sockets.tcp_tuple(
            IpEndpoint::new(LOCAL_ADDR.into(), 49_000),
            IpEndpoint::new(REMOTE_ADDR.into(), 3_005)
        ),
        Some(heir)
    );
    sockets.remove(duplicate);
    device.push_rx(segment(
        49_000,
        3_005,
        TcpControl::None,
        TcpSeqNumber(30_001),
        Some(TcpSeqNumber(40_001)),
        b"again",
    ));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(sockets.get::<tcp::Socket>(heir).recv_queue(), 5);
    assert_eq!(sockets.get::<tcp::Socket>(victim).recv_queue(), 0);
}

/// The listener map serves what no connection claims: a specific-address
/// pool outranks the wildcard pool on the same port, pool selection is
/// deterministic and replenishable, and a listening port still swallows the
/// bare probes a Listen socket always swallowed -- no reflector reset to
/// leak its existence.
#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp"))]
fn the_listener_map_serves_the_handshakes() {
    use crate::socket::tcp;

    const ADDR_ONE: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const ADDR_TWO: Ipv4Address = Ipv4Address::new(192, 168, 1, 5);
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);

    fn segment(
        dst_addr: Ipv4Address,
        local_port: u16,
        remote_port: u16,
        control: TcpControl,
    ) -> Vec<u8> {
        let tcp_repr = TcpRepr {
            src_port: remote_port,
            dst_port: local_port,
            control,
            seq_number: TcpSeqNumber(20_000),
            ack_number: None,
            window_len: 4096,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let ipv4_repr = Ipv4Repr {
            src_addr: REMOTE_ADDR,
            dst_addr,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        };
        let mut bytes = vec![0; ipv4_repr.buffer_len() + tcp_repr.buffer_len()];
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        tcp_repr.emit(
            &mut TcpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
            &REMOTE_ADDR.into(),
            &dst_addr.into(),
            &ChecksumCapabilities::default(),
        );
        bytes
    }

    fn socket() -> tcp::Socket<'static> {
        tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 4096]),
            tcp::SocketBuffer::new(vec![0; 4096]),
        )
    }

    fn state(sockets: &SocketSet<'_>, handle: SocketHandle) -> tcp::State {
        sockets.get::<tcp::Socket>(handle).state()
    }

    use crate::iface::SocketHandle;
    use crate::socket::tcp::State;

    let mut device = crate::tests::TestingDevice::new(Medium::Ip);
    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, Instant::ZERO);
    iface.update_ip_addrs(|addrs| {
        addrs.push(IpCidr::new(ADDR_ONE.into(), 24));
        addrs.push(IpCidr::new(ADDR_TWO.into(), 24));
    });
    let mut sockets = SocketSet::new();

    // The specific-address listener outranks the wildcard one on the same
    // port, even though the wildcard pool holds the lower handle.
    const SHARED_PORT: u16 = 47_000;
    let wildcard = sockets.add(0, socket());
    sockets.tcp_listen(wildcard, SHARED_PORT).unwrap();
    let specific = sockets.add(1, socket());
    sockets
        .tcp_listen(
            specific,
            IpListenEndpoint {
                addr: Some(ADDR_ONE.into()),
                port: SHARED_PORT,
            },
        )
        .unwrap();
    device.push_rx(segment(ADDR_ONE, SHARED_PORT, 1000, TcpControl::Syn));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(state(&sockets, specific), State::SynReceived);
    assert_eq!(state(&sockets, wildcard), State::Listen);

    // The wildcard pool serves the address the specific pool does not name.
    device.push_rx(segment(ADDR_TWO, SHARED_PORT, 1001, TcpControl::Syn));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(state(&sockets, wildcard), State::SynReceived);

    // Within a pool the lowest live handle serves; a consumed member leaves
    // the pool, and a replenished member rejoins it.
    const POOL_PORT: u16 = 47_100;
    let first = sockets.add(2, socket());
    sockets.tcp_listen(first, POOL_PORT).unwrap();
    let second = sockets.add(3, socket());
    sockets.tcp_listen(second, POOL_PORT).unwrap();
    device.push_rx(segment(ADDR_ONE, POOL_PORT, 1002, TcpControl::Syn));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(state(&sockets, first), State::SynReceived);
    assert_eq!(state(&sockets, second), State::Listen);
    device.push_rx(segment(ADDR_ONE, POOL_PORT, 1003, TcpControl::Syn));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(state(&sockets, second), State::SynReceived);
    let replenished = sockets.add(4, socket());
    sockets.tcp_listen(replenished, POOL_PORT).unwrap();
    device.push_rx(segment(ADDR_ONE, POOL_PORT, 1004, TcpControl::Syn));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(state(&sockets, replenished), State::SynReceived);

    // A bare FIN probe: swallowed by a listening port exactly as the Listen
    // socket always swallowed it, reset by a port with no listener. The
    // difference is what a port scanner reads. (Every earlier listener has
    // been consumed into a handshake, so the probe needs a live one.)
    let prober_target = sockets.add(5, socket());
    sockets.tcp_listen(prober_target, SHARED_PORT).unwrap();
    device.tx_queue.clear();
    device.push_rx(segment(ADDR_TWO, SHARED_PORT, 1005, TcpControl::Fin));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(
        device.tx_queue.len(),
        0,
        "a listening port must swallow a bare FIN, not answer it"
    );
    device.push_rx(segment(ADDR_ONE, 47_200, 1006, TcpControl::Fin));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(
        device.tx_queue.len(),
        1,
        "a port with no listener answers the probe with the reflector's reset"
    );
}

/// The UDP port map is the datagram demux: delivery by port among many
/// sockets, an exact-address binding outranking the wildcard, a broadcast
/// landing on the port whatever the binding, rebinding through the set, and
/// a departed port drawing ICMP port-unreachable.
#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-udp"))]
fn the_udp_port_map_is_the_demux() {
    use crate::socket::udp;

    const ADDR_ONE: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const ADDR_TWO: Ipv4Address = Ipv4Address::new(192, 168, 1, 5);
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const BROADCAST: Ipv4Address = Ipv4Address::new(192, 168, 1, 255);

    fn datagram(dst_addr: Ipv4Address, dst_port: u16, payload: &'static [u8]) -> Vec<u8> {
        let udp_repr = UdpRepr {
            src_port: 4000,
            dst_port,
        };
        let ipv4_repr = Ipv4Repr {
            src_addr: REMOTE_ADDR,
            dst_addr,
            next_header: IpProtocol::Udp,
            payload_len: udp_repr.header_len() + payload.len(),
            hop_limit: 64,
        };
        let mut bytes = vec![0; ipv4_repr.buffer_len() + udp_repr.header_len() + payload.len()];
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        udp_repr.emit(
            &mut UdpPacket::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
            &REMOTE_ADDR.into(),
            &dst_addr.into(),
            payload.len(),
            |buf| buf.copy_from_slice(payload),
            &ChecksumCapabilities::default(),
        );
        bytes
    }

    fn socket() -> udp::Socket<'static> {
        udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 256]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 256]),
        )
    }

    let mut device = crate::tests::TestingDevice::new(Medium::Ip);
    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, Instant::ZERO);
    iface.update_ip_addrs(|addrs| {
        addrs.push(IpCidr::new(ADDR_ONE.into(), 24));
        addrs.push(IpCidr::new(ADDR_TWO.into(), 24));
    });
    let mut sockets = SocketSet::new();

    // Ten ports; the datagram lands on exactly the one it names.
    let mut bound = Vec::new();
    for i in 0..10u64 {
        let handle = sockets.add(i, socket());
        sockets.udp_bind(handle, 46_000 + i as u16).unwrap();
        bound.push(handle);
    }
    device.push_rx(datagram(ADDR_ONE, 46_004, b"here"));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    for (i, handle) in bound.iter().enumerate() {
        let expected = if i == 4 { 4 } else { 0 };
        assert_eq!(
            sockets.get::<udp::Socket>(*handle).recv_queue(),
            expected,
            "port {i}"
        );
    }

    // An exact-address binding outranks the wildcard on the same port for a
    // unicast datagram; the wildcard serves the address nothing names; a
    // broadcast lands on the port's lowest handle whatever it is bound to.
    const SHARED_PORT: u16 = 46_100;
    let wildcard = sockets.add(10, socket());
    sockets.udp_bind(wildcard, SHARED_PORT).unwrap();
    let specific = sockets.add(11, socket());
    sockets
        .udp_bind(
            specific,
            IpListenEndpoint {
                addr: Some(ADDR_ONE.into()),
                port: SHARED_PORT,
            },
        )
        .unwrap();
    device.push_rx(datagram(ADDR_ONE, SHARED_PORT, b"exact"));
    device.push_rx(datagram(ADDR_TWO, SHARED_PORT, b"othr"));
    device.push_rx(datagram(BROADCAST, SHARED_PORT, b"all"));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    // specific: the exact-address unicast. wildcard: the other address plus
    // the broadcast (lowest handle on the port).
    assert_eq!(sockets.get::<udp::Socket>(specific).recv_queue(), 5);
    assert_eq!(sockets.get::<udp::Socket>(wildcard).recv_queue(), 7);

    // Rebinding goes through the set and moves the identity with it.
    let mover = bound[0];
    sockets.udp_close(mover);
    sockets.udp_bind(mover, 46_200).unwrap();
    device.push_rx(datagram(ADDR_ONE, 46_200, b"moved"));
    device.tx_queue.clear();
    device.push_rx(datagram(ADDR_ONE, 46_000, b"stale"));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(sockets.get::<udp::Socket>(mover).recv_queue(), 5);
    assert_eq!(
        device.tx_queue.len(),
        1,
        "the abandoned port answers with ICMP port-unreachable"
    );

    // A removed socket's port draws port-unreachable too: the entry retired
    // with it.
    sockets.remove(bound[6]);
    device.tx_queue.clear();
    device.push_rx(datagram(ADDR_ONE, 46_006, b"gone"));
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(device.tx_queue.len(), 1);
}

/// Egress service rotates. A pass starts where the device last refused a
/// socket -- that socket goes first -- and a completed pass moves its lead,
/// so a TX ring smaller than the ready set spreads across every socket
/// instead of draining the lowest ids first.
#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-udp"))]
fn egress_rotates_across_device_exhaustion() {
    use crate::socket::udp;

    const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const BASE_PORT: u16 = 47_300;
    const SOCKETS: usize = 3;
    const DATAGRAMS: usize = 4;

    fn socket() -> udp::Socket<'static> {
        udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 512]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 512]),
        )
    }

    let mut device = crate::tests::TestingDevice::new(Medium::Ip);
    // Two slots for three ready sockets: every pass leaves someone refused.
    device.tx_capacity = Some(2);
    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, Instant::ZERO);
    iface.update_ip_addrs(|addrs| {
        addrs.push(IpCidr::new(LOCAL_ADDR.into(), 24));
    });
    let mut sockets = SocketSet::new();

    let remote = IpEndpoint::new(REMOTE_ADDR.into(), 4000);
    for i in 0..SOCKETS {
        let handle = sockets.add(i as u64 + 1, socket());
        sockets.udp_bind(handle, BASE_PORT + i as u16).unwrap();
        let socket = sockets.get_mut::<udp::Socket>(handle);
        for _ in 0..DATAGRAMS {
            socket.send_slice(b"x", remote).unwrap();
        }
    }

    // Drain two frames per poll, recording which socket each came from.
    let mut order = Vec::new();
    for _ in 0..SOCKETS * DATAGRAMS {
        iface.poll(Instant::ZERO, &mut device, &mut sockets);
        while let Some(frame) = device.tx_queue.pop_front() {
            let ip = Ipv4Packet::new_checked(&frame).unwrap();
            let udp = UdpPacket::new_checked(ip.payload()).unwrap();
            order.push(udp.src_port());
        }
        if order.len() == SOCKETS * DATAGRAMS {
            break;
        }
    }

    // Everything got out, evenly.
    assert_eq!(order.len(), SOCKETS * DATAGRAMS, "sent: {order:?}");
    for i in 0..SOCKETS {
        let port = BASE_PORT + i as u16;
        assert_eq!(
            order.iter().filter(|p| **p == port).count(),
            DATAGRAMS,
            "socket {port}: {order:?}"
        );
    }
    // And the rotation is real: all three sockets appear within the first
    // four frames. The old restart-at-the-lowest-id pass sent both of the
    // first socket's slots twice before the third socket ever transmitted.
    let first_four = &order[..4];
    for i in 0..SOCKETS {
        let port = BASE_PORT + i as u16;
        assert!(
            first_four.contains(&port),
            "socket {port} shut out of the first window: {order:?}"
        );
    }
}

/// The poll index follows every mutation door: a set-mediated op and a
/// `get_mut` data op each mark the socket stale, the poll edge recomputes
/// its obligation, and quiescence parks the index on Ingress. The debug
/// oracle in `poll()` holds the invariant across the whole suite; this
/// pins the doors themselves.
#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-udp"))]
fn the_poll_index_follows_the_mutation_doors() {
    use crate::socket::{PollAt, udp};

    const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);

    let mut device = crate::tests::TestingDevice::new(Medium::Ip);
    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, Instant::ZERO);
    iface.update_ip_addrs(|addrs| {
        addrs.push(IpCidr::new(LOCAL_ADDR.into(), 24));
    });
    let mut sockets = SocketSet::new();

    let handle = sockets.add(
        1,
        udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 256]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 256]),
        ),
    );
    sockets.udp_bind(handle, 47_400).unwrap();
    // The op door: bind went through the set and left a stale mark.
    assert!(!sockets.poll_stale_is_empty());

    // The poll edge refreshes it; nothing to send parks it on Ingress.
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert!(sockets.poll_stale_is_empty());
    assert_eq!(sockets.poll_index_min(), PollAt::Ingress);

    // The data door: a datagram queued through `get_mut`.
    sockets
        .get_mut::<udp::Socket>(handle)
        .send_slice(b"x", IpEndpoint::new(REMOTE_ADDR.into(), 4000))
        .unwrap();
    assert!(!sockets.poll_stale_is_empty());

    // The poll edge sends it and the index returns to Ingress.
    iface.poll(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(device.tx_queue.len(), 1);
    assert_eq!(sockets.poll_index_min(), PollAt::Ingress);
}
