use super::*;
use moto_netstack::wire::IpAddress;

fn pair(ipv6: bool) -> (Stack, Stack, IpAddress) {
    let (client, server) = if ipv6 {
        ("fd20::2/128", "fd20::1/128")
    } else {
        ("10.20.0.2/32", "10.20.0.1/32")
    };
    let server: IpCidr = server.parse().unwrap();
    (
        Stack::new(&[client.parse().unwrap()], Instant::ZERO).unwrap(),
        Stack::new(&[server], Instant::ZERO).unwrap(),
        server.address(),
    )
}

fn pump(client: &mut Stack, server: &mut Stack, tick: &mut i64) {
    TestTransport::new(false).pump(client, server, tick);
}

struct TestTransport(Option<[crate::peer::Peer; 2]>);

impl TestTransport {
    fn new(encrypted: bool) -> Self {
        use boringtun::x25519::{PublicKey, StaticSecret};
        let public = |key| *PublicKey::from(&StaticSecret::from(key)).as_bytes();
        Self(encrypted.then(|| {
            std::array::from_fn(|index| {
                crate::peer::Peer::new(
                    [index as u8 + 1; 32],
                    public([2 - index as u8; 32]),
                    None,
                    Some(Self::address(1 - index)),
                )
            })
        }))
    }

    fn address(index: usize) -> std::net::SocketAddr {
        ([127, 0, 0, 1], 5000 + index as u16).into()
    }

    fn transfer(&mut self, stacks: &mut [&mut Stack; 2], from: usize) {
        use crate::peer::{Action, BUFFER_SIZE};
        let Some(peers) = &mut self.0 else {
            while let Some(packet) = stacks[from].take_packet() {
                assert!(stacks[1 - from].receive(&packet));
            }
            return;
        };
        let mut buffer = [0; BUFFER_SIZE];
        let mut wire = std::collections::VecDeque::new();
        while let Some(packet) = stacks[from].take_packet() {
            if let Action::Network(_, bytes) = peers[from].send(&packet, &mut buffer) {
                wire.push_back((1 - from, bytes.to_vec()));
            }
        }
        let mut operations = 0;
        while let Some((to, packet)) = wire.pop_front() {
            operations += 1;
            assert!(operations < 1024, "encrypted fixture did not quiesce");
            match peers[to].receive(Self::address(1 - to), &packet, &mut buffer) {
                Action::Network(_, bytes) => wire.push_back((1 - to, bytes.to_vec())),
                Action::Inner(bytes) => assert!(stacks[to].receive(bytes)),
                Action::None => {}
            }
            while let Action::Network(_, bytes) = peers[to].flush(&mut buffer) {
                wire.push_back((1 - to, bytes.to_vec()));
                assert!(wire.len() <= 256);
            }
        }
        assert!(peers.iter().all(|peer| peer.rejected == 0));
    }

    fn pump(&mut self, client: &mut Stack, server: &mut Stack, tick: &mut i64) {
        // Deterministic virtual time; no kernel sockets or external network.
        let mut stacks = [client, server];
        for _ in 0..1000 {
            let now = Instant::from_millis(*tick);
            *tick += 1;
            for from in 0..2 {
                stacks[from].poll(now);
                self.transfer(&mut stacks, from);
            }
        }
    }
}

fn connect(client: &mut Stack, remote: IpAddress, port: u16, tick: i64) -> SocketHandle {
    let socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
        tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
    );
    let handle = client.sockets.add(1000, socket);
    client.interface.poll(
        Instant::from_millis(tick),
        &mut client.link,
        &mut client.sockets,
    );
    client
        .sockets
        .tcp_connect(handle, client.interface.context(), (remote, port), 45000)
        .unwrap();
    handle
}

fn send(stack: &mut Stack, handle: SocketHandle, bytes: &[u8]) {
    let socket = stack.sockets.get_mut::<tcp::Socket>(handle);
    assert_eq!(socket.send_slice(bytes).unwrap(), bytes.len());
}

fn received(stack: &mut Stack, handle: SocketHandle, size: usize) -> Vec<u8> {
    let mut data = vec![0; size];
    let socket = stack.sockets.get_mut::<tcp::Socket>(handle);
    assert_eq!(socket.recv_slice(&mut data).unwrap(), size);
    data
}

#[test]
fn tcp_and_udp_echo_in_both_families() {
    for ipv6 in [false, true] {
        let (mut client, mut server, remote) = pair(ipv6);
        let mut tick = 0;
        let tcp = connect(&mut client, remote, TCP_ECHO_PORT, tick);
        pump(&mut client, &mut server, &mut tick);
        let payload: Vec<u8> = (0..65_537).map(|index| index as u8).collect();
        send(&mut client, tcp, &payload);
        pump(&mut client, &mut server, &mut tick);
        assert_eq!(received(&mut client, tcp, payload.len()), payload);
        let buffer = || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]);
        let udp = client
            .sockets
            .add(1001, udp::Socket::new(buffer(), buffer()));
        client.sockets.udp_bind(udp, 45001).unwrap();
        client
            .sockets
            .get_mut::<udp::Socket>(udp)
            .send_slice(&payload[..1372], (remote, UDP_ECHO_PORT))
            .unwrap();
        pump(&mut client, &mut server, &mut tick);
        let (bytes, peer) = client.sockets.get_mut::<udp::Socket>(udp).recv().unwrap();
        assert_eq!(bytes, &payload[..1372]);
        assert_eq!(peer.endpoint, (remote, UDP_ECHO_PORT).into());
        client.sockets.tcp_close(tcp);
        pump(&mut client, &mut server, &mut tick);
        assert!(!client.sockets.get::<tcp::Socket>(tcp).is_active());
    }
}

#[test]
fn rnetbench_handshake_and_flow_over_inner_tcp() {
    for ipv6 in [false, true] {
        for encrypted in [false, true] {
            let (mut client, mut server, remote) = pair(ipv6);
            let mut tick = 0;
            let mut transport = TestTransport::new(encrypted);
            let tcp = connect(&mut client, remote, BENCH_PORT, tick);
            transport.pump(&mut client, &mut server, &mut tick);
            send(&mut client, tcp, b"rnetbench_magic_client");
            transport.pump(&mut client, &mut server, &mut tick);
            let greeting = b"rnetbench_magic_server";
            assert_eq!(received(&mut client, tcp, greeting.len()), greeting);
            let header: Vec<u8> = [4_u64, 4096, 65_537]
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect();
            send(&mut client, tcp, &header);
            transport.pump(&mut client, &mut server, &mut tick);
            let data = received(&mut client, tcp, 65_537);
            for (offset, byte) in data.into_iter().enumerate() {
                assert_eq!(byte, offset as u8);
            }
            assert_eq!(client.sockets.get::<tcp::Socket>(tcp).recv_queue(), 0);
            assert_eq!(
                client.sockets.get::<tcp::Socket>(tcp).state(),
                tcp::State::Established
            );
            client.sockets.tcp_close(tcp);
            transport.pump(&mut client, &mut server, &mut tick);
            assert!(!client.sockets.get::<tcp::Socket>(tcp).is_active());
        }
    }
}

#[test]
fn peer_initiated_ping_reply_and_timeout() {
    for ipv6 in [false, true] {
        let (mut client, mut server, remote) = pair(ipv6);
        let mut tick = 0;
        client.start_ping(remote, 1, Instant::ZERO).unwrap();
        assert!(client.start_ping(remote, 2, Instant::ZERO).is_err());
        pump(&mut client, &mut server, &mut tick);
        assert_eq!(client.poll_ping(Instant::from_millis(tick)), Some(true));
        assert_eq!(client.poll_ping(Instant::from_millis(tick)), None);
        client
            .start_ping(remote, 2, Instant::from_millis(tick))
            .unwrap();
        client.poll(Instant::from_millis(tick));
        assert_eq!(client.poll_ping(Instant::from_millis(tick + 2999)), None);
        assert_eq!(
            client.poll_ping(Instant::from_millis(tick + 3000)),
            Some(false)
        );
        assert_eq!(client.poll_ping(Instant::from_millis(tick + 3000)), None);
    }
}
