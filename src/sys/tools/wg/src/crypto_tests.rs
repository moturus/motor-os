use crate::config::{Config, Peer};
use crate::crypto::{Action, BUFFER_SIZE, Crypto, MTU};
use boringtun::noise::{Tunn, TunnResult, rate_limiter::RateLimiter};
use boringtun::x25519::{PublicKey, StaticSecret};
use mock_instant::MockClock;
use std::net::SocketAddr;
use std::time::Duration;

fn public(seed: u8) -> [u8; 32] {
    *PublicKey::from(&StaticSecret::from([seed; 32])).as_bytes()
}

pub(crate) fn config(endpoint: Option<SocketAddr>, keepalive: Option<u16>) -> Config {
    Config {
        name: "wg0".into(),
        private_key: [7; 32],
        listen_port: 51820,
        transport_addresses: vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
        cidrs: vec![
            "10.20.0.1/32".parse().unwrap(),
            "fd00::1/128".parse().unwrap(),
        ],
        peers: vec![
            Peer {
                public_key: public(8),
                preshared_key: None,
                endpoint,
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
                persistent_keepalive: keepalive,
            },
            Peer {
                public_key: public(9),
                preshared_key: None,
                endpoint: None,
                allowed_ips: vec![
                    "10.20.0.99/32".parse().unwrap(),
                    "fd00::63/128".parse().unwrap(),
                ],
                persistent_keepalive: None,
            },
        ],
    }
}

pub(crate) fn remote(seed: u8) -> Tunn {
    Tunn::new(
        StaticSecret::from([seed; 32]),
        PublicKey::from(public(7)),
        None,
        None,
        0x123,
        None,
    )
}

pub(crate) fn wire(result: TunnResult<'_>) -> Vec<u8> {
    match result {
        TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
        _ => panic!("expected WireGuard datagram"),
    }
}

fn network(action: Action<'_>, expected: SocketAddr) -> Vec<u8> {
    match action {
        Action::Network {
            destination,
            packet,
        } => {
            assert_eq!(destination, expected);
            packet.to_vec()
        }
        _ => panic!("expected network output"),
    }
}

pub(crate) fn inner(v6: bool, source: u8, destination: u8, size: usize) -> Vec<u8> {
    let mut packet = vec![0; size];
    if v6 {
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((size - 40) as u16).to_be_bytes());
        packet[8] = 0xfd;
        packet[23] = source;
        packet[24] = 0xfd;
        packet[39] = destination;
    } else {
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(size as u16).to_be_bytes());
        packet[12..16].copy_from_slice(&[10, 20, 0, source]);
        packet[16..20].copy_from_slice(&[10, 20, 0, destination]);
    }
    packet
}

#[test]
fn authenticated_handshake_keepalive_roaming_and_source_ownership() {
    for outer in ["192.0.2.2:51820", "[2001:db8::2]:51820"] {
        MockClock::set_time(Duration::ZERO);
        let source: SocketAddr = outer.parse().unwrap();
        let mut crypto = Crypto::new(&config(None, None)).unwrap();
        let mut remote = remote(8);
        let mut output = [0; BUFFER_SIZE];
        let init = wire(remote.format_handshake_initiation(&mut output, false));
        let response = network(crypto.receive(source, &init, &mut output), source);
        assert_eq!(crypto.endpoint(0), Some(source));
        let keepalive = wire(remote.decapsulate(None, &response, &mut output));
        let mut moved = source;
        moved.set_port(51821);
        assert!(matches!(
            crypto.receive(moved, &keepalive, &mut output),
            Action::None
        ));
        assert_eq!(crypto.endpoint(0), Some(moved));

        for v6 in [false, true] {
            let payload = inner(v6, 2, 1, MTU);
            let encrypted = wire(remote.encapsulate(&payload, &mut output));
            match crypto.receive(moved, &encrypted, &mut output) {
                Action::Tunnel(bytes) => assert_eq!(bytes, payload),
                _ => panic!("authenticated payload was not delivered"),
            }
            assert!(matches!(
                crypto.receive(source, &encrypted, &mut output),
                Action::None
            ));
            assert_eq!(crypto.endpoint(0), Some(moved));
            let forbidden = wire(remote.encapsulate(&inner(v6, 99, 1, 60), &mut output));
            assert!(matches!(
                crypto.receive(moved, &forbidden, &mut output),
                Action::None
            ));
            assert!(matches!(
                crypto.encapsulate(&inner(v6, 1, 99, 60), &mut output),
                Action::None
            ));
            let outgoing = inner(v6, 1, 2, MTU);
            let encrypted = network(crypto.encapsulate(&outgoing, &mut output), moved);
            assert!(encrypted.len() <= MTU.next_multiple_of(16) + 32);
            match remote.decapsulate(None, &encrypted, &mut output) {
                TunnResult::WriteToTunnelV4(bytes, _) | TunnResult::WriteToTunnelV6(bytes, _) => {
                    assert_eq!(bytes, outgoing)
                }
                _ => panic!("peer could not decrypt outbound packet"),
            }
            let incoming = inner(v6, 2, 1, MTU);
            let mut padded = incoming.clone();
            padded.resize(MTU.next_multiple_of(16), 0);
            let encrypted = wire(remote.encapsulate(&padded, &mut output));
            assert_eq!(encrypted.len(), MTU.next_multiple_of(16) + 32);
            match crypto.receive(moved, &encrypted, &mut output) {
                Action::Tunnel(bytes) => assert_eq!(bytes, incoming),
                _ => panic!("maximum padded packet was not delivered"),
            }
        }
        assert_eq!(crypto.counters.disallowed_source, 2);
        assert_eq!(crypto.counters.no_endpoint, 2);
        assert_eq!(crypto.counters.unauthenticated, 2);
    }
}

#[test]
fn cookie_threshold_is_shared_and_each_datagram_is_charged_once() {
    MockClock::set_time(Duration::ZERO);
    let source: SocketAddr = "192.0.2.2:51820".parse().unwrap();
    let mut crypto = Crypto::new(&config(None, None)).unwrap();
    let mut output = [0; BUFFER_SIZE];
    let init = wire(remote(8).format_handshake_initiation(&mut output, false));
    let other_init = wire(remote(9).format_handshake_initiation(&mut output, false));
    for n in 0..100 {
        let packet = if n % 2 == 0 { &init } else { &other_init };
        if let Action::Network { packet, .. } = crypto.receive(source, packet, &mut output) {
            assert_ne!(packet[0], 3, "cookie threshold was charged more than once");
        }
    }
    let cookie = network(crypto.receive(source, &init, &mut output), source);
    assert_eq!(cookie[0], 3);
    assert_eq!(cookie.len(), 64);
    MockClock::advance(Duration::from_secs(1));
    crypto.begin_timer_tick();
    assert!(
        !matches!(crypto.receive(source, &init, &mut output), Action::Network { packet, .. } if packet[0] == 3)
    );

    let mut initiator = Crypto::new(&config(Some(source), None)).unwrap();
    let init = network(
        initiator.encapsulate(&inner(false, 1, 2, 60), &mut output),
        source,
    );
    let limiter = RateLimiter::new(&PublicKey::from(public(8)), 0);
    let challenge =
        match limiter.verify_packet(Some("192.0.2.1".parse().unwrap()), &init, &mut output) {
            Err(TunnResult::WriteToNetwork(bytes)) => bytes.to_vec(),
            _ => panic!("expected a cookie challenge"),
        };
    assert!(matches!(
        initiator.receive("192.0.2.99:9".parse().unwrap(), &challenge, &mut output),
        Action::None
    ));
    assert_eq!(initiator.endpoint(0), Some(source));
    assert_eq!(initiator.counters.unauthenticated, 0);
}

#[test]
fn rejects_unknown_peers_and_malformed_frames() {
    MockClock::set_time(Duration::ZERO);
    let source = "192.0.2.2:51820".parse().unwrap();
    let mut crypto = Crypto::new(&config(None, None)).unwrap();
    let mut output = [0; BUFFER_SIZE];
    let unknown = wire(remote(10).format_handshake_initiation(&mut output, false));
    assert!(matches!(
        crypto.receive(source, &unknown, &mut output),
        Action::None
    ));
    let mut unknown_index = [0; 32];
    unknown_index[0] = 4;
    unknown_index[4..8].copy_from_slice(&(99_u32 << 8).to_le_bytes());
    assert!(matches!(
        crypto.receive(source, &unknown_index, &mut output),
        Action::None
    ));
    assert_eq!(crypto.counters.unknown_peer, 2);
    assert_eq!(crypto.endpoint(0), None);
    assert!(matches!(
        crypto.receive(source, &[0; BUFFER_SIZE + 1], &mut output),
        Action::None
    ));
    for v6 in [false, true] {
        let mut packet = inner(v6, 1, 2, 60);
        packet.pop();
        assert!(matches!(
            crypto.encapsulate(&packet, &mut output),
            Action::None
        ));
        assert!(matches!(
            crypto.encapsulate(&inner(v6, 1, 2, MTU + 1), &mut output),
            Action::None
        ));
    }
    assert_eq!(crypto.counters.malformed, 5);
}

#[test]
fn mock_clock_drives_retry_flush_keepalive_rekey_and_expiry() {
    MockClock::set_time(Duration::ZERO);
    let source = "192.0.2.2:51820".parse().unwrap();
    let mut crypto = Crypto::new(&config(Some(source), Some(1))).unwrap();
    let mut remote = remote(8);
    let mut output = [0; BUFFER_SIZE];
    let payload = inner(false, 1, 2, 60);
    let _ = network(crypto.encapsulate(&payload, &mut output), source);
    MockClock::advance(Duration::from_millis(4999));
    assert!(matches!(crypto.timer(0, &mut output), Action::None));
    MockClock::advance(Duration::from_millis(1));
    let retry = network(crypto.timer(0, &mut output), source);
    assert_eq!(retry[0], 1);
    let response = wire(remote.decapsulate(None, &retry, &mut output));
    let keepalive = network(crypto.receive(source, &response, &mut output), source);
    assert_eq!(keepalive.len(), 32);
    assert!(matches!(
        remote.decapsulate(None, &keepalive, &mut output),
        TunnResult::Done
    ));
    assert!(crypto.needs_flush(0));
    let queued = network(crypto.flush(0, &mut output), source);
    match remote.decapsulate(None, &queued, &mut output) {
        TunnResult::WriteToTunnelV4(bytes, _) => assert_eq!(bytes, payload),
        _ => panic!("queued plaintext was not flushed"),
    }
    assert!(matches!(crypto.flush(0, &mut output), Action::None));
    assert!(!crypto.needs_flush(0));
    MockClock::advance(Duration::from_secs(1));
    let keepalive = network(crypto.timer(0, &mut output), source);
    assert_eq!(keepalive.len(), 32);
    let _ = network(crypto.encapsulate(&payload, &mut output), source);
    MockClock::advance(Duration::from_secs(119));
    let rekey = network(crypto.timer(0, &mut output), source);
    assert_eq!(rekey[0], 1);
    MockClock::advance(Duration::from_secs(421));
    let errors = crypto.counters.crypto_errors;
    assert!(matches!(crypto.timer(0, &mut output), Action::None));
    assert_eq!(crypto.counters.crypto_errors, errors + 1);
    assert_eq!(crypto.endpoint(0), Some(source));
}
