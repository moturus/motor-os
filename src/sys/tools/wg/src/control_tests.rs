use crate::control::*;
use ipnetwork::IpNetwork;
use std::net::{IpAddr, Ipv6Addr};

fn interface() -> Interface {
    Interface {
        name: "w".repeat(31),
        path: format!("/{}", "p".repeat(1023)),
        public_key: [9; 32],
        listen_port: 65535,
        transport_addresses: vec!["192.0.2.2".parse().unwrap(), "2001:db8::2".parse().unwrap()],
        cidrs: (1..=16)
            .map(|index| IpNetwork::new(IpAddr::V6(Ipv6Addr::from(index)), 128).unwrap())
            .collect(),
        state: State::Up,
        uptime_ms: 2400,
        age_ms: 900,
        peer_count: 16,
    }
}

fn peer() -> Peer {
    Peer {
        public_key: [10; 32],
        endpoint: Some("[2001:db8::1]:65535".parse().unwrap()),
        allowed_ips: (0..128)
            .map(|index| IpNetwork::new(IpAddr::V6(Ipv6Addr::from(index)), 128).unwrap())
            .collect(),
        keepalive: 65535,
        has_psk: true,
        handshake_ms: Some(1200),
        received: u64::MAX,
        sent: 7000,
    }
}

#[test]
fn maximum_control_records_fit_one_page_and_round_trip() {
    let interface = interface();
    let peer = peer();
    let encoded = interface.encode().unwrap();
    assert!(encoded.len() <= PAYLOAD_BYTES);
    assert_eq!(Interface::decode(&encoded).unwrap(), interface);
    let encoded = peer.encode().unwrap();
    assert!(encoded.len() <= PAYLOAD_BYTES);
    assert_eq!(Peer::decode(&encoded).unwrap(), peer);
}

#[test]
fn malformed_lengths_flags_and_counts_are_rejected() {
    let encoded = interface().encode().unwrap();
    for length in 0..encoded.len() {
        assert!(Interface::decode(&encoded[..length]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(Interface::decode(&trailing).is_err());
    let mut malformed = encoded;
    malformed[0..2].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(Interface::decode(&malformed).is_err());
    let encoded = peer().encode().unwrap();
    for length in 0..encoded.len() {
        assert!(Peer::decode(&encoded[..length]).is_err());
    }
    let mut malformed = encoded;
    malformed[32] = 2;
    assert!(Peer::decode(&malformed).is_err());
    let mut interface = interface();
    interface.peer_count = 17;
    assert!(interface.encode().is_err());
    let mut peer = peer();
    peer.allowed_ips.push(peer.allowed_ips[0]);
    assert!(peer.encode().is_err());
}

#[test]
fn status_distinguishes_lifecycle_sessions_and_snapshot_age() {
    let mut interface = interface();
    let mut peer = peer();
    interface.path = "/user/cfg/a\nconfig.toml".into();
    peer.handshake_ms = None;
    peer.endpoint = None;
    for (state, label) in [
        (State::Starting, "starting"),
        (State::Up, "up"),
        (State::Stopping, "stopping"),
    ] {
        interface.state = state;
        let text = display(123, &interface, &[peer.clone()]);
        assert!(text.contains(&format!("state: {label}")));
        assert!(text.contains("snapshot age: 900ms"));
        assert!(text.contains("none (no current session)"));
        assert!(text.contains("endpoint: not learned"));
        assert!(!text.contains("a\nconfig"));
        assert!(text.contains("a\\nconfig"));
    }
}
