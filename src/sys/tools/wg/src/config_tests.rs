use crate::config::*;
use base64::{Engine, engine::general_purpose::STANDARD};

fn private_key() -> String {
    STANDARD.encode([7; 32])
}

fn peer(id: u8, prefixes: &str) -> String {
    format!(
        "[[peers]]\npublic_key = '{}'\nallowed_ips = [{prefixes}]\n",
        STANDARD.encode([id; 32])
    )
}

fn header() -> String {
    format!(
        "name = 'wg0'\nprivate_key = '{}'\ntransport_addresses = ['192.0.2.2']\nlisten_port = 51820\ncidrs = ['10.20.0.2/32']\n",
        private_key()
    )
}

fn text() -> String {
    format!(
        "{}{}endpoint = '192.0.2.1:51820'\npersistent_keepalive = 25\n",
        header(),
        peer(8, "'10.20.0.0/24'")
    )
}

fn parse(text: &str) -> Result<Config> {
    Config::parse(text)
}

#[test]
fn explicit_and_responder_only_peers() {
    let config = parse(&text()).unwrap();
    assert_eq!(config.private_key, [7; 32]);
    assert_eq!(config.peers[0].public_key, [8; 32]);
    assert_eq!(config.peers[0].endpoint.unwrap().port(), 51820);
    assert_eq!(config.peers[0].persistent_keepalive, Some(25));
    let text = format!(
        "{}{}persistent_keepalive = 0\npreshared_key = '{}'\n",
        header(),
        peer(8, "'0.0.0.0/0'"),
        STANDARD.encode([9; 32])
    );
    let config = parse(&text).unwrap();
    assert!(config.peers[0].endpoint.is_none());
    assert!(config.peers[0].persistent_keepalive.is_none());
    assert_eq!(config.peers[0].preshared_key, Some([9; 32]));
}

#[test]
fn rejects_bad_keys_without_echoing_secrets() {
    for value in [
        "secret-content".to_owned(),
        STANDARD.encode([3; 31]),
        STANDARD.encode([3; 33]),
    ] {
        assert!(parse(&text().replace(&private_key(), &value)).is_err());
        let bad = text().replace(&STANDARD.encode([8; 32]), &value);
        assert!(!parse(&bad).err().unwrap().contains(&value));
    }
    assert!(parse(&format!("{}secret_field = 'secret-content'\n", text())).is_err());
    assert!(parse(&text().replace("listen_port", "secret_field")).is_err());
}

#[test]
fn endpoint_and_address_validation() {
    for address in [
        "vpn.example:51820",
        "192.0.2.1:0",
        "0.0.0.0:1",
        "239.0.0.1:1",
        "[2001:db8::1]:1",
        "[fe80::1%1]:1",
    ] {
        assert!(parse(&text().replace("192.0.2.1:51820", address)).is_err());
    }
    for (from, to) in [
        ("51820", "0"),
        ("['192.0.2.2']", "[]"),
        ("['192.0.2.2']", "['192.0.2.2', '192.0.2.3']"),
        ("10.20.0.2/32", "0.0.0.0/32"),
        ("10.20.0.0/24", "2001:db8::/64"),
    ] {
        assert!(parse(&text().replace(from, to)).is_err());
    }
    let ipv6 = text()
        .replace("192.0.2.2", "2001:db8::2")
        .replace("192.0.2.1:51820", "[2001:db8::1]:51820")
        .replace("10.20.0.2/32", "fd00::2/128")
        .replace("10.20.0.0/24", "fd00::/64");
    assert!(parse(&ipv6).is_ok());
}

#[test]
fn prefix_ownership_is_canonical_and_allows_nested_owners() {
    let base = format!("{}{}", header(), peer(8, "'0.0.0.0/0'"));
    assert!(parse(&format!("{base}{}", peer(9, "'10.20.0.0/24'"))).is_ok());
    assert!(parse(&format!("{base}{}", peer(8, "'10.20.0.0/24'"))).is_err());
    let duplicate = format!(
        "{}{}{}",
        header(),
        peer(8, "'10.20.0.0/24'"),
        peer(9, "'10.20.0.99/24'")
    );
    assert!(parse(&duplicate).is_err());
}

#[test]
fn bounded_input_and_runtime_admission() {
    assert!(parse(&" ".repeat(MAX_FILE_BYTES + 1)).is_err());
    assert!(parse(&text().replace("wg0", &"w".repeat(MAX_NAME_BYTES + 1))).is_err());
    assert!(parse(&text().replace("wg0", "../wg0")).is_err());
    let peers: String = (0..MAX_PEERS + 1)
        .map(|id| peer(id as u8, &format!("'10.20.{id}.0/24'")))
        .collect();
    assert!(parse(&format!("{}{peers}", header())).is_err());
    let prefixes = (0..MAX_PREFIXES + 1)
        .map(|id| format!("'10.20.{id}.0/24'"))
        .collect::<Vec<_>>()
        .join(",");
    assert!(parse(&format!("{}{}", header(), peer(8, &prefixes))).is_err());
}

#[test]
#[cfg(unix)]
fn checks_inline_file_permissions_and_ignores_sidecars() {
    use std::os::unix::fs::PermissionsExt;
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("wg-config-{}-{unique}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let config = directory.join("wg0.toml");
    let key = directory.join("wg0.key");
    let chmod = |path: &std::path::Path, mode| {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap()
    };
    std::fs::write(&key, format!("{}\n", private_key())).unwrap();
    for psk in [false, true] {
        let mut contents = text();
        if psk {
            contents += &format!("preshared_key = '{}'\n", STANDARD.encode([9; 32]));
        }
        if config.exists() {
            chmod(&config, 0o600);
        }
        std::fs::write(&config, contents).unwrap();
        for mode in [0o400, 0o440, 0o600, 0o640] {
            chmod(&config, mode);
            chmod(&key, mode);
            assert!(Config::load(&config).is_ok());
        }
        chmod(&key, 0o600);
        chmod(&config, 0o604);
        assert!(Config::load(&config).err().unwrap().contains("None role"));
    }
    chmod(&config, 0o600);
    chmod(&key, 0o600);
    std::fs::write(&key, vec![b'A'; MAX_FILE_BYTES + 1]).unwrap();
    assert!(Config::load(&config).is_ok());
    std::fs::remove_file(&key).unwrap();
    assert!(Config::load(&config).is_ok());
    std::fs::create_dir(&key).unwrap();
    assert!(Config::load(&config).is_ok());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn inline_identity_and_empty_peers() {
    let config = parse(&header()).unwrap();
    assert!(config.peers.is_empty());
    assert!(parse(&format!("{}peers = []\n", header())).is_ok());
    let text = format!(
        "public_key = '{}'\n{}",
        STANDARD.encode(config.public_key()),
        header()
    );
    assert!(parse(&text).unwrap() == config);
    assert!(
        parse(&text.replace(
            &STANDARD.encode(config.public_key()),
            &STANDARD.encode([0; 32])
        ))
        .is_err()
    );
    for field in ["name", "private_key"] {
        assert!(
            parse(
                &header()
                    .lines()
                    .filter(|line| !line.starts_with(field))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
            .is_err()
        );
    }
    let serialized = crate::edit::serialize(&config).unwrap();
    assert!(parse(&serialized).unwrap() == config);
    assert!(!serialized.contains("peers"));
}

#[test]
fn peer_edits_preserve_source_and_reject_conflicts() {
    let make_peer = || parse(&text()).unwrap().peers.remove(0);
    let inline = format!(
        "{{ public_key = '{}', allowed_ips = ['10.21.0.0/24'] }}",
        STANDARD.encode([9; 32])
    );
    for peers in [
        String::new(),
        "peers = []\n".into(),
        format!("'peers' = [{inline}] # trailing\n"),
        format!("peers = [\n{inline}, # ] pretend peers = []\n]\n"),
        peer(9, "'10.21.0.0/24'"),
    ] {
        for newline in ["\n", "\r\n"] {
            let source = format!("# Manual notes: [[peers]]\n{}{}# keep me", header(), peers)
                .replace('\n', newline);
            let edited = crate::edit::add_peer(&source, make_peer(), "office").unwrap();
            assert!(edited.contains("# keep me"));
            assert!(edited.contains(&format!("# Peer: office{newline}")));
            assert!(edited.contains(&header().replace('\n', newline)));
            let mut other = make_peer();
            other.public_key = [10; 32];
            other.allowed_ips = vec!["10.22.0.0/24".parse().unwrap()];
            let twice = crate::edit::add_peer(&edited, other, "office").unwrap();
            assert_eq!(twice.matches("# Peer: office").count(), 2);
            assert!(crate::edit::add_peer(&twice, make_peer(), "").is_err());
        }
    }
    for name in ["bad\nname", "bad\rname", "bad\u{1b}", &"n".repeat(129)] {
        assert!(crate::edit::add_peer(&header(), make_peer(), name).is_err());
    }
    let blank = crate::edit::add_peer(&header(), make_peer(), "  ").unwrap();
    assert!(!blank.contains("# Peer:"));
    let mut own_key = make_peer();
    own_key.public_key = parse(&header()).unwrap().public_key();
    assert!(crate::edit::add_peer(&header(), own_key, "").is_err());
    let mut duplicate_prefix = make_peer();
    duplicate_prefix.public_key = [10; 32];
    duplicate_prefix.allowed_ips = vec!["10.20.0.99/24".parse().unwrap()];
    assert!(crate::edit::add_peer(&text(), duplicate_prefix, "").is_err());
}
