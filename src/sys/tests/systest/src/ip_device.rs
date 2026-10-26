use moto_sdk::sys_io::api_ip_device::{Cidr, MAX_ADDRESSES, MAX_ROUTES, Registration};

pub fn run_all_tests() {
    test_registration_codec();
}

pub fn test_registration_codec() {
    let v4 = Cidr {
        address: "10.21.0.1".parse().unwrap(),
        prefix_len: 24,
    };
    let v6 = Cidr {
        address: "fd21::1".parse().unwrap(),
        prefix_len: 64,
    };
    let mut config = Registration {
        name: "wg0".into(),
        addresses: vec![v4, v6],
        routes: vec![v4.network().unwrap(), v6.network().unwrap()],
        mtu: 1420,
    };
    let mut bytes = [0; 4096];
    let length = config.encode(&mut bytes).unwrap();
    assert_eq!(Registration::decode(&bytes[..length]).unwrap(), config);
    for len in 0..length {
        assert!(Registration::decode(&bytes[..len]).is_err());
    }
    assert!(Registration::decode(&bytes[..length + 1]).is_err());
    // Invalid wire input is rejected before a device or shared-page parser exists.
    let first_cidr = 8 + config.name.len();
    for (offset, value) in [
        (0, 2),
        (1, 32),
        (2, 0),
        (2, MAX_ADDRESSES as u8 + 1),
        (3, MAX_ROUTES as u8 + 1),
        (6, 1),
        (7, 1),
        (8, b'/'),
        (first_cidr, 5),
        (first_cidr + 1, 33),
        (first_cidr + 6, 1),
        (first_cidr + 18 + 1, 129),
    ] {
        let mut invalid = bytes;
        invalid[offset] = value;
        assert!(
            Registration::decode(&invalid[..length]).is_err(),
            "accepted byte {offset}"
        );
    }
    config.mtu = 1279;
    assert!(config.validate().is_err());
    config.mtu = 4097;
    assert!(config.validate().is_err());
    config.mtu = 1420;
    config.routes[0] = v4; // Route host bits must be zero; local addresses keep theirs.
    assert!(config.validate().is_err());
    config.routes[0] = v4.network().unwrap();
    config.routes.push(config.routes[0]);
    assert!(config.validate().is_err());
    config.routes.pop();
    config.addresses.push(v4);
    assert!(config.validate().is_err());
    config.addresses.pop();
    config.addresses.remove(1);
    assert!(
        config.validate().is_err(),
        "IPv6 route without IPv6 local source"
    );
    config.addresses.push(v6);
    for prefix in [0, 1, 31, 32] {
        let cidr = Cidr {
            prefix_len: prefix,
            ..v4
        }
        .network()
        .unwrap();
        assert_eq!(cidr.network().unwrap(), cidr);
    }
    for prefix in [0, 1, 127, 128] {
        let cidr = Cidr {
            prefix_len: prefix,
            ..v6
        }
        .network()
        .unwrap();
        assert_eq!(cidr.network().unwrap(), cidr);
    }
    config.name = "w".repeat(31);
    config.addresses = (1..=MAX_ADDRESSES)
        .map(|n| Cidr {
            address: std::net::Ipv4Addr::new(10, 21, 0, n as u8).into(),
            prefix_len: 32,
        })
        .collect();
    config.routes = (0..MAX_ROUTES)
        .map(|n| Cidr {
            address: std::net::Ipv4Addr::new(10, 22, n as u8, 0).into(),
            prefix_len: 24,
        })
        .collect();
    let length = config.encode(&mut bytes).unwrap();
    assert!(length <= 4096);
    assert_eq!(Registration::decode(&bytes[..length]).unwrap(), config);
    config.addresses.push(v4);
    assert!(config.encode(&mut bytes).is_err());
    println!("ip_device::test_registration_codec PASS");
}
