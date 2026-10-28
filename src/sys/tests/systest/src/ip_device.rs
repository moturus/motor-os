use moto_sdk::sys_io::api_ip_device::{Cidr, MAX_ADDRESSES, MAX_ROUTES, Registration};

pub fn run_all_tests() {
    test_registration_codec();
    test_discovery();
    test_discovery_protocol();
    crate::ip_device_admission::test_admission_and_terminal_channel();
    crate::ip_device_live::test_reflected_transport_and_removal();
    crate::ip_device_live::test_provider_death_wakes_pending_ops();
    crate::ip_device_live::test_multiple_devices_and_wildcard_listener();
    crate::ip_device_live::test_removal_wakes_stream_and_datagram_writers();
    crate::ip_device_queues::test_full_queues_recover();
    crate::ip_device_udp::test_physical_bindings_and_ports();
}

pub(super) fn provider_pids() -> Vec<u64> {
    moto_sdk::sys_io::stats::IoStatsService::connect()
        .unwrap()
        .list_external_net_device_pids(Some(
            moto_rt::time::Instant::now() + std::time::Duration::from_secs(2),
        ))
        .unwrap()
}

fn test_discovery() {
    use moto_sdk::io::ip_device::IpDevice;
    // The VM has physical/loopback devices, but no external providers yet.
    assert!(provider_pids().is_empty());
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        let config = crate::ip_device_live::config(12);
        let first = IpDevice::register(&config).await.unwrap();
        assert_eq!(provider_pids(), vec![moto_sys::current_pid()]);
        assert!(IpDevice::register(&config).await.is_err());
        let second = IpDevice::register(&crate::ip_device_live::config(13))
            .await
            .unwrap();
        assert_eq!(provider_pids(), vec![moto_sys::current_pid()]);
        first.unregister().await.unwrap();
        assert_eq!(provider_pids(), vec![moto_sys::current_pid()]);
        second.unregister().await.unwrap();
        assert!(provider_pids().is_empty());
    });
    println!("ip_device::test_discovery PASS");
}

fn test_discovery_protocol() {
    use moto_sdk::ipc::sync::{ChannelSize, ClientConnection, RequestHeader};
    use moto_sdk::sys_io::stats::{
        CMD_LIST_EXTERNAL_NET_DEVICE_PIDS, ListExternalNetDevicePidsResponse,
        MAX_EXTERNAL_NET_DEVICE_PIDS, URL_IO_STATS,
    };
    let mut conn = ClientConnection::new(ChannelSize::Small).unwrap();
    conn.connect(URL_IO_STATS).unwrap();
    for (version, flags, expected) in [
        (1, 0, moto_rt::E_INVALID_ARGUMENT),
        (0, 1, moto_rt::E_INVALID_ARGUMENT),
        (0, 0, moto_rt::E_OK),
    ] {
        conn.req::<ListExternalNetDevicePidsResponse>()
            .pids
            .fill(u64::MAX);
        let req = conn.req::<RequestHeader>();
        req.cmd = CMD_LIST_EXTERNAL_NET_DEVICE_PIDS;
        req.ver = version;
        req.flags = flags;
        conn.do_rpc(Some(
            moto_rt::time::Instant::now() + std::time::Duration::from_secs(2),
        ))
        .unwrap();
        let response = conn.resp::<ListExternalNetDevicePidsResponse>();
        assert_eq!(response.header.result, expected);
        assert_eq!(response.header.ver, 0);
        assert_eq!(response.num_results, 0);
        assert!(response.pids.iter().all(|pid| *pid == 0));
        assert_eq!(conn.resp::<RequestHeader>().flags, 0);
    }
    // All fields, including the atomic sequence word, permit zero initialization.
    let mut response: ListExternalNetDevicePidsResponse = unsafe { std::mem::zeroed() };
    response.num_results = MAX_EXTERNAL_NET_DEVICE_PIDS as u64;
    assert_eq!(response.pids().unwrap().len(), MAX_EXTERNAL_NET_DEVICE_PIDS);
    for count in [MAX_EXTERNAL_NET_DEVICE_PIDS as u64 + 1, u64::MAX] {
        response.num_results = count;
        assert_eq!(response.pids(), Err(moto_rt::E_INVALID_ARGUMENT));
    }
    response.num_results = 0;
    response.header.ver = 1;
    assert_eq!(response.pids(), Err(moto_rt::E_INVALID_ARGUMENT));
    response.header.ver = 0;
    assert!(response.pids().unwrap().is_empty());
    response.header.result = moto_rt::E_NOT_READY;
    assert_eq!(response.pids(), Err(moto_rt::E_NOT_READY));
    println!("ip_device::test_discovery_protocol PASS");
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
