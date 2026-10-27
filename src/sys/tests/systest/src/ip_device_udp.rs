use crate::net_harness::{bounded, bounded_output, host_channel};
use moto_sdk::io::ip_device::IpDevice;
use moto_sdk::io::net::udp::UdpSocket;
use std::net::SocketAddr;

pub fn test_physical_bindings_and_ports() {
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        let (client, driver) = host_channel().await;
        let anchor = client.try_reserve().unwrap();
        let config = super::ip_device_live::config(10);
        let device = IpDevice::register(&config).await.unwrap();
        for (wildcard, loopback, virtual_ip) in [
            ("0.0.0.0:0", "127.0.0.1:0", config.addresses[0].address),
            ("[::]:0", "[::1]:0", config.addresses[1].address),
        ] {
            let ordinary = UdpSocket::bind_reserved(
                client.try_reserve().unwrap(),
                &wildcard.parse().unwrap(),
                None,
            )
            .await
            .unwrap();
            let local = *ordinary.local_addr();
            assert_ne!(local.ip(), virtual_ip);
            assert!(
                !local.ip().is_loopback(),
                "test image needs a physical address"
            );
            let conflict =
                UdpSocket::bind_physical_reserved(client.try_reserve().unwrap(), &local, None)
                    .await;
            assert!(matches!(conflict, Err(moto_rt::E_ALREADY_IN_USE)));
            let transport = UdpSocket::bind_physical_reserved(
                client.try_reserve().unwrap(),
                &SocketAddr::new(local.ip(), 0),
                None,
            )
            .await
            .unwrap();
            let port = *transport.local_addr();
            let conflict =
                UdpSocket::bind_reserved(client.try_reserve().unwrap(), &port, None).await;
            assert!(matches!(conflict, Err(moto_rt::E_ALREADY_IN_USE)));
            transport.send_to_future(b"physical", &local).await.unwrap();
            let mut bytes = [0; 16];
            let (length, source) = bounded_output(ordinary.recv_from_future(&mut bytes, false), 2)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&bytes[..length], b"physical");
            assert_eq!(source, port);
            drop(transport);
            let replacement =
                UdpSocket::bind_physical_reserved(client.try_reserve().unwrap(), &port, None)
                    .await
                    .unwrap();
            assert_eq!(*replacement.local_addr(), port);
            for invalid in [
                wildcard.parse().unwrap(),
                loopback.parse().unwrap(),
                SocketAddr::new(virtual_ip, 0),
            ] {
                let result = UdpSocket::bind_physical_reserved(
                    client.try_reserve().unwrap(),
                    &invalid,
                    None,
                )
                .await;
                assert!(matches!(result, Err(moto_rt::E_INVALID_ARGUMENT)));
            }
            drop((ordinary, replacement));
        }
        device.unregister().await.unwrap();
        drop(anchor);
        assert!(bounded(driver, 2).await);
        assert_eq!(client.reservations(), 0);
    });
    println!("ip_device_udp::test_physical_bindings_and_ports PASS");
}
