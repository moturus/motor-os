use super::*;
use crate::self_test::{SelfTest, st_assert, st_assert_eq};
use moto_netstack::wire::{IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr};
use moto_sdk::sys_io::api_ip_device::{Cidr, Registration};

pub(crate) const TESTS: &[SelfTest] = &[
    ("net::icmp::packet_echo_policy", packet_echo_policy),
    (
        "net::icmp::packet_probe_validation",
        packet_probe_validation,
    ),
];

fn registration() -> Registration {
    Registration {
        name: "ping".into(),
        mtu: 1420,
        addresses: vec![
            Cidr {
                address: "10.53.0.1".parse().unwrap(),
                prefix_len: 24,
            },
            Cidr {
                address: "fd53::1".parse().unwrap(),
                prefix_len: 64,
            },
        ],
        routes: Vec::new(),
    }
}

fn packet(
    source: IpAddr,
    destination: IpAddr,
    reply: bool,
    ident: u16,
    seq_no: u16,
    data: &[u8],
) -> Vec<u8> {
    let checksum = ChecksumCapabilities::default();
    let header = if source.is_ipv4() { 20 } else { 40 };
    let mut bytes = vec![0; header + 8 + data.len()];
    match (source, destination) {
        (IpAddr::V4(src_addr), IpAddr::V4(dst_addr)) => {
            let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
            Ipv4Repr {
                src_addr,
                dst_addr,
                next_header: IpProtocol::Icmp,
                payload_len: 8 + data.len(),
                hop_limit: 64,
            }
            .emit(&mut ip, &checksum);
            let repr = if reply {
                Icmpv4Repr::EchoReply {
                    ident,
                    seq_no,
                    data,
                }
            } else {
                Icmpv4Repr::EchoRequest {
                    ident,
                    seq_no,
                    data,
                }
            };
            repr.emit(
                &mut Icmpv4Packet::new_unchecked(ip.payload_mut()),
                &checksum,
            );
        }
        (IpAddr::V6(src_addr), IpAddr::V6(dst_addr)) => {
            let mut ip = Ipv6Packet::new_unchecked(&mut bytes[..]);
            Ipv6Repr {
                src_addr,
                dst_addr,
                next_header: IpProtocol::Icmpv6,
                payload_len: 8 + data.len(),
                hop_limit: 64,
            }
            .emit(&mut ip);
            let repr = if reply {
                Icmpv6Repr::EchoReply {
                    ident,
                    seq_no,
                    data,
                }
            } else {
                Icmpv6Repr::EchoRequest {
                    ident,
                    seq_no,
                    data,
                }
            };
            repr.emit(
                &src_addr,
                &dst_addr,
                &mut Icmpv6Packet::new_unchecked(ip.payload_mut()),
                &checksum,
            );
        }
        _ => unreachable!(),
    }
    bytes
}

fn poll(runtime: &NetRuntime, index: usize) {
    runtime.inner.borrow_mut().devices[index].poll(&runtime.stats, &runtime.backlog);
}

fn packet_echo_policy() -> std::result::Result<(), String> {
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        for enabled in [false, true] {
            let mut runtime = super::super::self_test::runtime()?;
            let config: super::super::config::NetConfig = toml::from_str(&format!(
                "auto_icmp_echo_reply = {enabled}\nloopback = false\n[devices]\n"
            ))
            .unwrap();
            runtime.interface_policy = (&config).into();
            let (index, device) = runtime
                .register_packet_device(registration())
                .await
                .unwrap();
            for (local, remote) in [("10.53.0.1", "10.53.0.2"), ("fd53::1", "fd53::2")] {
                let local = local.parse().unwrap();
                let remote = remote.parse().unwrap();
                let data = [1, 2, 3, 4];
                device.submit(&packet(remote, local, false, 7, 9, &data));
                poll(&runtime, index);
                let response = device.take_outbound();
                st_assert_eq!(response.is_some(), enabled);
                if let Some(response) = response {
                    let header = if local.is_ipv4() { 20 } else { 40 };
                    st_assert!(is_matching_reply(
                        &response.bytes()[header..],
                        local,
                        local,
                        remote,
                        7,
                        9,
                        &data
                    ));
                }
            }
            drop(device);
            runtime.remove_device(index).await;
            st_assert_eq!(runtime.stats.packet_buffer_bytes.get(), 0);
        }
        Ok(())
    })
}

fn packet_probe_validation() -> std::result::Result<(), String> {
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        let runtime = super::super::self_test::runtime()?;
        let (index, device) = runtime
            .register_packet_device(registration())
            .await
            .unwrap();
        let listener = io_channel::listen("sys_io_icmp_packet_test");
        let client = io_channel::ClientConnection::connect("sys_io_icmp_packet_test").unwrap();
        let (sender, _receiver) = listener.await.unwrap();
        for (local, remote, other) in [
            ("10.53.0.1", "10.53.0.2", "10.53.0.3"),
            ("fd53::1", "fd53::2", "fd53::3"),
        ] {
            let local: IpAddr = local.parse().unwrap();
            let remote = remote.parse().unwrap();
            let other = other.parse().unwrap();
            let header = if local.is_ipv4() { 20 } else { 40 };
            let size = 1420 - header - 8;
            let mut request =
                api_net::icmp_echo_request(remote, 9, size as u16, Duration::from_secs(1)).unwrap();
            request.id = 19;
            let probe = echo(&runtime, request, &sender);
            futures::pin_mut!(probe);
            st_assert!(futures::poll!(&mut probe).is_pending());
            poll(&runtime, index);
            let sent = device.take_outbound().unwrap();
            st_assert_eq!(sent.bytes().len(), 1420);
            let identifier =
                u16::from_be_bytes(sent.bytes()[header + 4..header + 6].try_into().unwrap());
            let data = make_payload(request.id, 9, size);
            let expected = packet(local, remote, false, identifier, 9, &data);
            st_assert_eq!(&sent.bytes()[header..], &expected[header..]);
            let addresses = if local.is_ipv4() { 12..20 } else { 8..40 };
            st_assert_eq!(&sent.bytes()[addresses.clone()], &expected[addresses]);
            drop(sent);

            // Each rejected response is consumed before checking that the
            // original request still waits for its own exact reply.
            for invalid in 0..6 {
                let mut payload = data.clone();
                if invalid == 3 {
                    payload[0] ^= 1;
                }
                let mut reply = packet(
                    if invalid == 0 { other } else { remote },
                    local,
                    invalid != 5,
                    identifier.wrapping_add(u16::from(invalid == 1)),
                    9 + u16::from(invalid == 2),
                    &payload,
                );
                if invalid == 4 {
                    reply[header + 2] ^= 1;
                }
                device.submit(&reply);
                poll(&runtime, index);
                st_assert!(futures::poll!(&mut probe).is_pending());
            }
            device.submit(&packet(remote, local, true, identifier, 9, &data));
            poll(&runtime, index);
            probe.await.unwrap();
            let response = api_net::decode_icmp_echo_response(&client.recv().unwrap()).unwrap();
            st_assert_eq!(response.source, remote);
            st_assert!(
                runtime.inner.borrow().devices[index]
                    .sockets
                    .iter()
                    .next()
                    .is_none()
            );

            let mut too_large =
                api_net::icmp_echo_request(remote, 9, (size + 1) as u16, Duration::from_secs(1))
                    .unwrap();
            too_large.id = 20;
            st_assert_eq!(
                echo(&runtime, too_large, &sender).await.unwrap_err().kind(),
                ErrorKind::InvalidInput
            );
            st_assert!(
                runtime.inner.borrow().devices[index]
                    .sockets
                    .iter()
                    .next()
                    .is_none()
            );

            let mut silent =
                api_net::icmp_echo_request(remote, 10, 1, Duration::from_millis(10)).unwrap();
            silent.id = 21;
            echo(&runtime, silent, &sender).await.unwrap();
            st_assert_eq!(client.recv().unwrap().status, moto_rt::E_TIMED_OUT);
            st_assert!(
                runtime.inner.borrow().devices[index]
                    .sockets
                    .iter()
                    .next()
                    .is_none()
            );
            while device.take_outbound().is_some() {}
        }
        drop(device);
        runtime.remove_device(index).await;
        st_assert_eq!(runtime.stats.packet_buffer_bytes.get(), 0);
        Ok(())
    })
}
