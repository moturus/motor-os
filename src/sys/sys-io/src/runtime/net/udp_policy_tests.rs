//! Native socket admission and queue teardown, with isolated interface state.
use super::super::{ClientConnection, NetRuntime, api_net, self_test, socket::MotoSocket};
use super::*;
use crate::runtime::channel_budget::ClientSender;
use crate::self_test::{SelfTest, st_assert, st_assert_eq};
use moto_sdk::ipc::io_channel::{self, Msg};
use moto_sdk::sys_io::api_ip_device::{Cidr, Registration};

pub(crate) const TESTS: &[SelfTest] = &[
    (
        "net::udp::address_loss_discards_nic_queue",
        address_loss_discards_nic_queue,
    ),
    (
        "net::udp::device_boundary_and_transport_bypass",
        device_boundary_and_transport_bypass,
    ),
    (
        "net::udp::address_loss_discards_transport_output",
        address_loss_discards_transport_output,
    ),
];

fn address_loss_discards_nic_queue() -> Result<(), String> {
    let mut queue = TxQueueState::new(TX_RESERVATION * 4);
    for (version, source) in [(4, 1), (6, 1), (4, 2), (6, 2)] {
        let mut frame = VirtioIoBuf::new_from_size_align(SMALL_BUF_SIZE).unwrap();
        frame.set_len(14 + if version == 4 { 28 } else { 48 });
        let bytes: &mut [u8] = frame.as_mut();
        bytes.fill(0);
        if version == 4 {
            bytes[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
            bytes[14] = 0x45;
            bytes[16..18].copy_from_slice(&28u16.to_be_bytes());
            bytes[26..30].copy_from_slice(&[10, 80, 0, source]);
        } else {
            bytes[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
            bytes[14] = 0x60;
            bytes[18..20].copy_from_slice(&8u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&0xfd80u16.to_be_bytes());
            bytes[37] = source;
        }
        st_assert!(queue.reserve());
        queue.push_packet(frame, 0);
    }
    queue.discard_source("10.80.0.1".parse().unwrap());
    queue.discard_source("fd80::1".parse().unwrap());
    st_assert_eq!(queue.work.len(), 2);
    st_assert_eq!(
        queue.bytes,
        queue
            .work
            .iter()
            .map(|(frame, _)| frame.capacity())
            .sum::<usize>()
    );
    queue.discard_source("10.80.0.2".parse().unwrap());
    queue.discard_source("fd80::2".parse().unwrap());
    st_assert!(queue.work.is_empty());
    st_assert_eq!(queue.bytes, 0);
    st_assert!(queue.reserve());
    queue.cancel_reservation();
    Ok(())
}

async fn channel(
    runtime: &NetRuntime,
) -> (
    ClientSender,
    io_channel::Sender,
    io_channel::Receiver,
    io_channel::Receiver,
) {
    let listener = io_channel::listen("sys_io_udp_policy_test");
    let (client, receiver) = io_channel::connect("sys_io_udp_policy_test").unwrap();
    let (sender, server_receiver) = listener.await.unwrap();
    let sender = runtime.channel_budget.admit_net(sender).ok().unwrap();
    runtime.inner.borrow_mut().clients.insert(
        sender.remote_handle(),
        ClientConnection::new(sender.clone(), u64::MAX),
    );
    runtime.stats.active_clients.set(1);
    (sender, client, receiver, server_receiver)
}

async fn bind(
    runtime: &NetRuntime,
    sender: &ClientSender,
    receiver: &mut io_channel::Receiver,
    address: &str,
    flags: u32,
) -> Msg {
    let mut request = api_net::bind_udp_socket_request(&address.parse().unwrap(), 0);
    request.flags = flags;
    MotoSocket::udp_bind(runtime, request, sender)
        .await
        .unwrap();
    receiver.recv().await.unwrap()
}

async fn send(
    runtime: &NetRuntime,
    sender: &ClientSender,
    client: &io_channel::Sender,
    receiver: &mut io_channel::Receiver,
    handle: u64,
    remote: &str,
) {
    let page = client.alloc_page(u64::MAX).await.unwrap();
    page.bytes_mut()[..6].copy_from_slice(b"queued");
    let request = api_net::udp_socket_tx_rx_msg(handle, page, 0, 6, &remote.parse().unwrap());
    MotoSocket::udp_tx(runtime, request, sender).await.unwrap();
    assert_eq!(
        receiver.recv().await.unwrap().command,
        api_net::NetCmd::UdpSocketTxRxAck as u16
    );
}

fn queued(runtime: &NetRuntime, index: usize, handle: u64) -> usize {
    runtime.inner.borrow().devices[index]
        .sockets
        .get::<moto_netstack::socket::udp::Socket>(handle.into())
        .send_queue()
}

fn device_boundary_and_transport_bypass() -> Result<(), String> {
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        for (local, virtual_ip, other_virtual, other_local, remote, default, wildcard) in [
            (
                "10.80.0.1/24",
                "10.90.0.1",
                "10.91.0.1",
                "10.81.0.1/24",
                "192.0.2.1",
                "0.0.0.0",
                "0.0.0.0:0",
            ),
            (
                "fd80::1/64",
                "fd90::1",
                "fd91::1",
                "fd81::1/64",
                "2001:db8::1",
                "::",
                "[::]:0",
            ),
        ] {
            let runtime = self_test::runtime()?;
            let config = |name: &str, address: &str, routes| Registration {
                name: name.into(),
                mtu: 1420,
                addresses: vec![Cidr {
                    address: address.parse().unwrap(),
                    prefix_len: if address.contains(':') { 128 } else { 32 },
                }],
                routes,
            };
            let broad = runtime
                .register_packet_device(config(
                    "wg0",
                    virtual_ip,
                    vec![Cidr {
                        address: default.parse().unwrap(),
                        prefix_len: 0,
                    }],
                ))
                .await
                .unwrap()
                .0;
            let narrow = runtime
                .register_packet_device(config("wg1", other_virtual, vec![]))
                .await
                .unwrap()
                .0;
            let physical = self_test::add_device(&runtime, "nic0", local);
            let second = self_test::add_device(&runtime, "nic1", other_local);
            // A loopback-backed NIC keeps this test entirely inside the runtime.
            runtime.inner.borrow_mut().devices[physical].external = true;
            let (sender, client, mut receiver, _server_receiver) = channel(&runtime).await;
            let ordinary = bind(&runtime, &sender, &mut receiver, wildcard, 0).await;
            let bound = api_net::get_socket_addr(&ordinary.payload);
            st_assert_eq!(
                bound.ip(),
                local.split('/').next().unwrap().parse::<IpAddr>().unwrap()
            );
            st_assert_eq!(
                runtime.find_route(&remote.parse().unwrap()).unwrap().0,
                broad
            );
            for (from, to, allowed) in [
                (physical, virtual_ip, false),
                (broad, other_virtual, false),
                (broad, remote, true),
                (broad, &bound.ip().to_string(), false),
                (physical, other_local.split('/').next().unwrap(), true),
                (second, &bound.ip().to_string(), true),
                (narrow, virtual_ip, false),
            ] {
                st_assert_eq!(
                    runtime
                        .inner
                        .borrow()
                        .udp_route_allowed(from, &to.parse().unwrap()),
                    allowed
                );
            }
            let destination = SocketAddr::new(remote.parse().unwrap(), 1234).to_string();
            send(
                &runtime,
                &sender,
                &client,
                &mut receiver,
                ordinary.handle,
                &destination,
            )
            .await;
            st_assert_eq!(runtime.stats.udp_tx_boundary_drops.get(), 1);
            st_assert_eq!(queued(&runtime, physical, ordinary.handle), 0);
            let transport_addr = SocketAddr::new(bound.ip(), 0).to_string();
            let transport = bind(
                &runtime,
                &sender,
                &mut receiver,
                &transport_addr,
                api_net::UDP_BIND_PHYSICAL_TRANSPORT,
            )
            .await;
            send(
                &runtime,
                &sender,
                &client,
                &mut receiver,
                transport.handle,
                &destination,
            )
            .await;
            st_assert_eq!(queued(&runtime, physical, transport.handle), 6);
            st_assert_eq!(runtime.stats.udp_tx_boundary_drops.get(), 1);
            // Even a local tunnel address must not capture encrypted transport.
            let tunnel = SocketAddr::new(virtual_ip.parse().unwrap(), 1234).to_string();
            send(
                &runtime,
                &sender,
                &client,
                &mut receiver,
                transport.handle,
                &tunnel,
            )
            .await;
            st_assert_eq!(queued(&runtime, physical, transport.handle), 12);
            for address in [
                wildcard.to_owned(),
                SocketAddr::new(virtual_ip.parse().unwrap(), 0).to_string(),
            ] {
                let mut request = api_net::bind_udp_socket_request(&address.parse().unwrap(), 0);
                request.flags = api_net::UDP_BIND_PHYSICAL_TRANSPORT;
                st_assert!(
                    MotoSocket::udp_bind(&runtime, request, &sender)
                        .await
                        .is_err()
                );
            }
            runtime.on_connection_done(sender.remote_handle()).await;
            for index in [broad, narrow, physical, second] {
                runtime.remove_device(index).await;
            }
        }
        Ok(())
    })
}

fn address_loss_discards_transport_output() -> Result<(), String> {
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        for (address, remote) in [
            ("10.80.0.1/24", "10.80.0.2:1234"),
            ("fd80::1/64", "[fd80::2]:1234"),
        ] {
            let runtime = self_test::runtime()?;
            let index = self_test::add_device(&runtime, "nic0", address);
            runtime.inner.borrow_mut().devices[index].external = true;
            let ip: IpAddr = address.split('/').next().unwrap().parse().unwrap();
            let local = SocketAddr::new(ip, 0).to_string();
            let (sender, client, mut receiver, _server_receiver) = channel(&runtime).await;
            let transport = bind(
                &runtime,
                &sender,
                &mut receiver,
                &local,
                api_net::UDP_BIND_PHYSICAL_TRANSPORT,
            )
            .await;
            let ordinary = bind(&runtime, &sender, &mut receiver, &local, 0).await;
            send(
                &runtime,
                &sender,
                &client,
                &mut receiver,
                transport.handle,
                remote,
            )
            .await;
            st_assert_eq!(queued(&runtime, index, transport.handle), 6);
            // No device task can run between the queued send and withdrawal.
            runtime.inner.borrow_mut().devices[index]
                .iface
                .update_ip_addrs(|addresses| addresses.clear());
            runtime.rebuild_ip_addresses();
            st_assert!(
                !runtime
                    .inner
                    .borrow()
                    .sockets
                    .contains_key(&transport.handle)
            );
            st_assert!(
                runtime
                    .inner
                    .borrow()
                    .sockets
                    .contains_key(&ordinary.handle)
            );
            st_assert_eq!(runtime.stats.udp_sockets.get(), 1);
            let notice = receiver.recv().await.unwrap();
            st_assert_eq!(
                notice.command,
                api_net::NetCmd::EvtUdpSocketInvalidated as u16
            );
            st_assert_eq!(notice.handle, transport.handle);
            // A stale IPC send cannot recreate the socket or enqueue output.
            let request =
                api_net::udp_socket_tx_rx_empty_msg(transport.handle, &remote.parse().unwrap());
            MotoSocket::udp_tx(&runtime, request, &sender)
                .await
                .unwrap();
            st_assert_eq!(runtime.stats.udp_tx_dropped.get(), 1);
            runtime.on_connection_done(sender.remote_handle()).await;
            runtime.remove_device(index).await;
        }
        Ok(())
    })
}
