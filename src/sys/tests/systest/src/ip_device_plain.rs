//! Test-only remote baseline: the same packet IPC and physical UDP as `wg`.
use moto_sdk::async_runtime::{self, LocalRuntime};
use moto_sdk::io::ip_device::{IpDevice, PacketReceiver, PacketSender};
use moto_sdk::io::net::udp::UdpSocket;
use moto_sdk::sys_io::api_ip_device::{Cidr, Registration};
use std::cell::Cell;
use std::future::Future;
use std::net::SocketAddr;
use std::task::Poll;

const MTU: usize = 1420;

async fn transmit(
    mut packets: PacketReceiver<'_>,
    socket: &UdpSocket,
    endpoint: SocketAddr,
    progress: &Cell<u64>,
) -> Result<(), u16> {
    let mut bytes = [0; MTU];
    loop {
        for _ in 0..16 {
            let length = packets
                .receive(&mut bytes)
                .await
                .map_err(|error| error as u16)?;
            socket.send_to_future(&bytes[..length], &endpoint).await?;
            progress.set(progress.get() + 1);
        }
        async_runtime::yield_now().await;
    }
}

async fn receive(
    packets: PacketSender<'_>,
    socket: &UdpSocket,
    endpoint: SocketAddr,
    progress: &Cell<u64>,
) -> Result<(), u16> {
    let mut bytes = [0; MTU + 1];
    loop {
        for _ in 0..16 {
            let (length, source) = socket.recv_from_future(&mut bytes, false).await?;
            if source == endpoint && length != 0 && length <= MTU {
                packets
                    .send(&bytes[..length])
                    .await
                    .map_err(|error| error as u16)?;
            }
            progress.set(progress.get() + 1);
        }
        async_runtime::yield_now().await;
    }
}

pub fn run(local: &str, endpoint: &str) {
    let local: SocketAddr = local.parse().unwrap();
    let endpoint: SocketAddr = endpoint.parse().unwrap();
    assert_eq!(local.is_ipv4(), endpoint.is_ipv4());
    assert!(!local.ip().is_unspecified() && !endpoint.ip().is_unspecified());
    assert_ne!(endpoint.port(), 0);
    LocalRuntime::new().block_on(async {
        let (client, driver) = crate::net_harness::host_channel().await;
        let anchor = client.try_reserve().unwrap();
        let socket = UdpSocket::bind_physical_reserved(client.try_reserve().unwrap(), &local, None)
            .await
            .unwrap();
        let addresses = vec![
            Cidr {
                address: "10.250.20.2".parse().unwrap(),
                prefix_len: 24,
            },
            Cidr {
                address: "fd50:20::2".parse().unwrap(),
                prefix_len: 64,
            },
        ];
        let mut device = IpDevice::register(&Registration {
            name: "wg_plain".into(),
            mtu: MTU as u16,
            routes: addresses
                .iter()
                .map(|cidr| cidr.network().unwrap())
                .collect(),
            addresses,
        })
        .await
        .unwrap();
        println!("wg_plain: active (pid={})", moto_sys::current_pid());
        let result = {
            let (sender, receiver) = device.split();
            let progress = Cell::new(0);
            let mut tx = std::pin::pin!(transmit(receiver, &socket, endpoint, &progress));
            let mut rx = std::pin::pin!(receive(sender, &socket, endpoint, &progress));
            loop {
                let before = progress.get();
                let result = std::future::poll_fn(|cx| {
                    if let Poll::Ready(result) = tx.as_mut().poll(cx) {
                        return Poll::Ready(result);
                    }
                    if let Poll::Ready(result) = rx.as_mut().poll(cx) {
                        return Poll::Ready(result);
                    }
                    if progress.get() != before {
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Pending
                })
                .await;
                if result.is_err() {
                    break result;
                }
                async_runtime::yield_to_io().await;
            }
        };
        drop(socket);
        device.unregister().await.unwrap();
        drop(anchor);
        driver.await;
        result.unwrap();
    });
}
