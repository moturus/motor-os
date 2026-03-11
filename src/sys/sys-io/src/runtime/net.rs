use ipnetwork::IpNetwork;
use moto_sys_io::api_net::NetCmd;
use smoltcp::wire::{IpCidr, IpEndpoint, Ipv4Cidr, Ipv6Cidr};
use std::cell::RefCell;
use std::net::SocketAddr;
use std::{
    io::{ErrorKind, Result},
    net::{IpAddr, Ipv4Addr},
    rc::Rc,
};
use virtio_async::virtio_net::NetDevice;

mod config;
mod udp;

enum SmoltcpDevice {
    // VirtIo(VirtioSmoltcpDevice),
    Loopback(smoltcp::phy::Loopback),
}

impl SmoltcpDevice {
    fn ethernet_address(&self) -> smoltcp::wire::EthernetAddress {
        match self {
            // Self::VirtIo(dev) => smoltcp::wire::EthernetAddress::from_bytes(dev.virtio_dev.mac()),
            Self::Loopback(_) => {
                smoltcp::wire::EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
            }
        }
    }
}

struct NetDev<'a> {
    name: String,
    config: config::DeviceCfg,

    device: SmoltcpDevice,
    iface: smoltcp::iface::Interface,
    sockets: smoltcp::iface::SocketSet<'a>,

    tcp_ports_in_use: std::collections::HashSet<u16>,
    udp_ports_in_use: std::collections::HashSet<u16>,

    notify: Rc<moto_async::LocalNotify>,
}

impl<'a> NetDev<'a> {
    fn new(name: &str, dev_cfg: &config::DeviceCfg, mut device: SmoltcpDevice) -> Self {
        let mut config = smoltcp::iface::Config::new(device.ethernet_address().into());
        config.random_seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|dur| dur.as_nanos() as u64)
            .unwrap_or(1234);

        let mut iface = match &mut device {
            // SmoltcpDevice::VirtIo(dev) => {
            //     smoltcp::iface::Interface::new(config, dev, smoltcp::time::Instant::now())
            // }
            SmoltcpDevice::Loopback(dev) => {
                smoltcp::iface::Interface::new(config, dev, smoltcp::time::Instant::now())
            }
        };

        iface.update_ip_addrs(|ip_addrs| {
            for cidr in &dev_cfg.cidrs {
                log::debug!(
                    "{}:{} added IP {:?} to {}",
                    file!(),
                    line!(),
                    cidr.ip(),
                    name
                );
                ip_addrs
                    .push(smoltcp::wire::IpCidr::new(
                        <smoltcp::wire::IpAddress as From<std::net::IpAddr>>::from(cidr.ip()),
                        cidr.prefix(),
                    ))
                    .unwrap();
            }
        });

        iface.routes_mut().update(|storage| {
            for route in &dev_cfg.routes {
                let rt = smoltcp::iface::Route {
                    cidr: ip_network_to_cidr(&route.ip_network),
                    via_router: route.gateway.into(),
                    preferred_until: None,
                    expires_at: None,
                };
                storage.push(rt).unwrap();
            }
        });

        Self {
            name: name.to_owned(),
            config: dev_cfg.clone(),
            device,
            iface,
            sockets: smoltcp::iface::SocketSet::new(vec![]),
            tcp_ports_in_use: std::collections::HashSet::new(),
            udp_ports_in_use: std::collections::HashSet::new(),
            notify: Rc::new(moto_async::LocalNotify::default()),
        }
    }
}

fn socket_addr_from_endpoint(endpoint: IpEndpoint) -> SocketAddr {
    let addr: IpAddr = endpoint.addr.into();
    SocketAddr::new(addr, endpoint.port)
}

fn ip_network_to_cidr(ip_network: &IpNetwork) -> IpCidr {
    match ip_network {
        IpNetwork::V4(network) => IpCidr::Ipv4(Ipv4Cidr::new(network.ip(), network.prefix())),
        IpNetwork::V6(network) => IpCidr::Ipv6(Ipv6Cidr::new(network.ip(), network.prefix())),
    }
}

fn addr_to_octets(addr: std::net::IpAddr) -> [u8; 16] {
    match addr {
        IpAddr::V4(addr) => {
            // Map IPv4 to IPv6.
            let mut octets = [0_u8; 16];
            let octets_4 = addr.octets();
            octets[10] = 255;
            octets[11] = 255;
            octets[12] = octets_4[0];
            octets[13] = octets_4[1];
            octets[14] = octets_4[2];
            octets[15] = octets_4[3];
            octets
        }
        IpAddr::V6(addr) => addr.octets(),
    }
}

pub(super) async fn init(
    devices: Vec<virtio_async::VirtioDevice>,
    fs: Rc<moto_async::LocalMutex<super::fs::FS>>,
) -> Result<()> {
    let cfg = config::load(fs).await?;
    log::debug!("NET cfg loaded OK.");

    let mut devices = vec![];

    if cfg.loopback {
        let mut loopback_cfg = config::DeviceCfg::new("02:00:00:00:00:01");
        loopback_cfg
            .cidrs
            .push(ipnetwork::IpNetwork::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8).unwrap());
        loopback_cfg
            .cidrs
            .push(ipnetwork::IpNetwork::V6("::1/128".parse().unwrap()));
        let loopback_dev = smoltcp::phy::Loopback::new(smoltcp::phy::Medium::Ethernet);
        let dev = NetDev::new(
            "loopback",
            &loopback_cfg,
            SmoltcpDevice::Loopback(loopback_dev),
        );
        devices.push(Rc::new(RefCell::new(dev)));
    }

    log::warn!("TODO: initialize virtio devices");

    if devices.is_empty() {
        return Ok(());
    }

    spawn_net_runtime(devices.clone()).await;
    log::info!("NET runtime started");
    smoke_test(devices).await;

    Ok(())
}

async fn spawn_net_runtime(devices: Vec<Rc<RefCell<NetDev<'static>>>>) {
    const NUM_LISTENERS: usize = 8;

    for device in &devices {
        spawn_device_runtime(device.clone());
    }

    for _ in 0..NUM_LISTENERS {
        spawn_new_listener(devices.clone()).await;
    }

    // Note: we must not return until there is a started listener,
    //       otherwise the FS is not yet functional.
}

fn spawn_device_runtime(device: Rc<RefCell<NetDev<'static>>>) {
    let _ = moto_async::LocalRuntime::spawn(async move {
        loop {
            let activity = {
                let mut device = device.borrow_mut();
                let NetDev {
                    name,
                    config,
                    device,
                    iface,
                    sockets,
                    tcp_ports_in_use,
                    udp_ports_in_use,
                    notify,
                } = &mut *device;
                match device {
                    SmoltcpDevice::Loopback(loopback) => {
                        iface.poll(smoltcp::time::Instant::now(), loopback, sockets)
                    }
                }
            };

            match activity {
                smoltcp::iface::PollResult::None => {
                    // futures::select! {
                    //     _ = device.wait_readable() => {}
                    //     _ = notify.notified() => {}
                    // }
                    let notify = device.borrow().notify.clone();
                    notify.notified().await;
                }
                smoltcp::iface::PollResult::SocketStateChanged => {
                    // Yield back to the executor: this allows the awakened socket tasks
                    // to run and read their data.
                    moto_async::yield_now().await;
                }
            }
        }
    });
}

async fn spawn_new_listener(devices: Vec<Rc<RefCell<NetDev<'static>>>>) {
    let (started_tx, started_rx) = moto_async::oneshot();
    let (connected_tx, connected_rx) = moto_async::oneshot();

    moto_async::LocalRuntime::spawn(async move {
        let _ = net_listener(devices.clone(), started_tx, connected_tx).await;
        // Spawn an extra one once the previous one is connected.
        let _ = connected_rx.await;
        spawn_new_listener(devices).await;
    });

    // Note: we must not return until there is a started listener,
    //       otherwise the FS is not yet functional.
    let _ = started_rx.await;
}

async fn net_listener(
    devices: Vec<Rc<RefCell<NetDev<'static>>>>,
    started_tx: moto_async::oneshot::Sender<()>,
    connected_tx: moto_async::oneshot::Sender<()>,
) -> Result<()> {
    let mut listener = core::pin::pin!(moto_ipc::io_channel::listen("sys-io"));

    // Do a poll to ensure the listener has started listening.
    let (sender, mut receiver) =
        match core::future::poll_fn(|cx| match listener.as_mut().poll(cx) {
            std::task::Poll::Ready(res) => std::task::Poll::Ready(Some(res)),
            std::task::Poll::Pending => std::task::Poll::Ready(None),
        })
        .await
        {
            Some(res) => res,
            None => {
                let _ = started_tx.send(());
                listener.await
            }
        }
        .map_err(|err| std::io::Error::from_raw_os_error(err as u16 as i32))?;
    let _ = connected_tx.send(());

    log::debug!("new NET connection 0x{:x}", sender.remote_handle().as_u64());

    // We want to process more than one message at at time (due to I/O waits), but
    // we don't want to have unlimited concurrency, we want backpressure.
    //
    // I tried to convert the receiver to a futures::Stream (via futures::stream::unfold()),
    // and then use futures::stream::for_each_concurrent, but this didn't work
    // with our runtime (maybe there is a bug in our runtime, maybe in for_each_concurrent).
    // (N.B.: futures::stream::for_each works).
    //
    // So we are using mpsc to implement "tickets".

    const MAX_IN_FLIGHT: usize = 64;
    let (ticket_tx, mut ticket_rx) = moto_async::channel(MAX_IN_FLIGHT);
    // Pre-populate.
    for _ in 0..MAX_IN_FLIGHT {
        let _ = ticket_tx.send(()).await;
    }

    loop {
        let _ticket = ticket_rx.recv().await;

        // Now that we have a ticket, we can poll for msg.
        match receiver.recv().await {
            Ok(msg) => {
                let sender = sender.clone();
                let devices = devices.clone();
                let ticket_tx = ticket_tx.clone();
                moto_async::LocalRuntime::spawn(async move {
                    on_msg(msg, sender, devices).await;
                    let _ = ticket_tx.send(()).await;
                });
            }
            Err(err) => {
                log::debug!(
                    "NET connection 0x{:x} done.",
                    sender.remote_handle().as_u64()
                );
                return Err(std::io::Error::from_raw_os_error(err as u16 as i32));
            }
        }
    }
}

async fn on_msg(
    msg: moto_ipc::io_channel::Msg,
    sender: moto_ipc::io_channel::Sender,
    devices: Vec<Rc<RefCell<NetDev<'static>>>>,
) {
    let Ok(net_cmd) = NetCmd::try_from(msg.command) else {
        let remote_handle = sender.remote_handle();

        #[cfg(debug_assertions)]
        log::debug!(
            "unrecognized command {} from endpoint 0x{:x}.",
            msg.command,
            remote_handle.as_u64()
        );

        let _ = moto_sys::SysCpu::kill_remote(remote_handle);
        return;
    };

    match net_cmd {
        NetCmd::UdpSocketBind => todo!(),

        // moto_sys_io::api_fs::CMD_MOVE_ENTRY => on_cmd_move_entry(msg, &sender, fs).await,
        cmd => {
            log::warn!(
                "Unrecognized NET command: {cmd:?} from endpoint 0x{:x}.",
                sender.remote_handle().as_u64()
            );
            let _ = moto_sys::SysCpu::kill_remote(sender.remote_handle());
            return;
        }
    }
}

async fn smoke_test(devices: Vec<Rc<RefCell<NetDev<'static>>>>) {
    let loopback = devices[0].clone();
    assert_eq!(loopback.borrow().name.as_str(), "loopback");

    let server_socket = udp::RawUdpSocket::bind(loopback.clone(), 8000);

    moto_async::LocalRuntime::spawn(async move {
        let mut buf = [0u8; 1024];
        let (len, endpoint) = server_socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"PING");
        server_socket.send_to(b"PONG", endpoint).await.unwrap();
    });

    // Yield to ensure the host server is actively listening before we send.
    // moto_async::yield_now().await;

    // 3. Setup Motor OS as the Client
    let client_socket = udp::RawUdpSocket::bind(loopback.clone(), 9000);
    let server_endpoint =
        smoltcp::wire::IpEndpoint::new(smoltcp::wire::IpAddress::v4(127, 0, 0, 1), 8000);

    client_socket
        .send_to(b"PING", server_endpoint)
        .await
        .unwrap();

    let mut motor_buf = [0u8; 1024];
    let (len, _src) = client_socket.recv_from(&mut motor_buf).await.unwrap();

    assert_eq!(&motor_buf[..len], b"PONG");

    log::info!("\n\nasync net smoke test pass!\n\n");
}
