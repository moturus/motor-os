use ipnetwork::IpNetwork;
use moto_sys::SysHandle;
use moto_sys_io::api_net::{self, NetCmd};
use smoltcp::wire::{IpCidr, IpEndpoint, Ipv4Cidr, Ipv6Cidr};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::{
    io::{ErrorKind, Result},
    net::{IpAddr, Ipv4Addr},
    rc::Rc,
};

use crate::util::map_err_into_native;

mod config;
mod device;
mod socket;
mod tcp_listener;

struct ClientConnection {
    sender: moto_ipc::io_channel::Sender,
    sockets: HashSet<u64>,
    tcp_listeners: HashSet<u64>,
}

impl Drop for ClientConnection {
    fn drop(&mut self) {
        assert!(self.sockets.is_empty());
    }
}

impl ClientConnection {
    fn new(sender: moto_ipc::io_channel::Sender) -> Self {
        Self {
            sender,
            sockets: HashSet::new(),
            tcp_listeners: HashSet::new(),
        }
    }
}

/// Net Runtime. Contains (owns) sockets, devices, client connections.
/// All of them directly owned (rather than via Rc<RefCell>), as
/// we never hold a reference over .await, and any cross-references
/// happen via Rc<RefCell<NetRuntime>>.
struct NetRuntimeInner {
    config: config::NetConfig,
    next_socket_id: u64,

    sockets: HashMap<u64, Rc<RefCell<socket::MotoSocket>>>,
    tcp_listeners: HashMap<u64, Rc<RefCell<tcp_listener::TcpListener>>>,

    // In the future, Motor OS may use Vec<Option<NetDev>>, but at the moment
    // Motor OS does not support device hot (un)plug.
    devices: Vec<device::NetDev<'static>>,

    // Dev name => Dev idx in Self::devices.
    device_map: HashMap<String, usize>,

    // IP => Dev idx.
    ip_addresses: HashMap<IpAddr, usize>,

    clients: HashMap<SysHandle, ClientConnection>,
}

impl NetRuntimeInner {
    fn next_socket_id(&mut self) -> u64 {
        let result = self.next_socket_id;
        self.next_socket_id += 1;
        result
    }

    fn get_ephemeral_tcp_port(
        &mut self,
        runtime: &NetRuntime,
        device_idx: usize,
        ip_addr: IpAddr,
    ) -> Option<Rc<EphemeralTcpPort>> {
        let local_port = self.devices[device_idx].get_ephemeral_tcp_port(&ip_addr)?;
        Some(Rc::new(EphemeralTcpPort {
            dev_idx: device_idx,
            port: local_port,
            runtime: runtime.clone(),
        }))
    }
}

#[derive(Clone)]
struct NetRuntime {
    inner: Rc<RefCell<NetRuntimeInner>>,
}

impl NetRuntime {
    async fn spawn_net_runtime(&self) {
        const NUM_LISTENERS: usize = 8;

        let num_devices = self.inner.borrow().devices.len();

        for idx in 0..num_devices {
            self.spawn_device_runtime(idx);
        }

        for _ in 0..NUM_LISTENERS {
            self.spawn_new_listener().await;
        }

        // Note: we must not return until there is a started listener.
    }

    fn spawn_device_runtime(&self, device_idx: usize) {
        let this = self.clone();

        let _ = moto_async::LocalRuntime::spawn(async move {
            let notify = this.inner.borrow().devices[device_idx].notify.clone();

            loop {
                let activity = this.inner.borrow_mut().devices[device_idx].poll();
                match activity {
                    smoltcp::iface::PollResult::None => {
                        let delay = this.inner.borrow_mut().devices[device_idx].poll_delay();
                        // Note: we cannot move the op from the previous line into the if
                        // condition below, because Rust will keep this.inner borrowed for
                        // the duration of the 'if'.
                        if let Some(delay) = delay {
                            use futures::FutureExt;

                            futures::select! {
                            _ = notify.notified().fuse() => (),
                            _ = moto_async::sleep(delay).fuse() => (),
                            }
                        } else {
                            notify.notified().await;
                        }
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

    async fn spawn_new_listener(&self) {
        let (started_tx, started_rx) = moto_async::oneshot();

        let this = self.clone();
        moto_async::LocalRuntime::spawn(async move {
            let (connected_tx, connected_rx) = moto_async::oneshot();
            let _ = this.net_listener(started_tx, connected_tx).await;
            // Spawn an extra one once the previous one is connected.
            let _ = connected_rx.await;
            this.spawn_new_listener().await;
        });

        // Note: we must not return until there is a started listener,
        //       otherwise the FS is not yet functional.
        let _ = started_rx.await;
    }

    async fn net_listener(
        &self,
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

        self.inner.borrow_mut().clients.insert(
            sender.remote_handle(),
            ClientConnection::new(sender.clone()),
        );
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
                    let this = self.clone();
                    let ticket_tx = ticket_tx.clone();
                    moto_async::LocalRuntime::spawn(async move {
                        this.on_msg(msg, sender).await;
                        let _ = ticket_tx.send(()).await;
                    });
                }
                Err(err) => {
                    self.on_connection_done(sender.remote_handle());
                    log::debug!(
                        "NET connection 0x{:x} done.",
                        sender.remote_handle().as_u64()
                    );

                    return Err(std::io::Error::from_raw_os_error(err as u16 as i32));
                }
            }
        }
    }

    fn get_sender(&self, conn_id: SysHandle) -> Option<moto_ipc::io_channel::Sender> {
        let mut inner = self.inner.borrow();
        inner.clients.get(&conn_id).map(|conn| conn.sender.clone())
    }

    fn on_connection_done(&self, conn_id: SysHandle) {
        let mut inner = self.inner.borrow_mut();
        let mut client = inner.clients.remove(&conn_id).unwrap();

        let mut sockets = Vec::with_capacity(client.sockets.len());
        for socket_id in client.sockets.drain() {
            sockets.push(inner.sockets.remove(&socket_id).unwrap());
        }
        drop(inner);

        log::debug!(
            "NET conn {} dropped with {} sockets.",
            conn_id.as_u64(),
            sockets.len()
        );
    }

    // Find the device to route through.
    fn find_route(&self, ip_addr: &IpAddr) -> Option<(usize, IpAddr)> {
        let inner = self.inner.borrow();

        // First, look through local addresses.
        if let Some(device_idx) = inner.ip_addresses.get(ip_addr) {
            return Some((*device_idx, *ip_addr));
        }

        // If not found, look through routes.
        let (dev_name, ip_addr) = inner.config.find_route(ip_addr)?;

        inner
            .devices
            .iter()
            .position(|dev| dev.name() == dev_name)
            .map(|dev_idx| (dev_idx, ip_addr))
    }

    fn get_ephemeral_tcp_port(
        &self,
        device_idx: usize,
        ip_addr: IpAddr,
    ) -> Option<Rc<EphemeralTcpPort>> {
        let local_port =
            self.inner.borrow_mut().devices[device_idx].get_ephemeral_tcp_port(&ip_addr)?;
        Some(Rc::new(EphemeralTcpPort {
            dev_idx: device_idx,
            port: local_port,
            runtime: self.clone(),
        }))
    }

    async fn on_msg(&self, msg: moto_ipc::io_channel::Msg, sender: moto_ipc::io_channel::Sender) {
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

        log::debug!("Got msg {net_cmd:?} for handle 0x{:x}", msg.handle);

        if let Err(err) = match net_cmd {
            NetCmd::TcpListenerBind => tcp_listener::TcpListener::bind(self, msg, &sender).await,
            NetCmd::TcpListenerAccept => {
                tcp_listener::TcpListener::accept(self, msg, &sender).await
            }

            NetCmd::TcpStreamConnect => socket::MotoSocket::tcp_connect(self, msg, &sender).await,
            NetCmd::TcpStreamTx => socket::MotoSocket::tcp_tx(self, msg, &sender).await,
            NetCmd::TcpStreamRxAck => {
                socket::MotoSocket::tcp_rx_ack_received(self, msg, &sender).await
            }
            NetCmd::TcpStreamClose => socket::MotoSocket::tcp_close(self, msg, &sender).await,

            NetCmd::UdpSocketBind => socket::MotoSocket::udp_bind(self, msg, &sender).await,
            NetCmd::UdpSocketTxRx => socket::MotoSocket::udp_tx(self, msg, &sender).await,
            NetCmd::UdpSocketDrop => socket::MotoSocket::udp_socket_drop(self, msg, &sender).await,

            cmd => {
                log::warn!(
                    "Unrecognized NET command: {cmd:?} from endpoint 0x{:x}.",
                    sender.remote_handle().as_u64()
                );
                let _ = moto_sys::SysCpu::kill_remote(sender.remote_handle());
                return;
            }
        } {
            log::debug!(
                "Cmd {net_cmd:?} for conn 0x{:x} failed: {err:?}.",
                sender.remote_handle().as_u64()
            );
            let mut resp = msg;
            resp.status = map_err_into_native(err).into();
            // Ignore errors below because it will be handled when the caller calls recv() next.
            let _ = sender.send(resp).await;
        }
    }
}

/// Initialize NetRuntime (and spawn runtime tasks in the current local executor).
/// Takes filesystem parameter to read net config.
pub(super) async fn init(
    devices: Vec<virtio_async::VirtioDevice>,
    fs: Rc<moto_async::LocalMutex<super::fs::FS>>,
) -> Result<()> {
    let config = config::load(fs).await?;
    log::debug!("NET cfg loaded OK.");

    let mut devices = vec![];

    if config.loopback {
        let mut loopback_cfg = config::DeviceCfg::new("02:00:00:00:00:01");
        loopback_cfg
            .cidrs
            .push(ipnetwork::IpNetwork::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8).unwrap());
        loopback_cfg
            .cidrs
            .push(ipnetwork::IpNetwork::V6("::1/128".parse().unwrap()));
        let loopback_dev = smoltcp::phy::Loopback::new(smoltcp::phy::Medium::Ethernet);
        let dev = device::NetDev::new(
            "loopback",
            &loopback_cfg,
            device::SmoltcpDevice::Loopback(loopback_dev),
        );
        devices.push(dev);
    }

    log::warn!("TODO: initialize virtio devices");

    if devices.is_empty() {
        return Ok(());
    }

    let mut device_map = HashMap::new();
    let mut device_idx = 0;
    let mut ip_addresses = HashMap::new();
    for device in &devices {
        assert!(
            device_map
                .insert(device.name().to_owned(), device_idx)
                .is_none()
        );
        for address in device.ip_addesses() {
            ip_addresses.insert(address, device_idx);
        }
        device_idx += 1;
    }

    let runtime = NetRuntime {
        inner: Rc::new(RefCell::new(NetRuntimeInner {
            config,
            next_socket_id: 1,
            sockets: HashMap::new(),
            tcp_listeners: HashMap::new(),
            devices,
            device_map,
            ip_addresses,
            clients: HashMap::new(),
        })),
    };

    runtime.spawn_net_runtime().await;
    log::debug!("NET runtime started");

    Ok(())
}

struct EphemeralTcpPort {
    pub dev_idx: usize,
    pub port: u16,
    pub runtime: NetRuntime,
}

impl Drop for EphemeralTcpPort {
    fn drop(&mut self) {
        let mut inner = self.runtime.inner.borrow_mut();
        inner.devices[self.dev_idx].free_ephemeral_tcp_port(self.port);
    }
}
