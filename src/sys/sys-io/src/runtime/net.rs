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

struct ClientConnection {
    sender: moto_ipc::io_channel::Sender,
    sockets: HashSet<u64>,
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

        #[cfg(debug_assertions)]
        self.smoke_test().await;

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
                        if let Some(delay) =
                            this.inner.borrow_mut().devices[device_idx].poll_delay()
                        {
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
        let (connected_tx, connected_rx) = moto_async::oneshot();

        let this = self.clone();
        moto_async::LocalRuntime::spawn(async move {
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
            let mut resp = msg;
            resp.status = map_err_into_native(err).into();
            // Ignore errors below because it will be handled when the caller calls recv() next.
            let _ = sender.send(resp).await;
        }
    }

    #[cfg(debug_assertions)]
    async fn smoke_test(&self) {
        log::info!("NET smoke test SKIPPED.");
        /*
        log::info!("NET smoke test starting.");

        let loopback_idx = *self.inner.borrow_mut().device_map.get("loopback").unwrap();
        let server_addr = "127.0.0.1:8000".parse().unwrap();
        self.inner.borrow_mut().devices[loopback_idx]
            .add_udp_addr_in_use(server_addr)
            .unwrap();
        let server_socket =
            socket::MotoSocket::create_udp_socket(self, loopback_idx, server_addr, 0.into(), 0);

        moto_async::LocalRuntime::spawn(async move {
            let mut buf = [0u8; 1024];
            let (len, endpoint) = server_socket.udp_recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], b"PING");
            server_socket.udp_send_to(b"PONG", endpoint).await.unwrap();
        });

        // Yield to ensure the host server is actively listening before we send.
        // moto_async::yield_now().await;

        // 3. Setup Motor OS as the Client
        let client_addr = "127.0.0.1:9000".parse().unwrap();
        self.inner.borrow_mut().devices[loopback_idx]
            .add_udp_addr_in_use(client_addr)
            .unwrap();
        let client_socket =
            socket::MotoSocket::create_udp_socket(self, loopback_idx, client_addr, 0.into(), 0);
        let server_endpoint =
            smoltcp::wire::IpEndpoint::new(smoltcp::wire::IpAddress::v4(127, 0, 0, 1), 8000);

        client_socket
            .udp_send_to(b"PING", server_endpoint)
            .await
            .unwrap();

        let mut motor_buf = [0u8; 1024];
        let (len, _src) = client_socket.udp_recv_from(&mut motor_buf).await.unwrap();

        assert_eq!(&motor_buf[..len], b"PONG");
        log::info!("NET smoke test PASS.");
        */
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
