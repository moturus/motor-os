use ipnetwork::IpNetwork;
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
mod udp;

/// Net Runtime. Contains (owns) sockets, devices, client connections.
/// All of them directly owned (rather than via Rc<RefCell>), as
/// we never hold a reference over .await, and any cross-references
/// happen via Rc<RefCell<NetRuntime>>.
struct NetRuntimeInner {
    config: config::NetConfig,
    next_socket_id: u64,
    sockets: HashMap<u64, socket::MotoSocket>,

    // In the future, Motor OS may use Vec<Option<NetDev>>, but at the moment
    // Motor OS does not support device hot (un)plug.
    devices: Vec<device::NetDev<'static>>,

    // Dev name => Dev idx in Self::devices.
    device_map: HashMap<String, usize>,

    // IP => Dev idx.
    ip_addresses: HashMap<IpAddr, usize>,

    udp_addresses_in_use: HashSet<SocketAddr>,
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

        // Note: we must not return until there is a started listener,
        //       otherwise the FS is not yet functional.
    }

    fn spawn_device_runtime(&self, device_idx: usize) {
        let this = self.clone();

        let _ = moto_async::LocalRuntime::spawn(async move {
            let notify = this.inner.borrow().devices[device_idx].notify.clone();

            loop {
                let activity = this.inner.borrow_mut().devices[device_idx].poll();
                match activity {
                    smoltcp::iface::PollResult::None => {
                        // futures::select! {
                        //     _ = device.wait_readable() => {}
                        //     _ = notify.notified() => {}
                        // }
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
                    log::debug!(
                        "NET connection 0x{:x} done.",
                        sender.remote_handle().as_u64()
                    );
                    return Err(std::io::Error::from_raw_os_error(err as u16 as i32));
                }
            }
        }
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

        if let Err(err) = match net_cmd {
            NetCmd::UdpSocketBind => self.udp_socket_bind(msg, &sender),

            // moto_sys_io::api_fs::CMD_MOVE_ENTRY => on_cmd_move_entry(msg, &sender, fs).await,
            cmd => {
                log::warn!(
                    "Unrecognized NET command: {cmd:?} from endpoint 0x{:x}.",
                    sender.remote_handle().as_u64()
                );
                let _ = moto_sys::SysCpu::kill_remote(sender.remote_handle());
                return;
            }
        } {
            let resp =
                moto_sys_io::api_fs::empty_resp_encode(msg.id, Err(map_err_into_native(err)));
            let _ = sender.send(resp).await;
        }
    }

    fn udp_socket_bind(
        &self,
        msg: moto_ipc::io_channel::Msg,
        sender: &moto_ipc::io_channel::Sender,
    ) -> Result<Option<moto_ipc::io_channel::Msg>> {
        todo!()
        /*
        let mut socket_addr = api_net::get_socket_addr(&msg.payload);
        let inner = self.inner.borrow_mut();
        let mut resp = msg;

        if inner.udp_addresses_in_use.contains(&socket_addr) {
            resp.status = moto_rt::E_ALREADY_IN_USE;
            return Ok(Some(resp));
        }

        // Verify that the IP is valid (if present) before the socket is created.
        let ip_addr = socket_addr.ip();

        if ip_addr.is_unspecified() {
            // We don't allow binding to an unspecified addr (yet?).
            resp.status = moto_rt::E_INVALID_ARGUMENT;
            return Ok(Some(resp));
        }
        let device_idx = {
            match inner.ip_addresses.get(&ip_addr) {
                Some(idx) => *idx,
                None => {
                    #[cfg(debug_assertions)]
                    log::debug!("IP addr {ip_addr:?} not found");

                    resp.status = moto_rt::E_INVALID_ARGUMENT;
                    return Ok(Some(resp));
                }
            }
        };

        // Allocate/assign port, if needed.
        let mut allocated_port = None;
        if socket_addr.port() == 0 {
            let local_port = match inner.devices[device_idx].get_ephemeral_udp_port(&ip_addr) {
                Some(port) => port,
                None => {
                    log::warn!("get_ephemeral_udp_port({ip_addr:?}) failed");

                    resp.status = moto_rt::E_OUT_OF_MEMORY;
                    return Ok(Some(resp));
                }
            };
            socket_addr.set_port(local_port);
            api_net::put_socket_addr(&mut resp.payload, &socket_addr);
            allocated_port = Some(local_port);
        }

        let Ok(udp_socket) = self.new_udp_socket_for_device(
            device_idx,
            conn.clone(),
            socket_addr,
            api_net::io_subchannel_mask(sqe.payload.args_8()[23]),
        ) else {
            if let Some(port) = allocated_port {
                inner.devices[device_idx].free_ephemeral_udp_port(port);
            }
            resp.status = moto_rt::E_INVALID_ARGUMENT;
            return Ok(Some(resp));
        };

        let udp_socket_id = udp_socket.id;
        self.socket_ids.insert(udp_socket.id);
        self.udp_addresses_in_use.insert(socket_addr);
        self.udp_sockets.insert(udp_socket.id, udp_socket);

        let conn_udp_sockets = match self.conn_udp_sockets.get_mut(&conn.wait_handle()) {
            Some(val) => val,
            None => {
                self.conn_udp_sockets
                    .insert(conn.wait_handle(), HashSet::new());
                self.conn_udp_sockets.get_mut(&conn.wait_handle()).unwrap()
            }
        };
        assert!(conn_udp_sockets.insert(udp_socket_id));

        #[cfg(debug_assertions)]
        log::debug!(
            "sys-io: new udp socket on {:?}, conn: 0x{:x}",
            socket_addr,
            conn.wait_handle().as_u64()
        );

        sqe.handle = udp_socket_id.into();
        sqe.status = moto_rt::E_OK;
        sqe
        */
    }

    #[cfg(debug_assertions)]
    async fn smoke_test(&self) {
        log::info!("NET smoke test starting.");

        let loopback_idx = *self.inner.borrow_mut().device_map.get("loopback").unwrap();
        let server_socket =
            udp::UdpSocket::bind(self, loopback_idx, "127.0.0.1:8000".parse().unwrap());

        moto_async::LocalRuntime::spawn(async move {
            let mut buf = [0u8; 1024];
            let (len, endpoint) = server_socket.udp_recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], b"PING");
            server_socket.udp_send_to(b"PONG", endpoint).await.unwrap();
        });

        // Yield to ensure the host server is actively listening before we send.
        // moto_async::yield_now().await;

        // 3. Setup Motor OS as the Client
        let client_socket =
            udp::UdpSocket::bind(self, loopback_idx, "127.0.0.1:9000".parse().unwrap());
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
    let mut pos = 0;
    for device in &devices {
        assert!(device_map.insert(device.name().to_owned(), pos).is_none());
        pos += 1;
    }

    let runtime = NetRuntime {
        inner: Rc::new(RefCell::new(NetRuntimeInner {
            config,
            next_socket_id: 1,
            sockets: HashMap::new(),
            devices,
            device_map,
            ip_addresses: Default::default(),
            udp_addresses_in_use: Default::default(),
        })),
    };

    runtime.spawn_net_runtime().await;
    log::info!("NET runtime started");

    Ok(())
}
