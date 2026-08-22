use ipnetwork::IpNetwork;
use moto_netstack::wire::{IpCidr, IpEndpoint, Ipv4Cidr, Ipv6Cidr};
use moto_sys::SysHandle;
use moto_sys_io::api_net::{self, NetCmd};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::{
    io::{ErrorKind, Result},
    net::{IpAddr, Ipv4Addr},
    rc::Rc,
};

use crate::runtime::channel_budget;
use crate::runtime::net::socket::MotoSocket;
use crate::util::map_err_into_native;

mod backlog;
mod completed;
mod config;
mod device;
mod half_open;
mod icmp;
mod pressure;
mod socket;
pub(crate) mod stats;
mod tcp_listener;

/// The net runtime's self-tests, gathered here because the modules holding them
/// are private to this one. See [`crate::self_test`].
#[cfg(debug_assertions)]
pub(crate) const SELF_TESTS: &[&[crate::self_test::SelfTest]] = &[
    backlog::self_test::TESTS,
    completed::self_test::TESTS,
    config::self_test::TESTS,
    device::self_test::TESTS,
    half_open::self_test::TESTS,
    stats::self_test::TESTS,
];

/// What a deferred listening-pool replenishment needs to resume: the oneshot
/// the replacement task is parked on (see `socket/tcp.rs`).
type HalfOpenBudget = half_open::HalfOpenBudget<moto_async::oneshot::Sender<()>>;

struct ClientConnection {
    sender: channel_budget::ClientSender,
    sockets: HashSet<u64>,
    tcp_listeners: HashSet<u64>,
    shutting_down: bool,
    pid: u64,
}

impl Drop for ClientConnection {
    fn drop(&mut self) {
        assert!(self.sockets.is_empty());
        assert!(self.tcp_listeners.is_empty());
    }
}

impl ClientConnection {
    fn new(sender: channel_budget::ClientSender) -> Self {
        Self {
            sender,
            sockets: HashSet::new(),
            tcp_listeners: HashSet::new(),
            shutting_down: false,
            pid: 0,
        }
    }
}

/// Net Runtime. Contains (owns) sockets, devices, client connections.
/// All of them directly owned (rather than via Rc<RefCell>), as
/// we never hold a reference over .await, and any cross-references
/// happen via Rc<RefCell<NetRuntime>>.
struct NetRuntimeInner {
    next_socket_id: u64,

    sockets: HashMap<u64, Rc<RefCell<socket::MotoSocket>>>,
    tcp_listeners: HashMap<u64, Rc<RefCell<tcp_listener::TcpListener>>>,

    // In the future, Motor OS may use Vec<Option<NetDev>>, but at the moment
    // Motor OS does not support device hot (un)plug.
    devices: Vec<device::NetDev<'static>>,

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
        let listeners = &self.tcp_listeners;
        let local_port = self.devices[device_idx].get_ephemeral_tcp_port(&ip_addr, |port| {
            let endpoint = SocketAddr::new(ip_addr, port);
            listeners
                .values()
                .any(|listener| listener.borrow().listens_on(endpoint, device_idx))
        })?;
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

    stats: Rc<stats::NetStats>,

    // Bounds the listening sockets waiting on unfinished handshakes.
    half_open: Rc<HalfOpenBudget>,

    // Sizes each listening pool against the bursts it actually meets.
    backlog: Rc<backlog::BacklogBudget>,

    // Bounds established sockets waiting for accept().
    completed: Rc<completed::CompletedBacklog>,

    // Refuses new memory-growing work while global availability is low.
    pressure: Rc<pressure::Pressure>,

    // Filesystem is used to write log/stats.
    fs: Rc<moto_async::LocalRwLock<super::fs::FS>>,

    channel_budget: Rc<channel_budget::ChannelBudget>,
}

impl NetRuntime {
    fn client_is_active(&self, handle: SysHandle) -> bool {
        self.inner
            .borrow()
            .clients
            .get(&handle)
            .is_some_and(|client| !client.shutting_down)
    }

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
            let notify = this.inner.borrow().devices[device_idx]
                .device_runtime_notify
                .clone();
            let name = this.inner.borrow().devices[device_idx].name().to_owned();

            // The timer armed for poll_delay(), kept across iterations. Under
            // load the notify branch below wins nearly every time, so arming a
            // fresh timer per iteration would queue -- and immediately cancel
            // -- ~80K timers/sec.
            let mut timer: Option<moto_async::Sleep> = None;

            loop {
                this.stats.poll_runs.set(this.stats.poll_runs.get() + 1);
                let activity =
                    this.inner.borrow_mut().devices[device_idx].poll(&this.stats, &this.backlog);
                // A poll that refused a connection request has just deepened
                // that listener's pool; the growth needs a way back.
                if this.backlog.needs_sweeper() {
                    backlog::spawn_sweeper(this.clone());
                }
                // Connections that verified SYN-cookie ACKs proved during
                // this poll: build each a socket into the accept path. Each
                // gets its own task -- the accept path can park on a slow
                // client's channel, which must not stall device polling.
                if this.inner.borrow().devices[device_idx].tcp_cookie_restores_pending() {
                    let restores =
                        this.inner.borrow_mut().devices[device_idx].take_tcp_cookie_restores();
                    for restore in restores {
                        let runtime = this.clone();
                        moto_async::LocalRuntime::spawn(async move {
                            socket::MotoSocket::create_tcp_restored_socket(
                                &runtime, device_idx, restore,
                            )
                            .await;
                        });
                    }
                }
                match activity {
                    moto_netstack::iface::PollResult::None => {
                        let delay = this.inner.borrow_mut().devices[device_idx].poll_delay();
                        // Note: we cannot move the op from the previous line into the if
                        // condition below, because Rust will keep this.inner borrowed for
                        // the duration of the 'if'.
                        if let Some(delay) = delay {
                            use futures::FutureExt;

                            // Re-arm only when the armed timer has fired, or
                            // would now fire too late: waking early just costs
                            // one extra poll() of an idle device, whereas
                            // waking late stalls it. Since poll_delay() is
                            // measured from now, an unchanged delay moves the
                            // deadline *later* every iteration, which is
                            // exactly the case this keeps out of the queue.
                            let now = moto_async::Instant::now();
                            let deadline = now + delay;
                            let reusable = timer.as_ref().is_some_and(|armed| {
                                armed.deadline() > now && armed.deadline() <= deadline
                            });
                            if !reusable {
                                timer = Some(moto_async::sleep_until(deadline));
                            }

                            // Dropping the select! only drops the borrow, so
                            // the timer stays armed for the next iteration.
                            let armed = timer.as_mut().unwrap();
                            futures::select! {
                            _ = notify.notified().fuse() => (),
                            _ = armed.fuse() => (),
                            }
                        } else {
                            notify.notified().await;
                        }
                    }
                    moto_netstack::iface::PollResult::SocketStateChanged => {
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
            // net_listener() replenishes the accept pool itself once a client
            // connects (before serving it), so a consumed listener is replaced
            // at connect time rather than at disconnect time. An Err is a
            // listener slot that did not turn into a served client -- arming
            // failed (at memory exhaustion `listen()`'s synchronous shared-
            // region map fails outright) or its client was refused -- so this
            // task keeps the slot, retrying with backoff rather than
            // spinning; the armed-listener floor below is what keeps clients
            // failing fast in the meantime.
            let mut started_tx = Some(started_tx);
            let mut backoff_ms = 10;
            loop {
                match this.net_listener(started_tx.take()).await {
                    Ok(()) => return,
                    Err(err) => {
                        log::debug!("net_listener() failed: {err:?}");
                        moto_async::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                        backoff_ms = (backoff_ms * 10).min(1000);
                    }
                }
            }
        });

        // Note: we must not return until there is a started listener,
        //       otherwise networking is not yet functional.
        let _ = started_rx.await;
    }

    /// The explicit no. This client connected, so it must never see the
    /// kernel's `NotFound` -- that is the one error its connect backoff
    /// retries through 10 s budgets (the 2026-08-10 bind-at-exhaustion
    /// crawl). Its first RPC is answered with `E_OUT_OF_MEMORY` and the
    /// channel closes; the wait is bounded so a client that never sends
    /// cannot pin the slot.
    async fn refuse_client(
        sender: moto_ipc::io_channel::Sender,
        mut receiver: moto_ipc::io_channel::Receiver,
    ) {
        use futures::FutureExt;

        let mut deadline =
            core::pin::pin!(moto_async::sleep(std::time::Duration::from_secs(2)).fuse());
        let mut first_rpc = core::pin::pin!(receiver.recv().fuse());
        futures::select! {
            msg = first_rpc => {
                if let Ok(msg) = msg {
                    let mut resp = msg;
                    resp.status = moto_rt::E_OUT_OF_MEMORY;
                    let _ = sender.send(resp).await;
                }
            }
            _ = deadline => {}
        }
    }

    async fn net_listener(
        &self,
        started_tx: Option<moto_async::oneshot::Sender<()>>,
    ) -> Result<()> {
        let mut listener = core::pin::pin!(moto_ipc::io_channel::listen("sys-io"));

        // Do a poll to ensure the listener has started listening.
        let (sender, mut receiver) = {
            let first_poll = core::future::poll_fn(|cx| match listener.as_mut().poll(cx) {
                std::task::Poll::Ready(res) => std::task::Poll::Ready(Some(res)),
                std::task::Poll::Pending => std::task::Poll::Ready(None),
            })
            .await;

            if let Some(started_tx) = started_tx {
                let _ = started_tx.send(());
            }

            match first_poll {
                Some(res) => res,
                None => {
                    // Armed: registered and parked for a client. The gauge is
                    // what the floor below reads -- while it is zero, every
                    // connect would answer `NotFound`.
                    let armed = &self.stats.net_listeners_armed;
                    armed.set(armed.get() + 1);
                    let res = listener.await;
                    armed.set(armed.get() - 1);
                    res
                }
            }
            .map_err(|err| std::io::Error::from_raw_os_error(err as u16 as i32))?
        };

        // The armed-listener floor: with no other listener armed (memory
        // exhaustion stopped replenishment), serving this client would leave
        // connects answering `NotFound`. Refuse it explicitly instead --
        // dropping the refused connection frees its channel pages, which is
        // exactly what this task's backoff retry needs to re-arm. Memory
        // pressure refuses the same way, now with the explicit error rather
        // than a silent drop.
        let at_floor = self.stats.net_listeners_armed.get() == 0;
        if at_floor || pressure::active() {
            if pressure::active() {
                self.pressure.client_refused();
            }
            self.stats
                .clients_refused
                .set(self.stats.clients_refused.get() + 1);
            Self::refuse_client(sender, receiver).await;
            return Err(ErrorKind::OutOfMemory.into());
        }

        // The wait-handle budget: past it, serving this channel would
        // eventually make the runtime thread's SysCpu::wait exceed the
        // kernel's handle cap, which is fatal (see channel_budget).
        let sender = match self.channel_budget.admit_net(sender) {
            Ok(sender) => sender,
            Err(sender) => {
                self.stats
                    .clients_refused
                    .set(self.stats.clients_refused.get() + 1);
                Self::refuse_client(sender, receiver).await;
                return Err(ErrorKind::OutOfMemory.into());
            }
        };

        self.inner.borrow_mut().clients.insert(
            sender.remote_handle(),
            ClientConnection::new(sender.clone()),
        );

        self.stats
            .active_clients
            .set(self.stats.active_clients.get() + 1);

        self.stats
            .total_clients
            .set(self.stats.total_clients.get() + 1);

        log::debug!("new NET connection 0x{:x}", sender.remote_handle().as_u64());

        // Replenish the accept pool now that this listener has a connection, so
        // NUM_LISTENERS bounds in-flight accepts rather than the number of
        // concurrent clients. Per the note in spawn_new_listener, this function
        // must not return Err below this point, or each disconnect would leak an
        // extra listener into the pool.
        self.spawn_new_listener().await;

        // We want to process more than one message at a time (due to I/O
        // waits), but with bounded concurrency for backpressure, so we use
        // mpsc "tickets".
        //
        // Historical note: for_each_concurrent used to hang here because
        // timer and SysHandle wakes bypassed nested combinator wakers. The
        // runtime stores wakers now, but the ticket loop stays: it keeps
        // the inline fast path below dispatchable per message.

        const MAX_IN_FLIGHT: usize = 64;
        let (ticket_tx, mut ticket_rx) = moto_async::channel(MAX_IN_FLIGHT);
        // Pre-populate.
        for _ in 0..MAX_IN_FLIGHT {
            let _ = ticket_tx.send(()).await;
        }

        loop {
            match receiver.recv().await {
                Ok(msg) => {
                    // Data-path fast path: TcpStreamTx and TcpStreamRxAck
                    // handlers complete synchronously (they never await;
                    // only the rare error-path response send can, which
                    // then just pauses this one client's ingress), so
                    // dispatch them inline — the per-message task spawn +
                    // ticket round-trip below costs a few µs, the dominant
                    // fixed cost of the TX data path (it is why TX messages
                    // are multi-page: fewer messages to spawn for).
                    if msg.command == (NetCmd::TcpStreamTx as u16)
                        || msg.command == (NetCmd::TcpStreamRxAck as u16)
                    {
                        self.on_msg(msg, sender.clone()).await;
                        continue;
                    }

                    // Control-path commands may genuinely await (accept,
                    // connect, close, ...), so they run as tasks; the
                    // tickets bound their concurrency.
                    let _ticket = ticket_rx.recv().await;
                    let sender = sender.clone();
                    let this = self.clone();
                    let ticket_tx = ticket_tx.clone();
                    moto_async::LocalRuntime::spawn(async move {
                        let remote_handle = sender.remote_handle();
                        if this.client_is_active(remote_handle) {
                            this.on_msg(msg, sender).await;
                        } else {
                            log::debug!(
                                "Dropping queued NET control message for closed connection 0x{:x}.",
                                remote_handle.as_u64()
                            );
                        }
                        let _ = ticket_tx.send(()).await;
                    });
                }
                Err(_) => {
                    self.on_connection_done(sender.remote_handle()).await;
                    log::debug!(
                        "NET connection 0x{:x} done.",
                        sender.remote_handle().as_u64()
                    );

                    // The replacement listener was already spawned at accept, so
                    // return Ok — returning Err would spawn a second one.
                    return Ok(());
                }
            }
        }
    }

    fn connection_pid(&self, conn_id: SysHandle) -> u64 {
        let mut inner = self.inner.borrow_mut();
        let Some(client) = inner.clients.get_mut(&conn_id) else {
            // Sockets can linger after their client is gone, so the pid may be unknown.
            return 0;
        };

        if client.pid == 0 {
            client.pid = moto_sys::SysObj::get_pid(conn_id).unwrap_or(0);
        }

        client.pid
    }

    async fn on_connection_done(&self, conn_id: SysHandle) {
        // First remove listeners, otherwise dropped listening sockets will spawn new ones.
        let mut tcp_listeners = {
            let mut inner = self.inner.borrow_mut();
            let client = inner.clients.get_mut(&conn_id).unwrap();
            if client.shutting_down {
                // Avoid concurrent shutdown routines.
                return;
            }
            client.shutting_down = true;
            let mut listener_ids = HashSet::new();
            core::mem::swap(&mut listener_ids, &mut client.tcp_listeners);

            let mut listeners = Vec::with_capacity(listener_ids.len());
            for listener_id in listener_ids.drain() {
                listeners.push(inner.tcp_listeners.remove(&listener_id).unwrap());
            }
            listeners
        };

        let listener_cnt = tcp_listeners.len();
        for mut tcp_listener in tcp_listeners {
            tcp_listener.borrow_mut().hard_reset();
        }
        // All listeners should be dropped by now.

        // Then remove sockets. Some may linger.
        let socket_cnt = {
            let mut socket_ids = {
                let mut inner = self.inner.borrow_mut();
                let client = inner.clients.get_mut(&conn_id).unwrap();

                let mut socket_ids = Vec::with_capacity(client.sockets.len());
                for socket_id in client.sockets.drain() {
                    socket_ids.push(socket_id);
                }

                socket_ids
            };

            // The client's socket set should mirror the runtime's. Nothing
            // has awaited since it was drained, so a missing entry is an
            // accounting defect -- but the loop below already tolerates one,
            // and it is not worth killing every other client over.
            for socket_id in &socket_ids {
                if self.inner.borrow().sockets.get(socket_id).is_none() {
                    log::error!(
                        "Client 0x{:x} listed unknown socket 0x{socket_id:x}.",
                        conn_id.as_u64()
                    );
                }
            }

            for socket_id in &socket_ids {
                // Because the loop below is asynchronous, removing one socket may trigger
                // another terminating/quitting, so not every client socket may be present.
                let maybe_tcp_socket = {
                    let socket = self.inner.borrow().sockets.get(socket_id).cloned();

                    socket.and_then(|moto_socket| {
                        if moto_socket.borrow().is_tcp() {
                            Some(moto_socket)
                        } else {
                            assert!(self.inner.borrow_mut().sockets.remove(socket_id).is_some());
                            None
                        }
                    })
                };
                if let Some(moto_socket) = maybe_tcp_socket {
                    MotoSocket::close_tcp_socket_inner(moto_socket, None).await;
                }
            }

            socket_ids.len()
        };

        // Finally, drop the client.
        let _ = self.inner.borrow_mut().clients.remove(&conn_id);

        self.stats
            .active_clients
            .set(self.stats.active_clients.get() - 1);

        log::debug!(
            "NET conn {} dropped with {} sockets and {} tcp listeners.",
            conn_id.as_u64(),
            socket_cnt,
            listener_cnt
        );
        // Note: client will drop here.
    }

    // Find the device to route through.
    fn find_route(&self, ip_addr: &IpAddr) -> Option<(usize, IpAddr)> {
        let inner = self.inner.borrow();

        // First, look through local addresses.
        if let Some(device_idx) = inner.ip_addresses.get(ip_addr) {
            return Some((*device_idx, *ip_addr));
        }

        config::find_route(
            inner
                .devices
                .iter()
                .enumerate()
                .map(|(device_idx, device)| (device_idx, device.config())),
            *ip_addr,
        )
    }

    fn get_ephemeral_tcp_port(
        &self,
        device_idx: usize,
        ip_addr: IpAddr,
    ) -> Option<Rc<EphemeralTcpPort>> {
        let local_port = self.inner.borrow_mut().devices[device_idx]
            .get_ephemeral_tcp_port(&ip_addr, |_| false)?;
        Some(Rc::new(EphemeralTcpPort {
            dev_idx: device_idx,
            port: local_port,
            runtime: self.clone(),
        }))
    }

    async fn on_msg(&self, msg: moto_ipc::io_channel::Msg, sender: channel_budget::ClientSender) {
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
            NetCmd::TcpListenerGetOption => {
                tcp_listener::TcpListener::get_option(self, msg, &sender).await
            }
            NetCmd::TcpListenerSetOption => {
                tcp_listener::TcpListener::set_option(self, msg, &sender).await
            }
            NetCmd::TcpListenerDrop => {
                tcp_listener::TcpListener::drop_from_client(self, msg, &sender).await
            }

            NetCmd::TcpStreamConnect => socket::MotoSocket::tcp_connect(self, msg, &sender).await,
            NetCmd::TcpStreamGetOption => {
                socket::MotoSocket::tcp_getsockopt(self, msg, &sender).await
            }
            NetCmd::TcpStreamSetOption => {
                socket::MotoSocket::tcp_setsockopt(self, msg, &sender).await
            }
            NetCmd::TcpStreamTx => socket::MotoSocket::tcp_tx(self, msg, &sender).await,
            NetCmd::TcpStreamRxAck => {
                socket::MotoSocket::tcp_rx_ack_received(self, msg, &sender).await
            }
            NetCmd::TcpStreamClose => socket::MotoSocket::tcp_close(self, msg, &sender).await,

            NetCmd::UdpSocketBind => socket::MotoSocket::udp_bind(self, msg, &sender).await,
            NetCmd::UdpSocketBindForRemote => {
                socket::MotoSocket::udp_bind_for_remote(self, msg, &sender).await
            }
            NetCmd::UdpSocketSetOption => {
                socket::MotoSocket::udp_setsockopt(self, msg, &sender).await
            }
            NetCmd::UdpSocketGetOption => {
                socket::MotoSocket::udp_getsockopt(self, msg, &sender).await
            }
            NetCmd::UdpSocketTxRx => socket::MotoSocket::udp_tx(self, msg, &sender).await,
            NetCmd::UdpSocketDrop => socket::MotoSocket::udp_socket_drop(self, msg, &sender).await,
            NetCmd::IcmpEcho => icmp::echo(self, msg, &sender).await,

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
    mut virtio_devices: Vec<Rc<virtio_async::virtio_net::NetDevice>>,
    fs: Rc<moto_async::LocalRwLock<super::fs::FS>>,
    channel_budget: Rc<channel_budget::ChannelBudget>,
) -> Result<()> {
    let config = config::load(&fs).await?;
    log::debug!("NET cfg loaded:\n{config:#?}.");

    // Created before the devices: their rx/tx tasks bump the device counters.
    let net_stats = Rc::new(stats::NetStats::default());

    let mut devices = vec![];

    if config.loopback {
        let mut loopback_cfg = config::DeviceCfg::new("02:00:00:00:00:01");
        loopback_cfg
            .cidrs
            .push(ipnetwork::IpNetwork::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8).unwrap());
        loopback_cfg
            .cidrs
            .push(ipnetwork::IpNetwork::V6("::1/128".parse().unwrap()));
        let loopback_dev = moto_netstack::phy::Loopback::new(moto_netstack::phy::Medium::Ip);
        let dev = device::NetDev::new(
            "loopback",
            &loopback_cfg,
            &config,
            device::NetstackDevice::Loopback(loopback_dev),
        );
        devices.push(dev);
    }

    for (device_name, device_cfg) in &config.devices {
        if let Some(pos) = virtio_devices
            .iter()
            .position(|dev| dev.mac() == &device_cfg.mac.raw())
        {
            let dev = virtio_devices.remove(pos);
            devices.push(device::NetDev::new(
                device_name,
                device_cfg,
                &config,
                device::NetstackDevice::VirtIo(device::VirtioDevice::new(dev, net_stats.clone())),
            ));
        } else {
            log::warn!("Cannot find NET device {device_cfg:?}.");
        }
    }

    for device in &virtio_devices {
        log::warn!("VirtioNET device {:?} not configured.", device.mac());
    }

    if devices.is_empty() {
        log::warn!(
            "NET runtime intentionally disabled: valid configuration produced zero usable devices."
        );
        return Ok(());
    }

    let mut device_idx = 0;
    let mut ip_addresses = HashMap::new();
    for device in &devices {
        for address in device.ip_addesses() {
            ip_addresses.insert(address, device_idx);
        }
        device_idx += 1;
    }

    let runtime = NetRuntime {
        inner: Rc::new(RefCell::new(NetRuntimeInner {
            next_socket_id: 1,
            sockets: HashMap::new(),
            tcp_listeners: HashMap::new(),
            devices,
            ip_addresses,
            clients: HashMap::new(),
        })),
        stats: net_stats.clone(),
        half_open: Rc::new(HalfOpenBudget::new(
            config.max_half_open_global,
            config.max_half_open_per_listener,
        )),
        backlog: Rc::new(backlog::BacklogBudget::new(
            net_stats.clone(),
            config.max_backlog_global,
            config.max_backlog_per_listener,
        )),
        completed: Rc::new(completed::CompletedBacklog::new(net_stats.clone())),
        pressure: Rc::new(pressure::Pressure::new(net_stats.clone())),
        fs: fs.clone(),
        channel_budget,
    };

    runtime.stats.num_devices.set(device_idx as u64);
    stats::spawn_stats_responder(runtime.clone());
    pressure::spawn_recovery(runtime.clone());

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
