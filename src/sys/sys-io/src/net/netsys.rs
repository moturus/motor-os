use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    rc::Rc,
    sync::Arc,
    time::Instant,
};

use crate::{net::netdev::EphemeralTcpPort, runtime::PendingCompletion};
use crate::{net::socket::UdpSocket, runtime::IoSubsystem};
use moto_ipc::io_channel;
use moto_sys::{ErrorCode, SysHandle};
use moto_sys_io::api_net::{self, TcpState};

use super::socket::SocketId;
use super::socket::{DeferredAction, TcpSocket};
use super::TcpRxBuf;
use super::{netdev::NetDev, TcpTxBuf};
use super::{smoltcp_helpers::socket_addr_from_endpoint, tcp_listener::TcpListenerId};
use super::{socket::SocketKind, tcp_listener::TcpListener};

// How many listening sockets to open (per specific SocketAddr).
const DEFAULT_NUM_LISTENING_SOCKETS: usize = 4;
const MAX_NUM_LISTENING_SOCKETS: usize = 32;
// How many concurrent connections per listener (any SocketAddr) to allow.
const _DEFAULT_MAX_CONNECTIONS_PER_LISTENER: usize = 16;

// TODO: make this configurable.
const MAX_TCP_SOCKET_CACHE_SIZE: usize = 32;

pub(super) struct NetSys {
    devices: Vec<NetDev>, // Never changes, as device_idx references inside here.
    wait_handles: HashMap<SysHandle, usize>, // Handle -> idx in self.devices.
    ip_addresses: HashMap<IpAddr, usize>,

    next_id: u64,

    pending_completions: VecDeque<PendingCompletion>,

    // NetSys owns all listeners, sockets, etc. in the system, via the hash maps below.
    tcp_listeners: HashMap<TcpListenerId, TcpListener>,
    tcp_sockets: HashMap<SocketId, TcpSocket>, // Active connections.
    udp_sockets: HashMap<SocketId, UdpSocket>,

    udp_addresses_in_use: HashSet<SocketAddr>,

    // An ordered list of all sockets in the system, to be used for stats reporting.
    socket_ids: std::collections::BTreeSet<SocketId>,

    // "Empty" sockets cached here.
    tcp_socket_cache: Vec<smoltcp::socket::tcp::Socket<'static>>,
    udp_socket_cache: Vec<smoltcp::socket::udp::Socket<'static>>,

    // Conn ID -> TCP listeners/sockets. Needed to e.g. protect one process
    // accessing another process's sockets, and to drop/clear when the process dies.
    conn_tcp_listeners: HashMap<SysHandle, HashSet<TcpListenerId>>,
    conn_tcp_sockets: HashMap<SysHandle, HashSet<SocketId>>,
    conn_udp_sockets: HashMap<SysHandle, HashSet<SocketId>>,

    woken_sockets: Rc<RefCell<VecDeque<SocketId>>>,
    wakers: std::collections::HashMap<SocketId, std::task::Waker>,

    rng: rand::rngs::SmallRng,
    deferred_sockets: timeq::TimeQ<SocketId>,

    // When a listener allocates an ephemeral port, the port is then shared
    // with the incoming tcp streams, so it is reference-counted. When the
    // last reference is dropped, it is added here to be released.
    ephemeral_tcp_ports_to_clear: crossbeam::queue::SegQueue<(usize, u16)>,

    config: super::config::NetConfig,
}

// We have one mutable reference that belongs to runtime, and one
// atomic/immutable reference here to short-circuit some (rare) ops.
static NET_SYS: std::sync::atomic::AtomicPtr<NetSys> =
    std::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

impl NetSys {
    pub fn new(config: super::config::NetConfig) -> Box<Self> {
        use rand::SeedableRng;

        let devices = super::netdev::init(&config);
        let self_ref = Box::new(Self {
            devices,
            wait_handles: HashMap::new(),
            ip_addresses: HashMap::new(),
            next_id: 1,
            tcp_listeners: HashMap::new(),
            tcp_sockets: HashMap::new(),
            udp_sockets: HashMap::new(),
            udp_addresses_in_use: HashSet::new(),
            socket_ids: std::collections::BTreeSet::new(),
            tcp_socket_cache: Vec::new(),
            udp_socket_cache: Vec::new(),
            pending_completions: VecDeque::new(),
            conn_tcp_listeners: HashMap::new(),
            conn_tcp_sockets: HashMap::new(),
            conn_udp_sockets: HashMap::new(),
            woken_sockets: Rc::new(std::cell::RefCell::new(VecDeque::new())),
            wakers: HashMap::new(),
            rng: rand::rngs::SmallRng::seed_from_u64(1337),
            deferred_sockets: timeq::TimeQ::default(),
            ephemeral_tcp_ports_to_clear: crossbeam::queue::SegQueue::new(),
            config,
        });

        let mut self_ref = unsafe {
            let self_ptr = Box::into_raw(self_ref);
            assert!(NET_SYS
                .swap(self_ptr, std::sync::atomic::Ordering::AcqRel)
                .is_null());
            Box::from_raw(self_ptr)
        };

        for idx in 0..self_ref.devices.len() {
            let device = &self_ref.devices[idx];
            for handle in device.wait_handles() {
                self_ref.wait_handles.insert(handle, idx);
            }
            for cidr in &device.dev_cfg().cidrs {
                self_ref.ip_addresses.insert(cidr.ip(), idx);
            }

            #[cfg(debug_assertions)]
            log::debug!("sys-io: initialized net device {}", device.name());
        }

        self_ref
    }

    fn get() -> &'static Self {
        unsafe {
            NET_SYS
                .load(std::sync::atomic::Ordering::Relaxed)
                .as_ref()
                .unwrap()
        }
    }

    fn tcp_listener_bind(
        &mut self,
        conn: &Rc<io_channel::ServerConnection>,
        mut sqe: io_channel::Msg,
    ) -> io_channel::Msg {
        if self.devices.is_empty() {
            sqe.status = moto_rt::E_NOT_FOUND;
            return sqe;
        }

        let mut socket_addr = api_net::get_socket_addr(&sqe.payload);

        // Verify that we are not listening on that address yet.
        for listener in self.tcp_listeners.values() {
            if *listener.socket_addr() == socket_addr {
                sqe.status = moto_rt::E_ALREADY_IN_USE;
                return sqe;
            }
        }

        // TODO: what if we are listening on *:PORT, and are asked to listen on IP:PORT?
        //       Maybe that's OK? A random listening socket will be picked up on an
        //       incoming connection.

        // Verify that the IP is valid (if present) before the listener is created.
        let ip_addr = socket_addr.ip();
        let device_idx: Option<usize> = if ip_addr.is_unspecified() {
            if socket_addr.port() == 0 {
                // We don't allow listening on an unspecified port if the IP is also unspecified.
                sqe.status = moto_rt::E_INVALID_ARGUMENT;
                return sqe;
            }
            None
        } else {
            match self.ip_addresses.get(&ip_addr) {
                Some(idx) => Some(*idx),
                None => {
                    #[cfg(debug_assertions)]
                    log::info!("IP addr {:?} not found", ip_addr);
                    sqe.status = moto_rt::E_INVALID_ARGUMENT;
                    return sqe;
                }
            }
        };

        let num_listeners = if sqe.flags == 0 {
            DEFAULT_NUM_LISTENING_SOCKETS
        } else {
            sqe.flags as usize
        };
        if num_listeners > MAX_NUM_LISTENING_SOCKETS {
            sqe.status = moto_rt::E_INVALID_ARGUMENT;
            return sqe;
        }

        // Allocate/assign port, if needed.
        let mut allocated_port = None;
        if socket_addr.port() == 0 {
            let local_port =
                match self.devices[device_idx.unwrap()].get_ephemeral_tcp_port(&ip_addr) {
                    Some(port) => port,
                    None => {
                        log::info!("get_ephemeral_port({:?}) failed", ip_addr);
                        sqe.status = moto_rt::E_OUT_OF_MEMORY;
                        return sqe;
                    }
                };
            socket_addr.set_port(local_port);
            api_net::put_socket_addr(&mut sqe.payload, &socket_addr);
            allocated_port = Some(Arc::new(EphemeralTcpPort {
                dev_idx: device_idx.unwrap(),
                port: local_port,
            }));
        }

        // Create TcpListener object.
        let listener_id: TcpListenerId = self.next_id(SocketKind::Tcp).into();
        let mut listener = TcpListener::new(conn.clone(), socket_addr);
        listener.ephemeral_tcp_port = allocated_port;
        self.tcp_listeners.insert(listener_id, listener);

        let conn_listeners = match self.conn_tcp_listeners.get_mut(&conn.wait_handle()) {
            Some(val) => val,
            None => {
                self.conn_tcp_listeners
                    .insert(conn.wait_handle(), HashSet::new());
                self.conn_tcp_listeners
                    .get_mut(&conn.wait_handle())
                    .unwrap()
            }
        };
        assert!(conn_listeners.insert(listener_id));

        #[cfg(debug_assertions)]
        log::debug!(
            "sys-io: new tcp listener on {:?}, conn: 0x{:x}",
            socket_addr,
            conn.wait_handle().as_u64()
        );

        // Start listening.
        match device_idx {
            None => {
                for idx in 0..self.devices.len() {
                    let cidrs = self.devices[idx].dev_cfg().cidrs.clone();
                    for cidr in &cidrs {
                        let local_addr = SocketAddr::new(cidr.ip(), socket_addr.port());
                        if let Err(err) = self.start_listening_on_device(
                            listener_id,
                            idx,
                            local_addr,
                            num_listeners,
                        ) {
                            assert!(self
                                .conn_tcp_listeners
                                .get_mut(&conn.wait_handle())
                                .unwrap()
                                .remove(&listener_id));
                            self.drop_tcp_listener(listener_id);
                            // TODO: maybe continue instead?
                            sqe.status = err;
                            return sqe;
                        }
                    }
                }
            }
            Some(device_idx) => {
                if let Err(err) = self.start_listening_on_device(
                    listener_id,
                    device_idx,
                    socket_addr,
                    num_listeners,
                ) {
                    assert!(self
                        .conn_tcp_listeners
                        .get_mut(&conn.wait_handle())
                        .unwrap()
                        .remove(&listener_id));
                    self.drop_tcp_listener(listener_id);

                    sqe.status = err;
                    return sqe;
                }
            }
        }

        sqe.handle = listener_id.into();
        sqe.status = moto_rt::E_OK;
        sqe
    }

    fn start_listening_on_device(
        &mut self,
        listener_id: TcpListenerId,
        device_idx: usize,
        socket_addr: SocketAddr,
        num_listeners: usize,
    ) -> Result<(), ErrorCode> {
        assert!(!socket_addr.ip().is_unspecified());

        for _ in 0..num_listeners {
            let (conn, ttl, shared_port) = {
                let listener = self.tcp_listeners.get_mut(&listener_id).unwrap();

                (
                    listener.conn().clone(),
                    listener.ttl(),
                    listener.ephemeral_tcp_port.clone(),
                )
            };
            let conn_handle = conn.wait_handle();
            let mut moto_socket = self.new_tcp_socket_for_device(device_idx, conn)?;
            let socket_id = moto_socket.id;
            moto_socket.listener_id = Some(listener_id);
            moto_socket.shared_ephemeral_port = shared_port;
            self.tcp_listeners
                .get_mut(&listener_id)
                .unwrap()
                .add_listening_socket(socket_id);
            moto_socket.state = TcpState::Listening;
            moto_socket.listening_on = Some(socket_addr);
            if let Some(conn_sockets) = self.conn_tcp_sockets.get_mut(&conn_handle) {
                conn_sockets.insert(moto_socket.id);
            } else {
                let mut conn_sockets = HashSet::new();
                conn_sockets.insert(moto_socket.id);
                self.conn_tcp_sockets.insert(conn_handle, conn_sockets);
            }

            let smol_handle = moto_socket.handle;
            self.socket_ids.insert(moto_socket.id);
            self.tcp_sockets.insert(moto_socket.id, moto_socket);

            let smol_socket = self.devices[device_idx]
                .sockets
                .get_mut::<smoltcp::socket::tcp::Socket>(smol_handle);
            smol_socket.set_hop_limit(Some(ttl));
            smol_socket
                .listen((socket_addr.ip(), socket_addr.port()))
                .map_err(|err| {
                    log::info!(
                        "{}:{} listen failed for address {:?}: {:?}",
                        file!(),
                        line!(),
                        socket_addr,
                        err
                    );
                    moto_rt::E_INVALID_ARGUMENT
                })?;
            log::debug!(
                "{}:{} started listener {:?} on device #{}",
                file!(),
                line!(),
                socket_addr,
                device_idx
            );
        }

        Ok(())
    }

    fn new_tcp_socket_for_device(
        &mut self,
        device_idx: usize,
        conn: Rc<io_channel::ServerConnection>,
    ) -> Result<TcpSocket, ErrorCode> {
        let pid = moto_sys::SysObj::get_pid(conn.wait_handle())?;

        let mut smol_socket = self.get_unused_tcp_socket();
        let socket_id = self.next_id(SocketKind::Tcp).into();

        let socket_waker = super::socket::SocketWaker::new(socket_id, self.woken_sockets.clone());
        let waker = unsafe { std::task::Waker::from_raw(socket_waker.into_raw_waker()) };
        smol_socket.register_recv_waker(&waker);
        smol_socket.register_send_waker(&waker);
        self.wakers.insert(socket_id, waker);

        let handle = self.devices[device_idx].sockets.add(smol_socket);

        log::debug!(
            "{}:{} new TCP socket 0x{:x}; {} active sockets.",
            file!(),
            line!(),
            u64::from(socket_id),
            self.tcp_sockets.len()
        );

        Ok(TcpSocket::new(socket_id, handle, device_idx, conn, pid))
    }

    fn new_udp_socket_for_device(
        &mut self,
        device_idx: usize,
        conn: Rc<io_channel::ServerConnection>,
        socket_addr: SocketAddr,
        subchannel_mask: u64,
    ) -> Result<UdpSocket, ErrorCode> {
        let pid = moto_sys::SysObj::get_pid(conn.wait_handle())?;

        let mut smol_socket = self.get_unused_udp_socket();
        if let Err(err) = smol_socket.bind((socket_addr.ip(), socket_addr.port())) {
            log::error!("smoltcp bind error: {:?}", err);
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        let socket_id = self.next_id(SocketKind::Udp).into();

        let socket_waker = super::socket::SocketWaker::new(socket_id, self.woken_sockets.clone());
        let waker = unsafe { std::task::Waker::from_raw(socket_waker.into_raw_waker()) };
        smol_socket.register_recv_waker(&waker);
        smol_socket.register_send_waker(&waker);
        self.wakers.insert(socket_id, waker);

        let handle = self.devices[device_idx].sockets.add(smol_socket);

        log::debug!(
            "{}:{} new UDP socket 0x{:x}; {} active sockets.",
            file!(),
            line!(),
            u64::from(socket_id),
            self.udp_sockets.len()
        );

        Ok(UdpSocket::new(
            socket_id,
            handle,
            device_idx,
            conn,
            pid,
            subchannel_mask,
            socket_addr,
        ))
    }

    fn drop_tcp_listener(&mut self, listener_id: TcpListenerId) {
        let mut listener = self.tcp_listeners.remove(&listener_id).unwrap();
        while let Some((mut req, conn)) = listener.get_pending_accept() {
            req.status = moto_rt::E_BAD_HANDLE;
            self.pending_completions.push_back(PendingCompletion {
                msg: req,
                endpoint_handle: conn.wait_handle(),
            });
        }

        while let Some((socket_id, _)) = listener.pop_pending_socket() {
            if self.tcp_sockets.contains_key(&socket_id) {
                self.drop_tcp_socket(socket_id);
            }
        }

        let ids = listener.take_listening_sockets();
        for id in ids {
            if self.tcp_sockets.contains_key(&id) {
                self.drop_tcp_socket(id);
            }
        }
    }

    fn drop_tcp_socket(&mut self, socket_id: SocketId) {
        let moto_socket = if let Some(s) = self.tcp_sockets.get_mut(&socket_id) {
            s
        } else {
            log::debug!("drop_tcp_socket: 0x{:x}: no socket", u64::from(socket_id));
            return;
        };
        moto_socket.tx_queue.clear();
        log::debug!(
            "dropping TCP socket 0x{:x}; RX done: {} TX done: {}",
            u64::from(socket_id),
            moto_socket.stats_rx_bytes,
            moto_socket.stats_tx_bytes
        );
        // moto_rt::error::log_backtrace(0);
        let smol_socket = self.devices[moto_socket.device_idx]
            .sockets
            .get_mut::<smoltcp::socket::tcp::Socket>(moto_socket.handle);

        smol_socket.abort();

        // Remove the waker so that any polls on the socket from below don't trigger
        // wakeups on the dropped socket.
        self.wakers.remove(&socket_id);

        // Poll the device to send the final RST. Otherwise smol_socket.abort() above
        // does nothing, and the remote connection is kept alive/hanging until it times out.
        // Need to poll all sockets on the device, not just the one being removed,
        // as on loopback devices the peer won't get notified.
        while self.devices[moto_socket.device_idx].poll() {}

        // Now we can remove moto_socket.
        let mut moto_socket = self.tcp_sockets.remove(&socket_id).unwrap();
        assert!(self.socket_ids.remove(&socket_id));
        while let Some(tx_buf) = moto_socket.tx_queue.pop_front() {
            core::mem::drop(tx_buf);
        }

        if let Some(conn_sockets) = self
            .conn_tcp_sockets
            .get_mut(&moto_socket.conn.wait_handle())
        {
            assert!(conn_sockets.remove(&socket_id));
        }

        if let Some(listener_id) = moto_socket.listener_id.take() {
            // When handling drop_tcp_listener cmd, the listener is first removed,
            // then its listening sockets are removed, so the next line will get None.
            if let Some(listener) = self.tcp_listeners.get_mut(&listener_id) {
                listener.remove_listening_socket(socket_id);
                listener.remove_pending_socket(socket_id);
            }
        }

        if let Some(mut cqe) = moto_socket.connect_req.take() {
            assert_eq!(moto_socket.state, TcpState::Connecting);
            cqe.status = moto_rt::E_BAD_HANDLE;
            self.pending_completions.push_back(PendingCompletion {
                msg: cqe,
                endpoint_handle: moto_socket.conn.wait_handle(),
            });
        }

        // Remove and cache the unused smol_socket.
        let smoltcp::socket::Socket::Tcp(smol_socket) = self.devices[moto_socket.device_idx]
            .sockets
            .remove(moto_socket.handle)
        else {
            panic!();
        };

        if let Some(port) = moto_socket.ephemeral_port.take() {
            self.devices[moto_socket.device_idx].free_ephemeral_tcp_port(port);
        }

        assert_eq!(smol_socket.state(), smoltcp::socket::tcp::State::Closed);
        self.put_unused_tcp_socket(smol_socket);
        #[cfg(debug_assertions)]
        log::debug!(
            "dropped tcp socket 0x{:x}; {} active sockets.",
            u64::from(socket_id),
            self.tcp_sockets.len()
        );
    }

    fn drop_udp_socket(&mut self, socket_id: SocketId) {
        let moto_socket = if let Some(s) = self.udp_sockets.get_mut(&socket_id) {
            s
        } else {
            log::debug!("drop_udp_socket: 0x{:x}: no socket", u64::from(socket_id));
            return;
        };

        let socket_addr = moto_socket.socket_addr;
        if let Some(msg) = moto_socket.rx_queue.take_msg() {
            // Need to free the stranded page.
            let sz = msg.payload.args_16()[10];
            if sz != 0 {
                let page_idx = msg.payload.shared_pages()[11];
                let _page = moto_socket.conn.get_page(page_idx).unwrap();
            }
        }

        let device_idx = moto_socket.device_idx;
        let smol_socket = self.devices[device_idx]
            .sockets
            .get_mut::<smoltcp::socket::udp::Socket>(moto_socket.handle);
        if smol_socket.send_queue() > 0 {
            // A MIO UDP test sends a UDP packet and immediately drops the socket,
            // so we need to give the socket a chance to actually send the packet out.
            self.devices[device_idx].poll();
        }

        assert!(self.udp_addresses_in_use.remove(&socket_addr));
        log::debug!("dropping UDP socket 0x{:x}", u64::from(socket_id),);

        // Remove the waker so that any polls on the socket from below don't trigger
        // wakeups on the dropped socket.
        self.wakers.remove(&socket_id);

        // Now we can remove moto_socket.
        let mut moto_socket = self.udp_sockets.remove(&socket_id).unwrap();
        assert!(self.socket_ids.remove(&socket_id));

        if let Some(conn_sockets) = self
            .conn_udp_sockets
            .get_mut(&moto_socket.conn.wait_handle())
        {
            assert!(conn_sockets.remove(&socket_id));
        }

        // Remove and cache the unused smol_socket.
        let smoltcp::socket::Socket::Udp(mut smol_socket) = self.devices[moto_socket.device_idx]
            .sockets
            .remove(moto_socket.handle)
        else {
            panic!();
        };

        smol_socket.close();

        if let Some(port) = moto_socket.ephemeral_port.take() {
            self.devices[moto_socket.device_idx].free_ephemeral_udp_port(port);
        }

        self.put_unused_udp_socket(smol_socket);
        #[cfg(debug_assertions)]
        log::debug!(
            "dropped udp socket 0x{:x}; {} active sockets.",
            u64::from(socket_id),
            self.udp_sockets.len()
        );
    }

    fn tcp_listener_accept(
        &mut self,
        conn: &Rc<io_channel::ServerConnection>,
        mut req: io_channel::Msg,
    ) -> Result<Option<io_channel::Msg>, ()> {
        let listener_id = req.handle.into();
        let listener = match self.tcp_listeners.get_mut(&listener_id) {
            Some(l) => l,
            None => {
                log::warn!("can't find listener 0x{:x}", req.handle);
                // return Err(());
                // TODO: how is this possible?
                return Ok(None);
            }
        };

        if listener.conn_handle() != conn.wait_handle() {
            // Validate that the listener and the connection belong to the same process.
            let pid1 = moto_sys::SysObj::get_pid(listener.conn_handle()).unwrap();
            let pid2 = moto_sys::SysObj::get_pid(conn.wait_handle()).unwrap();
            if pid1 != pid2 {
                log::warn!(
                    "wrong process 0x{:x} vs 0x{:x} for ID 0x{:x}",
                    pid1,
                    pid2,
                    req.handle
                );
                return Err(());
            }
        }

        if let Some((socket_id, socket_addr)) = listener.pop_pending_socket() {
            // TODO: the unwrap() below once triggered on remote drop.
            let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();
            assert_eq!(moto_socket.listener_id.unwrap(), listener_id);
            moto_socket.listener_id = None;

            moto_socket.subchannel_mask = req.payload.args_64()[0];

            // Note: we don't generate the state change event here because
            // we respond to the accept() request explicitly.
            moto_socket.state = TcpState::ReadWrite;
            req.handle = socket_id.into();
            api_net::put_socket_addr(&mut req.payload, &socket_addr);
            req.status = moto_rt::E_OK;
            self.pending_completions.push_back(PendingCompletion {
                msg: req,
                endpoint_handle: conn.wait_handle(),
            });

            let conn_handle = conn.wait_handle();
            moto_socket.conn = conn.clone();
            if let Some(conn_sockets) = self.conn_tcp_sockets.get_mut(&conn_handle) {
                conn_sockets.insert(socket_id);
            } else {
                let mut conn_sockets = HashSet::new();
                conn_sockets.insert(socket_id);
                self.conn_tcp_sockets.insert(conn_handle, conn_sockets);
            }

            #[cfg(debug_assertions)]
            log::debug!(
                "sys-io: 0x{:x}: accepted pending connection 0x{:x}",
                conn.wait_handle().as_u64(),
                u64::from(socket_id)
            );

            // Do rx after generating the accept completion, otherwise rx packets
            // may get delivered to the client for an unknown socket.
            self.do_tcp_rx(socket_id); // The socket can now Rx.
            return Ok(None);
        }

        #[cfg(debug_assertions)]
        log::debug!(
            "sys-io: 0x{:x}: pending accept",
            conn.wait_handle().as_u64(),
        );

        listener.add_pending_accept(req, conn);
        Ok(None)
    }

    fn tcp_listener_get_option(
        &mut self,
        _conn: &Rc<io_channel::ServerConnection>,
        mut msg: io_channel::Msg,
    ) -> io_channel::Msg {
        let listener_id = msg.handle.into();
        let listener = match self.tcp_listeners.get(&listener_id) {
            Some(l) => l,
            None => {
                msg.status = moto_rt::E_BAD_HANDLE;
                return msg;
            }
        };

        let options = msg.payload.args_64()[0];
        if options == 0 {
            msg.status = moto_rt::E_INVALID_ARGUMENT;
            return msg;
        }

        match options {
            api_net::TCP_OPTION_TTL => {
                msg.payload.args_8_mut()[23] = listener.ttl();
                msg.status = moto_rt::E_OK;
            }
            _ => {
                log::debug!("Invalid option 0x{}", options);
                msg.status = moto_rt::E_INVALID_ARGUMENT;
            }
        }

        msg
    }

    fn tcp_listener_set_option(
        &mut self,
        _conn: &Rc<io_channel::ServerConnection>,
        mut msg: io_channel::Msg,
    ) -> io_channel::Msg {
        let listener_id = msg.handle.into();
        let listener = match self.tcp_listeners.get_mut(&listener_id) {
            Some(l) => l,
            None => {
                msg.status = moto_rt::E_BAD_HANDLE;
                return msg;
            }
        };

        let options = msg.payload.args_64()[0];
        if options == 0 {
            msg.status = moto_rt::E_INVALID_ARGUMENT;
            return msg;
        }

        match options {
            api_net::TCP_OPTION_TTL => {
                let ttl = msg.payload.args_8()[23];
                let sockets = match listener.set_ttl(ttl) {
                    Ok(sockets) => sockets,
                    Err(err) => {
                        msg.status = err;
                        return msg;
                    }
                };

                for socket_id in sockets {
                    let moto_socket = self.tcp_sockets.get(&socket_id).unwrap();
                    let smol_socket = self.devices[moto_socket.device_idx]
                        .sockets
                        .get_mut::<smoltcp::socket::tcp::Socket>(moto_socket.handle);
                    smol_socket.set_hop_limit(Some(ttl));
                }

                msg.status = moto_rt::E_OK;
            }
            _ => {
                log::debug!("Invalid option 0x{}", options);
                msg.status = moto_rt::E_INVALID_ARGUMENT;
            }
        }

        msg
    }

    fn tcp_listener_drop(
        &mut self,
        conn: &Rc<io_channel::ServerConnection>,
        msg: io_channel::Msg,
    ) -> Result<(), ()> {
        let listener_id: TcpListenerId = msg.handle.into();
        let conn_handle = conn.wait_handle();
        let listener = match self.tcp_listeners.get_mut(&listener_id) {
            Some(val) => val,
            None => {
                return Err(());
            }
        };
        if listener.conn_handle() != conn_handle {
            return Err(());
        }

        if let Some(listeners) = self.conn_tcp_listeners.get_mut(&conn_handle) {
            assert!(listeners.remove(&listener_id));
        }
        self.drop_tcp_listener(listener_id);
        Ok(())
    }

    fn get_unused_tcp_socket(&mut self) -> smoltcp::socket::tcp::Socket<'static> {
        if let Some(socket) = self.tcp_socket_cache.pop() {
            socket
        } else {
            const RX_BUF_SZ: usize =
                io_channel::PAGE_SIZE * (api_net::TCP_RX_MAX_INFLIGHT as usize);
            let rx_buffer = smoltcp::socket::tcp::SocketBuffer::new(vec![0; RX_BUF_SZ]);
            let tx_buffer = smoltcp::socket::tcp::SocketBuffer::new(vec![0; 16384 * 2]);

            log::debug!("{}:{} new TCP socket", file!(), line!());
            smoltcp::socket::tcp::Socket::new(rx_buffer, tx_buffer)
        }
    }

    fn put_unused_tcp_socket(&mut self, socket: smoltcp::socket::tcp::Socket<'static>) {
        debug_assert_eq!(socket.state(), smoltcp::socket::tcp::State::Closed);
        if self.tcp_socket_cache.len() < MAX_TCP_SOCKET_CACHE_SIZE {
            self.tcp_socket_cache.push(socket);
        }
    }

    fn get_unused_udp_socket(&mut self) -> smoltcp::socket::udp::Socket<'static> {
        if let Some(socket) = self.udp_socket_cache.pop() {
            socket
        } else {
            let udp_rx_buffer = smoltcp::socket::udp::PacketBuffer::new(
                vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 64],
                vec![0; 65536],
            );
            let udp_tx_buffer = smoltcp::socket::udp::PacketBuffer::new(
                vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 64],
                vec![0; 65536],
            );
            smoltcp::socket::udp::Socket::new(udp_rx_buffer, udp_tx_buffer)
        }
    }

    fn put_unused_udp_socket(&mut self, socket: smoltcp::socket::udp::Socket<'static>) {
        debug_assert!(!socket.is_open());
        if self.udp_socket_cache.len() < MAX_TCP_SOCKET_CACHE_SIZE {
            self.udp_socket_cache.push(socket);
        }
    }

    fn tcp_stream_connect(
        &mut self,
        conn: &Rc<io_channel::ServerConnection>,
        mut sqe: io_channel::Msg,
    ) -> Option<io_channel::Msg> {
        let remote_addr = api_net::get_socket_addr(&sqe.payload);

        #[cfg(debug_assertions)]
        log::debug!(
            "sys-io: 0x{:x}: tcp connect to {:?}",
            conn.wait_handle().as_u64(),
            remote_addr
        );

        let (device_idx, local_ip_addr) = if let Some(pair) = self.find_route(&remote_addr.ip()) {
            pair
        } else {
            #[cfg(debug_assertions)]
            log::debug!(
                "sys-io: 0x{:x}: tcp connect to {:?}: route not found",
                conn.wait_handle().as_u64(),
                remote_addr
            );

            sqe.status = moto_rt::E_NOT_FOUND;
            return Some(sqe);
        };

        let local_port = match self.devices[device_idx].get_ephemeral_tcp_port(&local_ip_addr) {
            Some(port) => port,
            None => {
                log::info!("get_ephemeral_port({:?}) failed", local_ip_addr);
                sqe.status = moto_rt::E_OUT_OF_MEMORY;
                return Some(sqe);
            }
        };

        let Ok(mut moto_socket) = self.new_tcp_socket_for_device(device_idx, conn.clone()) else {
            self.devices[device_idx].free_ephemeral_tcp_port(local_port);
            sqe.status = moto_rt::E_INVALID_ARGUMENT;
            return Some(sqe);
        };
        moto_socket.subchannel_mask = api_net::io_subchannel_mask(sqe.payload.args_8()[23]);

        let conn_handle = conn.wait_handle();
        if let Some(conn_sockets) = self.conn_tcp_sockets.get_mut(&conn_handle) {
            conn_sockets.insert(moto_socket.id);
        } else {
            let mut conn_sockets = HashSet::new();
            conn_sockets.insert(moto_socket.id);
            self.conn_tcp_sockets.insert(conn_handle, conn_sockets);
        }

        let local_addr = SocketAddr::new(local_ip_addr, local_port);

        moto_socket.connect_req = Some(sqe);
        // Note: we don't generate the state change event because it is implied.
        moto_socket.state = TcpState::Connecting;
        moto_socket.ephemeral_port = Some(local_port);

        let smol_handle = moto_socket.handle;
        self.socket_ids.insert(moto_socket.id);
        self.tcp_sockets.insert(moto_socket.id, moto_socket);

        let smol_socket = self.devices[device_idx]
            .sockets
            .get_mut::<smoltcp::socket::tcp::Socket>(smol_handle);

        let timeout = api_net::tcp_stream_connect_timeout(&sqe);
        if let Some(timeout) = timeout {
            let now = moto_rt::time::Instant::now();
            if timeout <= now {
                // We check this upon receiving sqe; the thread got preempted or something.
                // Just use an arbitrary small timeout.
                smol_socket.set_timeout(Some(smoltcp::time::Duration::from_micros(10)));
            } else {
                smol_socket.set_timeout(Some(smoltcp::time::Duration::from_micros(
                    timeout.duration_since(now).as_micros() as u64,
                )));
            }
        }

        // 3. call connect
        if self.devices[device_idx]
            .connect_socket(smol_handle, &local_addr, &remote_addr)
            .is_err()
        {
            sqe.status = moto_rt::E_INVALID_ARGUMENT;
            return Some(sqe);
        }

        None
    }

    fn tcp_socket_from_msg(
        &self,
        conn_handle: SysHandle,
        sqe: &io_channel::Msg,
    ) -> Result<SocketId, io_channel::Msg> {
        let socket_id: SocketId = sqe.handle.into();

        // Validate that the socket belongs to the connection.
        if let Some(socks) = self.conn_tcp_sockets.get(&conn_handle) {
            if !socks.contains(&socket_id) {
                log::debug!(
                    "{}:{} bad socket 0x{:x}",
                    file!(),
                    line!(),
                    u64::from(socket_id)
                );
                let mut err = *sqe;
                err.status = moto_rt::E_NOT_FOUND;
                return Err(err);
            }
        } else {
            log::debug!(
                "{}:{} bad socket 0x{:x}",
                file!(),
                line!(),
                u64::from(socket_id)
            );
            let mut err = *sqe;
            err.status = moto_rt::E_INVALID_ARGUMENT;
            return Err(err);
        }

        Ok(socket_id)
    }

    fn udp_socket_from_msg(
        &self,
        conn_handle: SysHandle,
        sqe: &io_channel::Msg,
    ) -> Result<SocketId, io_channel::Msg> {
        let socket_id: SocketId = sqe.handle.into();

        // Validate that the socket belongs to the connection.
        if let Some(socks) = self.conn_udp_sockets.get(&conn_handle) {
            if !socks.contains(&socket_id) {
                log::debug!(
                    "{}:{} bad socket 0x{:x}",
                    file!(),
                    line!(),
                    u64::from(socket_id)
                );
                let mut err = *sqe;
                err.status = moto_rt::E_NOT_FOUND;
                return Err(err);
            }
        } else {
            log::debug!(
                "{}:{} bad socket 0x{:x}",
                file!(),
                line!(),
                u64::from(socket_id)
            );
            let mut err = *sqe;
            err.status = moto_rt::E_INVALID_ARGUMENT;
            return Err(err);
        }

        Ok(socket_id)
    }

    // Note: does not return anything because TX is one-way, nobody is listening for TX responses.
    fn tcp_stream_tx(&mut self, conn: &Rc<io_channel::ServerConnection>, msg: io_channel::Msg) {
        // Note: we need to get the page so that it is freed.
        let page_idx = msg.payload.shared_pages()[0];
        let page = if let Ok(page) = conn.get_page(page_idx) {
            page
        } else {
            // TODO: drop the connection?
            log::debug!("tcp_stream_write w/o bytes???");
            return;
        };
        let Ok(socket_id) = self.tcp_socket_from_msg(conn.wait_handle(), &msg) else {
            return;
        };

        let sz = msg.payload.args_64()[1] as usize;
        if sz > io_channel::PAGE_SIZE {
            // TODO: drop the connection?
            return;
        }

        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();
        match moto_socket.state {
            TcpState::Connecting | TcpState::Listening | TcpState::PendingAccept => panic!(),
            TcpState::ReadWrite | TcpState::WriteOnly => {}
            TcpState::ReadOnly | TcpState::Closed => {
                return;
            }
            TcpState::_Max => panic!(),
        }

        moto_socket.stats_tx_bytes += sz as u64;
        moto_socket.tx_queue.push_back(TcpTxBuf {
            page,
            len: sz,
            consumed: 0,
        });

        self.do_tcp_tx(socket_id);
    }

    fn tcp_stream_rx_ack(
        &mut self,
        conn: &Rc<io_channel::ServerConnection>,
        msg: io_channel::Msg,
    ) -> Result<(), ()> {
        let socket_id = match self.tcp_socket_from_msg(conn.wait_handle(), &msg) {
            Ok(s) => s,
            // Err(_) => return Err(()),
            Err(_) => return Ok(()), // The socket was dropped.
        };

        // Validate that the socket belongs to the connection.
        if let Some(socks) = self.conn_tcp_sockets.get(&conn.wait_handle()) {
            if !socks.contains(&socket_id) {
                return Err(());
            }
        } else {
            return Err(());
        }

        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();
        let rx_ack = msg.payload.args_64()[0];

        if rx_ack == 0 {
            if moto_socket.rx_ack != u64::MAX {
                return Err(());
            }
        } else if rx_ack > moto_socket.rx_seq || rx_ack <= moto_socket.rx_ack {
            return Err(());
        }
        moto_socket.rx_ack = rx_ack;

        self.do_tcp_rx(socket_id);

        Ok(())
    }

    fn tcp_stream_set_option(
        &mut self,
        conn: &Rc<io_channel::ServerConnection>,
        mut sqe: io_channel::Msg,
    ) -> io_channel::Msg {
        let socket_id = match self.tcp_socket_from_msg(conn.wait_handle(), &sqe) {
            Ok(x) => x,
            Err(err) => return err,
        };
        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();

        if moto_socket.state == TcpState::Connecting {
            log::debug!("{}:{} bad state", file!(), line!());
            sqe.status = moto_rt::E_INVALID_ARGUMENT;
            return sqe;
        }

        let mut options = sqe.payload.args_64()[0];
        if options == 0 {
            sqe.status = moto_rt::E_INVALID_ARGUMENT;
            return sqe;
        }

        if options == api_net::TCP_OPTION_NODELAY {
            let nodelay_u64 = sqe.payload.args_64()[1];
            let nodelay = match nodelay_u64 {
                1 => true,
                0 => false,
                _ => {
                    sqe.status = moto_rt::E_INVALID_ARGUMENT;
                    return sqe;
                }
            };

            let smol_socket = self.devices[moto_socket.device_idx]
                .sockets
                .get_mut::<smoltcp::socket::tcp::Socket>(moto_socket.handle);
            smol_socket.set_nagle_enabled(!nodelay);
            sqe.status = moto_rt::E_OK;
            return sqe;
        }

        if options == api_net::TCP_OPTION_TTL {
            let ttl = sqe.payload.args_32()[2];
            if ttl == 0 || ttl > 255 {
                sqe.status = moto_rt::E_INVALID_ARGUMENT;
                return sqe;
            };

            let smol_socket = self.devices[moto_socket.device_idx]
                .sockets
                .get_mut::<smoltcp::socket::tcp::Socket>(moto_socket.handle);
            smol_socket.set_hop_limit(Some(ttl as u8));
            sqe.status = moto_rt::E_OK;
            return sqe;
        }

        let shut_rd = if options & api_net::TCP_OPTION_SHUT_RD != 0 {
            options ^= api_net::TCP_OPTION_SHUT_RD;
            moto_socket.state.can_read()
        } else {
            false
        };

        let shut_wr = if options & api_net::TCP_OPTION_SHUT_WR != 0 {
            options ^= api_net::TCP_OPTION_SHUT_WR;
            moto_socket.state.can_write()
        } else {
            false
        };

        if options != 0 {
            sqe.status = moto_rt::E_INVALID_ARGUMENT;
            log::warn!("unrecognized TCP option 0x{:x}", options);
            return sqe;
        }

        if !(shut_rd || shut_wr) {
            sqe.status = moto_rt::E_OK; // Nothing to do.
            return sqe;
        }

        match moto_socket.state {
            TcpState::Connecting => unreachable!(), // We eliminated this option above.
            TcpState::Listening | TcpState::PendingAccept => {
                unreachable!("the client does not have SocketId")
            }
            TcpState::ReadWrite => {
                if shut_rd && shut_wr {
                    moto_socket.add_deferred_action(DeferredAction::Close, Instant::now());
                    self.defer_socket_action(socket_id, None);
                } else if shut_rd {
                    moto_socket.add_deferred_action(DeferredAction::CloseRd, Instant::now());
                    self.defer_socket_action(socket_id, None);
                } else {
                    assert!(shut_wr);
                    moto_socket.add_deferred_action(DeferredAction::CloseWr, Instant::now());
                    self.defer_socket_action(socket_id, None);
                }
            }
            TcpState::ReadOnly => {
                if shut_rd {
                    moto_socket.add_deferred_action(DeferredAction::Close, Instant::now());
                    self.defer_socket_action(socket_id, None);
                }
            }
            TcpState::WriteOnly => {
                if shut_wr {
                    moto_socket.add_deferred_action(DeferredAction::Close, Instant::now());
                    self.defer_socket_action(socket_id, None);
                }
            }
            TcpState::Closed => {}
            TcpState::_Max => panic!(),
        }

        sqe.status = moto_rt::E_OK;
        sqe
    }

    fn tcp_stream_get_option(
        &mut self,
        conn: &Rc<io_channel::ServerConnection>,
        mut sqe: io_channel::Msg,
    ) -> io_channel::Msg {
        let socket_id = match self.tcp_socket_from_msg(conn.wait_handle(), &sqe) {
            Ok(s) => s,
            Err(err) => return err,
        };

        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();

        if moto_socket.state == TcpState::Connecting {
            log::debug!("{}:{} bad state", file!(), line!());
            sqe.status = moto_rt::E_INVALID_ARGUMENT;
            return sqe;
        }

        let options = sqe.payload.args_64()[0];
        if options == 0 {
            sqe.status = moto_rt::E_INVALID_ARGUMENT;
            return sqe;
        }

        match options {
            api_net::TCP_OPTION_NODELAY => {
                let smol_socket = self.devices[moto_socket.device_idx]
                    .sockets
                    .get::<smoltcp::socket::tcp::Socket>(moto_socket.handle);
                let nodelay = !smol_socket.nagle_enabled();
                sqe.payload.args_64_mut()[0] = if nodelay { 1 } else { 0 };
                sqe.status = moto_rt::E_OK;
            }
            api_net::TCP_OPTION_TTL => {
                let smol_socket = self.devices[moto_socket.device_idx]
                    .sockets
                    .get::<smoltcp::socket::tcp::Socket>(moto_socket.handle);
                let ttl = if let Some(hl) = smol_socket.hop_limit() {
                    hl as u32
                } else {
                    64 // This is what smoltcp documentation implies.
                };
                sqe.payload.args_32_mut()[0] = ttl;
                sqe.status = moto_rt::E_OK;
            }
            _ => {
                log::debug!("Invalid option 0x{}", options);
                sqe.status = moto_rt::E_INVALID_ARGUMENT;
            }
        }

        sqe
    }

    fn tcp_stream_close(
        &mut self,
        conn: &Rc<io_channel::ServerConnection>,
        mut sqe: io_channel::Msg,
    ) -> Option<io_channel::Msg> {
        let socket_id = if let Ok(s) = self.tcp_socket_from_msg(conn.wait_handle(), &sqe) {
            s
        } else {
            sqe.status = moto_rt::E_INVALID_ARGUMENT;
            return Some(sqe);
        };
        log::debug!(
            "{}:{} tcp_stream_close 0x{:x}",
            file!(),
            line!(),
            u64::from(socket_id)
        );
        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();
        moto_socket.add_deferred_action(DeferredAction::Close, Instant::now());

        // We cannot call self.maybe_complete_deferred_action(socket_id) here
        // because we need to respond to the close request synchronously, and
        // the method above pushes sqes to the user.
        self.defer_socket_action(socket_id, None);

        sqe.status = moto_rt::E_OK;
        Some(sqe)
    }

    fn next_id(&mut self, kind: SocketKind) -> u64 {
        let res = self.next_id;
        self.next_id += 1;

        match kind {
            SocketKind::Tcp => (res << 1) + 1,
            SocketKind::Udp => res << 1,
        }
    }

    fn device_idx_from_name(&self, name: &str) -> usize {
        for idx in 0..self.devices.len() {
            if self.devices[idx].name() == name {
                return idx;
            }
        }
        panic!("{}:{} bad name '{}'", file!(), line!(), name)
    }

    // Find the device to route through.
    fn find_route(&self, ip_addr: &IpAddr) -> Option<(usize, IpAddr)> {
        // First, look through local addresses.
        if let Some(device_idx) = self.ip_addresses.get(ip_addr) {
            return Some((*device_idx, *ip_addr));
        }

        // If not found, look through routes.
        self.config
            .find_route(ip_addr)
            .map(|(dev_name, addr)| (self.device_idx_from_name(dev_name.as_str()), addr))
    }

    fn rx_buf_to_pc(
        socket_id: SocketId,
        endpoint_handle: SysHandle,
        x_buf: TcpRxBuf,
        rx_seq: u64,
    ) -> PendingCompletion {
        let (io_page, sz) = (x_buf.page, x_buf.consumed);
        let mut msg =
            moto_sys_io::api_net::tcp_stream_rx_msg(socket_id.into(), io_page, sz, rx_seq);
        msg.status = moto_rt::E_OK;

        PendingCompletion {
            msg,
            endpoint_handle,
        }
    }

    // Returns 'true' if the socket can do tx/rx.
    fn on_tcp_listener_connected(&mut self, socket_id: SocketId) -> bool {
        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();
        let device_idx = moto_socket.device_idx;
        let smol_socket = self.devices[device_idx]
            .sockets
            .get_mut::<smoltcp::socket::tcp::Socket>(moto_socket.handle);

        smol_socket.set_nagle_enabled(false); // A good idea, generally.
        smol_socket.set_ack_delay(None);

        let local_addr = super::smoltcp_helpers::socket_addr_from_endpoint(
            smol_socket.local_endpoint().unwrap(),
        );
        assert_eq!(local_addr, moto_socket.listening_on.unwrap());
        let remote_addr = super::smoltcp_helpers::socket_addr_from_endpoint(
            smol_socket.remote_endpoint().unwrap(),
        );

        let listener_id = *moto_socket.listener_id.as_ref().unwrap();
        let listener = self.tcp_listeners.get_mut(&listener_id).unwrap();
        let may_do_io = if let Some((mut msg, conn)) = listener.get_pending_accept() {
            assert!(listener.remove_listening_socket(socket_id));
            moto_socket.state = TcpState::ReadWrite;
            moto_socket.listener_id = None;
            let endpoint_handle = conn.wait_handle();
            moto_socket.subchannel_mask = msg.payload.args_64()[0];
            moto_socket.conn = conn;
            if let Some(conn_sockets) = self.conn_tcp_sockets.get_mut(&endpoint_handle) {
                conn_sockets.insert(socket_id);
            } else {
                let mut conn_sockets = HashSet::new();
                conn_sockets.insert(socket_id);
                self.conn_tcp_sockets.insert(endpoint_handle, conn_sockets);
            }
            msg.handle = moto_socket.id.into();
            api_net::put_socket_addr(&mut msg.payload, &remote_addr);
            msg.status = moto_rt::E_OK;
            self.pending_completions.push_back(PendingCompletion {
                msg,
                endpoint_handle,
            });
            true
        } else {
            assert_eq!(moto_socket.state, TcpState::Listening);
            // Note: we don't generate the state change event because accept() is handled explicitly.
            moto_socket.state = TcpState::PendingAccept;
            listener.add_pending_socket(moto_socket.id, remote_addr);
            false
        };

        #[cfg(debug_assertions)]
        log::debug!(
            "{}:{} on_tcp_listener_connected 0x{:x} - {:?}; accepted: {}",
            file!(),
            line!(),
            u64::from(socket_id),
            remote_addr,
            may_do_io
        );

        may_do_io
    }

    fn spawn_replacement_listener(&mut self, socket_id: SocketId) {
        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();
        assert_eq!(moto_socket.state, TcpState::Listening);
        assert!(!moto_socket.replacement_listener_created);
        moto_socket.replacement_listener_created = true;

        let device_idx = moto_socket.device_idx;
        let listener_id = *moto_socket.listener_id.as_ref().unwrap();
        let addr = moto_socket.listening_on.unwrap();
        if let Err(err) = self.start_listening_on_device(listener_id, device_idx, addr, 1) {
            log::error!(
                "{}:{} bind_on_device() failed with {:?}",
                file!(),
                line!(),
                err
            );
        }
    }

    fn on_socket_connected(&mut self, socket_id: SocketId) {
        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();
        let device_idx = moto_socket.device_idx;
        let smol_socket = self.devices[device_idx]
            .sockets
            .get_mut::<smoltcp::socket::tcp::Socket>(moto_socket.handle);

        // Without these, remotely dropped sockets may hang around indefinitely.
        smol_socket.set_timeout(Some(smoltcp::time::Duration::from_millis(5_000)));
        smol_socket.set_keep_alive(Some(smoltcp::time::Duration::from_millis(10_000)));
        smol_socket.set_nagle_enabled(false); // A good idea, generally.
        smol_socket.set_ack_delay(None);

        let local_addr = super::smoltcp_helpers::socket_addr_from_endpoint(
            smol_socket.local_endpoint().unwrap(),
        );

        let mut cqe = moto_socket.connect_req.take().unwrap();
        // Note: we don't generate the state change event because we have an explicit completion below.
        moto_socket.state = TcpState::ReadWrite;
        cqe.handle = moto_socket.id.into();
        api_net::put_socket_addr(&mut cqe.payload, &local_addr);
        cqe.status = moto_rt::E_OK;
        log::debug!(
            "on_socket_connected 0x{:x} {:?} -> ...",
            u64::from(socket_id),
            local_addr
        );
        self.pending_completions.push_back(PendingCompletion {
            msg: cqe,
            endpoint_handle: moto_socket.conn.wait_handle(),
        });

        self.do_tcp_rx(socket_id); // The socket can now Rx.
    }

    fn on_connect_failed(&mut self, socket_id: SocketId) {
        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();

        let mut cqe = moto_socket.connect_req.take().unwrap();
        // Note: we don't generate the state change event because of the explicit PC below.
        moto_socket.state = TcpState::Closed;
        cqe.handle = moto_socket.id.into();
        cqe.status = moto_rt::E_TIMED_OUT;
        self.pending_completions.push_back(PendingCompletion {
            msg: cqe,
            endpoint_handle: moto_socket.conn.wait_handle(),
        });

        log::debug!(
            "{}:{} connect_failed: 0x{:x}",
            file!(),
            line!(),
            u64::from(socket_id)
        );
        self.drop_tcp_socket(socket_id);
    }

    fn on_tcp_socket_poll(&mut self, socket_id: SocketId) {
        let waker = if let Some(waker) = self.wakers.get(&socket_id) {
            waker.clone()
        } else {
            return; // The socket has been removed/aborted.
        };
        let mut moto_socket = match self.tcp_sockets.get_mut(&socket_id) {
            Some(s) => s,
            None => return,
        };
        let smol_socket = self.devices[moto_socket.device_idx]
            .sockets
            .get_mut::<smoltcp::socket::tcp::Socket>(moto_socket.handle);

        // Registered wakers fire only once, so we need to re-register them every time.
        smol_socket.register_recv_waker(&waker);
        smol_socket.register_send_waker(&waker);

        let can_recv = smol_socket.can_recv();
        let can_send = smol_socket.can_send();
        let smol_state = smol_socket.state();

        if moto_socket.state == TcpState::Listening
            && smol_socket.state() != smoltcp::socket::tcp::State::Listen
            && !moto_socket.replacement_listener_created
        {
            self.spawn_replacement_listener(socket_id);

            // Must re-initialize moto_socket and smol_socket because the borrow-checker
            //  complains about self.spawn_replacement_listener() above.
            moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();
        }

        let moto_state = moto_socket.state;

        /*
          RFC 793: https://datatracker.ietf.org/doc/html/rfc793

          TCP states:

            LISTEN - represents waiting for a connection request from any remote
            TCP and port.

            SYN-SENT - represents waiting for a matching connection request
            after having sent a connection request.

            SYN-RECEIVED - represents waiting for a confirming connection
            request acknowledgment after having both received and sent a
            connection request.

            ESTABLISHED - represents an open connection, data received can be
            delivered to the user.  The normal state for the data transfer phase
            of the connection.

            FIN-WAIT-1 - represents waiting for a connection termination request
            from the remote TCP, or an acknowledgment of the connection
            termination request previously sent.

            FIN-WAIT-2 - represents waiting for a connection termination request
            from the remote TCP.

            CLOSE-WAIT - represents waiting for a connection termination request
            from the local user.

            CLOSING - represents waiting for a connection termination request
            acknowledgment from the remote TCP.

            LAST-ACK - represents waiting for an acknowledgment of the
            connection termination request previously sent to the remote TCP
            (which includes an acknowledgment of its connection termination
            request).


                                     +---------+ ---------\      active OPEN
                                     |  CLOSED |            \    -----------
                                     +---------+<---------\   \   create TCB
                                       |     ^              \   \  snd SYN
                          passive OPEN |     |   CLOSE        \   \
                          ------------ |     | ----------       \   \
                           create TCB  |     | delete TCB         \   \
                                       V     |                      \   \
                                     +---------+            CLOSE    |    \
                                     |  LISTEN |          ---------- |     |
                                     +---------+          delete TCB |     |
                          rcv SYN      |     |     SEND              |     |
                         -----------   |     |    -------            |     V
        +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
        |         |<-----------------           ------------------>|         |
        |   SYN   |                    rcv SYN                     |   SYN   |
        |   RCVD  |<-----------------------------------------------|   SENT  |
        |         |                    snd ACK                     |         |
        |         |------------------           -------------------|         |
        +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
          |           --------------   |     |   -----------
          |                  x         |     |     snd ACK
          |                            V     V
          |  CLOSE                   +---------+
          | -------                  |  ESTAB  |
          | snd FIN                  +---------+
          |                   CLOSE    |     |    rcv FIN
          V                  -------   |     |    -------
        +---------+          snd FIN  /       \   snd ACK          +---------+
        |  FIN    |<-----------------           ------------------>|  CLOSE  |
        | WAIT-1  |------------------                              |   WAIT  |
        +---------+          rcv FIN  \                            +---------+
          | rcv ACK of FIN   -------   |                            CLOSE  |
          | --------------   snd ACK   |                           ------- |
          V        x                   V                           snd FIN V
        +---------+                  +---------+                   +---------+
        |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
        +---------+                  +---------+                   +---------+
          |                rcv ACK of FIN |                 rcv ACK of FIN |
          |  rcv FIN       -------------- |    Timeout=2MSL -------------- |
          |  -------              x       V    ------------        x       V
           \ snd ACK                 +---------+delete TCB         +---------+
            ------------------------>|TIME WAIT|------------------>| CLOSED  |
                                     +---------+                   +---------+
        */
        match smol_state {
            smoltcp::socket::tcp::State::Listen => {
                assert_eq!(moto_socket.state, TcpState::Listening);
                return;
            }
            smoltcp::socket::tcp::State::SynSent | smoltcp::socket::tcp::State::SynReceived => {
                assert!(
                    moto_socket.state == TcpState::Connecting
                        || moto_socket.state == TcpState::Listening
                );
                return;
            }

            smoltcp::socket::tcp::State::Established => {
                if moto_socket.state == TcpState::Listening {
                    if !self.on_tcp_listener_connected(socket_id) {
                        return; // Cannot do I/O yet: need the user to accept the connection.
                    }
                } else if moto_socket.state == TcpState::Connecting {
                    self.on_socket_connected(socket_id);
                } else if moto_socket.state == TcpState::PendingAccept {
                    return; // Cannot do I/O: the above.
                }
            }

            // Local TX closed (by a local action).
            smoltcp::socket::tcp::State::FinWait1 => match moto_state {
                TcpState::Connecting => {
                    self.on_connect_failed(socket_id); // Drops the socket.
                    return;
                }
                TcpState::Listening | TcpState::PendingAccept => {
                    self.drop_tcp_socket(socket_id);
                    return;
                }
                TcpState::WriteOnly => {
                    log::debug!(
                        "socket 0x{:x} WriteOnly => (deferred) Close",
                        u64::from(socket_id)
                    );
                    moto_socket.add_deferred_action(DeferredAction::Close, Instant::now());
                }
                TcpState::ReadWrite => {
                    moto_socket.add_deferred_action(DeferredAction::CloseWr, Instant::now());
                }
                TcpState::ReadOnly => {}
                _ => panic!("Unexpected TcpState {:?}", moto_socket.state),
            },

            // The remote socket has closed its write end; we can still
            // write into our side, and the remote socket can read.
            smoltcp::socket::tcp::State::CloseWait => match moto_state {
                TcpState::Connecting => {
                    panic!("bad state transition: {:?} => CloseWait", moto_state)
                } // Impossible.
                TcpState::Listening | TcpState::PendingAccept => {
                    self.drop_tcp_socket(socket_id);
                    return;
                }
                TcpState::ReadOnly => {
                    log::debug!(
                        "socket 0x{:x} ReadOnly => (deferred) Close",
                        u64::from(socket_id)
                    );
                    moto_socket.add_deferred_action(DeferredAction::Close, Instant::now());
                }
                TcpState::ReadWrite => {
                    moto_socket.add_deferred_action(DeferredAction::CloseRd, Instant::now());
                }
                // Nothing to do.
                TcpState::WriteOnly => {}
                _ => panic!("Unexpected TcpState {:?}", moto_state),
            },

            smoltcp::socket::tcp::State::Closed => match moto_state {
                TcpState::Connecting => {
                    self.on_connect_failed(socket_id); // Will drop the socket.
                    return;
                }
                TcpState::Listening | TcpState::PendingAccept => {
                    self.drop_tcp_socket(socket_id);
                    return;
                }
                TcpState::WriteOnly | TcpState::ReadOnly | TcpState::ReadWrite => {
                    log::debug!("socket 0x{:x} => (deferred) Close", u64::from(socket_id));
                    moto_socket.add_deferred_action(DeferredAction::Close, Instant::now());
                }
                _ => panic!("Unexpected TcpState {:?}", moto_state),
            },
            smoltcp::socket::tcp::State::FinWait2
            | smoltcp::socket::tcp::State::Closing
            | smoltcp::socket::tcp::State::LastAck
            | smoltcp::socket::tcp::State::TimeWait => {}
        }

        if can_recv {
            self.do_tcp_rx(socket_id);
        }
        if can_send {
            self.do_tcp_tx(socket_id);
        }

        self.maybe_complete_deferred_action(socket_id);
    }

    fn on_udp_socket_poll(&mut self, socket_id: SocketId) {
        let waker = if let Some(waker) = self.wakers.get(&socket_id) {
            waker.clone()
        } else {
            return; // The socket has been removed/aborted.
        };
        let moto_socket = match self.udp_sockets.get_mut(&socket_id) {
            Some(s) => s,
            None => return,
        };
        let smol_socket = self.devices[moto_socket.device_idx]
            .sockets
            .get_mut::<smoltcp::socket::udp::Socket>(moto_socket.handle);

        // Registered wakers fire only once, so we need to re-register them every time.
        smol_socket.register_recv_waker(&waker);
        smol_socket.register_send_waker(&waker);

        let can_recv = smol_socket.can_recv();
        let can_send = smol_socket.can_send();

        // log::debug!(
        //     "on_udp_socket_poll 0x{:x}: can_recv: {} can_send: {}",
        //     u64::from(socket_id),
        //     can_recv,
        //     can_send
        // );
        if can_recv {
            self.do_udp_rx(socket_id);
        }

        if can_send {
            self.do_udp_tx(socket_id);
        }
    }

    fn process_polled_sockets(&mut self) {
        loop {
            let Some(socket_id) = self.woken_sockets.borrow_mut().pop_front() else {
                break;
            };

            match socket_id.kind() {
                SocketKind::Tcp => self.on_tcp_socket_poll(socket_id),
                SocketKind::Udp => self.on_udp_socket_poll(socket_id),
            }
        }
        assert!(self.woken_sockets.borrow().is_empty());
    }

    fn notify_socket_state_changed(&mut self, socket_id: SocketId) {
        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();

        let mut msg = io_channel::Msg::new();
        msg.command = api_net::NetCmd::EvtTcpStreamStateChanged as u16;
        msg.handle = moto_socket.id.into();
        msg.payload.args_32_mut()[0] = moto_socket.state.into();
        msg.status = moto_rt::E_OK;

        self.pending_completions.push_back(PendingCompletion {
            msg,
            endpoint_handle: moto_socket.conn.wait_handle(),
        });
    }

    fn maybe_complete_deferred_action(&mut self, socket_id: SocketId) {
        if socket_id.kind() == SocketKind::Udp {
            log::error!("maybe_complete_deferred_action: UDP not impl");
            return;
        }

        let Some(moto_socket) = self.tcp_sockets.get_mut(&socket_id) else {
            // Deferred action sockets may get enqueued more than once.
            return;
        };

        let Some((deferred_action, started)) = moto_socket.take_deferred_action() else {
            return;
        };

        let smol_socket = self.devices[moto_socket.device_idx]
            .sockets
            .get_mut::<smoltcp::socket::tcp::Socket>(moto_socket.handle);

        let may_send = smol_socket.may_send();

        match deferred_action {
            DeferredAction::CloseRd => {
                if smol_socket.recv_queue() > 0 {
                    moto_socket.add_deferred_action(deferred_action, started);
                    self.defer_socket_action(socket_id, Some(started));
                    return; // Not yet.
                }
                match moto_socket.state {
                    TcpState::ReadWrite => moto_socket.state = TcpState::WriteOnly,
                    TcpState::ReadOnly => moto_socket.state = TcpState::Closed,

                    // The user can close the read half locally in Rust (shutdown(read)),
                    // but this has no equivalent in low-level TCP states, so when
                    // the remote socket calls close(), we generate CloseRd deferred action.
                    TcpState::WriteOnly => return,
                    _ => panic!(
                        "unexpected socket state {:?} for socket 0x{:x}",
                        moto_socket.state,
                        u64::from(socket_id)
                    ),
                }
            }
            DeferredAction::CloseWr => {
                if may_send && (!moto_socket.tx_queue.is_empty() || smol_socket.send_queue() > 0) {
                    moto_socket.add_deferred_action(deferred_action, started);
                    self.defer_socket_action(socket_id, Some(started));
                    return; // Not yet.
                }
                match moto_socket.state {
                    TcpState::ReadWrite => moto_socket.state = TcpState::ReadOnly,
                    TcpState::WriteOnly => moto_socket.state = TcpState::Closed,
                    _ => panic!(
                        "unexpected socket state {:?} for socket 0x{:x}",
                        moto_socket.state,
                        u64::from(socket_id)
                    ),
                }
                smol_socket.close();
            }
            DeferredAction::Close => {
                if smol_socket.recv_queue() > 0 {
                    moto_socket.add_deferred_action(deferred_action, started);
                    self.defer_socket_action(socket_id, Some(started));
                    return; // Not yet.
                }
                if may_send && (!moto_socket.tx_queue.is_empty() || smol_socket.send_queue() > 0) {
                    moto_socket.add_deferred_action(deferred_action, started);
                    self.defer_socket_action(socket_id, Some(started));
                    return; // Not yet.
                }
                assert_ne!(moto_socket.state, TcpState::Closed);
                moto_socket.state = TcpState::Closed;
            }
        }

        let moto_state = moto_socket.state;
        if moto_state == TcpState::Closed {
            self.notify_socket_state_changed(socket_id);
            self.drop_tcp_socket(socket_id); // Will abort smol_socket.
            return;
        }

        let smol_state = smol_socket.state();
        let may_send = smol_socket.may_send();

        if !moto_state.can_write() && may_send {
            smol_socket.close();
        }

        if smol_state == smoltcp::socket::tcp::State::Closed {
            // We won't poll the smol socket, as it is closed, so we need
            // to manually poll it via deferred_action_sockets.
            moto_socket.add_deferred_action(deferred_action, started);
            self.defer_socket_action(socket_id, Some(started));
        }

        self.notify_socket_state_changed(socket_id);
    }

    fn do_tcp_rx(&mut self, socket_id: SocketId) {
        let Some(moto_socket) = self.tcp_sockets.get_mut(&socket_id) else {
            // Deferred action sockets may get enqueued more than once.
            return;
        };

        let smol_socket = self.devices[moto_socket.device_idx]
            .sockets
            .get_mut::<smoltcp::socket::tcp::Socket>(moto_socket.handle);

        if moto_socket.rx_ack == u64::MAX
            || (moto_socket.rx_seq > (moto_socket.rx_ack + api_net::TCP_RX_MAX_INFLIGHT))
        {
            return;
        }

        // We are attempting to deliver any incoming bytes even if the peer has closed the connection.
        while smol_socket.recv_queue() > 0 {
            let page = match moto_socket.conn.alloc_page(moto_socket.subchannel_mask) {
                Ok(page) => page,
                Err(err) => {
                    assert_eq!(err, moto_rt::E_NOT_READY);
                    self.defer_socket_action(socket_id, None);
                    return;
                }
            };
            let mut rx_buf = TcpRxBuf::new(page);
            let mut receive_closure = |bytes: &mut [u8]| {
                let len = bytes.len().min(io_channel::PAGE_SIZE - rx_buf.consumed);
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        rx_buf.bytes_mut().as_mut_ptr(),
                        len,
                    );
                }

                rx_buf.consume(len);
                (len, ())
            };

            smol_socket.recv(&mut receive_closure).unwrap();

            moto_socket.rx_seq += 1;
            moto_socket.stats_rx_bytes += rx_buf.consumed as u64;
            self.pending_completions.push_back(Self::rx_buf_to_pc(
                socket_id,
                moto_socket.conn.wait_handle(),
                rx_buf,
                moto_socket.rx_seq,
            ));

            if moto_socket.rx_seq > (moto_socket.rx_ack + api_net::TCP_RX_MAX_INFLIGHT) {
                self.defer_socket_action(socket_id, None);
                return;
            }
        }

        self.maybe_complete_deferred_action(socket_id);
    }

    fn do_udp_rx(&mut self, socket_id: SocketId) {
        let Some(moto_socket) = self.udp_sockets.get_mut(&socket_id) else {
            // Deferred action sockets may get enqueued more than once.
            return;
        };

        let smol_socket = self.devices[moto_socket.device_idx]
            .sockets
            .get_mut::<smoltcp::socket::udp::Socket>(moto_socket.handle);

        let page_allocator = |subchannel_mask| moto_socket.conn.alloc_page(subchannel_mask);

        if let Ok((buf, udp_metadata)) = smol_socket.recv() {
            let addr: SocketAddr = socket_addr_from_endpoint(udp_metadata.endpoint);
            log::debug!(
                "UDP socket 0x{:x} got {} bytes from {:?}",
                u64::from(socket_id),
                buf.len(),
                addr
            );
            moto_socket.rx_queue.push_back(buf, addr);
        }

        while let Some(mut msg) = moto_socket.rx_queue.pop_front(page_allocator) {
            msg.status = moto_rt::E_OK;

            log::debug!("pending RX msg for UDP socket 0x{:x}", u64::from(socket_id));
            self.pending_completions.push_back(PendingCompletion {
                msg,
                endpoint_handle: moto_socket.conn.wait_handle(),
            });
        }

        if !moto_socket.rx_queue.is_empty() || smol_socket.can_recv() {
            self.defer_socket_action(socket_id, None);
        }
    }

    fn do_tcp_tx(&mut self, socket_id: SocketId) {
        let Some(moto_socket) = self.tcp_sockets.get_mut(&socket_id) else {
            // Deferred action sockets may get enqueued more than once.
            return;
        };
        let smol_socket = self.devices[moto_socket.device_idx]
            .sockets
            .get_mut::<smoltcp::socket::tcp::Socket>(moto_socket.handle);

        while smol_socket.can_send() {
            let mut tx_buf = if let Some(x) = moto_socket.tx_queue.pop_front() {
                x
            } else {
                break;
            };

            match smol_socket.send_slice(tx_buf.bytes()) {
                Ok(usize) => {
                    tx_buf.consume(usize);
                    if tx_buf.is_consumed() {
                        // Client writes are completed in tcp_stream_write,
                        // actual socket writes happen later/asynchronously.
                        continue;
                    } else {
                        // moto_socket.
                        moto_socket.tx_queue.push_front(tx_buf);
                        continue;
                    }
                }
                Err(_err) => todo!(),
            }
        }

        self.maybe_complete_deferred_action(socket_id);
    }

    fn do_udp_tx(&mut self, socket_id: SocketId) {
        let Some(moto_socket) = self.udp_sockets.get_mut(&socket_id) else {
            // Deferred action sockets may get enqueued more than once.
            return;
        };

        let conn = moto_socket.conn.clone();

        let smol_socket = self.devices[moto_socket.device_idx]
            .sockets
            .get_mut::<smoltcp::socket::udp::Socket>(moto_socket.handle);

        let mut did_send = false;
        loop {
            let Ok(datagram) = moto_socket.tx_queue.next_datagram() else {
                log::info!(
                    "Killing process 0x{:x} due to bad UDP fragment",
                    moto_socket.pid
                );
                let _ = moto_sys::SysCpu::kill_remote(conn.wait_handle());
                return;
            };

            let Some(datagram) = datagram else {
                break;
            };

            if let Err(err) = smol_socket.send_slice(datagram.slice(), datagram.addr) {
                match err {
                    smoltcp::socket::udp::SendError::Unaddressable => {
                        log::debug!("Cannot send UDP packet to {:?}.", datagram.addr);
                        // TODO: do we need to notify the user?
                        continue;
                    }
                    smoltcp::socket::udp::SendError::BufferFull => {
                        // Can't send the packet: re-insert it into the pending queue.
                        moto_socket.tx_queue.push_front(datagram);
                        break;
                    }
                }
            } else {
                did_send = true;
                log::debug!(
                    "UDP: socket 0x{:x} sent {} bytes to {:?}",
                    u64::from(socket_id),
                    datagram.slice().len(),
                    datagram.addr
                );
            }
        }

        if did_send {
            self.udp_tx_ack(&conn, socket_id);
        }
    }

    const MAX_DEFERRED_ACTION_SECS: u64 = 30;
    const MIN_DEFERRED_ACTION_NS: u64 = 300;

    fn defer_socket_action(&mut self, socket_id: SocketId, started: Option<Instant>) {
        if let Some(started) = started {
            if Self::backoff_done(started) {
                log::debug!(
                    "Dropping socket 0x{:x} due to timeout.",
                    u64::from(socket_id)
                );

                match socket_id.kind() {
                    SocketKind::Tcp => self.drop_tcp_socket(socket_id),
                    SocketKind::Udp => self.drop_udp_socket(socket_id),
                };
                return;
            }
        }

        let next = self.backoff(started);
        self.deferred_sockets.add_at(next, socket_id);
    }

    fn backoff(&mut self, prev: Option<Instant>) -> Instant {
        use rand::Rng;

        let now = Instant::now();

        let Some(prev) = prev else {
            return now
                + core::time::Duration::from_nanos(self.rng.random_range(
                    Self::MIN_DEFERRED_ACTION_NS..(Self::MIN_DEFERRED_ACTION_NS * 2),
                ));
        };

        let diff: u64 = (now - prev).as_nanos().try_into().unwrap();

        now + core::time::Duration::from_nanos(self.rng.random_range((diff * 4)..(diff * 8)))
    }

    fn backoff_done(started: Instant) -> bool {
        (Instant::now() - started).as_secs() > Self::MAX_DEFERRED_ACTION_SECS
    }

    fn udp_socket_drop(&mut self, conn: &Rc<io_channel::ServerConnection>, sqe: io_channel::Msg) {
        let Ok(socket_id) = self.udp_socket_from_msg(conn.wait_handle(), &sqe) else {
            // TODO: drop the connection?
            return;
        };

        self.drop_udp_socket(socket_id);
    }

    fn udp_socket_bind(
        &mut self,
        conn: &Rc<io_channel::ServerConnection>,
        mut sqe: io_channel::Msg,
    ) -> io_channel::Msg {
        if self.devices.is_empty() {
            sqe.status = moto_rt::E_NOT_FOUND;
            return sqe;
        }

        let mut socket_addr = api_net::get_socket_addr(&sqe.payload);

        if self.udp_addresses_in_use.contains(&socket_addr) {
            sqe.status = moto_rt::E_ALREADY_IN_USE;
            return sqe;
        }

        // Verify that the IP is valid (if present) before the socket is created.
        let ip_addr = socket_addr.ip();

        if ip_addr.is_unspecified() {
            // We don't allow binding to an unspecified addr (yet?).
            sqe.status = moto_rt::E_INVALID_ARGUMENT;
            return sqe;
        }
        let device_idx = {
            match self.ip_addresses.get(&ip_addr) {
                Some(idx) => *idx,
                None => {
                    #[cfg(debug_assertions)]
                    log::debug!("IP addr {:?} not found", ip_addr);
                    sqe.status = moto_rt::E_INVALID_ARGUMENT;
                    return sqe;
                }
            }
        };

        // Allocate/assign port, if needed.
        let mut allocated_port = None;
        if socket_addr.port() == 0 {
            let local_port = match self.devices[device_idx].get_ephemeral_udp_port(&ip_addr) {
                Some(port) => port,
                None => {
                    log::warn!("get_ephemeral_udp_port({:?}) failed", ip_addr);
                    sqe.status = moto_rt::E_OUT_OF_MEMORY;
                    return sqe;
                }
            };
            socket_addr.set_port(local_port);
            api_net::put_socket_addr(&mut sqe.payload, &socket_addr);
            allocated_port = Some(local_port);
        }

        let Ok(udp_socket) = self.new_udp_socket_for_device(
            device_idx,
            conn.clone(),
            socket_addr,
            api_net::io_subchannel_mask(sqe.payload.args_8()[23]),
        ) else {
            if let Some(port) = allocated_port {
                self.devices[device_idx].free_ephemeral_udp_port(port);
            }
            sqe.status = moto_rt::E_INVALID_ARGUMENT;
            return sqe;
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
    }

    fn udp_socket_tx(&mut self, conn: &Rc<io_channel::ServerConnection>, sqe: io_channel::Msg) {
        let Ok(socket_id) = self.udp_socket_from_msg(conn.wait_handle(), &sqe) else {
            // Note: we need to get the page so that it is freed.
            let page_idx = sqe.payload.shared_pages()[11];
            let _ = conn.get_page(page_idx);
            // TODO: drop the connection?
            return;
        };

        let fragment_id = sqe.payload.args_16()[9];
        let moto_socket = self.udp_sockets.get_mut(&socket_id).unwrap();
        if moto_socket
            .tx_queue
            .push_back(sqe, |idx| conn.get_page(idx))
            .is_err()
        {
            log::info!(
                "Killing process 0x{:x} due to bad UDP fragment",
                moto_socket.pid
            );
            let _ = moto_sys::SysCpu::kill_remote(conn.wait_handle());
            return;
        }

        if fragment_id != 0 {
            // Notify the client that we've consumed the io page.
            self.udp_tx_ack(conn, socket_id);
        }

        self.do_udp_tx(socket_id);
    }

    fn udp_tx_ack(&mut self, conn: &Rc<io_channel::ServerConnection>, socket_id: SocketId) {
        let mut msg = io_channel::Msg::new();
        msg.command = api_net::NetCmd::UdpSocketTxRxAck.as_u16();
        msg.handle = u64::from(socket_id);

        self.pending_completions.push_back(PendingCompletion {
            msg,
            endpoint_handle: conn.wait_handle(),
        });
    }

    fn poll_devices(&mut self) -> bool {
        let mut polled = false;
        for dev in &mut self.devices {
            polled |= dev.poll();
        }

        polled
    }
}

impl IoSubsystem for NetSys {
    fn wait_handles(&self) -> Vec<SysHandle> {
        let mut res = Vec::new();
        for handle in self.wait_handles.keys() {
            res.push(*handle);
        }

        res
    }

    fn process_wakeup(&mut self, _handle: moto_sys::SysHandle) {
        // TODO: maybe mark the device as woken, and don't poll non-woken devices?
        // let idx = self.wait_handles.get(&handle).unwrap();
        // self.devices[*idx].process_wakeup(handle);
    }

    fn process_sqe(
        &mut self,
        conn: &Rc<io_channel::ServerConnection>,
        msg: io_channel::Msg,
    ) -> Result<Option<io_channel::Msg>, ()> {
        debug_assert_eq!(msg.status(), moto_rt::E_NOT_READY);

        // log::debug!("{}:{} got SQE cmd {}", file!(), line!(), msg.command);

        let Ok(net_cmd) = api_net::NetCmd::try_from(msg.command) else {
            #[cfg(debug_assertions)]
            log::debug!(
                "{}:{} unrecognized command {} from endpoint 0x{:x}",
                file!(),
                line!(),
                msg.command,
                conn.wait_handle().as_u64()
            );

            return Err(());
        };
        match net_cmd {
            api_net::NetCmd::TcpListenerBind => Ok(Some(self.tcp_listener_bind(conn, msg))),
            api_net::NetCmd::TcpListenerAccept => self.tcp_listener_accept(conn, msg),
            api_net::NetCmd::TcpListenerDrop => self.tcp_listener_drop(conn, msg).map(|_| None),
            api_net::NetCmd::TcpListenerSetOption => {
                Ok(Some(self.tcp_listener_set_option(conn, msg)))
            }
            api_net::NetCmd::TcpListenerGetOption => {
                Ok(Some(self.tcp_listener_get_option(conn, msg)))
            }
            api_net::NetCmd::TcpStreamConnect => Ok(self.tcp_stream_connect(conn, msg)),
            api_net::NetCmd::TcpStreamTx => {
                self.tcp_stream_tx(conn, msg);
                Ok(None)
            }
            api_net::NetCmd::TcpStreamRxAck => self.tcp_stream_rx_ack(conn, msg).map(|_| None),
            api_net::NetCmd::TcpStreamSetOption => Ok(Some(self.tcp_stream_set_option(conn, msg))),
            api_net::NetCmd::TcpStreamGetOption => Ok(Some(self.tcp_stream_get_option(conn, msg))),
            api_net::NetCmd::TcpStreamClose => Ok(self.tcp_stream_close(conn, msg)),

            api_net::NetCmd::UdpSocketBind => Ok(Some(self.udp_socket_bind(conn, msg))),
            api_net::NetCmd::UdpSocketDrop => {
                self.udp_socket_drop(conn, msg);
                Ok(None)
            }
            api_net::NetCmd::UdpSocketTxRx => {
                self.udp_socket_tx(conn, msg);
                Ok(None)
            }
            _ => {
                #[cfg(debug_assertions)]
                log::debug!(
                    "{}:{} unrecognized command {} from endpoint 0x{:x}",
                    file!(),
                    line!(),
                    msg.command,
                    conn.wait_handle().as_u64()
                );

                Err(())
            }
        }
    }

    fn on_connection_drop(&mut self, conn: SysHandle) {
        log::debug!("conn 0x{:x} done", conn.as_u64());
        if let Some(udp_sockets) = self.conn_udp_sockets.remove(&conn) {
            for socket_id in udp_sockets {
                self.drop_udp_socket(socket_id);
            }
        }

        if let Some(tcp_sockets) = self.conn_tcp_sockets.remove(&conn) {
            for socket_id in tcp_sockets {
                self.drop_tcp_socket(socket_id);
            }
        }

        if let Some(listeners) = self.conn_tcp_listeners.remove(&conn) {
            for listener_id in listeners {
                self.drop_tcp_listener(listener_id);
            }
        }

        log::debug!("conn 0x{:x} dropped", conn.as_u64());
    }

    fn poll(&mut self) -> Option<PendingCompletion> {
        let now = Instant::now();

        while let Some(socket_id) = self.deferred_sockets.pop_at(now) {
            match socket_id.kind() {
                SocketKind::Tcp => {
                    self.do_tcp_tx(socket_id); // May insert socket_id back into self.deferred_action_sockets.
                    self.do_tcp_rx(socket_id); // May insert socket_id back into self.deferred_action_sockets.
                }
                SocketKind::Udp => {
                    self.do_udp_tx(socket_id);
                    self.do_udp_rx(socket_id);
                }
            }
        }

        // client writes (tcp_stream_write) wake sockets; make sure we
        // process them before polling devices.
        self.process_polled_sockets();

        if let Some(prev) = self.pending_completions.pop_front() {
            return Some(prev);
        }

        loop {
            let polled = self.poll_devices();

            // Sometimes, e.g. on listener bind, sockets will get polled/woken
            // outside of dev.poll(), so we cannot rely on only !polled.
            if !polled && self.woken_sockets.borrow().is_empty() {
                break;
            }

            self.process_polled_sockets();
            assert!(self.woken_sockets.borrow().is_empty());

            // We don't want to loop here forever, which can happen if sockets do
            // stuff in the background.
            if let Some(prev) = self.pending_completions.pop_front() {
                return Some(prev);
            }
        }

        self.pending_completions.pop_front()
    }

    fn wait_timeout(&mut self) -> Option<core::time::Duration> {
        let mut timeout = None;

        for device_idx in 0..self.devices.len() {
            let dev = self.devices.get_mut(device_idx).unwrap();
            if let Some(timo) = dev.wait_timeout() {
                match timeout {
                    Some(prev) => {
                        if prev > timo {
                            timeout = Some(timo);
                        }
                    }
                    None => timeout = Some(timo),
                }
            }
        }

        if let Some(timo) = self.deferred_sockets.next_at() {
            let timo = timo - Instant::now();
            match timeout {
                Some(prev) => {
                    if prev > timo {
                        timeout = Some(timo);
                    }
                }
                None => timeout = Some(timo),
            }
        }

        timeout
    }

    fn get_stats(&mut self, msg: &crate::runtime::internal_queue::Msg) {
        let num_results = moto_sys_io::stats::MAX_TCP_SOCKET_STATS.min(self.socket_ids.len());

        let payload = msg
            .payload
            .clone()
            .downcast::<crate::runtime::io_stats::GetTcpStatsPayload>()
            .unwrap();

        let start_id = SocketId::from(payload.start_id);
        let mut results = Vec::new();

        for &socket_id in self.socket_ids.range(start_id..) {
            let moto_socket = self.tcp_sockets.get(&socket_id).unwrap();
            let device_idx = moto_socket.device_idx;
            let smol_socket = self.devices[device_idx]
                .sockets
                .get_mut::<smoltcp::socket::tcp::Socket>(moto_socket.handle);

            let mut stats = moto_sys_io::stats::TcpSocketStatsV1 {
                id: moto_socket.id.into(),
                device_id: device_idx as u64,
                pid: moto_socket.pid,
                ..Default::default()
            };

            let local_addr = if let Some(e) = smol_socket.local_endpoint() {
                Some(super::smoltcp_helpers::socket_addr_from_endpoint(e))
            } else {
                moto_socket.listening_on
            };
            let remote_addr = smol_socket
                .remote_endpoint()
                .map(super::smoltcp_helpers::socket_addr_from_endpoint);

            if let Some(addr) = local_addr {
                stats.local_port = addr.port();
                stats.local_addr = super::smoltcp_helpers::addr_to_octets(addr.ip());
            }

            if let Some(addr) = remote_addr {
                stats.remote_port = addr.port();
                stats.remote_addr = super::smoltcp_helpers::addr_to_octets(addr.ip());
            }

            stats.tcp_state = moto_socket.state;
            stats.smoltcp_state = smol_socket.state();

            results.push(stats);
            if results.len() == num_results {
                break;
            }
        }

        payload.results.swap(results);
    }

    fn dump_state(&mut self) {
        for socket in self.tcp_sockets.values() {
            socket.dump_state();
        }
    }
}

pub(super) fn on_ephemeral_tcp_port_dropped(device_idx: usize, port: u16) {
    NetSys::get()
        .ephemeral_tcp_ports_to_clear
        .push((device_idx, port));
}
