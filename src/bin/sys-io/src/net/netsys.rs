use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    rc::Rc,
};

use crate::runtime::IoSubsystem;
use crate::runtime::PendingCompletion;
use moto_ipc::io_channel;
use moto_runtime::rt_api::{self, net::TcpState};
use moto_sys::{ErrorCode, SysHandle};

use super::socket::MotoSocket;
use super::socket::SocketId;
use super::tcp_listener::TcpListener;
use super::tcp_listener::TcpListenerId;
use super::RxBuf;
use super::{netdev::NetDev, TxBuf};

// How many listening sockets to open (per specific SocketAddr).
const DEFAULT_NUM_LISTENING_SOCKETS: usize = 4;
const MAX_NUM_LISTENING_SOCKETS: usize = 32;
// How many concurrent connections per listener (any SocketAddr) to allow.
const _DEFAULT_MAX_CONNECTIONS_PER_LISTENER: usize = 16;

pub(super) struct NetSys {
    devices: Vec<NetDev>, // Never changes, as device_idx references inside here.
    wait_handles: HashMap<SysHandle, usize>, // Handle -> idx in self.devices.
    ip_addresses: HashMap<IpAddr, usize>,

    next_id: u64,

    pending_completions: VecDeque<PendingCompletion>,

    // NetSys owns all listeners, sockets, etc. in the system, via the hash maps below.
    tcp_listeners: HashMap<TcpListenerId, TcpListener>,
    tcp_sockets: HashMap<SocketId, MotoSocket>, // Active connections.

    // If we can't allocate an IO buffer (page) for RX for a socket, the socket is placed here.
    pending_tcp_rx: VecDeque<SocketId>,

    // "Empty" sockets cached here.
    tcp_socket_cache: Vec<smoltcp::socket::tcp::Socket<'static>>,

    // Conn ID -> TCP listeners/sockets. Needed to e.g. protect one process
    // accessing another process's sockets, and to drop/clear when the process dies.
    conn_tcp_listeners: HashMap<SysHandle, HashSet<TcpListenerId>>,
    conn_tcp_sockets: HashMap<SysHandle, HashSet<SocketId>>,

    woken_sockets: Rc<RefCell<VecDeque<SocketId>>>,
    wakers: std::collections::HashMap<SocketId, std::task::Waker>,

    // config: config::NetConfig,
    config: super::config::NetConfig,
}

impl NetSys {
    pub fn new(config: super::config::NetConfig) -> Box<Self> {
        let devices = super::netdev::init(&config);
        let mut self_ref = Box::new(Self {
            devices,
            wait_handles: HashMap::new(),
            ip_addresses: HashMap::new(),
            next_id: 1,
            tcp_listeners: HashMap::new(),
            tcp_sockets: HashMap::new(),
            pending_tcp_rx: VecDeque::new(),
            tcp_socket_cache: Vec::new(),
            pending_completions: VecDeque::new(),
            conn_tcp_listeners: HashMap::new(),
            conn_tcp_sockets: HashMap::new(),
            woken_sockets: Rc::new(std::cell::RefCell::new(VecDeque::new())),
            wakers: HashMap::new(),
            config,
        });

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

    fn tcp_listener_bind(
        &mut self,
        conn: &Rc<io_channel::ServerConnection>,
        mut sqe: io_channel::Msg,
    ) -> io_channel::Msg {
        if self.devices.is_empty() {
            sqe.status = ErrorCode::NotFound.into();
            return sqe;
        }

        let socket_addr = match rt_api::net::get_socket_addr(&sqe.payload) {
            Ok(addr) => addr,
            Err(err) => {
                sqe.status = err.into();
                return sqe;
            }
        };

        // Verify that we are not listening on that address yet.
        for (_, listener) in &self.tcp_listeners {
            if *listener.socket_addr() == socket_addr {
                sqe.status = ErrorCode::AlreadyInUse.into();
                return sqe;
            }
        }

        // TODO: what if we are listening on *:PORT, and are asked to listen on IP:PORT?
        //       Maybe that's OK? A random listening socket will be picked up on an
        //       incoming connection.

        // Verify that the IP is valid (if present) before the listener is created.
        let ip_addr = socket_addr.ip();
        let device_idx: Option<usize> = if ip_addr.is_unspecified() {
            None
        } else {
            match self.ip_addresses.get(&ip_addr) {
                Some(idx) => Some(*idx),
                None => {
                    sqe.status = ErrorCode::InvalidArgument.into();
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
            sqe.status = ErrorCode::InvalidArgument.into();
            return sqe;
        }

        let listener_id: TcpListenerId = self.next_id().into();
        let listener = TcpListener::new(conn.clone(), socket_addr);
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
        assert!(conn_listeners.insert(listener_id.into()));

        #[cfg(debug_assertions)]
        log::debug!(
            "sys-io: new tcp listener on {:?}, conn: 0x{:x}",
            socket_addr,
            conn.wait_handle().as_u64()
        );

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
                            self.drop_tcp_listener(listener_id);
                            sqe.status = err.into();
                            return sqe;
                        }
                    }
                }
            }
            Some(idx) => {
                if let Err(err) =
                    self.start_listening_on_device(listener_id, idx, socket_addr, num_listeners)
                {
                    self.drop_tcp_listener(listener_id);
                    sqe.status = err.into();
                    return sqe;
                }
            }
        }

        sqe.handle = listener_id.into();
        sqe.status = ErrorCode::Ok.into();
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
            let mut moto_socket = self.new_socket_for_device(device_idx)?;
            let socket_id = moto_socket.id;
            moto_socket.listener_id = Some(listener_id);
            self.tcp_listeners
                .get_mut(&listener_id)
                .unwrap()
                .add_listening_socket(socket_id);
            moto_socket.state = TcpState::Listening;

            let smol_handle = moto_socket.handle;
            self.tcp_sockets.insert(moto_socket.id, moto_socket);

            let smol_socket = self.devices[device_idx]
                .sockets
                .get_mut::<smoltcp::socket::tcp::Socket>(smol_handle);
            smol_socket
                .listen((socket_addr.ip(), socket_addr.port()))
                .unwrap();
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

    fn new_socket_for_device(&mut self, device_idx: usize) -> Result<MotoSocket, ErrorCode> {
        let mut smol_socket = self.get_unused_tcp_socket()?;
        let socket_id = self.next_id().into();

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

        Ok(MotoSocket {
            id: socket_id,
            handle,
            device_idx,
            conn: None,
            listener_id: None,
            connect_req: None,
            ephemeral_port: None,
            tx_queue: VecDeque::new(),
            rx_seq: 0,
            rx_ack: u64::MAX,
            state: TcpState::Closed,
            rx_closed_notified: false,
            subchannel_mask: u64::MAX,
        })
    }

    fn drop_tcp_listener(&mut self, listener_id: TcpListenerId) {
        let mut listener = self.tcp_listeners.remove(&listener_id).unwrap();
        while let Some((mut req, conn)) = listener.get_pending_accept() {
            req.status = ErrorCode::BadHandle.into();
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
        self.cancel_tcp_tx(socket_id);

        let mut moto_socket = self.tcp_sockets.remove(&socket_id).unwrap();
        while let Some(tx_buf) = moto_socket.tx_queue.pop_front() {
            core::mem::drop(tx_buf);
        }

        if let Some(conn) = moto_socket.conn.as_ref() {
            if let Some(conn_sockets) = self.conn_tcp_sockets.get_mut(&conn.wait_handle()) {
                assert!(conn_sockets.remove(&socket_id));
            }
        }

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

        let smol_socket = match self.devices[moto_socket.device_idx]
            .sockets
            .remove(moto_socket.handle)
        {
            smoltcp::socket::Socket::Tcp(s) => s,
            _ => panic!(),
        };

        if let Some(port) = moto_socket.ephemeral_port.take() {
            self.devices[moto_socket.device_idx].free_ephemeral_port(port);
        }

        if let Some(listener_id) = moto_socket.listener_id.take() {
            // When handling drop_tcp_listener cmd, the listener is first removed,
            // then its listening sockets are removed, so the next line will get None.
            if let Some(listener) = self.tcp_listeners.get_mut(&listener_id) {
                listener.remove_listening_socket(socket_id);
            }
        }

        if let Some(mut cqe) = moto_socket.connect_req.take() {
            assert_eq!(moto_socket.state, TcpState::Connecting);
            cqe.status = ErrorCode::BadHandle.into();
            self.pending_completions.push_back(PendingCompletion {
                msg: cqe,
                endpoint_handle: moto_socket.conn.as_ref().unwrap().wait_handle(),
            });
        }

        self.put_unused_tcp_socket(smol_socket);
        #[cfg(debug_assertions)]
        log::debug!(
            "{}:{} dropped tcp socket 0x{:x}; {} active sockets.",
            file!(),
            line!(),
            u64::from(socket_id),
            self.tcp_sockets.len()
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
                return Err(());
            }
        };

        if listener.conn_handle() != conn.wait_handle() {
            // Validate that the listener and the connection belong to the same process.
            let pid1 = moto_sys::syscalls::SysCtl::get_pid(listener.conn_handle()).unwrap();
            let pid2 = moto_sys::syscalls::SysCtl::get_pid(conn.wait_handle()).unwrap();
            if pid1 != pid2 {
                return Err(());
            }
        }

        if let Some((socket_id, socket_addr)) = listener.pop_pending_socket() {
            // TODO: the unwrap() below once triggered on remote drop.
            let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();
            assert!(moto_socket.listener_id.is_none());

            moto_socket.subchannel_mask = req.payload.args_64()[0];

            // Note: we don't generate the state change event here because
            // we respond to the accept() request explicitly.
            moto_socket.state = TcpState::ReadWrite;
            req.handle = socket_id.into();
            rt_api::net::put_socket_addr(&mut req.payload, &socket_addr);
            req.status = ErrorCode::Ok.into();
            self.pending_completions.push_back(PendingCompletion {
                msg: req,
                endpoint_handle: conn.wait_handle(),
            });

            let conn_handle = conn.wait_handle();
            moto_socket.conn = Some(conn.clone());
            if let Some(conn_sockets) = self.conn_tcp_sockets.get_mut(&conn_handle) {
                conn_sockets.insert(socket_id);
            } else {
                let mut conn_sockets = HashSet::new();
                conn_sockets.insert(socket_id);
                self.conn_tcp_sockets.insert(conn_handle, conn_sockets);
            }

            // Do rx after generating the accept completion, otherwise rx packets
            // may get delivered to the client for an unknown socket.
            self.do_tcp_rx(socket_id); // The socket can now Rx.
            return Ok(None);
        }

        listener.add_pending_accept(req, conn);
        Ok(None)
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

    fn get_unused_tcp_socket(
        &mut self,
    ) -> Result<smoltcp::socket::tcp::Socket<'static>, ErrorCode> {
        if let Some(socket) = self.tcp_socket_cache.pop() {
            Ok(socket)
        } else {
            const RX_BUF_SZ: usize =
                io_channel::PAGE_SIZE * (rt_api::net::TCP_RX_MAX_INFLIGHT as usize);
            let rx_buffer = smoltcp::socket::tcp::SocketBuffer::new(vec![0; RX_BUF_SZ]);
            let tx_buffer = smoltcp::socket::tcp::SocketBuffer::new(vec![0; 16384 * 2]);

            log::debug!("{}:{} new TCP socket", file!(), line!());
            Ok(smoltcp::socket::tcp::Socket::new(rx_buffer, tx_buffer))
        }
    }

    fn put_unused_tcp_socket(&mut self, socket: smoltcp::socket::tcp::Socket<'static>) {
        debug_assert_eq!(socket.state(), smoltcp::socket::tcp::State::Closed);
        // TODO: limit the size of the cache (i.e. drop socket if the cache is too large).
        self.tcp_socket_cache.push(socket);
    }

    fn tcp_stream_connect(
        &mut self,
        conn: &Rc<io_channel::ServerConnection>,
        mut sqe: io_channel::Msg,
    ) -> Option<io_channel::Msg> {
        let remote_addr = match rt_api::net::get_socket_addr(&sqe.payload) {
            Ok(addr) => addr,
            Err(err) => {
                sqe.status = err.into();
                return Some(sqe);
            }
        };

        let timeout = rt_api::net::tcp_stream_connect_timeout(&sqe);
        if let Some(timo) = timeout {
            if timo <= moto_sys::time::Instant::now() {
                sqe.status = ErrorCode::TimedOut.into();
                return Some(sqe);
            }
        };

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

            sqe.status = ErrorCode::NotFound.into();
            return Some(sqe);
        };

        let local_port =
            match self.devices[device_idx].get_ephemeral_port(&local_ip_addr, &remote_addr) {
                Some(port) => port,
                None => {
                    log::info!("get_ephemeral_port({:?}) failed", local_ip_addr);
                    sqe.status = ErrorCode::OutOfMemory.into();
                    return Some(sqe);
                }
            };

        let mut moto_socket = match self.new_socket_for_device(device_idx) {
            Ok(s) => s,
            Err(err) => {
                sqe.status = err.into();
                return Some(sqe);
            }
        };
        moto_socket.subchannel_mask = sqe.payload.args_64()[0];

        moto_socket.conn = Some(conn.clone());
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
        self.tcp_sockets.insert(moto_socket.id, moto_socket);

        let smol_socket = self.devices[device_idx]
            .sockets
            .get_mut::<smoltcp::socket::tcp::Socket>(smol_handle);

        if let Some(timeout) = timeout {
            let now = moto_sys::time::Instant::now();
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
        self.devices[device_idx].connect_socket(smol_handle, &local_addr, &remote_addr);

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
                log::debug!("{}:{} bad socket", file!(), line!());
                let mut err = *sqe;
                err.status = ErrorCode::InvalidArgument.into();
                return Err(err);
            }
        } else {
            log::debug!("{}:{} bad socket", file!(), line!());
            let mut err = *sqe;
            err.status = ErrorCode::InvalidArgument.into();
            return Err(err);
        }

        Ok(socket_id)
    }

    // Note: does not return anything because TX is one-way, nobody is listening for TX responses.
    fn tcp_stream_write(&mut self, conn: &Rc<io_channel::ServerConnection>, msg: io_channel::Msg) {
        // Note: we need to get the page so that it is freed.
        let page_idx = msg.payload.shared_pages()[0];
        let page = if let Ok(page) = conn.get_page(page_idx) {
            page
        } else {
            return;
        };
        let socket_id = if let Ok(s) = self.tcp_socket_from_msg(conn.wait_handle(), &msg) {
            s
        } else {
            return;
        };

        // Validate that the socket belongs to the connection.
        if let Some(socks) = self.conn_tcp_sockets.get(&conn.wait_handle()) {
            if !socks.contains(&socket_id) {
                return;
            }
        } else {
            return;
        }

        let sz = msg.payload.args_64()[1] as usize;
        if sz > io_channel::PAGE_SIZE {
            return;
        }

        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();
        match moto_socket.state {
            TcpState::Connecting | TcpState::Listening | TcpState::PendingAccept => panic!(),
            TcpState::ReadWrite | TcpState::WriteOnly => {}
            TcpState::ReadOnly | TcpState::Closed => {
                // log::debug!(
                //     "{}:{} write request issued for non-writable socket 0x{:x}",
                //     file!(),
                //     line!(),
                //     u64::from(socket_id)
                // );
                return;
            }
            TcpState::_Max => panic!(),
        }

        moto_socket.tx_queue.push_back(TxBuf {
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
            Err(_) => return Err(()),
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
            sqe.status = ErrorCode::InvalidArgument.into();
            return sqe;
        }

        let mut options = sqe.payload.args_64()[0];
        if options == 0 {
            sqe.status = ErrorCode::InvalidArgument.into();
            return sqe;
        }

        if options == rt_api::net::TCP_OPTION_NODELAY {
            let nodelay_u64 = sqe.payload.args_64()[1];
            let nodelay = match nodelay_u64 {
                1 => true,
                0 => false,
                _ => {
                    sqe.status = ErrorCode::InvalidArgument.into();
                    return sqe;
                }
            };

            let smol_socket = self.devices[moto_socket.device_idx]
                .sockets
                .get_mut::<smoltcp::socket::tcp::Socket>(moto_socket.handle);
            smol_socket.set_nagle_enabled(!nodelay);
            sqe.status = ErrorCode::Ok.into();
            return sqe;
        }

        if options == rt_api::net::TCP_OPTION_TTL {
            let ttl = sqe.payload.args_32()[2];
            if ttl == 0 || ttl > 255 {
                sqe.status = ErrorCode::InvalidArgument.into();
                return sqe;
            };

            let smol_socket = self.devices[moto_socket.device_idx]
                .sockets
                .get_mut::<smoltcp::socket::tcp::Socket>(moto_socket.handle);
            smol_socket.set_hop_limit(Some(ttl as u8));
            sqe.status = ErrorCode::Ok.into();
            return sqe;
        }

        let shut_rd =
            (options & rt_api::net::TCP_OPTION_SHUT_RD != 0) && moto_socket.state.can_read();
        options ^= rt_api::net::TCP_OPTION_SHUT_RD;

        let shut_wr =
            (options & rt_api::net::TCP_OPTION_SHUT_WR != 0) && moto_socket.state.can_write();
        options ^= rt_api::net::TCP_OPTION_SHUT_WR;

        if options != 0 {
            sqe.status = ErrorCode::InvalidArgument.into();
            return sqe;
        }

        if !(shut_rd || shut_wr) {
            sqe.status = ErrorCode::Ok.into(); // Nothing to do.
            return sqe;
        }

        let smol_socket = self.devices[moto_socket.device_idx]
            .sockets
            .get_mut::<smoltcp::socket::tcp::Socket>(moto_socket.handle);

        match moto_socket.state {
            TcpState::Connecting => unreachable!(), // We eliminated this option above.
            TcpState::Listening | TcpState::PendingAccept => {
                unreachable!("the client does not have SocketId")
            }
            TcpState::ReadWrite => {
                if shut_rd && shut_wr {
                    moto_socket.state = TcpState::Closed;
                    sqe.payload.args_32_mut()[5] = moto_socket.state.into();
                    smol_socket.close();
                    self.cancel_tcp_tx(socket_id);
                } else if shut_rd {
                    moto_socket.state = TcpState::WriteOnly;
                    sqe.payload.args_32_mut()[5] = moto_socket.state.into();
                } else {
                    assert!(shut_wr);
                    moto_socket.state = TcpState::ReadOnly;
                    sqe.payload.args_32_mut()[5] = moto_socket.state.into();
                    smol_socket.close();
                    self.cancel_tcp_tx(socket_id);
                }
            }
            TcpState::ReadOnly => {
                if shut_wr {
                    assert!(moto_socket.tx_queue.is_empty());
                    moto_socket.state = TcpState::Closed;
                    sqe.payload.args_32_mut()[5] = moto_socket.state.into();
                    smol_socket.close();
                }
            }
            TcpState::WriteOnly => {
                if shut_rd {
                    moto_socket.state = TcpState::Closed;
                    sqe.payload.args_32_mut()[5] = moto_socket.state.into();
                    smol_socket.close();
                    self.cancel_tcp_tx(socket_id);
                }
            }
            TcpState::Closed => {}
            TcpState::_Max => panic!(),
        }

        sqe.status = ErrorCode::Ok.into();
        return sqe;
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
            sqe.status = ErrorCode::InvalidArgument.into();
            return sqe;
        }

        let options = sqe.payload.args_64()[0];
        if options == 0 {
            sqe.status = ErrorCode::InvalidArgument.into();
            return sqe;
        }

        match options {
            rt_api::net::TCP_OPTION_NODELAY => {
                let smol_socket = self.devices[moto_socket.device_idx]
                    .sockets
                    .get::<smoltcp::socket::tcp::Socket>(moto_socket.handle);
                let nodelay = !smol_socket.nagle_enabled();
                sqe.payload.args_64_mut()[0] = if nodelay { 1 } else { 0 };
                sqe.status = ErrorCode::Ok.into();
            }
            rt_api::net::TCP_OPTION_TTL => {
                let smol_socket = self.devices[moto_socket.device_idx]
                    .sockets
                    .get::<smoltcp::socket::tcp::Socket>(moto_socket.handle);
                let ttl = if let Some(hl) = smol_socket.hop_limit() {
                    hl as u32
                } else {
                    64 // This is what smoltcp documentation implies.
                };
                sqe.payload.args_32_mut()[0] = ttl;
                sqe.status = ErrorCode::Ok.into();
            }
            _ => {
                log::debug!("Invalid option 0x{}", options);
                sqe.status = ErrorCode::InvalidArgument.into();
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
            sqe.status = ErrorCode::InvalidArgument.into();
            return Some(sqe);
        };
        log::debug!(
            "{}:{} tcp_stream_close 0x{:x}",
            file!(),
            line!(),
            u64::from(socket_id)
        );
        // While there can still be outgoing writes that need completion,
        // we drop everything here: let the user-side worry about
        // not dropping connections before writes are complete.
        // TODO: implement SO_LINGER (Rust: TcpStream::set_linger()).
        self.drop_tcp_socket(socket_id);
        sqe.status = ErrorCode::Ok.into();
        Some(sqe)
    }

    fn next_id(&mut self) -> u64 {
        let res = self.next_id;
        self.next_id += 1;
        res
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
        match self.ip_addresses.get(ip_addr) {
            Some(device_idx) => return Some((*device_idx, *ip_addr)),
            None => {}
        }

        // If not found, look through routes.
        self.config
            .find_route(ip_addr)
            .map(|(dev_name, addr)| (self.device_idx_from_name(dev_name.as_str()), addr))
    }

    fn rx_buf_to_pc(
        socket_id: SocketId,
        endpoint_handle: SysHandle,
        x_buf: RxBuf,
        rx_seq: u64,
    ) -> PendingCompletion {
        let (io_page, sz) = (x_buf.page, x_buf.consumed);
        let mut msg =
            moto_runtime::rt_api::net::tcp_stream_rx_msg(socket_id.into(), io_page, sz, rx_seq);
        msg.status = ErrorCode::Ok.into();

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

        // Without these, remotely dropped sockets may hang around indefinitely.
        smol_socket.set_timeout(Some(smoltcp::time::Duration::from_millis(5_000)));
        smol_socket.set_keep_alive(Some(smoltcp::time::Duration::from_millis(10_000)));
        smol_socket.set_nagle_enabled(false); // A good idea, generally.
        smol_socket.set_ack_delay(None);

        let local_addr = super::smoltcp_helpers::socket_addr_from_endpoint(
            smol_socket.local_endpoint().unwrap(),
        );
        let remote_addr = super::smoltcp_helpers::socket_addr_from_endpoint(
            smol_socket.remote_endpoint().unwrap(),
        );

        let listener_id = moto_socket.listener_id.take().unwrap();
        let listener = self.tcp_listeners.get_mut(&listener_id).unwrap();
        let may_do_io = if let Some((mut msg, conn)) = listener.get_pending_accept() {
            moto_socket.state = TcpState::ReadWrite;
            let endpoint_handle = conn.wait_handle();
            moto_socket.subchannel_mask = msg.payload.args_64()[0];
            moto_socket.conn = Some(conn);
            if let Some(conn_sockets) = self.conn_tcp_sockets.get_mut(&endpoint_handle) {
                conn_sockets.insert(socket_id);
            } else {
                let mut conn_sockets = HashSet::new();
                conn_sockets.insert(socket_id);
                self.conn_tcp_sockets.insert(endpoint_handle, conn_sockets);
            }
            msg.handle = moto_socket.id.into();
            rt_api::net::put_socket_addr(&mut msg.payload, &remote_addr);
            msg.status = ErrorCode::Ok.into();
            self.pending_completions.push_back(PendingCompletion {
                msg,
                endpoint_handle,
            });
            true
        } else {
            // TODO: this codepath is probably untested (usually accept request comes before remote connects).
            assert_eq!(moto_socket.state, TcpState::Listening);
            // Note: we don't generate the state change event because accept() is handled explicitly.
            moto_socket.state = TcpState::PendingAccept;
            listener.add_pending_socket(moto_socket.id, remote_addr);
            false
        };

        #[cfg(debug_assertions)]
        log::debug!(
            "{}:{} on_tcp_listener_connected 0x{:x} - {:?}",
            file!(),
            line!(),
            u64::from(socket_id),
            remote_addr
        );

        // One listening socket has been consumed (became a connected socket),
        // so we create another one.
        if let Err(err) = self.start_listening_on_device(listener_id, device_idx, local_addr, 1) {
            log::error!(
                "{}:{} bind_on_device() failed with {:?}",
                file!(),
                line!(),
                err
            );
        }

        may_do_io
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
        rt_api::net::put_socket_addr(&mut cqe.payload, &local_addr);
        cqe.status = ErrorCode::Ok.into();
        self.pending_completions.push_back(PendingCompletion {
            msg: cqe,
            endpoint_handle: moto_socket.conn.as_ref().unwrap().wait_handle(),
        });

        self.do_tcp_rx(socket_id); // The socket can now Rx.
    }

    fn on_connect_failed(&mut self, socket_id: SocketId) {
        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();

        let mut cqe = moto_socket.connect_req.take().unwrap();
        // Note: we don't generate the state change event because of the explicit PC below.
        moto_socket.state = TcpState::Closed;
        cqe.handle = moto_socket.id.into();
        cqe.status = ErrorCode::TimedOut.into();
        self.pending_completions.push_back(PendingCompletion {
            msg: cqe,
            endpoint_handle: moto_socket.conn.as_ref().unwrap().wait_handle(),
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
        let moto_socket = match self.tcp_sockets.get_mut(&socket_id) {
            Some(s) => s,
            None => return,
        };
        let smol_socket = self.devices[moto_socket.device_idx]
            .sockets
            .get_mut::<smoltcp::socket::tcp::Socket>(moto_socket.handle);

        // Registered wakers fire only once, so we need to re-register them every time.
        smol_socket.register_recv_waker(&waker);
        smol_socket.register_send_waker(&waker);

        let may_send = smol_socket.may_send();
        let can_recv = smol_socket.can_recv() || !moto_socket.rx_closed_notified;
        let can_send = smol_socket.can_send();
        let state = smol_socket.state();

        #[cfg(debug_assertions)]
        let mut dbg_moto_state = moto_socket.state;

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
        match state {
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
                        return; // Cannot do I/O.
                    }
                } else if moto_socket.state == TcpState::Connecting {
                    self.on_socket_connected(socket_id);
                } else if moto_socket.state == TcpState::PendingAccept {
                    return; // Cannot do I/O.
                }
            }

            smoltcp::socket::tcp::State::Closed => match moto_socket.state {
                TcpState::Connecting => {
                    self.on_connect_failed(socket_id);
                    return;
                }
                TcpState::Listening => panic!(), // Impossible.
                TcpState::PendingAccept => todo!(),
                TcpState::ReadWrite | TcpState::ReadOnly | TcpState::WriteOnly => {
                    moto_socket.state = TcpState::Closed;
                    #[cfg(debug_assertions)]
                    {
                        dbg_moto_state = moto_socket.state;
                    }
                    self.on_socket_state_changed(socket_id);
                }
                TcpState::Closed => {}
                TcpState::_Max => panic!(),
            },

            smoltcp::socket::tcp::State::CloseWait => match moto_socket.state {
                TcpState::Connecting | TcpState::Listening => panic!(), // Impossible.
                TcpState::PendingAccept => {
                    self.drop_tcp_socket(socket_id);
                    return;
                }
                TcpState::ReadOnly | TcpState::WriteOnly | TcpState::ReadWrite => {
                    // The remote end closed its write channel, but there still
                    // may be bytes in the socket TX buffer. While we _may_ try
                    // to send pending data, this is most likely a waste of resources,
                    // so we close the socket on our side unconditionally.
                    //
                    // TL;DR: leaking CLOSE_WAIT sockets is a thing. We don't want that.
                    smol_socket.close();
                    moto_socket.state = TcpState::Closed;
                    #[cfg(debug_assertions)]
                    {
                        dbg_moto_state = moto_socket.state;
                    }
                    self.on_socket_state_changed(socket_id);
                }

                TcpState::Closed => {}
                TcpState::_Max => panic!(),
            },

            smoltcp::socket::tcp::State::FinWait1 => {
                match moto_socket.state {
                    TcpState::Listening
                    | TcpState::PendingAccept
                    | TcpState::Connecting
                    | TcpState::ReadWrite
                    | TcpState::WriteOnly => panic!(), // Impossible.
                    TcpState::ReadOnly | TcpState::Closed => {}
                    TcpState::_Max => panic!(),
                }
            }
            smoltcp::socket::tcp::State::FinWait2
            | smoltcp::socket::tcp::State::Closing
            | smoltcp::socket::tcp::State::LastAck
            | smoltcp::socket::tcp::State::TimeWait => {
                assert_eq!(moto_socket.state, TcpState::Closed);
            }
        }

        #[cfg(debug_assertions)]
        if state != smoltcp::socket::tcp::State::Established {
            log::debug!(
                "socket state: {:?} for socket 0x{:x} can_recv: {:?} moto state: {:?}",
                state,
                u64::from(socket_id),
                can_recv,
                dbg_moto_state
            );
        }

        if can_recv {
            self.do_tcp_rx(socket_id);
        }

        if can_send {
            self.do_tcp_tx(socket_id);
        } else if !may_send {
            self.cancel_tcp_tx(socket_id);
        }
    }

    fn process_polled_sockets(&mut self) {
        loop {
            let socket_id = if let Some(socket_id) = self.woken_sockets.borrow_mut().pop_front() {
                socket_id
            } else {
                break;
            };
            self.on_tcp_socket_poll(socket_id);
        }
        assert!(self.woken_sockets.borrow().is_empty());
    }

    fn on_socket_state_changed(&mut self, socket_id: SocketId) {
        let moto_socket = self.tcp_sockets.get(&socket_id).unwrap();
        let mut msg = io_channel::Msg::new();
        msg.command = rt_api::net::EVT_TCP_STREAM_STATE_CHANGED;
        msg.handle = moto_socket.id.into();
        msg.payload.args_32_mut()[0] = moto_socket.state.into();
        msg.status = ErrorCode::Ok.into();

        self.pending_completions.push_back(PendingCompletion {
            msg,
            endpoint_handle: moto_socket.conn.as_ref().unwrap().wait_handle(),
        });
    }

    fn do_tcp_rx(&mut self, socket_id: SocketId) {
        let moto_socket = if let Some(socket) = self.tcp_sockets.get_mut(&socket_id) {
            socket
        } else {
            // The socket may have been closed/removed while sitting on self.pending_tcp_rx.
            return;
        };
        let smol_socket = self.devices[moto_socket.device_idx]
            .sockets
            .get_mut::<smoltcp::socket::tcp::Socket>(moto_socket.handle);

        if moto_socket.rx_ack == u64::MAX
            || (moto_socket.rx_seq > (moto_socket.rx_ack + rt_api::net::TCP_RX_MAX_INFLIGHT))
        {
            // #[cfg(debug_assertions)]
            // if moto_socket.rx_ack != u64::MAX {
            //     log::debug!(
            //         "{}:{} TCP RX: stuck seq: {} ack: {} state: {:?}",
            //         file!(),
            //         line!(),
            //         moto_socket.rx_seq,
            //         moto_socket.rx_ack,
            //         moto_socket.state
            //     );
            // }
            return;
        }

        // We are attempting to deliver any incoming bytes even if the peer has closed the connection.
        while smol_socket.recv_queue() > 0 {
            let page = match moto_socket.conn.as_ref().unwrap().alloc_page(0xFF) {
                Ok(page) => page,
                Err(err) => {
                    assert_eq!(err, ErrorCode::NotReady);
                    self.pending_tcp_rx.push_back(socket_id);
                    return;
                }
            };
            let mut rx_buf = RxBuf::new(page);
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

            // #[cfg(debug_assertions)]
            // log::debug!(
            //     "{}:{} TcpRx event: seq {} {} bytes",
            //     file!(),
            //     line!(),
            //     moto_socket.rx_seq,
            //     rx_buf.consumed
            // );

            moto_socket.rx_seq += 1;
            self.pending_completions.push_back(Self::rx_buf_to_pc(
                socket_id,
                moto_socket.conn.as_ref().unwrap().wait_handle(),
                rx_buf,
                moto_socket.rx_seq,
            ));

            if moto_socket.rx_seq > (moto_socket.rx_ack + rt_api::net::TCP_RX_MAX_INFLIGHT) {
                break;
            }
        }

        // While the process knows about the socket state, it does not know that there are
        // no cached RX packets. The code below delivers a zero-sized RX packet to that end.
        if smol_socket.recv_queue() == 0
            && (moto_socket.state == TcpState::WriteOnly || moto_socket.state == TcpState::Closed)
        {
            if !moto_socket.rx_closed_notified {
                moto_socket.rx_seq += 1;

                let mut msg = io_channel::Msg::new();
                msg.command = rt_api::net::CMD_TCP_STREAM_RX;
                msg.handle = moto_socket.id.into();
                msg.payload.shared_pages_mut()[0] = u16::MAX;
                msg.payload.args_64_mut()[1] = 0;
                msg.payload.args_64_mut()[2] = moto_socket.rx_seq;
                msg.status = ErrorCode::Ok.into();

                self.pending_completions.push_back(PendingCompletion {
                    msg,
                    endpoint_handle: moto_socket.conn.as_ref().unwrap().wait_handle(),
                });
                moto_socket.rx_closed_notified = true;
                log::debug!(
                    "{}:{} RX Closed for socket 0x{:x}",
                    file!(),
                    line!(),
                    u64::from(socket_id)
                );
            }
        }
    }

    fn do_tcp_tx(&mut self, socket_id: SocketId) {
        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();
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
                        moto_socket.tx_queue.push_front(tx_buf);
                        continue;
                    }
                }
                Err(_err) => todo!(),
            }
        }
    }

    fn cancel_tcp_tx(&mut self, socket_id: SocketId) {
        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();
        // TODO: Linux keeps sending buffered packets after socket close. Should we do the same?
        moto_socket.tx_queue.clear();
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
        debug_assert_eq!(msg.status(), ErrorCode::NotReady);

        // log::debug!("{}:{} got SQE cmd {}", file!(), line!(), msg.command);

        match msg.command {
            rt_api::net::CMD_TCP_LISTENER_BIND => Ok(Some(self.tcp_listener_bind(conn, msg))),
            rt_api::net::CMD_TCP_LISTENER_ACCEPT => self.tcp_listener_accept(conn, msg),
            rt_api::net::CMD_TCP_LISTENER_DROP => self.tcp_listener_drop(conn, msg).map(|_| None),
            rt_api::net::CMD_TCP_STREAM_CONNECT => Ok(self.tcp_stream_connect(conn, msg)),
            rt_api::net::CMD_TCP_STREAM_TX => {
                self.tcp_stream_write(conn, msg);
                Ok(None)
            }
            rt_api::net::CMD_TCP_STREAM_RX_ACK => self.tcp_stream_rx_ack(conn, msg).map(|_| None),
            rt_api::net::CMD_TCP_STREAM_SET_OPTION => {
                Ok(Some(self.tcp_stream_set_option(conn, msg)))
            }
            rt_api::net::CMD_TCP_STREAM_GET_OPTION => {
                Ok(Some(self.tcp_stream_get_option(conn, msg)))
            }
            rt_api::net::CMD_TCP_STREAM_CLOSE => Ok(self.tcp_stream_close(conn, msg)),
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
        let mut pending_tcp_rx: VecDeque<SocketId> = VecDeque::new();
        core::mem::swap(&mut pending_tcp_rx, &mut self.pending_tcp_rx);
        while let Some(socket_id) = pending_tcp_rx.pop_front() {
            self.do_tcp_rx(socket_id); // May insert socket_id back into self.pending_tcp_rx.
        }

        // client writes (tcp_stream_write) wake sockets; make sure we
        // process them before polling devices.
        self.process_polled_sockets();

        if let Some(prev) = self.pending_completions.pop_front() {
            return Some(prev);
        }

        loop {
            let mut polled = false;
            for dev in &mut self.devices {
                polled |= dev.poll();
            }

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

        timeout
    }
}
