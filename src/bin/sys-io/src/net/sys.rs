use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    rc::Rc,
};

use crate::runtime::IoSubsystem;
use crate::runtime::{process::Process, PendingCompletion};
use moto_ipc::io_channel;
use moto_runtime::rt_api::{self, net::TcpState};
use moto_sys::{ErrorCode, SysHandle};

use super::netdev::NetDev;
use super::socket::MotoSocket;
use super::socket::SocketId;
use super::tcp_listener::TcpListener;
use super::tcp_listener::TcpListenerId;
use super::IoBuf;

// How many listening sockets to open (per specific SocketAddr).
const _DEFAULT_MAX_LISTENING_SOCKETS: usize = 4;
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

    // "Empty" sockets cached here.
    tcp_socket_cache: Vec<smoltcp::socket::tcp::Socket<'static>>,

    // Process ID -> TCP listeners/sockets. Needed to e.g. protect one process
    // accessing another process's sockets, and to drop/clear when the process dies.
    process_tcp_listeners: HashMap<SysHandle, HashSet<TcpListenerId>>,
    process_tcp_sockets: HashMap<SysHandle, HashSet<SocketId>>,

    woken_sockets: Rc<RefCell<VecDeque<SocketId>>>,
    wakers: std::collections::HashMap<SocketId, std::task::Waker>,

    // Read/write timeouts.
    tcp_rw_timeouts: BTreeMap<moto_sys::time::Instant, Vec<SocketId>>,

    // config: config::NetConfig,
    config: super::config::NetConfig,
}

impl NetSys {
    // If a timeout expires within TIMEOUT_GRANULARITY, we indicate no waiting.
    const TIMEOUT_GRANULARITY: core::time::Duration = core::time::Duration::from_nanos(50);

    pub fn new(config: super::config::NetConfig) -> Box<Self> {
        #[cfg(debug_assertions)]
        log::debug!(
            "{}:{} TODO: tcp stream read does one buffer at a time. Enqueue more?.",
            file!(),
            line!()
        );

        let devices = super::netdev::init(&config);
        let mut self_ref = Box::new(Self {
            devices,
            wait_handles: HashMap::new(),
            ip_addresses: HashMap::new(),
            next_id: 1,
            tcp_listeners: HashMap::new(),
            tcp_sockets: HashMap::new(),
            tcp_socket_cache: Vec::new(),
            pending_completions: VecDeque::new(),
            process_tcp_listeners: HashMap::new(),
            process_tcp_sockets: HashMap::new(),
            woken_sockets: Rc::new(std::cell::RefCell::new(VecDeque::new())),
            wakers: HashMap::new(),
            tcp_rw_timeouts: BTreeMap::new(),
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
        proc: &mut Process,
        mut sqe: io_channel::QueueEntry,
    ) -> io_channel::QueueEntry {
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

        let listener_id: TcpListenerId = self.next_id().into();
        let listener = TcpListener::new(proc.handle(), socket_addr);
        self.tcp_listeners.insert(listener_id, listener);

        let proc_listeners = match self.process_tcp_listeners.get_mut(&proc.handle()) {
            Some(val) => val,
            None => {
                self.process_tcp_listeners
                    .insert(proc.handle(), HashSet::new());
                self.process_tcp_listeners.get_mut(&proc.handle()).unwrap()
            }
        };
        assert!(proc_listeners.insert(listener_id.into()));

        #[cfg(debug_assertions)]
        log::debug!(
            "sys-io: new tcp listener on {:?}, conn: 0x{:x}",
            socket_addr,
            proc.handle().as_u64()
        );

        match device_idx {
            None => {
                for idx in 0..self.devices.len() {
                    let cidrs = self.devices[idx].dev_cfg().cidrs.clone();
                    for cidr in &cidrs {
                        let local_addr = SocketAddr::new(cidr.ip(), socket_addr.port());
                        if let Err(err) = self.bind_on_device(listener_id, idx, local_addr) {
                            self.drop_tcp_listener(listener_id);
                            sqe.status = err.into();
                            return sqe;
                        }
                    }
                }
            }
            Some(idx) => {
                if let Err(err) = self.bind_on_device(listener_id, idx, socket_addr) {
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

    fn bind_on_device(
        &mut self,
        listener_id: TcpListenerId,
        device_idx: usize,
        socket_addr: SocketAddr,
    ) -> Result<(), ErrorCode> {
        assert!(!socket_addr.ip().is_unspecified());
        let proc_handle = self.tcp_listeners.get(&listener_id).unwrap().proc_handle();
        let mut moto_socket = self.new_socket_for_device(device_idx, proc_handle)?;
        let socket_id = moto_socket.id;
        moto_socket.listener_id = Some(listener_id);
        self.tcp_listeners
            .get_mut(&listener_id)
            .unwrap()
            .add_listening_socket(socket_id);
        moto_socket.state = TcpState::Connecting;

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
        Ok(())
    }

    fn new_socket_for_device(
        &mut self,
        device_idx: usize,
        proc_handle: SysHandle,
    ) -> Result<MotoSocket, ErrorCode> {
        let mut socket = self.get_unused_tcp_socket()?;
        let socket_id = self.next_id().into();

        let socket_waker = super::socket::SocketWaker::new(socket_id, self.woken_sockets.clone());
        let waker = unsafe { std::task::Waker::from_raw(socket_waker.into_raw_waker()) };
        socket.register_recv_waker(&waker);
        socket.register_send_waker(&waker);
        self.wakers.insert(socket_id, waker);

        if let Some(proc_sockets) = self.process_tcp_sockets.get_mut(&proc_handle) {
            proc_sockets.insert(socket_id);
        } else {
            let mut proc_sockets = HashSet::new();
            proc_sockets.insert(socket_id);
            self.process_tcp_sockets.insert(proc_handle, proc_sockets);
        }
        let handle = self.devices[device_idx].sockets.add(socket);

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
            proc_handle,
            listener_id: None,
            connect_sqe: None,
            ephemeral_port: None,
            tx_bufs: VecDeque::new(),
            rx_bufs: VecDeque::new(),
            state: TcpState::Closed,
            read_timeout: std::time::Duration::MAX,
            write_timeout: std::time::Duration::MAX,
            next_timeout: None,
        })
    }

    fn drop_tcp_listener(&mut self, listener_id: TcpListenerId) {
        let mut listener = self.tcp_listeners.remove(&listener_id).unwrap();
        while let Some(mut cqe) = listener.get_pending_accept() {
            cqe.status = ErrorCode::BadHandle.into();
            self.pending_completions.push_back(PendingCompletion {
                cqe,
                endpoint_handle: listener.proc_handle(),
            });
        }

        while let Some((socket_id, _)) = listener.get_connected_socket() {
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
        self.cancel_tcp_rx(socket_id);
        self.cancel_tcp_rx(socket_id);

        let mut moto_socket = self.tcp_sockets.remove(&socket_id).unwrap();
        if let Some(proc_sockets) = self.process_tcp_sockets.get_mut(&moto_socket.proc_handle) {
            assert!(proc_sockets.remove(&socket_id));
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

        if let Some(mut cqe) = moto_socket.connect_sqe.take() {
            cqe.status = ErrorCode::BadHandle.into();
            self.pending_completions.push_back(PendingCompletion {
                cqe,
                endpoint_handle: moto_socket.proc_handle,
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
        proc: &mut Process,
        mut sqe: io_channel::QueueEntry,
    ) -> Option<io_channel::QueueEntry> {
        let listener_id = sqe.handle.into();
        let listener = match self.tcp_listeners.get_mut(&listener_id) {
            Some(l) => l,
            None => {
                sqe.status = ErrorCode::InvalidArgument.into();
                return Some(sqe);
            }
        };

        if listener.proc_handle() != proc.handle() {
            sqe.status = ErrorCode::InvalidArgument.into();
            return Some(sqe);
        }

        while let Some((socket_id, socket_addr)) = listener.get_connected_socket() {
            if let Some(moto_socket) = self.tcp_sockets.get_mut(&socket_id) {
                assert!(moto_socket.listener_id.is_none());
                moto_socket.state = TcpState::ReadWrite;
                sqe.handle = socket_id.into();
                rt_api::net::put_socket_addr(&mut sqe.payload, &socket_addr);
                sqe.status = ErrorCode::Ok.into();
                return Some(sqe);
            }
            // The socket was dropped without accepting.
        }

        listener.add_pending_accept(sqe);
        None
    }

    fn tcp_listener_drop(
        &mut self,
        proc: &mut Process,
        mut sqe: io_channel::QueueEntry,
    ) -> Option<io_channel::QueueEntry> {
        let listener_id: TcpListenerId = sqe.handle.into();
        let proc_handle = proc.handle();
        let listener = match self.tcp_listeners.get_mut(&listener_id) {
            Some(val) => val,
            None => {
                sqe.status = ErrorCode::InvalidArgument.into();
                return Some(sqe);
            }
        };
        if listener.proc_handle() != proc_handle {
            sqe.status = ErrorCode::InvalidArgument.into();
            return Some(sqe);
        }

        if let Some(listeners) = self.process_tcp_listeners.get_mut(&proc.handle()) {
            assert!(listeners.remove(&listener_id));
        }
        self.drop_tcp_listener(listener_id);

        sqe.status = ErrorCode::Ok.into();
        return Some(sqe);
    }

    fn get_unused_tcp_socket(
        &mut self,
    ) -> Result<smoltcp::socket::tcp::Socket<'static>, ErrorCode> {
        if let Some(socket) = self.tcp_socket_cache.pop() {
            Ok(socket)
        } else {
            let rx_buffer = smoltcp::socket::tcp::SocketBuffer::new(vec![0; 65536]);
            let tx_buffer = smoltcp::socket::tcp::SocketBuffer::new(vec![0; 16384]);

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
        proc: &mut Process,
        mut sqe: io_channel::QueueEntry,
    ) -> Option<io_channel::QueueEntry> {
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
            proc.handle().as_u64(),
            remote_addr
        );

        let (device_idx, local_ip_addr) = if let Some(pair) = self.find_route(&remote_addr.ip()) {
            pair
        } else {
            #[cfg(debug_assertions)]
            log::debug!(
                "sys-io: 0x{:x}: tcp connect to {:?}: route not found",
                proc.handle().as_u64(),
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

        let mut moto_socket = match self.new_socket_for_device(device_idx, proc.handle()) {
            Ok(s) => s,
            Err(err) => {
                sqe.status = err.into();
                return Some(sqe);
            }
        };
        let local_addr = SocketAddr::new(local_ip_addr, local_port);

        moto_socket.connect_sqe = Some(sqe);
        moto_socket.state = TcpState::Connecting;
        moto_socket.ephemeral_port = Some(local_port);

        let smol_handle = moto_socket.handle;
        self.tcp_sockets.insert(moto_socket.id, moto_socket);

        let smol_socket = self.devices[device_idx]
            .sockets
            .get_mut::<smoltcp::socket::tcp::Socket>(smol_handle);

        if let Some(timeout) = timeout {
            let nanos = timeout.as_u64();
            let now = moto_sys::time::Instant::now().as_u64();
            if nanos <= now {
                // We check this upon receiving sqe; the thread got preempted or something.
                // Just use an arbitrary small timeout.
                smol_socket.set_timeout(Some(smoltcp::time::Duration::from_micros(10)));
            } else {
                smol_socket.set_timeout(Some(smoltcp::time::Duration::from_micros(
                    (nanos + 999 - now) / 1000,
                )));
            }
        }

        // 3. call connect
        self.devices[device_idx].connect_socket(smol_handle, &local_addr, &remote_addr);

        None
    }

    fn tcp_socket_from_sqe(
        &self,
        proc_handle: SysHandle,
        sqe: &io_channel::QueueEntry,
    ) -> Result<SocketId, io_channel::QueueEntry> {
        let socket_id: SocketId = sqe.handle.into();

        // Validate that the socket belongs to the process.
        if let Some(socks) = self.process_tcp_sockets.get(&proc_handle) {
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

    fn tcp_stream_write(
        &mut self,
        proc: &mut Process,
        mut sqe: io_channel::QueueEntry,
    ) -> Option<io_channel::QueueEntry> {
        let socket_id = match self.tcp_socket_from_sqe(proc.handle(), &sqe) {
            Ok(s) => s,
            Err(err) => return Some(err),
        };

        // Validate that the socket belongs to the process.
        if let Some(socks) = self.process_tcp_sockets.get(&proc.handle()) {
            if !socks.contains(&socket_id) {
                sqe.status = ErrorCode::InvalidArgument.into();
                return Some(sqe);
            }
        } else {
            sqe.status = ErrorCode::InvalidArgument.into();
            return Some(sqe);
        }

        let page_idx = sqe.payload.shared_pages()[0];
        let page = match proc.conn().shared_page(page_idx) {
            Ok(page) => page,
            Err(err) => {
                sqe.status = err.into();
                return Some(sqe);
            }
        };
        let sz = sqe.payload.args_64()[1] as usize;
        let bytes = page.bytes();
        if sz > bytes.len() {
            sqe.status = ErrorCode::InvalidArgument.into();
            page.forget();
            return Some(sqe);
        }
        let bytes = &bytes[0..sz];

        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();
        match moto_socket.state {
            TcpState::Connecting => panic!(),
            TcpState::ReadWrite | TcpState::WriteOnly => {}
            TcpState::ReadOnly | TcpState::Closed => {
                log::debug!(
                    "{}:{} write request issued for non-writable socket 0x{:x}",
                    file!(),
                    line!(),
                    u64::from(socket_id)
                );
                // Unix/Linux expect a successful write with zero bytes written.
                sqe.payload.args_64_mut()[1] = 0;
                page.forget();
                sqe.status = ErrorCode::Ok.into();
                return Some(sqe);
            }
        }
        moto_socket.tx_bufs.push_back(IoBuf::new(sqe, bytes));
        page.forget();
        self.do_tcp_tx(socket_id);
        self.process_rw_timeout(socket_id, moto_sys::time::Instant::now());

        None
    }

    fn tcp_stream_read(
        &mut self,
        proc: &mut Process,
        mut sqe: io_channel::QueueEntry,
    ) -> Option<io_channel::QueueEntry> {
        let socket_id = match self.tcp_socket_from_sqe(proc.handle(), &sqe) {
            Ok(s) => s,
            Err(err) => return Some(err),
        };

        let page_idx = sqe.payload.shared_pages()[0];
        let page = match proc.conn().shared_page(page_idx) {
            Ok(page) => page,
            Err(err) => {
                sqe.status = err.into();
                return Some(sqe);
            }
        };
        let sz = sqe.payload.args_64()[1] as usize;
        let bytes = page.bytes();
        if sz > bytes.len() {
            sqe.status = ErrorCode::InvalidArgument.into();
            page.forget();
            return Some(sqe);
        }
        let bytes = &bytes[0..sz];

        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();
        match moto_socket.state {
            TcpState::Connecting => panic!(),
            TcpState::ReadWrite | TcpState::ReadOnly => {}
            TcpState::WriteOnly | TcpState::Closed => {
                log::debug!(
                    "{}:{} read request issued for non-readable socket 0x{:x}",
                    file!(),
                    line!(),
                    u64::from(socket_id)
                );
                // Unix/Linux expect a successful read with zero bytes written.
                sqe.payload.args_64_mut()[1] = 0;
                sqe.status = ErrorCode::Ok.into();
                page.forget();
                return Some(sqe);
            }
        }
        let io_buf = IoBuf::new(sqe, bytes);
        let rx_buf = {
            if let Some(rx_buf) = moto_socket.rx_bufs.pop_front() {
                moto_socket.rx_bufs.push_back(io_buf);
                rx_buf
            } else {
                io_buf
            }
        };

        page.forget();
        self.do_tcp_rx_buf(socket_id, rx_buf);
        self.process_rw_timeout(socket_id, moto_sys::time::Instant::now());
        None
    }

    fn tcp_stream_set_option(
        &mut self,
        proc: &mut Process,
        mut sqe: io_channel::QueueEntry,
    ) -> Option<io_channel::QueueEntry> {
        let socket_id = match self.tcp_socket_from_sqe(proc.handle(), &sqe) {
            Ok(s) => s,
            Err(err) => return Some(err),
        };

        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();

        if moto_socket.state == TcpState::Connecting {
            log::debug!("{}:{} bad state", file!(), line!());
            sqe.status = ErrorCode::InvalidArgument.into();
            return Some(sqe);
        }

        let mut options = sqe.payload.args_64()[0];
        if options == 0 {
            sqe.status = ErrorCode::InvalidArgument.into();
            return Some(sqe);
        }

        if options == rt_api::net::TCP_OPTION_READ_TIMEOUT
            || options == rt_api::net::TCP_OPTION_WRITE_TIMEOUT
        {
            let timo_ns = sqe.payload.args_64()[1];
            let timo = if timo_ns == u64::MAX {
                std::time::Duration::MAX
            } else {
                std::time::Duration::from_nanos(timo_ns)
            };

            if options == rt_api::net::TCP_OPTION_READ_TIMEOUT {
                self.set_read_timeout(socket_id, timo);
            } else {
                self.set_write_timeout(socket_id, timo);
            }

            sqe.status = ErrorCode::Ok.into();
            return Some(sqe);
        }

        if options == rt_api::net::TCP_OPTION_NODELAY {
            let nodelay_u64 = sqe.payload.args_64()[1];
            let nodelay = match nodelay_u64 {
                1 => true,
                0 => false,
                _ => {
                    sqe.status = ErrorCode::InvalidArgument.into();
                    return Some(sqe);
                }
            };

            let smol_socket = self.devices[moto_socket.device_idx]
                .sockets
                .get_mut::<smoltcp::socket::tcp::Socket>(moto_socket.handle);
            smol_socket.set_nagle_enabled(!nodelay);
            sqe.status = ErrorCode::Ok.into();
            return Some(sqe);
        }

        if options == rt_api::net::TCP_OPTION_TTL {
            let ttl = sqe.payload.args_32()[2];
            if ttl == 0 || ttl > 255 {
                sqe.status = ErrorCode::InvalidArgument.into();
                return Some(sqe);
            };

            let smol_socket = self.devices[moto_socket.device_idx]
                .sockets
                .get_mut::<smoltcp::socket::tcp::Socket>(moto_socket.handle);
            smol_socket.set_hop_limit(Some(ttl as u8));
            sqe.status = ErrorCode::Ok.into();
            return Some(sqe);
        }

        let shut_rd =
            (options & rt_api::net::TCP_OPTION_SHUT_RD != 0) && moto_socket.state.can_read();
        options ^= rt_api::net::TCP_OPTION_SHUT_RD;

        let shut_wr =
            (options & rt_api::net::TCP_OPTION_SHUT_WR != 0) && moto_socket.state.can_write();
        options ^= rt_api::net::TCP_OPTION_SHUT_WR;

        if options != 0 {
            sqe.status = ErrorCode::InvalidArgument.into();
            return Some(sqe);
        }

        if !(shut_rd || shut_wr) {
            sqe.status = ErrorCode::Ok.into(); // Nothing to do.
            return Some(sqe);
        }

        let smol_socket = self.devices[moto_socket.device_idx]
            .sockets
            .get_mut::<smoltcp::socket::tcp::Socket>(moto_socket.handle);

        match moto_socket.state {
            TcpState::Connecting => unreachable!(), // We eliminated this option above.
            TcpState::ReadWrite => {
                if shut_rd && shut_wr {
                    moto_socket.state = TcpState::Closed;
                    smol_socket.close();
                    self.cancel_tcp_rx(socket_id);
                    self.cancel_tcp_tx(socket_id);
                } else if shut_rd {
                    moto_socket.state = TcpState::WriteOnly;
                    self.cancel_tcp_rx(socket_id);
                } else {
                    assert!(shut_wr);
                    moto_socket.state = TcpState::ReadOnly;
                    smol_socket.close();
                    self.cancel_tcp_tx(socket_id);
                }
            }
            TcpState::ReadOnly => {
                if shut_wr {
                    assert!(moto_socket.tx_bufs.is_empty());
                    moto_socket.state = TcpState::Closed;
                    smol_socket.close();
                    self.cancel_tcp_rx(socket_id);
                }
            }
            TcpState::WriteOnly => {
                if shut_rd {
                    assert!(moto_socket.rx_bufs.is_empty());
                    moto_socket.state = TcpState::Closed;
                    smol_socket.close();
                    self.cancel_tcp_tx(socket_id);
                }
            }
            TcpState::Closed => {}
        }

        sqe.status = ErrorCode::Ok.into();
        return Some(sqe);
    }

    fn tcp_stream_get_option(
        &mut self,
        proc: &mut Process,
        mut sqe: io_channel::QueueEntry,
    ) -> Option<io_channel::QueueEntry> {
        let socket_id = match self.tcp_socket_from_sqe(proc.handle(), &sqe) {
            Ok(s) => s,
            Err(err) => return Some(err),
        };

        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();

        if moto_socket.state == TcpState::Connecting {
            log::debug!("{}:{} bad state", file!(), line!());
            sqe.status = ErrorCode::InvalidArgument.into();
            return Some(sqe);
        }

        let options = sqe.payload.args_64()[0];
        if options == 0 {
            sqe.status = ErrorCode::InvalidArgument.into();
            return Some(sqe);
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
            rt_api::net::TCP_OPTION_READ_TIMEOUT => {
                sqe.payload.args_64_mut()[0] =
                    if moto_socket.read_timeout == core::time::Duration::MAX {
                        u64::MAX
                    } else {
                        moto_socket.read_timeout.as_nanos() as u64
                    };
                sqe.status = ErrorCode::Ok.into();
            }
            rt_api::net::TCP_OPTION_WRITE_TIMEOUT => {
                sqe.payload.args_64_mut()[0] =
                    if moto_socket.write_timeout == core::time::Duration::MAX {
                        u64::MAX
                    } else {
                        moto_socket.write_timeout.as_nanos() as u64
                    };
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

        Some(sqe)
    }

    fn tcp_stream_drop(
        &mut self,
        proc: &mut Process,
        mut sqe: io_channel::QueueEntry,
    ) -> Option<io_channel::QueueEntry> {
        let socket_id = match self.tcp_socket_from_sqe(proc.handle(), &sqe) {
            Ok(s) => s,
            Err(err) => return Some(err),
        };
        log::debug!(
            "{}:{} tcp_stream_drop 0x{:x}",
            file!(),
            line!(),
            u64::from(socket_id)
        );
        // While there can still be outgoing writes that need completion,
        // we drop everything here: let the user-side worry about
        // not dropping connections before writes are complete.
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

    fn io_buf_to_pc(endpoint_handle: SysHandle, x_buf: IoBuf) -> PendingCompletion {
        assert_ne!(x_buf.status, ErrorCode::NotReady);
        let mut cqe = x_buf.sqe;
        cqe.payload.args_64_mut()[1] = x_buf.consumed as u64;
        cqe.status = x_buf.status.into();
        PendingCompletion {
            cqe,
            endpoint_handle,
        }
    }

    fn on_tcp_listener_connected(&mut self, socket_id: SocketId) {
        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();
        let device_idx = moto_socket.device_idx;
        let smol_socket = self.devices[device_idx]
            .sockets
            .get_mut::<smoltcp::socket::tcp::Socket>(moto_socket.handle);

        // Without these, remotely dropped sockets may hang around indefinitely.
        smol_socket.set_timeout(Some(smoltcp::time::Duration::from_millis(5_000)));
        smol_socket.set_keep_alive(Some(smoltcp::time::Duration::from_millis(10_000)));

        let local_addr = super::smoltcp_helpers::socket_addr_from_endpoint(
            smol_socket.local_endpoint().unwrap(),
        );
        let remote_addr = super::smoltcp_helpers::socket_addr_from_endpoint(
            smol_socket.remote_endpoint().unwrap(),
        );

        let listener_id = moto_socket.listener_id.take().unwrap();
        let listener = self.tcp_listeners.get_mut(&listener_id).unwrap();
        if let Some(mut cqe) = listener.get_pending_accept() {
            // TODO: this codepath is probably untested (usually accept request come before remote connects).
            listener.remove_listening_socket(moto_socket.id);
            moto_socket.state = TcpState::ReadWrite;
            cqe.handle = moto_socket.id.into();
            rt_api::net::put_socket_addr(&mut cqe.payload, &remote_addr);
            cqe.status = ErrorCode::Ok.into();
            self.pending_completions.push_back(PendingCompletion {
                cqe,
                endpoint_handle: listener.proc_handle(),
            });
        } else {
            listener.add_connected_socket(moto_socket.id, remote_addr);
        }
        #[cfg(debug_assertions)]
        log::debug!(
            "{}:{} on_tcp_listener_connected 0x{:x} - {:?}",
            file!(),
            line!(),
            u64::from(socket_id),
            remote_addr
        );

        if let Err(err) = self.bind_on_device(listener_id, device_idx, local_addr) {
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

        let remote_addr = super::smoltcp_helpers::socket_addr_from_endpoint(
            smol_socket.remote_endpoint().unwrap(),
        );

        let mut cqe = moto_socket.connect_sqe.take().unwrap();
        moto_socket.state = TcpState::ReadWrite;
        cqe.handle = moto_socket.id.into();
        rt_api::net::put_socket_addr(&mut cqe.payload, &remote_addr);
        cqe.status = ErrorCode::Ok.into();
        self.pending_completions.push_back(PendingCompletion {
            cqe,
            endpoint_handle: moto_socket.proc_handle,
        });

        log::debug!(
            "{}:{} on_socket_connected 0x{:x} - {:?}",
            file!(),
            line!(),
            u64::from(socket_id),
            remote_addr
        );
    }

    fn on_connect_failed(&mut self, socket_id: SocketId) {
        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();

        let mut cqe = moto_socket.connect_sqe.take().unwrap();
        moto_socket.state = TcpState::Closed;
        cqe.handle = moto_socket.id.into();
        cqe.status = ErrorCode::TimedOut.into();
        self.pending_completions.push_back(PendingCompletion {
            cqe,
            endpoint_handle: moto_socket.proc_handle,
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

        let may_recv = smol_socket.may_recv();
        let may_send = smol_socket.may_send();
        let can_recv = smol_socket.can_recv();
        let can_send = smol_socket.can_send();
        let state = smol_socket.state();

        log::debug!(
            "{}:{} on_tcp_socket_poll 0x{:x} - {:?}",
            file!(),
            line!(),
            u64::from(socket_id),
            state
        );

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
            smoltcp::socket::tcp::State::Listen
            | smoltcp::socket::tcp::State::SynSent
            | smoltcp::socket::tcp::State::SynReceived => {
                assert_eq!(moto_socket.state, TcpState::Connecting);
            }

            smoltcp::socket::tcp::State::Established => {
                if moto_socket.listener_id.is_some() {
                    assert_eq!(moto_socket.state, TcpState::Connecting);
                    self.on_tcp_listener_connected(socket_id);
                } else if moto_socket.connect_sqe.is_some() {
                    assert_eq!(moto_socket.state, TcpState::Connecting);
                    self.on_socket_connected(socket_id);
                }
            }

            smoltcp::socket::tcp::State::Closed => {
                if moto_socket.connect_sqe.is_some() {
                    // This can happen on connect failure.
                    assert_eq!(moto_socket.state, TcpState::Connecting);
                    self.on_connect_failed(socket_id);
                    return;
                }
            }
            smoltcp::socket::tcp::State::CloseWait => {
                // The remote end closed its write channel, but there still
                // may be bytes in the socket rx buffer.
                match moto_socket.state {
                    TcpState::Connecting => panic!(), // Impossible.
                    TcpState::ReadWrite => moto_socket.state = TcpState::WriteOnly,
                    TcpState::ReadOnly => moto_socket.state = TcpState::Closed,
                    TcpState::WriteOnly | TcpState::Closed => {}
                }
            }
            smoltcp::socket::tcp::State::FinWait1 => {
                match moto_socket.state {
                    TcpState::Connecting | TcpState::ReadWrite | TcpState::WriteOnly => panic!(), // Impossible.
                    TcpState::ReadOnly | TcpState::Closed => {}
                }
            }
            smoltcp::socket::tcp::State::FinWait2
            | smoltcp::socket::tcp::State::Closing
            | smoltcp::socket::tcp::State::LastAck
            | smoltcp::socket::tcp::State::TimeWait => {
                assert_eq!(moto_socket.state, TcpState::Closed);
            }
        }

        if can_recv {
            self.do_tcp_rx(socket_id);
        } else if !may_recv {
            self.cancel_tcp_rx(socket_id);
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

    fn do_tcp_rx(&mut self, socket_id: SocketId) {
        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();

        if let Some(rx_buf) = moto_socket.rx_bufs.pop_front() {
            self.do_tcp_rx_buf(socket_id, rx_buf);
        }
    }

    fn do_tcp_rx_buf(&mut self, socket_id: SocketId, mut rx_buf: IoBuf) {
        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();
        let smol_socket = self.devices[moto_socket.device_idx]
            .sockets
            .get_mut::<smoltcp::socket::tcp::Socket>(moto_socket.handle);

        debug_assert_eq!(0, rx_buf.consumed);

        let mut receive_closure = |bytes: &mut [u8]| {
            let len = bytes.len().min(rx_buf.buf_len - rx_buf.consumed);
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), rx_buf.buf_ptr as *mut u8, len);
            }

            rx_buf.consumed += len;

            (len, rx_buf.is_consumed())
        };

        while smol_socket.recv_queue() > 0 {
            if smol_socket.recv(&mut receive_closure).unwrap() {
                break;
            }
        }

        if rx_buf.consumed == 0 && smol_socket.may_recv() {
            // Keep the buffer.
            moto_socket.rx_bufs.push_front(rx_buf);
            return;
        }

        #[cfg(debug_assertions)]
        log::debug!(
            "{}:{} TcpRx event: {} bytes",
            file!(),
            line!(),
            rx_buf.consumed
        );

        rx_buf.status = ErrorCode::Ok;
        self.pending_completions
            .push_back(Self::io_buf_to_pc(moto_socket.proc_handle, rx_buf));
    }

    fn do_tcp_tx(&mut self, socket_id: SocketId) {
        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();
        let smol_socket = self.devices[moto_socket.device_idx]
            .sockets
            .get_mut::<smoltcp::socket::tcp::Socket>(moto_socket.handle);
        if !smol_socket.can_send() {
            return;
        }

        let tx_buf = moto_socket.tx_bufs.pop_front();
        if tx_buf.is_none() {
            return;
        }

        let mut tx_buf = tx_buf.unwrap();
        match smol_socket.send_slice(tx_buf.bytes()) {
            Ok(usize) => {
                tx_buf.consume(usize);
                if tx_buf.is_consumed() {
                    tx_buf.status = ErrorCode::Ok;
                    self.pending_completions
                        .push_back(Self::io_buf_to_pc(moto_socket.proc_handle, tx_buf));
                } else {
                    moto_socket.tx_bufs.push_front(tx_buf);
                }
            }
            Err(_err) => todo!(),
        }
    }

    fn cancel_tcp_rx(&mut self, socket_id: SocketId) {
        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();
        while let Some(mut rx_buf) = moto_socket.rx_bufs.pop_front() {
            rx_buf.consumed = 0;
            rx_buf.status = ErrorCode::Ok;
            self.pending_completions
                .push_back(Self::io_buf_to_pc(moto_socket.proc_handle, rx_buf));
        }
    }

    fn cancel_tcp_tx(&mut self, socket_id: SocketId) {
        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();
        while let Some(mut tx_buf) = moto_socket.tx_bufs.pop_front() {
            tx_buf.consumed = 0;
            tx_buf.status = ErrorCode::Ok;
            self.pending_completions
                .push_back(Self::io_buf_to_pc(moto_socket.proc_handle, tx_buf));
        }
    }

    fn add_socket_timeout(&mut self, socket_id: SocketId) {
        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();

        let next_read_timeout = if moto_socket.read_timeout != std::time::Duration::MAX {
            moto_socket
                .rx_bufs
                .front()
                .map(|x| x.expires(&moto_socket.read_timeout))
        } else {
            None
        };
        let next_write_timeout = if moto_socket.write_timeout != std::time::Duration::MAX {
            moto_socket
                .tx_bufs
                .front()
                .map(|x| x.expires(&moto_socket.write_timeout))
        } else {
            None
        };

        if next_read_timeout.is_none() && next_write_timeout.is_none() {
            moto_socket.next_timeout = None;
            return;
        }

        let timo = if let Some(r_timo) = next_read_timeout {
            if let Some(w_timo) = next_write_timeout {
                r_timo.min(w_timo)
            } else {
                r_timo
            }
        } else {
            next_write_timeout.unwrap()
        };

        moto_socket.next_timeout = Some(timo);

        if let Some(socks) = self.tcp_rw_timeouts.get_mut(&timo) {
            socks.push(socket_id);
        } else {
            self.tcp_rw_timeouts.insert(timo, vec![socket_id]);
        }
    }

    fn remove_socket_timeout(&mut self, socket_id: SocketId) {
        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();

        if let Some(timo) = moto_socket.next_timeout.take() {
            if let Some(socks) = self.tcp_rw_timeouts.get_mut(&timo) {
                for idx in 0..socks.len() {
                    if socks[idx] == socket_id {
                        socks.remove(idx);
                        break;
                    }
                }
                if socks.is_empty() {
                    self.tcp_rw_timeouts.remove(&timo);
                }
            }
        }
    }

    fn set_read_timeout(&mut self, socket_id: SocketId, timeout: core::time::Duration) {
        let moto_socket = self.tcp_sockets.get(&socket_id).unwrap();
        if moto_socket.read_timeout == timeout {
            return;
        }

        self.remove_socket_timeout(socket_id);
        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();
        moto_socket.read_timeout = timeout;

        self.add_socket_timeout(socket_id);
    }

    fn set_write_timeout(&mut self, socket_id: SocketId, timeout: core::time::Duration) {
        let moto_socket = self.tcp_sockets.get(&socket_id).unwrap();
        if moto_socket.write_timeout == timeout {
            return;
        }

        self.remove_socket_timeout(socket_id);
        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();
        moto_socket.write_timeout = timeout;

        self.add_socket_timeout(socket_id);
    }

    fn process_rw_timeout(&mut self, socket_id: SocketId, now: moto_sys::time::Instant) {
        let moto_socket = self.tcp_sockets.get_mut(&socket_id).unwrap();

        let cutoff = now + Self::TIMEOUT_GRANULARITY;
        if let Some(timo) = moto_socket.next_timeout.as_ref() {
            if *timo > cutoff {
                return;
            }
        }
        // else: don't return, as when there are no rx/tx bufs, the socket doesn't have next_timeout.

        if moto_socket.read_timeout != std::time::Duration::MAX {
            while let Some(x_buf) = moto_socket.rx_bufs.front() {
                if x_buf.expired(&moto_socket.read_timeout, cutoff) {
                    let mut x_buf = moto_socket.rx_bufs.pop_front().unwrap();

                    x_buf.status = ErrorCode::TimedOut;
                    self.pending_completions
                        .push_back(Self::io_buf_to_pc(moto_socket.proc_handle, x_buf));
                } else {
                    break;
                }
            }
        }

        if moto_socket.write_timeout != std::time::Duration::MAX {
            while let Some(x_buf) = moto_socket.tx_bufs.front() {
                if x_buf.expired(&moto_socket.write_timeout, cutoff) {
                    let mut x_buf = moto_socket.rx_bufs.pop_front().unwrap();

                    x_buf.status = ErrorCode::TimedOut;
                    self.pending_completions
                        .push_back(Self::io_buf_to_pc(moto_socket.proc_handle, x_buf));
                } else {
                    break;
                }
            }
        }

        self.remove_socket_timeout(socket_id);
        self.add_socket_timeout(socket_id);
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
        proc: &mut Process,
        mut sqe: io_channel::QueueEntry,
    ) -> Option<io_channel::QueueEntry> {
        debug_assert_eq!(sqe.status(), ErrorCode::NotReady);

        log::debug!("{}:{} got SQE cmd {}", file!(), line!(), sqe.command);

        match sqe.command {
            rt_api::net::CMD_TCP_LISTENER_BIND => Some(self.tcp_listener_bind(proc, sqe)),
            rt_api::net::CMD_TCP_LISTENER_ACCEPT => self.tcp_listener_accept(proc, sqe),
            rt_api::net::CMD_TCP_LISTENER_DROP => self.tcp_listener_drop(proc, sqe),
            rt_api::net::CMD_TCP_STREAM_CONNECT => self.tcp_stream_connect(proc, sqe),
            rt_api::net::CMD_TCP_STREAM_WRITE => self.tcp_stream_write(proc, sqe),
            rt_api::net::CMD_TCP_STREAM_READ => self.tcp_stream_read(proc, sqe),
            rt_api::net::CMD_TCP_STREAM_SET_OPTION => self.tcp_stream_set_option(proc, sqe),
            rt_api::net::CMD_TCP_STREAM_GET_OPTION => self.tcp_stream_get_option(proc, sqe),
            rt_api::net::CMD_TCP_STREAM_DROP => self.tcp_stream_drop(proc, sqe),
            _ => {
                #[cfg(debug_assertions)]
                log::debug!(
                    "{}:{} unrecognized command {} from endpoint 0x{:x}",
                    file!(),
                    line!(),
                    sqe.command,
                    proc.handle().as_u64()
                );

                sqe.status = ErrorCode::InvalidArgument.into();
                Some(sqe)
            }
        }
    }

    fn on_process_drop(&mut self, proc: &mut Process) {
        if let Some(tcp_sockets) = self.process_tcp_sockets.remove(&proc.handle()) {
            for socket_id in tcp_sockets {
                self.drop_tcp_socket(socket_id);
            }
        }

        if let Some(listeners) = self.process_tcp_listeners.remove(&proc.handle()) {
            for listener_id in listeners {
                let mut listener = self.tcp_listeners.remove(&listener_id).unwrap();
                while let Some(mut cqe) = listener.get_pending_accept() {
                    cqe.status = ErrorCode::BadHandle.into();
                    self.pending_completions.push_back(PendingCompletion {
                        cqe,
                        endpoint_handle: listener.proc_handle(),
                    });
                }
            }
        }

        log::debug!(
            "{}:{} process 0x{:x} dropped",
            file!(),
            line!(),
            proc.handle().as_u64()
        );
    }

    fn poll(&mut self) -> Option<PendingCompletion> {
        let now = moto_sys::time::Instant::now();

        loop {
            if let Some((timo, _)) = self.tcp_rw_timeouts.first_key_value() {
                if now >= (*timo - Self::TIMEOUT_GRANULARITY) {
                    let timo = *timo;
                    let socks = self.tcp_rw_timeouts.remove(&timo).unwrap();
                    for socket_id in socks {
                        self.process_rw_timeout(socket_id, now);
                    }
                    continue;
                }
            }
            break;
        }

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
        }

        self.pending_completions.pop_front()
    }

    fn wait_timeout(&mut self) -> Option<core::time::Duration> {
        let mut timeout = None;

        if let Some((timo, _)) = self.tcp_rw_timeouts.first_key_value() {
            let now = moto_sys::time::Instant::now();
            if now >= (*timo - Self::TIMEOUT_GRANULARITY) {
                return Some(core::time::Duration::ZERO);
            }

            timeout = Some(timo.duration_since(now));
        }

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
