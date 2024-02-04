// VirtIO network interface/device.
//
// This module is somewhat complicated because it connects
// virtio, smoltcp, and our async IO, which are all unaware of each other.
//
// If you want to understand some of this easier, look at netdev_loopback.rs,
// which does not have to deal with virtio and smoltcp and so is much simpler.
use super::{
    config::{DeviceCfg, IpRoute},
    netdev::{NetDev, NetEvent, NetInterface},
    util::SocketWaker,
    IoBuf,
};
use moto_sys::{ErrorCode, SysHandle};
use smoltcp::{
    iface::{Config, SocketHandle, SocketSet},
    phy::{DeviceCapabilities, RxToken, TxToken},
    socket::tcp::SocketBuffer,
};
use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    marker::PhantomPinned,
    net::SocketAddr,
    rc::Rc,
};

const PAGE_SIZE_SMALL: usize = moto_sys::syscalls::SysMem::PAGE_SIZE_SMALL as usize;

struct VirtioRxToken {
    dev: *mut VirtioNetDev,
}

impl VirtioRxToken {
    fn dev(&mut self) -> &mut VirtioNetDev {
        unsafe { self.dev.as_mut().unwrap() }
    }
}

impl RxToken for VirtioRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        assert!(self.dev().rx_bytes > 0);
        let rx_bytes = self.dev().rx_bytes as usize;
        let buf = self.dev().rx_buf_mut();
        let buf = &mut buf[VirtioNetDev::TX_RX_HEADER_LEN..];
        let res = f(&mut buf[0..rx_bytes]);
        self.dev().rx_bytes = 0;
        moto_virtio::virtio_net::post_receive(self.dev().rx_buf_mut()).unwrap();

        res
    }
}

struct VirtioTxToken {
    dev: *mut VirtioNetDev,
}

impl VirtioTxToken {
    fn dev(&self) -> &mut VirtioNetDev {
        unsafe { self.dev.as_mut().unwrap() }
    }
}

impl TxToken for VirtioTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        if len == 0 {
            let mut buf = [0_u8; 4];
            return f(&mut buf[..]);
        }

        if self.dev().have_tx {
            self.dev().poll_virtio_tx();
            if self.dev().have_tx {
                let mut buffer = vec![0u8; len];
                let result = f(&mut buffer);
                self.dev().pending_tx.push_back(buffer);

                return result;
            }
        }

        self.dev().have_tx = true;
        let buf = self.dev().tx_buf_mut();
        assert!(buf.len() >= len);
        let buf = &mut buf[0..len];
        let res = f(buf);

        #[cfg(debug_assertions)]
        crate::moto_log!(
            "{}:{} enqueueing tx {} bytes into the NIC",
            file!(),
            line!(),
            len
        );
        moto_virtio::virtio_net::post_send(self.dev().tx_header(), buf).unwrap();
        res
    }
}

struct VirtioDeviceAdapter {
    dev: *mut VirtioNetDev,
}

impl VirtioDeviceAdapter {
    fn dev(&mut self) -> &mut VirtioNetDev {
        unsafe { self.dev.as_mut().unwrap() }
    }
}

impl smoltcp::phy::Device for VirtioDeviceAdapter {
    type RxToken<'a> = VirtioRxToken
    where
        Self: 'a;

    type TxToken<'a> = VirtioTxToken
    where
        Self: 'a;

    // Note: this is called from smoltcp::iface::Interface::poll().
    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.dev().poll_virtio_rx();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        if self.dev().rx_bytes == 0 {
            // No bytes to read.
            return None;
        }
        Some((
            VirtioRxToken { dev: self.dev },
            VirtioTxToken { dev: self.dev },
        ))
    }

    // Note: this is called from smoltcp::iface::Interface::poll() if smoltcp has bytes to send.
    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        self.dev().poll_virtio_tx();
        Some(VirtioTxToken { dev: self.dev })
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = smoltcp::phy::Medium::Ethernet;
        caps.max_transmission_unit = 1500;
        caps.max_burst_size = Some(1);

        caps
    }
}

struct VirtioTcpStream {
    socket_handle: SocketHandle,
    rx_bufs: VecDeque<IoBuf>,
    tx_bufs: VecDeque<IoBuf>,
    local_addr: SocketAddr,
    remote_addr: Option<SocketAddr>,
}

struct VirtioNetDev {
    adapter: VirtioDeviceAdapter,
    iface: smoltcp::iface::Interface,
    sockets: SocketSet<'static>,

    tcp_listeners_by_addr: HashMap<SocketAddr, Rc<RefCell<VirtioTcpStream>>>,
    tcp_listeners_by_handle: HashMap<SocketHandle, Rc<RefCell<VirtioTcpStream>>>,
    tcp_streams_by_addr: HashMap<(SocketAddr, SocketAddr), Rc<RefCell<VirtioTcpStream>>>,
    tcp_streams_by_handle: HashMap<SocketHandle, Rc<RefCell<VirtioTcpStream>>>,
    wakers: HashMap<SocketHandle, std::task::Waker>,

    woken_sockets: Rc<RefCell<VecDeque<SocketHandle>>>,

    // Sometimes tx_page is busy, but smoltcp wants to send some bytes; we store
    // these bytes in here.
    pending_tx: VecDeque<Vec<u8>>,

    rx_wait_handle: SysHandle,
    tx_wait_handle: SysHandle,
    events: VecDeque<NetEvent>,
    tx_page: usize,
    rx_page: usize,
    rx_bytes: u32, // have bytes in rx_page
    have_tx: bool, // have bytes in tx_page
    _pin: std::marker::PhantomPinned,
}

impl VirtioNetDev {
    const TX_RX_HEADER_LEN: usize = moto_virtio::virtio_net::header_len();

    fn new(device_config: &DeviceCfg, routes: &Vec<IpRoute>) -> Box<Self> {
        let addr =
            smoltcp::wire::EthernetAddress::from_bytes(&moto_virtio::virtio_net::mac().unwrap());
        // let mut config = Config::new();
        // config.hardware_addr = Some(smoltcp::wire::HardwareAddress::Ethernet(addr));
        let mut config = Config::new(smoltcp::wire::HardwareAddress::Ethernet(addr));
        config.random_seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|dur| dur.as_nanos() as u64)
            .unwrap_or(1234);

        let mut adapter = VirtioDeviceAdapter {
            dev: core::ptr::null_mut(),
        };
        let mut iface =
            smoltcp::iface::Interface::new(config, &mut adapter, smoltcp::time::Instant::now());

        iface.update_ip_addrs(|ip_addrs| {
            for cidr in &device_config.cidrs {
                ip_addrs
                    .push(smoltcp::wire::IpCidr::new(
                        <smoltcp::wire::IpAddress as From<std::net::IpAddr>>::from(cidr.addr),
                        cidr.prefix,
                    ))
                    .unwrap();
            }
        });

        assert_eq!(routes.len(), 1);
        let route = match routes[0].gateway {
            std::net::IpAddr::V4(addr) => addr,
            std::net::IpAddr::V6(_) => todo!(),
        };
        iface
            .routes_mut()
            .add_default_ipv4_route(
                <smoltcp::wire::Ipv4Address as From<std::net::Ipv4Addr>>::from(route),
            )
            .unwrap();

        let tx_page =
            moto_sys::syscalls::SysMem::alloc(moto_sys::syscalls::SysMem::PAGE_SIZE_SMALL, 1)
                .unwrap() as usize;
        let rx_page =
            moto_sys::syscalls::SysMem::alloc(moto_sys::syscalls::SysMem::PAGE_SIZE_SMALL, 1)
                .unwrap() as usize;

        let mut net_dev = Box::new(Self {
            adapter,
            iface,
            sockets: SocketSet::new(vec![]),
            tcp_listeners_by_addr: HashMap::new(),
            tcp_listeners_by_handle: HashMap::new(),
            tcp_streams_by_addr: HashMap::new(),
            tcp_streams_by_handle: HashMap::new(),
            wakers: HashMap::new(),
            woken_sockets: Rc::new(RefCell::new(VecDeque::new())),
            rx_wait_handle: SysHandle::from_u64(moto_virtio::virtio_net::rx_wait_handle()),
            tx_wait_handle: SysHandle::from_u64(moto_virtio::virtio_net::tx_wait_handle()),
            events: VecDeque::new(),
            pending_tx: VecDeque::new(),
            tx_page,
            rx_page,
            rx_bytes: 0,
            have_tx: false,
            _pin: PhantomPinned::default(),
        });

        net_dev.adapter.dev = net_dev.as_mut() as *mut _;
        moto_virtio::virtio_net::post_receive(net_dev.rx_buf_mut()).unwrap();
        // net_dev.rx_bytes = moto_virtio::virtio_net::consume_receive();

        net_dev
    }

    fn rx_buf_mut(&self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.rx_page as *mut u8, PAGE_SIZE_SMALL) }
    }

    fn tx_buf_mut(&self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(
                (self.tx_page + Self::TX_RX_HEADER_LEN) as *mut u8,
                PAGE_SIZE_SMALL - Self::TX_RX_HEADER_LEN,
            )
        }
    }

    fn tx_header(&self) -> &mut moto_virtio::virtio_net::Header {
        unsafe {
            (self.tx_page as *mut moto_virtio::virtio_net::Header)
                .as_mut()
                .unwrap()
        }
    }

    fn poll_virtio_rx(&mut self) {
        if self.rx_bytes == 0 {
            self.rx_bytes = moto_virtio::virtio_net::consume_receive();
            if self.rx_bytes != 0 {
                #[cfg(debug_assertions)]
                crate::moto_log!(
                    "{}:{} got {} RX bytes in the NIC",
                    file!(),
                    line!(),
                    self.rx_bytes
                );
            }
        }
    }

    fn poll_virtio_tx(&mut self) {
        if self.have_tx {
            if moto_virtio::virtio_net::poll_send() {
                #[cfg(debug_assertions)]
                crate::moto_log!("TX completed");
                self.have_tx = false;
            } else {
                return;
            }
        }

        if let Some(packet) = self.pending_tx.pop_front() {
            self.have_tx = true;

            let buf = self.tx_buf_mut();
            assert!(buf.len() >= packet.len());
            let buf = &mut buf[0..packet.len()];
            unsafe {
                core::ptr::copy_nonoverlapping(packet.as_ptr(), buf.as_mut_ptr(), packet.len());
            }

            #[cfg(debug_assertions)]
            crate::moto_log!(
                "{}:{} enqueueing tx {} bytes into the NIC",
                file!(),
                line!(),
                packet.len()
            );
            moto_virtio::virtio_net::post_send(self.tx_header(), buf).unwrap();
        }
    }

    fn do_tcp_listener_bind(&mut self, addr: &std::net::SocketAddr) {
        assert!(!self.tcp_listeners_by_addr.contains_key(addr));

        if !addr.ip().is_unspecified() {
            self.tcp_listener_bind_addr(addr);
            return;
        }

        let mut iaddrs: Vec<std::net::IpAddr> = vec![];
        for iaddr in self.iface.ip_addrs() {
            iaddrs.push(iaddr.address().into());
        }

        for iaddr in &iaddrs {
            let sock_addr = std::net::SocketAddr::from((*iaddr, addr.port()));
            self.tcp_listener_bind_addr(&sock_addr);
        }
    }

    fn tcp_listener_bind_addr(&mut self, addr: &std::net::SocketAddr) {
        assert!(!addr.ip().is_unspecified());

        let rx_buffer = SocketBuffer::new(vec![0; 65536]);
        let tx_buffer = SocketBuffer::new(vec![0; 16384]);

        let socket = smoltcp::socket::tcp::Socket::new(rx_buffer, tx_buffer);
        let handle = self.sockets.add(socket);

        let stream = Rc::new(RefCell::new(VirtioTcpStream {
            socket_handle: handle,
            rx_bufs: VecDeque::new(),
            tx_bufs: VecDeque::new(),
            local_addr: addr.clone(),
            remote_addr: None,
        }));
        self.tcp_listeners_by_addr.insert(*addr, stream.clone());
        self.tcp_listeners_by_handle.insert(handle, stream);

        let socket_waker = SocketWaker::new(handle, self.woken_sockets.clone());
        let waker = unsafe { std::task::Waker::from_raw(socket_waker.into_raw_waker()) };
        self.wakers.insert(handle, waker.clone());

        let socket = self.sockets.get_mut::<smoltcp::socket::tcp::Socket>(handle);
        socket.register_recv_waker(&waker);
        socket.register_send_waker(&waker);

        socket.listen((addr.ip(), addr.port())).unwrap();
        crate::moto_log!("{}:{} - bind {:?}", file!(), line!(), addr);
    }

    fn shutdown_tcp_stream(
        &mut self,
        local_addr: &std::net::SocketAddr,
        remote_addr: &std::net::SocketAddr,
        shut_rd: bool,
        shut_wr: bool,
    ) {
        // NetSys in sys.rs ensures the stream exists. It also keeps track of which
        // shutdown flag has been set, so here we only need to cancel existing buffers.
        let mut stream = self
            .tcp_streams_by_addr
            .get(&(*local_addr, *remote_addr))
            .unwrap()
            .borrow_mut();

        if shut_rd {
            while let Some(mut rx_buf) = stream.rx_bufs.pop_front() {
                rx_buf.consumed = 0;
                rx_buf.status = ErrorCode::Ok;
                self.events.push_back(NetEvent::TcpRx((
                    local_addr.clone(),
                    remote_addr.clone(),
                    rx_buf,
                )));
            }
        }

        if shut_wr {
            while let Some(mut tx_buf) = stream.tx_bufs.pop_front() {
                tx_buf.consumed = 0;
                tx_buf.status = ErrorCode::Ok;
                self.events.push_back(NetEvent::TcpTx((
                    local_addr.clone(),
                    remote_addr.clone(),
                    tx_buf,
                )));
            }
        }
    }

    fn do_hard_drop_tcp_listener(&mut self, addr: &std::net::SocketAddr) {
        if !addr.ip().is_unspecified() {
            self.do_hard_drop_tcp_listener_addr(addr);
            return;
        }

        let mut iaddrs: Vec<std::net::IpAddr> = vec![];
        for iaddr in self.iface.ip_addrs() {
            iaddrs.push(iaddr.address().into());
        }

        for iaddr in &iaddrs {
            let sock_addr = std::net::SocketAddr::from((*iaddr, addr.port()));
            self.do_hard_drop_tcp_listener_addr(&sock_addr);
        }
    }

    fn do_hard_drop_tcp_listener_addr(&mut self, addr: &std::net::SocketAddr) {
        assert!(!addr.ip().is_unspecified());
        let stream = self.tcp_listeners_by_addr.remove(addr).unwrap();
        let handle = stream.borrow().socket_handle;
        assert!(self.tcp_listeners_by_handle.remove(&handle).is_some());
        assert!(self.wakers.remove(&handle).is_some());
        let socket = self.sockets.remove(handle);

        if let smoltcp::socket::Socket::Tcp(mut socket) = socket {
            socket.abort();
        } else {
            panic!()
        }
        #[cfg(debug_assertions)]
        crate::moto_log!("{}:{} hard_drop_tcp_listener", file!(), line!());
    }

    fn on_tcp_listener_connected(&mut self, handle: SocketHandle) {
        assert!(self.tcp_listeners_by_handle.remove(&handle).is_some());

        let socket = self.sockets.get_mut::<smoltcp::socket::tcp::Socket>(handle);

        // Without these, remotely dropped sockets may hang around indefinitely.
        socket.set_timeout(Some(smoltcp::time::Duration::from_millis(100)));
        socket.set_keep_alive(Some(smoltcp::time::Duration::from_millis(1000)));

        let local_addr =
            super::smoltcp_helpers::socket_addr_from_endpoint(socket.local_endpoint().unwrap());
        let remote_addr =
            super::smoltcp_helpers::socket_addr_from_endpoint(socket.remote_endpoint().unwrap());
        let stream = self.tcp_listeners_by_addr.remove(&local_addr).unwrap();
        assert_eq!(stream.borrow().local_addr, local_addr);
        stream.borrow_mut().remote_addr = Some(remote_addr.clone());
        assert!(self
            .tcp_streams_by_addr
            .insert((local_addr, remote_addr), stream.clone())
            .is_none());
        assert!(self.tcp_streams_by_handle.insert(handle, stream).is_none());

        self.events
            .push_back(NetEvent::IncomingTcpConnect((local_addr, remote_addr)));

        #[cfg(debug_assertions)]
        crate::moto_log!(
            "on_tcp_listener_connected: {:?} <- {:?}",
            local_addr,
            remote_addr
        );

        crate::ENABLE_LOG.store(true, core::sync::atomic::Ordering::Relaxed);

        self.do_tcp_listener_bind(&local_addr);
    }

    fn cancel_tcp_rx(&mut self, handle: SocketHandle) {
        // let socket = self.sockets.get_mut::<smoltcp::socket::tcp::Socket>(handle);
        // let local_addr =
        //     super::smoltcp_helpers::socket_addr_from_endpoint(socket.local_endpoint().unwrap());
        // let remote_addr =
        //     super::smoltcp_helpers::socket_addr_from_endpoint(socket.remote_endpoint().unwrap());

        let mut stream = self
            .tcp_streams_by_handle
            .get_mut(&handle)
            .unwrap()
            .borrow_mut();
        let local_addr = stream.local_addr.clone();
        let remote_addr = stream.remote_addr.as_ref().unwrap().clone();
        while let Some(mut rx_buf) = stream.rx_bufs.pop_front() {
            rx_buf.consumed = 0;
            rx_buf.status = ErrorCode::Ok;
            self.events
                .push_back(NetEvent::TcpRx((local_addr, remote_addr, rx_buf)));
        }
    }

    fn cancel_tcp_tx(&mut self, handle: SocketHandle) {
        // let socket = self.sockets.get_mut::<smoltcp::socket::tcp::Socket>(handle);
        // let local_addr =
        //     super::smoltcp_helpers::socket_addr_from_endpoint(socket.local_endpoint().unwrap());
        // let remote_addr =
        //     super::smoltcp_helpers::socket_addr_from_endpoint(socket.remote_endpoint().unwrap());

        let mut stream = self
            .tcp_streams_by_handle
            .get_mut(&handle)
            .unwrap()
            .borrow_mut();
        let local_addr = stream.local_addr.clone();
        let remote_addr = stream.remote_addr.as_ref().unwrap().clone();
        while let Some(mut tx_buf) = stream.tx_bufs.pop_front() {
            tx_buf.consumed = 0;
            tx_buf.status = ErrorCode::Ok;
            self.events
                .push_back(NetEvent::TcpTx((local_addr, remote_addr, tx_buf)));
        }
    }

    fn on_tcp_socket_poll(&mut self, handle: SocketHandle) {
        let waker = if let Some(waker) = self.wakers.get(&handle) {
            waker.clone()
        } else {
            return; // The socket has been removed/aborted.
        };
        let socket = self.sockets.get_mut::<smoltcp::socket::tcp::Socket>(handle);
        socket.register_recv_waker(&waker);
        socket.register_send_waker(&waker);

        let may_recv = socket.may_recv();
        let may_send = socket.may_send();
        let can_recv = socket.can_recv();
        let can_send = socket.can_send();
        let state = socket.state();

        match state {
            smoltcp::socket::tcp::State::Listen => return,
            smoltcp::socket::tcp::State::SynSent => return,
            smoltcp::socket::tcp::State::SynReceived => return,

            smoltcp::socket::tcp::State::Established => {
                if self.tcp_listeners_by_handle.contains_key(&handle) {
                    self.on_tcp_listener_connected(handle);
                }
            }

            smoltcp::socket::tcp::State::CloseWait => {
                // #[cfg(debug_assertions)]
                crate::moto_log!("{}:{} socket CloseWait", file!(), line!());
            }
            smoltcp::socket::tcp::State::Closed => {
                // #[cfg(debug_assertions)]
                crate::moto_log!("{}:{} socket Closed", file!(), line!());
            }
            _ => todo!("socket state: {:?}", state),
        }

        if can_recv {
            self.do_tcp_rx(handle);
        } else if !may_recv {
            self.cancel_tcp_rx(handle);
        }

        if can_send {
            self.do_tcp_tx(handle);
        } else if !may_send {
            self.cancel_tcp_tx(handle);
        }
    }

    fn process_polled_sockets(&mut self) -> bool {
        let mut did_work = false;
        loop {
            if self.woken_sockets.borrow().len() == 0 {
                break;
            }
            did_work = true;

            let mut woken = VecDeque::new();
            core::mem::swap(&mut woken, &mut *self.woken_sockets.borrow_mut());
            assert_eq!(0, self.woken_sockets.borrow().len());

            for h in &woken {
                self.on_tcp_socket_poll(*h);
            }
        }

        did_work
    }

    fn do_poll(&mut self) -> bool {
        let mut did_work = false;

        loop {
            did_work |= self.process_polled_sockets();
            if self.woken_sockets.borrow().len() > 0 {
                continue;
            }
            {
                let Self {
                    iface,
                    adapter,
                    sockets,
                    ..
                } = self;
                if !iface.poll(smoltcp::time::Instant::now(), adapter, sockets) {
                    if self.woken_sockets.borrow().len() > 0 {
                        // This sometimes happen, not clear why.
                        continue;
                    }
                    return did_work;
                }
            }
        }
    }

    fn do_tcp_rx(&mut self, handle: SocketHandle) {
        let mut stream = self
            .tcp_streams_by_handle
            .get_mut(&handle)
            .unwrap()
            .borrow_mut();

        if let Some(rx_buf) = stream.rx_bufs.pop_front() {
            core::mem::drop(stream);
            self.do_tcp_rx_buf(handle, rx_buf);
        }
    }

    fn do_tcp_rx_buf(&mut self, socket_handle: SocketHandle, mut rx_buf: IoBuf) {
        debug_assert_eq!(0, rx_buf.consumed);

        let socket = self
            .sockets
            .get_mut::<smoltcp::socket::tcp::Socket>(socket_handle);

        let mut receive_closure = |bytes: &mut [u8]| {
            let len = bytes.len().min(rx_buf.buf_len - rx_buf.consumed);
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), rx_buf.buf_ptr as *mut u8, len);
            }

            rx_buf.consumed += len;

            (len, rx_buf.is_consumed())
        };

        while socket.recv_queue() > 0 {
            if socket.recv(&mut receive_closure).unwrap() {
                break;
            }
        }

        if rx_buf.consumed == 0 && socket.may_recv() {
            // Keep the buffer.
            let mut stream = self
                .tcp_streams_by_handle
                .get(&socket_handle)
                .unwrap()
                .borrow_mut();

            stream.rx_bufs.push_front(rx_buf);
            return;
        }

        #[cfg(debug_assertions)]
        crate::moto_log!(
            "{}:{} TcpRx event: {} bytes",
            file!(),
            line!(),
            rx_buf.consumed
        );

        let local_addr =
            super::smoltcp_helpers::socket_addr_from_endpoint(socket.local_endpoint().unwrap());
        let remote_addr =
            super::smoltcp_helpers::socket_addr_from_endpoint(socket.remote_endpoint().unwrap());

        rx_buf.status = ErrorCode::Ok;
        self.events
            .push_back(NetEvent::TcpRx((local_addr, remote_addr, rx_buf)));
    }

    fn do_tcp_tx(&mut self, handle: SocketHandle) {
        let mut stream = self
            .tcp_streams_by_handle
            .get(&handle)
            .unwrap()
            .borrow_mut();

        let socket = self.sockets.get_mut::<smoltcp::socket::tcp::Socket>(handle);
        if !socket.can_send() {
            return;
        }

        let tx_buf = stream.tx_bufs.pop_front();
        if tx_buf.is_none() {
            return;
        }

        let mut tx_buf = tx_buf.unwrap();
        match socket.send_slice(tx_buf.bytes()) {
            Ok(usize) => {
                tx_buf.consume(usize);
                if tx_buf.is_consumed() {
                    tx_buf.status = ErrorCode::Ok;
                    let local_addr = super::smoltcp_helpers::socket_addr_from_endpoint(
                        socket.local_endpoint().unwrap(),
                    );
                    let remote_addr = super::smoltcp_helpers::socket_addr_from_endpoint(
                        socket.remote_endpoint().unwrap(),
                    );
                    self.events
                        .push_back(NetEvent::TcpTx((local_addr, remote_addr, tx_buf)));
                } else {
                    stream.tx_bufs.push_front(tx_buf);
                }
            }
            Err(_err) => todo!(),
        }
    }
}

impl NetInterface for VirtioNetDev {
    fn wait_handles(&self) -> Vec<moto_sys::SysHandle> {
        vec![self.rx_wait_handle, self.tx_wait_handle]
    }

    fn poll(&mut self) -> Option<super::netdev::NetEvent> {
        while self.do_poll() {}
        self.events.pop_front()
    }

    fn wait_timeout(&mut self) -> Option<core::time::Duration> {
        let Self { iface, sockets, .. } = self;
        iface
            .poll_delay(smoltcp::time::Instant::now(), sockets)
            .map(|d| d.into())
    }

    fn process_wakeup(&mut self, _handle: moto_sys::SysHandle) {
        self.do_poll();
    }

    fn tcp_listener_bind(&mut self, addr: &std::net::SocketAddr) {
        self.do_tcp_listener_bind(addr);
        self.do_poll();
    }

    fn tcp_listener_drop(&mut self, addr: &std::net::SocketAddr) {
        self.do_hard_drop_tcp_listener(addr)
    }

    fn tcp_stream_connect(
        &mut self,
        local_addr: &std::net::SocketAddr,
        remote_addr: &std::net::SocketAddr,
        timeout: Option<moto_sys::time::Instant>,
    ) {
        // 1. validate the local addr matches self
        // #[cfg(debug_assertions)]
        // for cidr in self.iface.ip_addrs() {
        //     if cidr.address() == ??
        // }

        // 2. create socket
        let rx_buffer = SocketBuffer::new(vec![0; 4000]);
        let tx_buffer = SocketBuffer::new(vec![0; 4000]);
        let socket = smoltcp::socket::tcp::Socket::new(rx_buffer, tx_buffer);
        let handle = self.sockets.add(socket);

        let stream = Rc::new(RefCell::new(VirtioTcpStream {
            socket_handle: handle,
            rx_bufs: VecDeque::new(),
            tx_bufs: VecDeque::new(),
            local_addr: local_addr.clone(),
            remote_addr: Some(remote_addr.clone()),
        }));
        self.tcp_streams_by_addr
            .insert((*local_addr, *remote_addr), stream.clone());
        self.tcp_streams_by_handle.insert(handle, stream);

        let socket_waker = SocketWaker::new(handle, self.woken_sockets.clone());
        let waker = unsafe { std::task::Waker::from_raw(socket_waker.into_raw_waker()) };
        self.wakers.insert(handle, waker.clone());

        let socket = self.sockets.get_mut::<smoltcp::socket::tcp::Socket>(handle);
        socket.register_recv_waker(&waker);
        socket.register_send_waker(&waker);

        if let Some(timeout) = timeout {
            let nanos = timeout.as_u64();
            let now = moto_sys::time::Instant::now().as_u64();
            if nanos <= now {
                // We check this upon receiving sqe; the thread got preempted or something.
                // Just use an arbitrary small timeout.
                socket.set_timeout(Some(smoltcp::time::Duration::from_micros(10)));
            } else {
                socket.set_timeout(Some(smoltcp::time::Duration::from_micros(
                    (nanos + 999 - now) / 1000,
                )));
            }
        }

        // 3. call connect
        socket
            .connect(
                self.iface.context(),
                (remote_addr.ip(), remote_addr.port()),
                (local_addr.ip(), local_addr.port()),
            )
            .unwrap();

        #[cfg(debug_assertions)]
        crate::moto_log!("tcp_connected");
        self.do_poll();
    }

    fn tcp_stream_write(
        &mut self,
        local_addr: &std::net::SocketAddr,
        remote_addr: &std::net::SocketAddr,
        mut write_buf: super::IoBuf,
    ) {
        #[cfg(debug_assertions)]
        crate::moto_log!("tcp_stream_write");
        let stream = self.tcp_streams_by_addr.get(&(*local_addr, *remote_addr));

        if stream.is_none() {
            // The connection was dropped/removed.
            write_buf.status = ErrorCode::UnexpectedEof;
            self.events
                .push_back(NetEvent::TcpTx((*local_addr, *remote_addr, write_buf)));
            return;
        }
        let mut stream = stream.unwrap().borrow_mut();
        stream.tx_bufs.push_back(write_buf);

        let handle = stream.socket_handle;
        drop(stream); // Needed to remove the borrowing of self.

        self.do_tcp_tx(handle);
    }

    fn tcp_stream_read(
        &mut self,
        local_addr: &std::net::SocketAddr,
        remote_addr: &std::net::SocketAddr,
        mut read_buf: super::IoBuf,
    ) {
        let stream = self.tcp_streams_by_addr.get(&(*local_addr, *remote_addr));

        if stream.is_none() {
            // The connection was dropped/removed.
            read_buf.status = ErrorCode::UnexpectedEof;
            self.events
                .push_back(NetEvent::TcpRx((*local_addr, *remote_addr, read_buf)));
            return;
        }
        let mut stream = stream.unwrap().borrow_mut();

        let rx_buf = {
            if let Some(rx_buf) = stream.rx_bufs.pop_front() {
                stream.rx_bufs.push_back(read_buf);
                rx_buf
            } else {
                read_buf
            }
        };
        let handle = stream.socket_handle;
        core::mem::drop(stream); // The borrow checker is unhappy without this.

        self.do_tcp_rx_buf(handle, rx_buf);
    }

    fn tcp_stream_shutdown(
        &mut self,
        local_addr: &std::net::SocketAddr,
        remote_addr: &std::net::SocketAddr,
        shut_rd: bool,
        shut_wr: bool,
    ) {
        self.shutdown_tcp_stream(local_addr, remote_addr, shut_rd, shut_wr)
    }

    fn tcp_stream_drop(
        &mut self,
        local_addr: &std::net::SocketAddr,
        remote_addr: &std::net::SocketAddr,
    ) {
        self.hard_drop_tcp_stream(local_addr, remote_addr)
    }

    fn hard_drop_tcp_listener(&mut self, addr: &std::net::SocketAddr) {
        self.do_hard_drop_tcp_listener(addr)
    }

    fn hard_drop_tcp_stream(
        &mut self,
        local_addr: &std::net::SocketAddr,
        remote_addr: &std::net::SocketAddr,
    ) {
        let stream = if let Some(stream) = self
            .tcp_streams_by_addr
            .remove(&(*local_addr, *remote_addr))
        {
            stream
        } else {
            panic!();
        };
        let handle = stream.borrow().socket_handle;
        assert!(self.tcp_streams_by_handle.remove(&handle).is_some());
        assert!(self.wakers.remove(&handle).is_some());
        let socket = self.sockets.remove(handle);

        if let smoltcp::socket::Socket::Tcp(mut socket) = socket {
            socket.abort();
        } else {
            panic!()
        }
        // #[cfg(debug_assertions)]
        crate::moto_log!("{}:{} hard_drop_tcp_stream", file!(), line!());
    }

    fn tcp_stream_set_read_timeout(
        &mut self,
        _local_addr: &SocketAddr,
        _remote_addr: &SocketAddr,
        _timeout: Option<std::time::Duration>,
    ) -> ErrorCode {
        #[cfg(debug_assertions)]
        crate::moto_log!("{}:{} TODO", file!(), line!());
        // Note: smoltcp Socket::set_timeout() sets internal TCP timeout.
        //       This method here sets read timeout on the client side, not
        //       on the network side.
        crate::moto_log!("{}:{} TODO", file!(), line!());
        ErrorCode::Ok
    }

    fn tcp_stream_set_write_timeout(
        &mut self,
        _local_addr: &SocketAddr,
        _remote_addr: &SocketAddr,
        _timeout: Option<std::time::Duration>,
    ) -> ErrorCode {
        // Note: smoltcp Socket::set_timeout() sets internal TCP timeout.
        //       This method here sets write timeout on the client side, not
        //       on the network side.
        crate::moto_log!("{}:{} TODO", file!(), line!());
        ErrorCode::Ok
    }

    fn tcp_stream_set_nodelay(
        &mut self,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        nodelay: bool,
    ) -> ErrorCode {
        let stream = self.tcp_streams_by_addr.get(&(*local_addr, *remote_addr));

        if stream.is_none() {
            return ErrorCode::UnexpectedEof;
        }
        let stream = unsafe { stream.unwrap_unchecked() };

        let socket = self
            .sockets
            .get_mut::<smoltcp::socket::tcp::Socket>(stream.borrow().socket_handle);
        socket.set_nagle_enabled(!nodelay);

        #[cfg(debug_assertions)]
        crate::moto_log!(
            "{}:{} tcp_stream_set_nodelay({})",
            file!(),
            line!(),
            nodelay
        );

        ErrorCode::Ok
    }
}

pub(super) fn init(config: &super::config::NetConfig) -> Vec<Box<NetDev>> {
    if !moto_virtio::virtio_net::ok() || config.devices.len() == 0 {
        return vec![];
    }

    if config.devices.len() > 1 {
        crate::moto_log!("sys-io: warning: only one VirtIO NET device is supported");
    }

    let dev_cfg = config.devices.get(&"virtio_net_0".to_owned()).unwrap();
    let mut routes = vec![];
    for route in &config.routes {
        if route.device_name == "virtio_net_0" {
            routes.push(route.clone());
        }
    }
    let dev = Box::new(NetDev::new(
        dev_cfg.cidrs.clone(),
        VirtioNetDev::new(dev_cfg, &routes),
        dev_cfg.name.clone(),
    ));

    vec![dev]
}
