use std::{
    collections::{HashMap, VecDeque},
    sync::atomic::*,
};

use moto_virtio::virtio_net::RxBuffer;
use smoltcp::{
    iface::{Config, SocketHandle, SocketSet},
    phy::{DeviceCapabilities, RxToken, TxToken},
};

static NET_DEV: AtomicPtr<spin::Mutex<NetDev>> = AtomicPtr::new(core::ptr::null_mut());

const IP: &str = "10.0.2.15"; // QEMU user networking default IP
const GATEWAY: &str = "10.0.2.2"; // QEMU user networking gateway

const RX_BUFFER_CACHE_SZ: usize = 4;
static EMPTY_BUFFERS: spin::Mutex<Vec<Box<RxBuffer>>> = spin::Mutex::new(vec![]);
static FULL_BUFFERS: spin::Mutex<VecDeque<Box<RxBuffer>>> = spin::Mutex::new(VecDeque::new());
static EMPTY_BUFFER_CNT: AtomicU32 = AtomicU32::new(0);
static FULL_BUFFER_CNT: AtomicU32 = AtomicU32::new(0);

pub struct VirtioRxToken {
    rx_buffer: Option<Box<RxBuffer>>,
}

impl RxToken for VirtioRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut rx_buffer = self.rx_buffer.take().unwrap();
        let res = f(rx_buffer.bytes_mut());
        EMPTY_BUFFERS.lock().push(rx_buffer);
        EMPTY_BUFFER_CNT.fetch_add(1, Ordering::Relaxed);
        res
    }
}

pub struct VirtioTxToken {}

impl TxToken for VirtioTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf: Vec<u8> = alloc::vec::Vec::with_capacity(len);
        // Safe because the capacity is >= len.
        unsafe { buf.set_len(len) };
        let res = f(buf.as_mut_slice());
        moto_virtio::virtio_net::transmit(buf.as_slice()).unwrap();
        res
    }
}

pub struct VirtioDeviceAdapter {}

impl smoltcp::phy::Device for VirtioDeviceAdapter {
    type RxToken<'a> = VirtioRxToken
    where
        Self: 'a;

    type TxToken<'a> = VirtioTxToken
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if FULL_BUFFER_CNT.load(Ordering::Relaxed) == 0 {
            return None;
        }
        FULL_BUFFER_CNT.fetch_sub(1, Ordering::Relaxed);
        Some((
            VirtioRxToken {
                rx_buffer: FULL_BUFFERS.lock().pop_front(),
            },
            VirtioTxToken {},
        ))
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtioTxToken {})
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = smoltcp::phy::Medium::Ethernet;
        caps.max_transmission_unit = 1514;
        caps.max_burst_size = Some(1);

        caps
    }
}

pub struct NetDev {
    adapter: VirtioDeviceAdapter,
    iface: smoltcp::iface::Interface,
    sockets: SocketSet<'static>,
    handlers: HashMap<SocketHandle, super::TcpRecvHandler>,
}

impl NetDev {
    fn inst() -> &'static spin::Mutex<Self> {
        let ptr = NET_DEV.load(Ordering::Relaxed);
        unsafe { ptr.as_ref().unwrap() }
    }

    pub fn init() -> Result<(), ()> {
        if !moto_virtio::virtio_net::ok() {
            return Err(());
        }

        let mut config = Config::new();
        let addr =
            smoltcp::wire::EthernetAddress::from_bytes(&moto_virtio::virtio_net::mac().unwrap());
        config.hardware_addr = Some(smoltcp::wire::HardwareAddress::Ethernet(addr));
        config.random_seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|dur| dur.as_nanos() as u64)
            .unwrap_or(1234);

        let mut adapter = VirtioDeviceAdapter {};
        let mut iface = smoltcp::iface::Interface::new(config, &mut adapter);

        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(smoltcp::wire::IpCidr::new(
                    <smoltcp::wire::IpAddress as std::str::FromStr>::from_str(IP).unwrap(),
                    24,
                ))
                .unwrap();
        });

        iface
            .routes_mut()
            .add_default_ipv4_route(
                <smoltcp::wire::Ipv4Address as std::str::FromStr>::from_str(GATEWAY).unwrap(),
            )
            .unwrap();

        let net_dev = Box::into_raw(Box::new(spin::Mutex::new(NetDev {
            adapter,
            iface,
            sockets: SocketSet::new(vec![]),
            handlers: HashMap::new(),
        })));

        let prev = NET_DEV.swap(net_dev, Ordering::AcqRel);
        assert!(prev.is_null());

        {
            let mut empty_buffers = EMPTY_BUFFERS.lock();
            empty_buffers.reserve_exact(RX_BUFFER_CACHE_SZ);
            for _ in 0..RX_BUFFER_CACHE_SZ {
                empty_buffers.push(Box::new(RxBuffer::new()));
            }
        }
        EMPTY_BUFFER_CNT.store(RX_BUFFER_CACHE_SZ as u32, Ordering::Relaxed);

        std::thread::spawn(Self::start);

        Ok(())
    }

    fn start() {
        std::thread::spawn(Self::rx_thread);
        loop {
            Self::poll();
            moto_runtime::futex_wait(&FULL_BUFFER_CNT, 0, None);
        }
    }

    fn rx_thread() {
        loop {
            moto_runtime::futex_wait(&EMPTY_BUFFER_CNT, 0, None);
            let mut rx_buffer = EMPTY_BUFFERS.lock().pop().unwrap();
            EMPTY_BUFFER_CNT.fetch_sub(1, Ordering::Relaxed);

            moto_virtio::virtio_net::receive(rx_buffer.as_mut()).unwrap();
            FULL_BUFFERS.lock().push_back(rx_buffer);
            FULL_BUFFER_CNT.fetch_add(1, Ordering::Relaxed);
            moto_runtime::futex_wake(&FULL_BUFFER_CNT);
        }
    }

    fn poll() {
        let mut self_ = Self::inst().lock();
        let timestamp = smoltcp::time::Instant::now();
        let NetDev {
            iface,
            adapter,
            sockets,
            handlers,
        } = &mut *self_;
        iface.poll(timestamp, adapter, sockets);

        for (handle, socket) in sockets.iter_mut() {
            match socket {
                smoltcp::socket::Socket::Raw(_) => todo!(),
                smoltcp::socket::Socket::Icmp(_) => todo!(),
                smoltcp::socket::Socket::Udp(_) => todo!(),
                smoltcp::socket::Socket::Tcp(ref mut sock) => {
                    if sock.can_recv() {
                        handlers.get(&handle).unwrap().can_recv(sock);
                    }
                }
                smoltcp::socket::Socket::Dhcpv4(_) => todo!(),
                smoltcp::socket::Socket::Dns(_) => todo!(),
            }
        }
    }
}

pub(super) fn init() -> Result<(), ()> {
    NetDev::init()
}

pub(super) fn add_tcp_socket(
    mut socket: smoltcp::socket::tcp::Socket<'static>,
    port: u16,
    handler: super::TcpRecvHandler,
) -> SocketHandle {
    let mut dev = NetDev::inst().lock();

    socket.listen(port).unwrap();
    let handle = dev.sockets.add(socket);
    dev.handlers.insert(handle, handler);

    handle
}
