//! This is mostly plumbing smoltcp into our async runtime.
use std::{
    cell::RefCell,
    collections::VecDeque,
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    rc::Rc,
};

use super::config;
use virtio_async::virtio_net::NetDevice;

type RxQueue = Rc<RefCell<VecDeque<Vec<u8>>>>;
type TxQueue = Rc<RefCell<VecDeque<Vec<u8>>>>;

pub(super) struct VirtioDevice {
    inner: Rc<NetDevice>,
    rx_queue: RxQueue,
    tx_queue: TxQueue,

    // The device will notify rx_notify when it updates rx_queue.
    rx_notify: Rc<moto_async::LocalNotify>,
    // The device will listen on tx_notify for tx_queue updates.
    tx_notify: Rc<moto_async::LocalNotify>,
    mtu: u16,
}

impl VirtioDevice {
    pub(super) fn new(inner: Rc<NetDevice>) -> Self {
        let mtu = inner.mtu().unwrap_or(1536);
        let this = Self {
            inner,
            rx_queue: Default::default(),
            tx_queue: Default::default(),
            rx_notify: Default::default(),
            tx_notify: Default::default(),
            mtu,
        };

        let _ = moto_async::LocalRuntime::spawn(Self::rx_task(
            this.inner.clone(),
            this.rx_queue.clone(),
            this.rx_notify.clone(),
        ));
        let _ = moto_async::LocalRuntime::spawn(Self::tx_task(
            this.inner.clone(),
            this.tx_queue.clone(),
            this.tx_notify.clone(),
        ));

        this
    }

    async fn rx_task(
        net_dev: Rc<NetDevice>,
        rx_queue: RxQueue,
        rx_notify: Rc<moto_async::LocalNotify>,
    ) {
        // Submit RX buffers to net_dev. Wait. Once RX happens, push
        // the buffer into rx_queue, notify. Once RX buffer is consumed,
        // push it again into net_dev.

        // TODO: optimize.

        let rxq_sz = net_dev.rxq_sz() as usize;

        // Pre-submit blocks.
        let mut completions = VecDeque::with_capacity(rxq_sz);
        for _ in 0..rxq_sz {
            completions.push_back(net_dev.clone().post_read(BlockWrapper::new_empty()).await);
        }

        const HEADER_LEN: usize = virtio_async::virtio_net::header_len();

        loop {
            let completion = completions.pop_front().unwrap();
            let (block, result) = completion.await;
            let sz_read = result.unwrap() as usize;

            log::debug!("NET: RX {sz_read} bytes.");
            let rx_vec = block.as_ref()[HEADER_LEN..sz_read].to_vec();
            rx_queue.borrow_mut().push_back(rx_vec);
            rx_notify.notify_one();

            completions.push_back(net_dev.clone().post_read(BlockWrapper::new_empty()).await);
        }
    }

    async fn tx_task(
        net_dev: Rc<NetDevice>,
        tx_queue: RxQueue,
        tx_notify: Rc<moto_async::LocalNotify>,
    ) {
        let mut completions = VecDeque::new();
        let txq_sz = net_dev.txq_sz() as usize;

        loop {
            if completions.len() == txq_sz {
                let completion = completions.pop_front().unwrap();
                let _ = completion.await;
            }
            let maybe_tx_vec = tx_queue.borrow_mut().pop_front();

            if let Some(tx_vec) = maybe_tx_vec {
                // TODO: optimize
                let block = BlockWrapper::from_bytes(&tx_vec);
                log::debug!("NET TX {} bytes", tx_vec.len());
                completions.push_back(net_dev.clone().post_write(block).await);
            } else {
                tx_notify.notified().await;
            }
        }
    }
}

struct BlockWrapper {
    block: Box<async_fs::Block>,
    len: usize,
}

impl BlockWrapper {
    fn new_empty() -> Self {
        Self {
            block: Box::new(async_fs::Block::new_zeroed()),
            len: async_fs::BLOCK_SIZE,
        }
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut this = Self::new_empty();
        this.block.as_bytes_mut()[..bytes.len()].clone_from_slice(bytes);
        this.len = bytes.len();
        this
    }
}

impl AsRef<[u8]> for BlockWrapper {
    fn as_ref(&self) -> &[u8] {
        &self.block.as_bytes()[..self.len]
    }
}

impl AsMut<[u8]> for BlockWrapper {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.block.as_bytes_mut()[..self.len]
    }
}

pub struct VirtioRxToken(Vec<u8>);

impl smoltcp::phy::RxToken for VirtioRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        log::debug!("RxToken: consume {}", self.0.len());
        f(&mut self.0)
    }
}

pub struct VirtioTxToken {
    tx_queue: TxQueue,
    tx_notify: Rc<moto_async::LocalNotify>,
}

impl smoltcp::phy::TxToken for VirtioTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        log::debug!("TxToken: consume {len}.");
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        self.tx_queue.borrow_mut().push_back(buffer);
        self.tx_notify.notify_one();
        log::debug!("TxToken: consume {len}.");
        result
    }
}

impl smoltcp::phy::Device for VirtioDevice {
    type RxToken<'a>
        = VirtioRxToken
    where
        Self: 'a;

    type TxToken<'a>
        = VirtioTxToken
    where
        Self: 'a;

    fn receive(
        &mut self,
        timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        log::debug!("VirtioDevice::receive()");
        self.rx_queue.borrow_mut().pop_front().map(|buf| {
            log::debug!("VirtioDevice::receive(): have {} bytes.", buf.len());
            (
                VirtioRxToken(buf),
                VirtioTxToken {
                    tx_queue: self.tx_queue.clone(),
                    tx_notify: self.tx_notify.clone(),
                },
            )
        })
    }

    fn transmit(&mut self, timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        log::debug!("VirtioDevice::transmit()");
        Some(VirtioTxToken {
            tx_queue: self.tx_queue.clone(),
            tx_notify: self.tx_notify.clone(),
        })
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.medium = smoltcp::phy::Medium::Ethernet;
        caps.max_transmission_unit = self.mtu as usize;
        caps
    }
}

pub(super) enum SmoltcpDevice {
    VirtIo(VirtioDevice),
    Loopback(smoltcp::phy::Loopback),
}

pub(super) struct NetDev<'a> {
    name: String,
    config: config::DeviceCfg,

    device: SmoltcpDevice,
    iface: smoltcp::iface::Interface,
    pub(super) sockets: smoltcp::iface::SocketSet<'a>,

    udp_ports_in_use: std::collections::HashSet<u16>,
    udp_addresses_in_use: std::collections::HashSet<SocketAddr>,

    tcp_ports_in_use: std::collections::HashSet<u16>,

    // This is the notify that drives smoltcp device runtime in net.rs.
    pub(super) device_runtime_notify: Rc<moto_async::LocalNotify>,
}

impl<'a> NetDev<'a> {
    pub(super) fn new(name: &str, dev_cfg: &config::DeviceCfg, mut device: SmoltcpDevice) -> Self {
        let mut config = smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ethernet(
            smoltcp::wire::EthernetAddress::from_bytes(&dev_cfg.mac.raw()),
        ));
        config.random_seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|dur| dur.as_nanos() as u64)
            .unwrap_or(1234);
        config.discovery_silent_time = smoltcp::time::Duration::from_millis(5);
        log::debug!(
            "Initializing net device {name} with\nmac {:x?}",
            dev_cfg.mac
        );

        let (mut iface, notify) = match &mut device {
            SmoltcpDevice::VirtIo(dev) => (
                smoltcp::iface::Interface::new(config, dev, smoltcp::time::Instant::now()),
                // Smoltcp interfaces have a single poll() that does both RX and TX.
                // RX is driven by VirtioNET device; TX is driven by user sockets.
                //
                // A better stack would have these separate.
                dev.rx_notify.clone(),
            ),
            SmoltcpDevice::Loopback(dev) => (
                smoltcp::iface::Interface::new(config, dev, smoltcp::time::Instant::now()),
                // The loopback device has a self-contained runtime notify.
                Rc::new(moto_async::LocalNotify::default()),
            ),
        };

        iface.update_ip_addrs(|ip_addrs| {
            for cidr in &dev_cfg.cidrs {
                log::debug!("added IP \n\t{:?} to {}", cidr.ip(), name);
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
                    cidr: config::ip_network_to_cidr(&route.ip_network),
                    via_router: route.gateway.into(),
                    preferred_until: None,
                    expires_at: None,
                };
                log::debug!("adding route \n{route:#?} to {name}");
                storage.push(rt).unwrap();
            }
        });

        log::debug!("New NET device {name}.");

        Self {
            name: name.to_owned(),
            config: dev_cfg.clone(),
            device,
            iface,
            sockets: smoltcp::iface::SocketSet::new(vec![]),
            udp_ports_in_use: std::collections::HashSet::new(),
            udp_addresses_in_use: std::collections::HashSet::new(),
            tcp_ports_in_use: std::collections::HashSet::new(),
            device_runtime_notify: notify,
        }
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) fn config(&self) -> &config::DeviceCfg {
        &self.config
    }

    // Have to have this as a method here because it borrows self twice: for the socket and for the iface.
    pub(super) fn tcp_connect(
        &mut self,
        handle: smoltcp::iface::SocketHandle,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<(), ()> {
        let smol_socket = self.sockets.get_mut::<smoltcp::socket::tcp::Socket>(handle);
        smol_socket
            .connect(self.iface.context(), remote_addr, local_addr)
            .map_err(|_err| {
                log::warn!("Connect {local_addr:?} => {remote_addr:?} failed: {_err:?}");
            })?;

        self.device_runtime_notify.notify_one();
        Ok(())
    }

    pub(super) fn poll(&mut self) -> smoltcp::iface::PollResult {
        let NetDev {
            name,
            config,
            device,
            iface,
            sockets,
            udp_ports_in_use,
            udp_addresses_in_use,
            tcp_ports_in_use,
            device_runtime_notify: notify,
        } = self;
        match device {
            SmoltcpDevice::Loopback(loopback) => {
                iface.poll(smoltcp::time::Instant::now(), loopback, sockets)
            }
            SmoltcpDevice::VirtIo(virtio_device) => {
                iface.poll(smoltcp::time::Instant::now(), virtio_device, sockets)
            }
        }
    }

    pub(super) fn poll_delay(&mut self) -> Option<std::time::Duration> {
        let NetDev {
            name,
            config,
            device,
            iface,
            sockets,
            udp_ports_in_use,
            udp_addresses_in_use,
            tcp_ports_in_use,
            device_runtime_notify: notify,
        } = self;
        match device {
            SmoltcpDevice::Loopback(loopback) => iface
                .poll_delay(smoltcp::time::Instant::now(), sockets)
                .map(|d| d.into()),
            SmoltcpDevice::VirtIo(virtio_device) => iface
                .poll_delay(smoltcp::time::Instant::now(), sockets)
                .map(|d| d.into()),
        }
    }

    pub(super) fn ip_addesses(&self) -> Vec<IpAddr> {
        let cidrs = self.iface.ip_addrs();
        let mut addresses = Vec::with_capacity(cidrs.len());
        for cidr in cidrs {
            addresses.push(cidr.address().into());
        }

        addresses
    }

    pub(super) fn get_ephemeral_udp_port(&mut self, _local_ip_addr: &IpAddr) -> Option<u16> {
        // See https://en.wikipedia.org/wiki/Ephemeral_port.
        const EPHEMERAL_PORT_MIN: u16 = 49152;
        const EPHEMERAL_PORT_MAX: u16 = 65535;

        // TODO: do better than a linear search.
        for port in EPHEMERAL_PORT_MIN..=EPHEMERAL_PORT_MAX {
            if !self.udp_ports_in_use.contains(&port) {
                self.udp_ports_in_use.insert(port);
                return Some(port);
            }
        }

        None
    }

    pub(super) fn free_ephemeral_udp_port(&mut self, port: u16) {
        self.udp_ports_in_use.remove(&port);
    }

    pub(super) fn add_udp_addr_in_use(&mut self, addr: SocketAddr) -> std::io::Result<()> {
        if self.udp_addresses_in_use.insert(addr) {
            Ok(())
        } else {
            Err(std::io::Error::from(ErrorKind::AddrInUse))
        }
    }

    pub(super) fn remove_udp_addr_in_use(&mut self, addr: &SocketAddr) {
        assert!(self.udp_addresses_in_use.remove(addr));
        log::debug!("{}: removed udp addr in use {addr:?}", self.name);
    }

    pub(super) fn get_ephemeral_tcp_port(&mut self, _local_ip_addr: &IpAddr) -> Option<u16> {
        // See https://en.wikipedia.org/wiki/Ephemeral_port.
        const EPHEMERAL_PORT_MIN: u16 = 49152;
        const EPHEMERAL_PORT_MAX: u16 = 65535;

        // TODO: do better than a linear search.
        for port in EPHEMERAL_PORT_MIN..=EPHEMERAL_PORT_MAX {
            if !self.tcp_ports_in_use.contains(&port) {
                self.tcp_ports_in_use.insert(port);
                return Some(port);
            }
        }

        None
    }

    pub(super) fn free_ephemeral_tcp_port(&mut self, port: u16) {
        self.tcp_ports_in_use.remove(&port);
    }
}
