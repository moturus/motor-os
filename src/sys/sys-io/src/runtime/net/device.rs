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

pub(super) struct VirtioDevice {
    inner: Rc<NetDevice>,
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: Rc<RefCell<VecDeque<Vec<u8>>>>,
}

impl VirtioDevice {
    pub(super) fn new(inner: Rc<NetDevice>) -> Self {
        log::error!("spawn RX and TX tasks");
        Self {
            inner,
            rx_queue: Default::default(),
            tx_queue: Default::default(),
        }
    }
}

pub struct VirtioRxToken(Vec<u8>);

impl smoltcp::phy::RxToken for VirtioRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&mut self.0)
    }
}

pub struct VirtioTxToken {
    tx_queue: Rc<RefCell<VecDeque<Vec<u8>>>>,
}

impl smoltcp::phy::TxToken for VirtioTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        self.tx_queue.borrow_mut().push_back(buffer);
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
        self.rx_queue.pop_front().map(|buf| {
            (
                VirtioRxToken(buf),
                VirtioTxToken {
                    tx_queue: Rc::clone(&self.tx_queue),
                },
            )
        })
    }

    fn transmit(&mut self, timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtioTxToken {
            tx_queue: Rc::clone(&self.tx_queue),
        })
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.medium = smoltcp::phy::Medium::Ethernet;
        caps.max_transmission_unit = self.inner.mtu().map(|mtu| mtu as usize).unwrap_or(1536);
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

    pub(super) notify: Rc<moto_async::LocalNotify>,
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

        let mut iface = match &mut device {
            SmoltcpDevice::VirtIo(dev) => {
                smoltcp::iface::Interface::new(config, dev, smoltcp::time::Instant::now())
            }
            SmoltcpDevice::Loopback(dev) => {
                smoltcp::iface::Interface::new(config, dev, smoltcp::time::Instant::now())
            }
        };

        iface.update_ip_addrs(|ip_addrs| {
            for cidr in &dev_cfg.cidrs {
                log::debug!(
                    "{}:{} added IP {:?} to {}",
                    file!(),
                    line!(),
                    cidr.ip(),
                    name
                );
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
            notify: Rc::new(moto_async::LocalNotify::default()),
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

        self.notify.notify_one();
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
            notify,
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
            notify,
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
