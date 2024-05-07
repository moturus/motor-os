use std::collections::VecDeque;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;

use moto_sys::SysHandle;
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::phy::Loopback;
use smoltcp::phy::{RxToken, TxToken};

use super::config::DeviceCfg;

struct VirtioRxToken {
    dev: *mut VirtioSmoltcpDevice,
}

impl VirtioRxToken {
    fn dev(&self) -> &mut VirtioSmoltcpDevice {
        unsafe { self.dev.as_mut().unwrap() }
    }
}

impl RxToken for VirtioRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        if let Some(rx_packet) = self.dev().rx_packet.as_ref() {
            let buf = rx_packet.bytes_mut();
            // log::debug!("consuming {} RX bytes", buf.len());
            let res = f(buf);
            self.dev().rx_packet = None;

            self.dev().poll_virtio_rx();

            res
        } else {
            unreachable!()
        }
    }
}

struct VirtioTxToken {
    dev: *mut VirtioSmoltcpDevice,
}

impl VirtioTxToken {
    fn dev(&self) -> &mut VirtioSmoltcpDevice {
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

        // log::debug!("Tx consume {} bytes", len);

        if !self.dev().pending_tx.is_empty() {
            self.dev().send_pending_tx();
        }

        if self.dev().pending_tx.is_empty() {
            if let Some(tx_packet) = self.dev().virtio_dev.tx_get() {
                let buf = tx_packet.bytes_mut();
                assert!(buf.len() >= len);
                let packet = &mut buf[0..len];
                let res = f(packet);

                // #[cfg(debug_assertions)]
                // log::debug!("enqueueing tx {} bytes into the NIC (zero pending)", len);
                tx_packet.consume(len as u16);
                return res;
            }
        }

        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.dev().tx_queued += buffer.len();
        self.dev().pending_tx.push_back(buffer);

        // rnetbench can push this above 80k
        // static mut MAX_Q: usize = 64000;
        // unsafe {
        //     if self.dev().tx_queued > MAX_Q {
        //         MAX_Q = self.dev().tx_queued;
        //         log::info!("DEV: pending tx bytes: {}", MAX_Q);
        //     }
        // }

        result
    }
}

struct VirtioSmoltcpDevice {
    // If virtio_dev does not have available TX buffers, we store outgoing bytes here.
    pending_tx: VecDeque<Vec<u8>>,
    tx_queued: usize,

    virtio_dev: moto_virtio::virtio_net::NetDev,

    rx_packet: Option<moto_virtio::virtio_net::RxPacket>,
}

impl VirtioSmoltcpDevice {
    fn new(dev_cfg: &super::config::DeviceCfg) -> Option<Self> {
        let mac = dev_cfg.mac.raw();

        let virtio_dev = moto_virtio::virtio_net::take_by_mac(&mac)?;

        let mut self_ = Self {
            pending_tx: VecDeque::new(),
            tx_queued: 0,
            virtio_dev,
            rx_packet: None,
        };
        self_.virtio_dev.start_receiving();

        Some(self_)
    }

    fn wait_handles(&self) -> Vec<SysHandle> {
        self.virtio_dev
            .wait_handles()
            .iter()
            .map(|num| num.into())
            .collect()
    }

    fn poll_virtio_rx(&mut self) {
        if self.rx_packet.is_none() {
            self.rx_packet = self.virtio_dev.rx_get();

            // #[cfg(debug_assertions)]
            // if let Some(packet) = &self.rx_packet {
            //     log::debug!("got {} RX bytes in the NIC", packet.bytes_mut().len());
            // }
        }
    }

    fn send_pending_tx(&mut self) {
        if self.pending_tx.is_empty() {
            return;
        }

        while let Some(tx_packet) = self.virtio_dev.tx_get() {
            let packet = self.pending_tx.pop_front().unwrap();

            let buf = tx_packet.bytes_mut();
            assert!(buf.len() >= packet.len());
            let buf = &mut buf[0..packet.len()];
            unsafe {
                core::ptr::copy_nonoverlapping(packet.as_ptr(), buf.as_mut_ptr(), packet.len());
            }

            // #[cfg(debug_assertions)]
            // log::debug!("enqueueing tx {} bytes into the NIC", packet.len());
            tx_packet.consume(packet.len() as u16);

            if self.pending_tx.is_empty() {
                return;
            }
        }
    }
}

impl smoltcp::phy::Device for VirtioSmoltcpDevice {
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
        self.poll_virtio_rx();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        if self.rx_packet.is_none() {
            // No bytes to read.
            return None;
        }
        Some((
            VirtioRxToken {
                dev: self as *mut Self,
            },
            VirtioTxToken {
                dev: self as *mut Self,
            },
        ))
    }

    // Note: this is called from smoltcp::iface::Interface::poll() if smoltcp has bytes to send.
    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtioTxToken {
            dev: self as *mut Self,
        })
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.medium = smoltcp::phy::Medium::Ethernet;
        caps.max_transmission_unit = if let Some(mtu) = self.virtio_dev.mtu() {
            mtu as usize
        } else {
            1536
        };

        caps
    }
}

enum SmoltcpDevice {
    VirtIo(VirtioSmoltcpDevice),
    Loopback(smoltcp::phy::Loopback),
}

impl SmoltcpDevice {
    fn ethernet_address(&self) -> smoltcp::wire::EthernetAddress {
        match self {
            Self::VirtIo(dev) => smoltcp::wire::EthernetAddress::from_bytes(dev.virtio_dev.mac()),
            Self::Loopback(_) => {
                smoltcp::wire::EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
            }
        }
    }
}

pub(super) struct NetDev {
    name: String,
    config: super::config::DeviceCfg,

    device: SmoltcpDevice,
    iface: smoltcp::iface::Interface,
    pub sockets: SocketSet<'static>,

    ports_in_use: std::collections::HashSet<u16>,
}

impl NetDev {
    // See https://en.wikipedia.org/wiki/Ephemeral_port.
    const EPHEMERAL_PORT_MIN: u16 = 49152;
    const EPHEMERAL_PORT_MAX: u16 = 65535;

    // NetInterface forwarders.
    pub fn wait_handles(&self) -> Vec<SysHandle> {
        match &self.device {
            SmoltcpDevice::VirtIo(dev) => dev.wait_handles(),
            SmoltcpDevice::Loopback(_) => vec![],
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    fn new(name: &str, dev_cfg: &super::config::DeviceCfg, mut device: SmoltcpDevice) -> Self {
        let mut config = smoltcp::iface::Config::new(device.ethernet_address().into());
        config.random_seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|dur| dur.as_nanos() as u64)
            .unwrap_or(1234);

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
                    cidr: super::smoltcp_helpers::ip_network_to_cidr(&route.ip_network),
                    via_router: route.gateway.into(),
                    preferred_until: None,
                    expires_at: None,
                };
                storage.push(rt).unwrap();
            }
        });
        Self {
            name: name.to_owned(),
            config: dev_cfg.clone(),
            device,
            iface,
            sockets: SocketSet::new(vec![]),
            ports_in_use: std::collections::HashSet::new(),
        }
    }

    pub fn wait_timeout(&mut self) -> Option<core::time::Duration> {
        let Self { iface, sockets, .. } = self;
        iface
            .poll_delay(smoltcp::time::Instant::now(), sockets)
            .map(|d| d.into())
    }

    pub fn dev_cfg(&self) -> &super::config::DeviceCfg {
        &self.config
    }

    pub fn get_ephemeral_port(
        &mut self,
        _local_ip_addr: &IpAddr,
        _remote_addr: &SocketAddr,
    ) -> Option<u16> {
        // TODO: do better than a linear search.
        for port in Self::EPHEMERAL_PORT_MIN..=Self::EPHEMERAL_PORT_MAX {
            if !self.ports_in_use.contains(&port) {
                self.ports_in_use.insert(port);
                return Some(port);
            }
        }

        None
    }

    pub fn free_ephemeral_port(&mut self, port: u16) {
        self.ports_in_use.remove(&port);
    }

    // Have to have this as a method here because it borrows self twice: for the socket and for the iface.
    pub fn connect_socket(
        &mut self,
        handle: SocketHandle,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
    ) {
        let smol_socket = self.sockets.get_mut::<smoltcp::socket::tcp::Socket>(handle);
        smol_socket
            .connect(
                self.iface.context(),
                (remote_addr.ip(), remote_addr.port()),
                (local_addr.ip(), local_addr.port()),
            )
            .unwrap();
    }

    pub fn poll(&mut self) -> bool {
        if let SmoltcpDevice::VirtIo(dev) = &mut self.device {
            if !dev.pending_tx.is_empty() {
                dev.send_pending_tx();
            }
        }

        let Self {
            iface,
            device,
            sockets,
            ..
        } = self;

        match device {
            SmoltcpDevice::VirtIo(dev) => iface.poll(smoltcp::time::Instant::now(), dev, sockets),
            SmoltcpDevice::Loopback(dev) => iface.poll(smoltcp::time::Instant::now(), dev, sockets),
        }
    }
}

pub(super) fn init(config: &super::config::NetConfig) -> Vec<NetDev> {
    let mut result = vec![];

    if config.loopback {
        let mut loopback_cfg = DeviceCfg::new("02:00:00:00:00:01");
        loopback_cfg
            .cidrs
            .push(ipnetwork::IpNetwork::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8).unwrap());
        let loopback_dev = Loopback::new(smoltcp::phy::Medium::Ethernet);
        let dev = NetDev::new(
            "loopback",
            &loopback_cfg,
            SmoltcpDevice::Loopback(loopback_dev),
        );
        result.push(dev);
    }

    for (dev_name, dev_cfg) in &config.devices {
        if let Some(dev_inner) = VirtioSmoltcpDevice::new(dev_cfg) {
            let dev = NetDev::new(dev_name, dev_cfg, SmoltcpDevice::VirtIo(dev_inner));
            result.push(dev);
        } else {
            log::warn!(
                "VirtIO Net device {}:{:?} not found.",
                dev_name,
                dev_cfg.mac
            );
        }
    }

    result
}
