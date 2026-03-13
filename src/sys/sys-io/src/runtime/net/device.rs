use std::rc::Rc;

use super::config;
use virtio_async::virtio_net::NetDevice;

pub(super) enum SmoltcpDevice {
    // VirtIo(VirtioSmoltcpDevice),
    Loopback(smoltcp::phy::Loopback),
}

impl SmoltcpDevice {
    fn ethernet_address(&self) -> smoltcp::wire::EthernetAddress {
        match self {
            // Self::VirtIo(dev) => smoltcp::wire::EthernetAddress::from_bytes(dev.virtio_dev.mac()),
            Self::Loopback(_) => {
                smoltcp::wire::EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
            }
        }
    }
}

pub(super) struct NetDev<'a> {
    name: String,
    config: config::DeviceCfg,

    device: SmoltcpDevice,
    iface: smoltcp::iface::Interface,
    pub(super) sockets: smoltcp::iface::SocketSet<'a>,

    tcp_ports_in_use: std::collections::HashSet<u16>,
    udp_ports_in_use: std::collections::HashSet<u16>,

    pub(super) notify: Rc<moto_async::LocalNotify>,
}

impl<'a> NetDev<'a> {
    pub(super) fn new(name: &str, dev_cfg: &config::DeviceCfg, mut device: SmoltcpDevice) -> Self {
        let mut config = smoltcp::iface::Config::new(device.ethernet_address().into());
        config.random_seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|dur| dur.as_nanos() as u64)
            .unwrap_or(1234);

        let mut iface = match &mut device {
            // SmoltcpDevice::VirtIo(dev) => {
            //     smoltcp::iface::Interface::new(config, dev, smoltcp::time::Instant::now())
            // }
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

        Self {
            name: name.to_owned(),
            config: dev_cfg.clone(),
            device,
            iface,
            sockets: smoltcp::iface::SocketSet::new(vec![]),
            tcp_ports_in_use: std::collections::HashSet::new(),
            udp_ports_in_use: std::collections::HashSet::new(),
            notify: Rc::new(moto_async::LocalNotify::default()),
        }
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) fn poll(&mut self) -> smoltcp::iface::PollResult {
        let NetDev {
            name,
            config,
            device,
            iface,
            sockets,
            tcp_ports_in_use,
            udp_ports_in_use,
            notify,
        } = self;
        match device {
            SmoltcpDevice::Loopback(loopback) => {
                iface.poll(smoltcp::time::Instant::now(), loopback, sockets)
            }
        }
    }
}
