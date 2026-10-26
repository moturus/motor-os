//! Device admission and publication on the single-threaded net runtime.
use super::*;
use moto_sdk::sys_io::api_ip_device::Registration;

const MAX_DEVICES: usize = 4;

impl NetRuntime {
    pub(super) async fn register_packet_device(
        &self,
        registration: Registration,
    ) -> Result<(usize, packet_device::PacketDevice)> {
        registration
            .validate()
            .map_err(crate::util::map_native_error)?;
        self.pressure.admit()?;
        let mut cfg = config::DeviceCfg {
            mac: None,
            dhcp: false,
            cidrs: Vec::new(),
            routes: Vec::new(),
            dns_servers: Vec::new(),
        };
        cfg.cidrs
            .try_reserve_exact(registration.addresses.len())
            .map_err(|_| ErrorKind::OutOfMemory)?;
        cfg.routes
            .try_reserve_exact(registration.routes.len())
            .map_err(|_| ErrorKind::OutOfMemory)?;
        cfg.cidrs.extend(
            registration
                .addresses
                .iter()
                .map(|cidr| IpNetwork::new(cidr.address, cidr.prefix_len).unwrap()),
        );
        cfg.routes
            .extend(registration.routes.iter().map(|cidr| config::IpRoute {
                ip_network: IpNetwork::new(cidr.address, cidr.prefix_len).unwrap(),
                gateway: None,
            }));
        let mut listeners = Vec::new();
        {
            let mut inner = self.inner.borrow_mut();
            if inner.devices.packet_count() >= MAX_DEVICES {
                return Err(ErrorKind::OutOfMemory.into());
            }
            for (_, device) in inner.devices.iter() {
                if device.name() == registration.name {
                    return Err(ErrorKind::AlreadyExists.into());
                }
                if device.is_packet()
                    && cfg.routes.iter().any(|route| {
                        device
                            .config()
                            .routes
                            .iter()
                            .any(|existing| existing.ip_network == route.ip_network)
                    })
                {
                    return Err(ErrorKind::AddrInUse.into());
                }
            }
            if cfg
                .cidrs
                .iter()
                .any(|cidr| inner.ip_addresses.contains_key(&cidr.ip()))
            {
                return Err(ErrorKind::AddrInUse.into());
            }
            inner.devices.prepare_push()?;
            inner
                .ip_addresses
                .try_reserve(cfg.cidrs.len())
                .map_err(|_| ErrorKind::OutOfMemory)?;
            listeners
                .try_reserve_exact(inner.tcp_listeners.len())
                .map_err(|_| ErrorKind::OutOfMemory)?;
            listeners.extend(inner.tcp_listeners.values().cloned());
        }
        // An explicit listener with a withdrawn address can coexist with a
        // wildcard until that address returns. Refuse conflicting expansion.
        let mut ports = HashSet::new();
        ports
            .try_reserve(listeners.len())
            .map_err(|_| ErrorKind::OutOfMemory)?;
        for address in &registration.addresses {
            ports.clear();
            for listener in &listeners {
                let listener = listener.borrow();
                if listener.accepts_address(address.address) && !ports.insert(listener.port()) {
                    return Err(ErrorKind::AddrInUse.into());
                }
            }
        }
        let packet =
            packet_device::PacketDevice::new(registration.mtu as usize, self.stats.clone())?;
        let device = device::NetDev::try_new(
            registration.name,
            cfg,
            self.interface_policy,
            device::NetstackDevice::Packet(packet.clone()),
        )?;
        let index = {
            let mut inner = self.inner.borrow_mut();
            let index = inner.devices.push(device);
            for address in &registration.addresses {
                inner.ip_addresses.insert(address.address, index);
            }
            index
        };
        self.stats.num_devices.set(self.stats.num_devices.get() + 1);
        // No await can expose the temporary tables. A failure withdraws them
        // before yielding to any tasks spawned by listener construction.
        for address in &registration.addresses {
            for listener in &listeners {
                if let Err(error) =
                    tcp_listener::TcpListener::try_add_address(listener, address.address, index)
                {
                    drop(listeners);
                    drop(packet);
                    self.remove_device_inner(index, false).await;
                    return Err(error);
                }
            }
        }
        self.spawn_device_runtime(index);
        Ok((index, packet))
    }
}

#[cfg(debug_assertions)]
#[path = "registration_tests.rs"]
pub(crate) mod self_test;
