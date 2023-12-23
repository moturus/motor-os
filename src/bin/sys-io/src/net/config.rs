use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
};

use configparser::ini::Ini;
use moto_sys::ErrorCode;
use ipnetwork::{IpNetwork, Ipv4Network};

#[derive(Clone)]
pub(super) struct IpCidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

pub(super) struct DeviceCfg {
    pub name: String,
    pub cidrs: Vec<IpCidr>,
}

#[derive(Clone)]
pub(super) struct IpRoute {
    pub ip_network: IpNetwork,
    pub gateway: IpAddr,
    pub device_name: String,
}

impl IpRoute {
    pub fn is_reachable(&self, addr: &IpAddr) -> bool {
        match self.ip_network {
            IpNetwork::V4(net) => {
                if let IpAddr::V4(addr_v4) = addr {
                    if net.prefix() == 0 {
                        // The default gateway.
                        return true;
                    }
                    if net.contains(addr_v4.clone()) {
                        return true;
                    }
                    return false;
                }
                return false;
            }
            IpNetwork::V6(_) => todo!(),
        }
    }
}

#[derive(Default)]
pub(super) struct NetConfig {
    pub devices: HashMap<String, DeviceCfg>, // name -> device
    pub routes: Vec<IpRoute>,
}

pub(super) fn load() -> Result<NetConfig, ErrorCode> {
    // TODO: we now fail on all errors; we should try to assume
    //       reasonable defaults.
    let mut config = Ini::new();
    let map = config.load("/sys/cfg/sys-net.cfg").map_err(|err| {
        crate::moto_log!("Error loading sys-net.cfg: {:?}", err);
        ErrorCode::InvalidFilename
    })?;

    #[cfg(debug_assertions)]
    crate::moto_log!("sys-net.cfg: {:#?}", map);

    let version = map
        .get("default")
        .and_then(|d| d.get("cfg_version").and_then(|gw| gw.clone()));
    if version.is_none() || (version.unwrap() != "1") {
        crate::moto_log!("sys-net.cfg: default::cfg_version must be '1'.");
        return Err(ErrorCode::InvalidArgument);
    }

    let ipv4_gw_addr = map
        .get("default")
        .and_then(|d| d.get("ipv4_gateway_addr").and_then(|gw| gw.clone()));

    let ipv4_gw_device = map
        .get("default")
        .and_then(|d| d.get("ipv4_gateway_device").and_then(|gw| gw.clone()));

    let dev0_ipv4_cidr = map
        .get("virtio_net_0")
        .and_then(|net| net.get("ipv4_addr").and_then(|addr| addr.clone()));

    let mut net_config = NetConfig::default();

    if let Some(gw) = ipv4_gw_addr {
        if ipv4_gw_device.is_none() {
            crate::moto_log!("sys-net.cfg: default::ipv4_gateway_device missing.");
            return Err(ErrorCode::InvalidArgument);
        }
        let gw_device_name = ipv4_gw_device.unwrap();
        let gw_addr = IpAddr::parse_ascii(gw.as_bytes()).map_err(|_| ErrorCode::InvalidArgument)?;
        let ip_network = match gw_addr {
            IpAddr::V4(_) => IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(0, 0, 0, 0), 0).unwrap()),
            IpAddr::V6(_) => todo!(),
        };
        net_config.routes.push(IpRoute {
            device_name: gw_device_name,
            ip_network: ip_network,
            gateway: gw_addr,
        });
    }

    if let Some(cidr) = dev0_ipv4_cidr {
        let addr_prefix: Vec<&str> = cidr.split('/').collect();
        if addr_prefix.len() != 2 {
            crate::moto_log!("sys-net.cfg: invalid IP CIDR of virtio_net_0: '{}'", cidr);
            return Err(ErrorCode::InvalidArgument);
        }
        let dev_addr = IpAddr::parse_ascii(addr_prefix[0].as_bytes()).map_err(|_| {
            crate::moto_log!("sys-net.cfg: invalid IP CIDR of virtio_net_0: '{}'", cidr);
            ErrorCode::InvalidArgument
        })?;
        let prefix = <u8 as std::str::FromStr>::from_str(addr_prefix[1]).map_err(|_| {
            crate::moto_log!("sys-net.cfg: invalid IP CIDR of virtio_net_0: '{}'", cidr);
            ErrorCode::InvalidArgument
        })?;
        let mut device = DeviceCfg {
            name: "virtio_net_0".to_owned(),
            cidrs: vec![],
        };
        device.cidrs.push(IpCidr {
            addr: dev_addr,
            prefix,
        });
        net_config.devices.insert("virtio_net_0".to_owned(), device);
    }

    Ok(net_config)
}
