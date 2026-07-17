use async_fs::FileSystem;
use ipnetwork::IpNetwork;
use moto_sys::ErrorCode;
use serde::{Deserialize, Deserializer, de};
use smoltcp::wire::{IpCidr, IpEndpoint, Ipv4Cidr, Ipv6Cidr};
use std::{
    collections::BTreeMap,
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    rc::Rc,
};

#[derive(Clone)]
pub(super) struct MacAddress([u8; 6]);

impl MacAddress {
    pub fn raw(&self) -> [u8; 6] {
        self.0
    }
}

impl std::fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "\"{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\"",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

fn ox_char_to_byte(b: u8) -> Result<u8, String> {
    if b.is_ascii_digit() {
        return Ok(b - b'0');
    }
    if (b'a'..=b'f').contains(&b) {
        return Ok(b - b'a' + 10);
    }
    if (b'A'..=b'F').contains(&b) {
        return Ok(b - b'A' + 10);
    }

    Err("Failed to parse MAC.".to_owned())
}

impl std::str::FromStr for MacAddress {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let maybe_bytes: Vec<&str> = s.split(':').collect();
        if maybe_bytes.len() != 6 {
            return Err(format!("Failed to parse MAC: {s}."));
        }

        let mut mac = [0_u8; 6];
        for idx in 0..6 {
            let maybe_byte = maybe_bytes[idx].as_bytes();
            if maybe_byte.len() != 2 {
                return Err(format!("Failed to parse MAC: {s}."));
            }

            let b0 = ox_char_to_byte(maybe_byte[0])?;
            let b1 = ox_char_to_byte(maybe_byte[1])?;
            mac[idx] = (b0 << 4) + b1;
        }

        Ok(MacAddress(mac))
    }
}

impl<'de> Deserialize<'de> for MacAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        std::str::FromStr::from_str(&s).map_err(de::Error::custom)
    }
}

#[derive(Clone, Deserialize, Debug)]
pub(super) struct IpRoute {
    pub ip_network: IpNetwork,
    pub gateway: IpAddr,
}

#[derive(Clone, Deserialize, Debug)]
pub(super) struct DeviceCfg {
    pub mac: MacAddress,
    pub cidrs: Vec<IpNetwork>,
    pub routes: Vec<IpRoute>,
}

impl DeviceCfg {
    pub fn new(mac: &str) -> Self {
        use std::str::FromStr;
        Self {
            mac: MacAddress::from_str(mac).unwrap(),
            cidrs: vec![],
            routes: vec![],
        }
    }
}

#[derive(Deserialize, Debug)]
pub(super) struct NetConfig {
    pub loopback: bool,
    pub devices: BTreeMap<String, DeviceCfg>,
}

fn same_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

/// Select an active device and source address for `dst`.
///
/// Directly connected networks and configured routes compete by prefix length.
/// A configured gateway must itself be reachable through one of the device's
/// directly connected CIDRs.
pub(super) fn find_route<'a>(
    devices: impl Iterator<Item = (usize, &'a DeviceCfg)>,
    dst: IpAddr,
) -> Option<(usize, IpAddr)> {
    let mut best: Option<(u8, bool, usize, IpAddr)> = None;

    let mut consider = |prefix: u8, direct: bool, device_idx: usize, source: IpAddr| {
        let replace = best.is_none_or(|(best_prefix, best_direct, _, _)| {
            prefix > best_prefix || (prefix == best_prefix && direct && !best_direct)
        });
        if replace {
            best = Some((prefix, direct, device_idx, source));
        }
    };

    for (device_idx, device) in devices {
        for cidr in &device.cidrs {
            if same_family(cidr.ip(), dst) && cidr.contains(dst) {
                consider(cidr.prefix(), true, device_idx, cidr.ip());
            }
        }

        for route in &device.routes {
            if !same_family(route.ip_network.ip(), dst) || !route.ip_network.contains(dst) {
                continue;
            }
            if route.gateway.is_unspecified() || !same_family(route.gateway, dst) {
                continue;
            }

            let source = device
                .cidrs
                .iter()
                .filter(|cidr| same_family(cidr.ip(), dst) && cidr.contains(route.gateway))
                .max_by_key(|cidr| cidr.prefix())
                .map(IpNetwork::ip);

            if let Some(source) = source {
                consider(route.ip_network.prefix(), false, device_idx, source);
            }
        }
    }

    best.map(|(_, _, device_idx, source)| (device_idx, source))
}

/// Load net config. Note that we cannot use std::fs::*, as it will block forever.
pub(super) async fn load(
    fs: &Rc<moto_async::LocalRwLock<super::super::fs::FS>>,
) -> std::io::Result<NetConfig> {
    const CFG_PATH: &str = "/sys/cfg/sys-net.toml";

    let fs_mut = fs.read().await;
    let Some((sys_dir, _)) = fs_mut
        .stat(async_fs::Role::System, async_fs::ROOT_ID, "sys")
        .await
        .inspect_err(|err| log::error!("Error reading {CFG_PATH}: {err:?}."))?
    else {
        log::error!("Loading net config: {CFG_PATH} not found.");
        return Err(std::io::Error::from(ErrorKind::InvalidInput));
    };
    let Some((cfg_dir, _)) = fs_mut
        .stat(async_fs::Role::System, sys_dir, "cfg")
        .await
        .inspect_err(|err| log::error!("Error reading {CFG_PATH}: {err:?}."))?
    else {
        log::error!("Loading net config: {CFG_PATH} not found.");
        return Err(std::io::Error::from(ErrorKind::InvalidInput));
    };
    let Some((cfg_file, _)) = fs_mut
        .stat(async_fs::Role::System, cfg_dir, "sys-net.toml")
        .await
        .inspect_err(|err| log::error!("Error reading {CFG_PATH}: {err:?}."))?
    else {
        log::error!("Loading net config: {CFG_PATH} not found.");
        return Err(std::io::Error::from(ErrorKind::InvalidInput));
    };

    let mut buf = [0; 4096];
    let sz = fs_mut
        .read(async_fs::Role::System, cfg_file, 0, &mut buf)
        .await
        .inspect_err(|err| log::error!("Error reading {CFG_PATH}: {err:?}."))?;
    let bytes = &buf[..sz];

    let Ok(config_str) = str::from_utf8(bytes) else {
        log::error!("{}:{} error reading {}.", file!(), line!(), CFG_PATH);
        return Err(std::io::Error::from(ErrorKind::InvalidInput));
    };

    toml::from_str::<NetConfig>(config_str).map_err(|err| {
        log::error!(
            "{}:{} error parsing {}: {:#?}.",
            file!(),
            line!(),
            CFG_PATH,
            err
        );
        std::io::Error::from(ErrorKind::InvalidInput)
    })
}

pub(super) fn socket_addr_from_endpoint(endpoint: IpEndpoint) -> SocketAddr {
    let addr: IpAddr = endpoint.addr.into();
    SocketAddr::new(addr, endpoint.port)
}

pub(super) fn ip_network_to_cidr(ip_network: &IpNetwork) -> IpCidr {
    match ip_network {
        IpNetwork::V4(network) => IpCidr::Ipv4(Ipv4Cidr::new(network.ip(), network.prefix())),
        IpNetwork::V6(network) => IpCidr::Ipv6(Ipv6Cidr::new(network.ip(), network.prefix())),
    }
}

fn addr_to_octets(addr: std::net::IpAddr) -> [u8; 16] {
    match addr {
        IpAddr::V4(addr) => {
            // Map IPv4 to IPv6.
            let mut octets = [0_u8; 16];
            let octets_4 = addr.octets();
            octets[10] = 255;
            octets[11] = 255;
            octets[12] = octets_4[0];
            octets[13] = octets_4[1];
            octets[14] = octets_4[2];
            octets[15] = octets_4[3];
            octets
        }
        IpAddr::V6(addr) => addr.octets(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(cidr: &str, routes: &[(&str, &str)]) -> DeviceCfg {
        let mut device = DeviceCfg::new("02:00:00:00:00:01");
        device.cidrs.push(cidr.parse().unwrap());
        for (network, gateway) in routes {
            device.routes.push(IpRoute {
                ip_network: network.parse().unwrap(),
                gateway: gateway.parse().unwrap(),
            });
        }
        device
    }

    #[test]
    fn route_selection_handles_connected_and_default_routes() {
        let net0 = device("192.168.4.2/24", &[("0.0.0.0/0", "192.168.4.1")]);
        let devices = [(0, &net0)];

        assert_eq!(
            find_route(devices.into_iter(), "192.168.4.99".parse().unwrap()),
            Some((0, "192.168.4.2".parse().unwrap()))
        );
        assert_eq!(
            find_route(devices.into_iter(), "1.1.1.1".parse().unwrap()),
            Some((0, "192.168.4.2".parse().unwrap()))
        );
    }

    #[test]
    fn route_selection_prefers_the_longest_prefix() {
        let net0 = device("192.168.4.2/24", &[("0.0.0.0/0", "192.168.4.1")]);
        let net1 = device("192.168.6.2/24", &[("203.0.113.0/24", "192.168.6.1")]);
        let devices = [(0, &net0), (1, &net1)];

        assert_eq!(
            find_route(devices.into_iter(), "203.0.113.7".parse().unwrap()),
            Some((1, "192.168.6.2".parse().unwrap()))
        );
    }

    #[test]
    fn route_selection_rejects_wrong_family_and_off_link_gateway() {
        let wrong_family = device("192.168.4.2/24", &[("::/0", "2001:db8::1")]);
        let off_link = device("192.168.4.2/24", &[("0.0.0.0/0", "10.0.0.1")]);

        assert_eq!(
            find_route(
                [(0, &wrong_family)].into_iter(),
                "2001:db8::7".parse().unwrap()
            ),
            None
        );
        assert_eq!(
            find_route([(0, &off_link)].into_iter(), "1.1.1.1".parse().unwrap()),
            None
        );
    }

    #[test]
    fn route_selection_includes_loopback_cidr() {
        let loopback = device("127.0.0.1/8", &[]);
        assert_eq!(
            find_route([(3, &loopback)].into_iter(), "127.0.0.2".parse().unwrap()),
            Some((3, "127.0.0.1".parse().unwrap()))
        );
    }
}
