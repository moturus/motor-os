use std::{collections::BTreeMap, net::IpAddr};

use ipnetwork::IpNetwork;
use moto_sys::ErrorCode;
use serde::{de, Deserialize, Deserializer};

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
    if b >= b'0' && b <= b'9' {
        return Ok(b - b'0');
    }
    if b >= b'a' && b <= b'f' {
        return Ok(b - b'a' + 10);
    }
    if b >= b'A' && b <= b'F' {
        return Ok(b - b'A' + 10);
    }

    Err("Failed to parse MAC.".to_owned())
}

impl std::str::FromStr for MacAddress {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let maybe_bytes: Vec<&str> = s.split(':').collect();
        if maybe_bytes.len() != 6 {
            return Err(format!("Failed to parse MAC: {}.", s));
        }

        let mut mac = [0_u8; 6];
        for idx in 0..6 {
            let maybe_byte = maybe_bytes[idx].as_bytes();
            if maybe_byte.len() != 2 {
                return Err(format!("Failed to parse MAC: {}.", s));
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
    #[allow(unused)]
    pub loopback: bool,
    pub devices: BTreeMap<String, DeviceCfg>,
}

pub(super) fn load() -> Result<NetConfig, ErrorCode> {
    const CFG_PATH: &str = "/sys/cfg/sys-net.toml";
    let config_str = if let Ok(s) = std::fs::read_to_string(CFG_PATH) {
        s
    } else {
        log::error!("{}:{} error reading {}.", file!(), line!(), CFG_PATH);
        return Err(ErrorCode::InvalidArgument);
    };

    toml::from_str::<NetConfig>(config_str.as_str()).map_err(|err| {
        log::error!(
            "{}:{} error parsing {}: {:#?}.",
            file!(),
            line!(),
            CFG_PATH,
            err
        );
        ErrorCode::InvalidArgument
    })
}

// Find the device name and the local IP address to route to dst.
impl NetConfig {
    pub(super) fn find_route(&self, dst: &IpAddr) -> Option<(String, IpAddr)> {
        for (dev_name, dev_cfg) in &self.devices {
            for route in &dev_cfg.routes {
                if route.ip_network.contains(*dst) {
                    for cidr in &dev_cfg.cidrs {
                        if cidr.contains(*dst) && route.ip_network.contains(cidr.ip()) {
                            return Some((dev_name.to_owned(), cidr.ip()));
                        }
                    }
                }
            }
        }

        None
    }
}
