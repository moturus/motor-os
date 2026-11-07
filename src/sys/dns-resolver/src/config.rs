use std::collections::BTreeMap;
use std::io::{self, Read};
use std::net::IpAddr;

use serde::Deserialize;

const CONFIG_PATH: &str = "/system/cfg/sys-net.toml";
const DHCP_PATH: &str = "/system/tmp/sys-io/dhcp.toml";
const MAX_CONFIG_BYTES: usize = 64 * 1024;
const MAX_NAMESERVERS: usize = 2;

// Read only the resolver's part of the network configuration. sys-io owns
// validation and installation of addresses, routes, and network limits.
#[derive(Deserialize)]
pub(super) struct Config {
    devices: BTreeMap<String, Device>,
}

#[derive(Deserialize)]
struct Device {
    #[serde(default)]
    dhcp: bool,
    #[serde(default)]
    dns_servers: Vec<IpAddr>,
}

#[derive(Deserialize)]
struct Snapshot {
    active_devices: Vec<String>,
    devices: BTreeMap<String, DhcpDevice>,
}

#[derive(Deserialize)]
struct DhcpDevice {
    lease: Option<Lease>,
}

#[derive(Deserialize)]
struct Lease {
    dns_servers: Vec<IpAddr>,
    expires_at_unix_ms: i64,
}

impl Config {
    fn parse(contents: &str) -> io::Result<Self> {
        let config: Self = toml::from_str(contents).map_err(io::Error::other)?;
        if config
            .devices
            .values()
            .any(|device| device.dhcp && !device.dns_servers.is_empty())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DHCP and static DNS servers cannot be combined on one device",
            ));
        }
        Ok(config)
    }

    fn nameservers(&self, snapshot: &Snapshot, now: i64) -> Vec<IpAddr> {
        let mut servers = Vec::new();
        // Match sys-io's configuration-name order, then each device's list.
        for (name, device) in &self.devices {
            if !snapshot.active_devices.contains(name) {
                continue;
            }
            let candidates = if device.dhcp {
                snapshot
                    .devices
                    .get(name)
                    .and_then(|device| device.lease.as_ref())
                    .filter(|lease| lease.expires_at_unix_ms > now)
                    .map_or(&[][..], |lease| lease.dns_servers.as_slice())
            } else {
                &device.dns_servers
            };
            for &server in candidates {
                // The compatibility listener must never forward to itself.
                if !server.is_unspecified()
                    && server.to_canonical() != IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                    && !servers.contains(&server)
                {
                    servers.push(server);
                    if servers.len() == MAX_NAMESERVERS {
                        return servers;
                    }
                }
            }
        }
        servers
    }
}

fn read(path: &str, max_bytes: usize) -> io::Result<String> {
    let mut contents = String::new();
    std::fs::File::open(path)?
        .take((max_bytes + 1) as u64)
        .read_to_string(&mut contents)?;
    if contents.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "network configuration exceeds its size limit",
        ));
    }
    Ok(contents)
}

pub(super) fn nameservers() -> io::Result<Vec<IpAddr>> {
    let config = Config::parse(&read(CONFIG_PATH, MAX_CONFIG_BYTES)?)?;
    // Lease metadata can be larger than the input configuration that names NICs.
    let snapshot: Snapshot =
        toml::from_str(&read(DHCP_PATH, 1024 * 1024)?).map_err(io::Error::other)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis();
    Ok(config.nameservers(&snapshot, now.try_into().map_err(io::Error::other)?))
}

pub(super) fn self_test() {
    let snapshot: Snapshot =
        toml::from_str("active_devices = ['a', 'z', 'net0']\n[devices]").unwrap();
    let config = Config::parse(
        r#"
        loopback = true
        auto_icmp_echo_reply = true
        [devices.z]
        dns_servers = ["203.0.113.53"]
        [devices.a]
        cidrs = ["192.0.2.1/24"]
        routes = [{ ip_network = "0.0.0.0/0", gateway = "192.0.2.2" }]
        dns_servers = ["0.0.0.0", "::", "192.0.2.53", "192.0.2.53", "2001:db8::53"]
        "#,
    )
    .unwrap();
    assert_eq!(
        config.nameservers(&snapshot, 0),
        [
            "192.0.2.53".parse::<IpAddr>().unwrap(),
            "2001:db8::53".parse::<IpAddr>().unwrap(),
        ]
    );
    for contents in ["[devices]", "[devices.net0]", "[devices.net0]\ndhcp = true"] {
        assert!(Config::parse(contents)
            .unwrap()
            .nameservers(&snapshot, 0)
            .is_empty());
    }
    for contents in [
        "not toml",
        "dns_servers = ['192.0.2.53']",
        "[devices.net0]\ndns_servers = '192.0.2.53'",
        "[devices.net0]\ndns_servers = ['not an address']",
        "[devices.net0]\ndhcp = true\ndns_servers = ['192.0.2.53']",
    ] {
        assert!(Config::parse(contents).is_err(), "accepted {contents}");
    }
    let config =
        Config::parse("[devices.a]\ndhcp = true\n[devices.z]\ndns_servers = ['203.0.113.53']")
            .unwrap();
    let mut snapshot: Snapshot = toml::from_str(
        "active_devices = ['a', 'z']\n[devices.a.lease]\ndns_servers = ['192.0.2.53']\nexpires_at_unix_ms = 1000",
    ).unwrap();
    let static_server: IpAddr = "203.0.113.53".parse().unwrap();
    assert_eq!(
        config.nameservers(&snapshot, 999),
        ["192.0.2.53".parse().unwrap(), static_server]
    );
    assert_eq!(config.nameservers(&snapshot, 1000), [static_server]);
    snapshot
        .devices
        .get_mut("a")
        .unwrap()
        .lease
        .as_mut()
        .unwrap()
        .expires_at_unix_ms = 2000;
    assert_eq!(config.nameservers(&snapshot, 1000).len(), 2);
    snapshot.devices.get_mut("a").unwrap().lease = None;
    assert_eq!(config.nameservers(&snapshot, 1000), [static_server]);
    snapshot.active_devices.clear();
    assert!(config.nameservers(&snapshot, 0).is_empty());
    let self_forward =
        Config::parse("[devices.a]\ndns_servers = ['127.0.0.1', '::ffff:127.0.0.1']").unwrap();
    snapshot.active_devices.push("a".into());
    assert!(self_forward.nameservers(&snapshot, 0).is_empty());
}
