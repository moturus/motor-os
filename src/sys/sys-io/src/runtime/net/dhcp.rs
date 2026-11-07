//! A snapshot of current boot-interface state, published outside the root FS.
use serde::Serialize;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

#[derive(Clone, Debug, Serialize)]
pub(super) struct Lease {
    pub address: String,
    pub router: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub server_address: Ipv4Addr,
    pub server_identifier: Ipv4Addr,
    pub acquired_at_unix_ms: i64,
    pub renew_at_unix_ms: i64,
    pub rebind_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}

#[derive(Serialize)]
struct Device<'a> {
    lease: Option<&'a Lease>,
}

#[derive(Serialize)]
struct Snapshot<'a> {
    active_devices: Vec<&'a str>,
    devices: BTreeMap<&'a str, Device<'a>>,
}

pub(super) fn snapshot(devices: &super::devices::Devices) -> std::io::Result<String> {
    let snapshot = Snapshot {
        active_devices: devices.iter().map(|(_, device)| device.name()).collect(),
        devices: devices
            .iter()
            .filter(|(_, device)| device.config().dhcp)
            .map(|(_, device)| {
                (
                    device.name(),
                    Device {
                        lease: device.dhcp_details.as_ref(),
                    },
                )
            })
            .collect(),
    };
    toml::to_string(&snapshot).map_err(std::io::Error::other)
}

#[cfg(debug_assertions)]
pub(super) const TESTS: &[crate::self_test::SelfTest] = &[("net::dhcp::snapshot", self_test)];

#[cfg(debug_assertions)]
fn self_test() -> Result<(), String> {
    use crate::self_test::{st_assert, st_assert_eq};
    let mut lease = Lease {
        address: "192.0.2.10/24".into(),
        router: Some("192.0.2.1".parse().unwrap()),
        dns_servers: vec!["192.0.2.53".parse().unwrap()],
        server_address: "192.0.2.2".parse().unwrap(),
        server_identifier: "192.0.2.3".parse().unwrap(),
        acquired_at_unix_ms: 100,
        renew_at_unix_ms: 500,
        rebind_at_unix_ms: 875,
        expires_at_unix_ms: 1000,
    };
    // TOML encoding must preserve arbitrary configuration names without
    // interpreting dots or quotes as extra tables or fields.
    let name = "net.\"0";
    for generation in 0..3 {
        if generation == 1 {
            lease.expires_at_unix_ms = 2000;
        }
        let snapshot = Snapshot {
            active_devices: vec![name],
            devices: [(
                name,
                Device {
                    lease: (generation != 2).then_some(&lease),
                },
            )]
            .into(),
        };
        let text = toml::to_string(&snapshot).map_err(|error| error.to_string())?;
        let value: toml::Value = toml::from_str(&text).map_err(|error| error.to_string())?;
        st_assert_eq!(value["active_devices"][0].as_str(), Some(name));
        let device = &value["devices"][name];
        if generation == 2 {
            st_assert!(device.get("lease").is_none());
        } else {
            let state = &device["lease"];
            st_assert_eq!(state["address"].as_str(), Some("192.0.2.10/24"));
            st_assert_eq!(state["server_identifier"].as_str(), Some("192.0.2.3"));
            st_assert_eq!(state["dns_servers"][0].as_str(), Some("192.0.2.53"));
            st_assert_eq!(
                state["expires_at_unix_ms"].as_integer(),
                Some(lease.expires_at_unix_ms)
            );
        }
    }
    Ok(())
}
