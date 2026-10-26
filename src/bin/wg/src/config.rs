//! Bounded configuration with errors that never quote secret input.
use base64::{Engine, engine::general_purpose::STANDARD};
use ipnetwork::IpNetwork;
use serde::Deserialize;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

pub const MAX_FILE_BYTES: usize = 64 * 1024;
pub const MAX_PEERS: usize = 16;
pub const MAX_PREFIXES: usize = 128;
pub const MAX_ADDRESSES: usize = 16;
pub const MAX_NAME_BYTES: usize = 31;

pub type Result<T> = std::result::Result<T, &'static str>;

// Deliberately no Debug: a config contains the private key and optional PSKs.
pub struct Config {
    pub name: String,
    pub private_key: [u8; 32],
    pub transport_addresses: Vec<IpAddr>,
    pub listen_port: u16,
    pub cidrs: Vec<IpNetwork>,
    pub peers: Vec<Peer>,
}

pub struct Peer {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpNetwork>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    transport_addresses: Vec<IpAddr>,
    listen_port: u16,
    cidrs: Vec<IpNetwork>,
    peers: Vec<RawPeer>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPeer {
    public_key: String,
    preshared_key: Option<String>,
    endpoint: Option<String>,
    allowed_ips: Vec<IpNetwork>,
    persistent_keepalive: Option<u16>,
}

fn key(encoded: &str) -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    if STANDARD.decode_slice(encoded.trim(), &mut bytes) != Ok(bytes.len()) {
        return Err("keys must be base64 values encoding exactly 32 bytes");
    }
    Ok(bytes)
}

fn unicast(address: IpAddr) -> bool {
    !address.is_unspecified()
        && !address.is_multicast()
        && !matches!(address, IpAddr::V4(address) if address.is_broadcast())
}

impl Config {
    pub fn parse(name: &str, text: &str, private_key: &str) -> Result<Self> {
        if name.is_empty()
            || name.len() > MAX_NAME_BYTES
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        {
            return Err("invalid device name in config filename");
        }
        if text.len() > MAX_FILE_BYTES || private_key.len() > MAX_FILE_BYTES {
            return Err("config and key files are limited to 64 KiB each");
        }
        let raw: RawConfig =
            toml::from_str(text).map_err(|_| "invalid WireGuard TOML configuration")?;
        if raw.listen_port == 0 {
            return Err("listen_port must be nonzero");
        }
        if raw.transport_addresses.is_empty() || raw.transport_addresses.len() > 2 {
            return Err("configure one physical transport address per enabled IP family");
        }
        let mut families = HashSet::new();
        for address in &raw.transport_addresses {
            if !unicast(*address) || !families.insert(address.is_ipv4()) {
                return Err("transport addresses must be unicast and have distinct families");
            }
        }
        if raw.cidrs.is_empty() || raw.cidrs.len() > MAX_ADDRESSES {
            return Err("configure between 1 and 16 tunnel addresses");
        }
        let mut addresses = HashSet::new();
        for cidr in &raw.cidrs {
            if !unicast(cidr.ip()) || !addresses.insert(cidr.ip()) {
                return Err("tunnel addresses must be unique unicast addresses");
            }
        }
        if raw.peers.is_empty() || raw.peers.len() > MAX_PEERS {
            return Err("configure between 1 and 16 peers");
        }
        let mut keys = HashSet::new();
        let mut prefixes = HashSet::new();
        let mut peers = Vec::with_capacity(raw.peers.len());
        for raw_peer in raw.peers {
            let public_key = key(&raw_peer.public_key)?;
            if !keys.insert(public_key) {
                return Err("duplicate peer public key");
            }
            let endpoint = raw_peer
                .endpoint
                .as_deref()
                .map(|text| {
                    if text.contains('%') {
                        return Err("endpoint scope IDs are unsupported");
                    }
                    let address: SocketAddr = text
                        .parse()
                        .map_err(|_| "endpoint must be a numeric IP address and port")?;
                    if address.port() == 0 || !unicast(address.ip()) {
                        return Err("endpoint must be unicast with a nonzero port");
                    }
                    if !families.contains(&address.is_ipv4()) {
                        return Err("endpoint family has no configured physical transport");
                    }
                    Ok(address)
                })
                .transpose()?;
            if raw_peer.allowed_ips.is_empty() {
                return Err("each peer requires allowed_ips");
            }
            let mut allowed_ips = Vec::with_capacity(raw_peer.allowed_ips.len());
            for cidr in raw_peer.allowed_ips {
                let prefix = IpNetwork::new(cidr.network(), cidr.prefix()).unwrap();
                if !addresses
                    .iter()
                    .any(|address| address.is_ipv4() == prefix.is_ipv4())
                {
                    return Err("allowed_ips family has no local tunnel address");
                }
                if !prefixes.insert(prefix) {
                    return Err("duplicate allowed_ips prefix");
                }
                if prefixes.len() > MAX_PREFIXES {
                    return Err("allowed_ips is limited to 128 prefixes in total");
                }
                allowed_ips.push(prefix);
            }
            peers.push(Peer {
                public_key,
                preshared_key: raw_peer.preshared_key.as_deref().map(key).transpose()?,
                endpoint,
                allowed_ips,
                persistent_keepalive: raw_peer
                    .persistent_keepalive
                    .filter(|seconds| *seconds != 0),
            });
        }
        Ok(Self {
            name: name.to_owned(),
            private_key: key(private_key)?,
            transport_addresses: raw.transport_addresses,
            listen_port: raw.listen_port,
            cidrs: raw.cidrs,
            peers,
        })
    }
}
