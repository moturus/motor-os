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
#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    pub name: String,
    pub private_key: [u8; 32],
    pub transport_addresses: Vec<IpAddr>,
    pub listen_port: u16,
    pub cidrs: Vec<IpNetwork>,
    pub peers: Vec<Peer>,
}

#[derive(Clone, PartialEq, Eq)]
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
    name: String,
    private_key: String,
    public_key: Option<String>,
    transport_addresses: Vec<IpAddr>,
    listen_port: u16,
    cidrs: Vec<IpNetwork>,
    #[serde(default)]
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

pub fn key(encoded: &str) -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    if STANDARD.decode_slice(encoded.trim(), &mut bytes) != Ok(bytes.len()) {
        return Err("keys must be base64 values encoding exactly 32 bytes");
    }
    Ok(bytes)
}

pub fn unicast(address: IpAddr) -> bool {
    !address.is_unspecified()
        && !address.is_multicast()
        && !matches!(address, IpAddr::V4(address) if address.is_broadcast())
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        if path.extension().and_then(|value| value.to_str()) != Some("toml") {
            return Err("configuration filename must end in .toml");
        }
        let text = crate::files::read(path)?;
        Self::parse(&text)
    }

    pub fn public_key(&self) -> [u8; 32] {
        public_key(self.private_key)
    }

    pub fn parse(text: &str) -> Result<Self> {
        if text.len() > MAX_FILE_BYTES {
            return Err("configuration is limited to 64 KiB");
        }
        let raw: RawConfig =
            toml::from_str(text).map_err(|_| "invalid WireGuard TOML configuration")?;
        validate_name(&raw.name)?;
        let private_key = key(&raw.private_key)?;
        let own_key = public_key(private_key);
        if raw
            .public_key
            .as_deref()
            .map(key)
            .transpose()?
            .is_some_and(|key| key != own_key)
        {
            return Err("public_key does not match private_key");
        }
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
        if raw.peers.len() > MAX_PEERS {
            return Err("configure at most 16 peers");
        }
        let mut keys = HashSet::new();
        let mut prefixes = HashSet::new();
        let mut peers = Vec::with_capacity(raw.peers.len());
        for raw_peer in raw.peers {
            let public_key = key(&raw_peer.public_key)?;
            if public_key == own_key {
                return Err("peer public key is the interface's own key");
            }
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
            name: raw.name,
            private_key,
            transport_addresses: raw.transport_addresses,
            listen_port: raw.listen_port,
            cidrs: raw.cidrs,
            peers,
        })
    }
}

pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > MAX_NAME_BYTES
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
    {
        return Err("interface name must be 1–31 ASCII letters, digits, underscores or hyphens");
    }
    Ok(())
}

pub fn public_key(private: [u8; 32]) -> [u8; 32] {
    use boringtun::x25519::{PublicKey, StaticSecret};
    PublicKey::from(&StaticSecret::from(private)).to_bytes()
}
