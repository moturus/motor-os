use async_fs::FileSystem;
use ipnetwork::IpNetwork;
use moto_netstack::wire::{IpCidr, IpEndpoint, Ipv4Cidr, Ipv6Cidr};
use moto_sys::ErrorCode;
use serde::{Deserialize, Deserializer, de};
use std::{
    collections::BTreeMap,
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    rc::Rc,
};

use super::backlog::{DEFAULT_MAX_BACKLOG_GLOBAL, DEFAULT_MAX_BACKLOG_PER_LISTENER};
use super::device::{DEFAULT_MAX_RST_RATE, DEFAULT_MAX_SYN_COOKIE_RATE};
use super::half_open::{DEFAULT_MAX_HALF_OPEN_GLOBAL, DEFAULT_MAX_HALF_OPEN_PER_LISTENER};
use std::num::NonZeroU32;

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
    pub auto_icmp_echo_reply: bool,
    pub loopback: bool,

    /// Half-open (SYN-RECEIVED) caps; see [`super::half_open`]. Absent keys
    /// keep the compiled-in defaults, so a config written before the caps
    /// existed still loads. `NonZeroUsize` refuses a zero while parsing: zero
    /// parks listening-pool replenishments that nothing could ever resume.
    #[serde(default = "default_max_half_open_global")]
    pub max_half_open_global: NonZeroUsize,
    #[serde(default = "default_max_half_open_per_listener")]
    pub max_half_open_per_listener: NonZeroUsize,

    /// How far a listening pool may grow under demand; see [`super::backlog`].
    /// Zero is refused for the same reason: it reads as "never grow", which is
    /// the behavior the growth exists to fix, and says so far less clearly than
    /// leaving the keys out.
    #[serde(default = "default_max_backlog_global")]
    pub max_backlog_global: NonZeroUsize,
    #[serde(default = "default_max_backlog_per_listener")]
    pub max_backlog_per_listener: NonZeroUsize,

    /// Egress rate limits, responses per second per external device, on the
    /// replies the netstack sends with no socket behind them; see
    /// [`super::device`]'s defaults for the rationale and figures. Zero is
    /// refused because it is ambiguous -- "unlimited" to one reader, "never
    /// respond" to the other -- and either intent is better written out: omit
    /// the key for the default, or set an absurdly large rate for unlimited.
    #[serde(default = "default_max_rst_rate")]
    pub max_rst_rate: NonZeroU32,
    #[serde(default = "default_max_syn_cookie_rate")]
    pub max_syn_cookie_rate: NonZeroU32,

    pub devices: BTreeMap<String, DeviceCfg>,
}

fn default_max_half_open_global() -> NonZeroUsize {
    DEFAULT_MAX_HALF_OPEN_GLOBAL
}

fn default_max_half_open_per_listener() -> NonZeroUsize {
    DEFAULT_MAX_HALF_OPEN_PER_LISTENER
}

fn default_max_backlog_global() -> NonZeroUsize {
    DEFAULT_MAX_BACKLOG_GLOBAL
}

fn default_max_backlog_per_listener() -> NonZeroUsize {
    DEFAULT_MAX_BACKLOG_PER_LISTENER
}

fn default_max_rst_rate() -> NonZeroU32 {
    DEFAULT_MAX_RST_RATE
}

fn default_max_syn_cookie_rate() -> NonZeroU32 {
    DEFAULT_MAX_SYN_COOKIE_RATE
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

/// Where the next read must stop: the end of the block `read` sits in, or the
/// end of the file, whichever comes first.
///
/// Separate from [`load`] because it is the part that can be quietly wrong.
/// `FileSystem::read` *fails* a request that crosses a block rather than
/// returning a short count, so an over-long chunk is an error and an over-short
/// one silently costs a round trip per call. Neither shows up in a config that
/// happens to fit in one block, which every config did until this was written.
fn chunk_end(read: usize, len: usize) -> usize {
    ((read / async_fs::BLOCK_SIZE + 1) * async_fs::BLOCK_SIZE).min(len)
}

/// Load net config. Note that we cannot use std::fs::*, as it will block forever.
pub(super) async fn load(
    fs: &Rc<moto_async::LocalRwLock<super::super::fs::FS>>,
) -> std::io::Result<NetConfig> {
    const CFG_PATH: &str = "/system/cfg/sys-net.toml";

    let fs_mut = fs.read().await;
    let Some((system_dir, _)) = fs_mut
        .stat(async_fs::Role::System, async_fs::ROOT_ID, "system")
        .await
        .inspect_err(|err| log::error!("Error reading {CFG_PATH}: {err:?}."))?
    else {
        log::error!("Loading net config: {CFG_PATH} not found.");
        return Err(std::io::Error::from(ErrorKind::InvalidInput));
    };
    let Some((cfg_dir, _)) = fs_mut
        .stat(async_fs::Role::System, system_dir, "cfg")
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

    // Read the whole file, and know that it is whole.
    //
    // This was one `read` into a 4096-byte array, with the returned length taken
    // as the file. Both halves of that were wrong, and both failed *silently*
    // into a parse of a prefix -- which is the bad case, because a prefix of a
    // TOML file is usually still valid TOML. A file cut after a complete
    // `[devices.netN]` table parses fine and simply has fewer devices than the
    // operator wrote. Nothing would say so.
    //
    // The array was one `async_fs::BLOCK_SIZE`, and a config is mostly
    // explanatory comments, which grow: the shipped one is already over half of
    // it.
    //
    // The loop below reads a block at a time because `FileSystem::read`'s
    // "cross-block reads may not be supported" is stronger than it sounds --
    // `MotorFs::read` *fails* such a read rather than returning a short count,
    // with `cross-block reads are not supported (yet?)`. So a caller cannot
    // discover the boundary by asking; it has to align its requests to it.
    let size = fs_mut
        .metadata(async_fs::Role::System, cfg_file)
        .await
        .inspect_err(|err| log::error!("Error reading {CFG_PATH}: {err:?}."))?
        .size;

    // A bound is still wanted, because the size comes from the filesystem and
    // this allocates it. 64 KiB is ~28 times the shipped config and far below
    // anything worth worrying about allocating.
    const MAX_CFG_SIZE: u64 = 64 * 1024;
    if size > MAX_CFG_SIZE {
        log::error!("{CFG_PATH} is {size} bytes; the limit is {MAX_CFG_SIZE}.");
        return Err(std::io::Error::from(ErrorKind::InvalidInput));
    }

    let mut buf = vec![0u8; size as usize];
    let mut read = 0usize;
    while read < buf.len() {
        let chunk = chunk_end(read, buf.len());
        let n = fs_mut
            .read(
                async_fs::Role::System,
                cfg_file,
                read as u64,
                &mut buf[read..chunk],
            )
            .await
            .inspect_err(|err| log::error!("Error reading {CFG_PATH}: {err:?}."))?;
        if n == 0 {
            // Short of the size the filesystem just reported. Refusing beats
            // parsing what did arrive, which is the silent-prefix failure this
            // loop exists to remove.
            log::error!("{CFG_PATH}: read {read} of {size} bytes before the file ended.");
            return Err(std::io::Error::from(ErrorKind::InvalidInput));
        }
        read += n;
    }

    let Ok(config_str) = str::from_utf8(&buf) else {
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

/// These ran nowhere before: they were `#[cfg(test)]`, and sys-io has no
/// reachable `cargo test`. See [`crate::self_test`].
#[cfg(debug_assertions)]
pub(crate) mod self_test {
    use super::*;
    use crate::self_test::{SelfTest, st_assert, st_assert_eq};

    pub(crate) const TESTS: &[SelfTest] = &[
        (
            "net::config::the_config_read_walks_whole_blocks",
            the_config_read_walks_whole_blocks,
        ),
        (
            "net::config::parses_echo_reply_policy",
            parses_echo_reply_policy,
        ),
        (
            "net::config::route_selection_handles_connected_and_default_routes",
            route_selection_handles_connected_and_default_routes,
        ),
        (
            "net::config::route_selection_prefers_the_longest_prefix",
            route_selection_prefers_the_longest_prefix,
        ),
        (
            "net::config::route_selection_rejects_wrong_family_and_off_link_gateway",
            route_selection_rejects_wrong_family_and_off_link_gateway,
        ),
        (
            "net::config::route_selection_includes_loopback_cidr",
            route_selection_includes_loopback_cidr,
        ),
        (
            "net::config::defaults_the_half_open_caps",
            defaults_the_half_open_caps,
        ),
        (
            "net::config::parses_the_half_open_caps",
            parses_the_half_open_caps,
        ),
        (
            "net::config::defaults_the_backlog_caps",
            defaults_the_backlog_caps,
        ),
        (
            "net::config::parses_the_backlog_caps",
            parses_the_backlog_caps,
        ),
        (
            "net::config::defaults_the_egress_rate_limits",
            defaults_the_egress_rate_limits,
        ),
        (
            "net::config::parses_the_egress_rate_limits",
            parses_the_egress_rate_limits,
        ),
    ];

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

    /// `/system/cfg/sys-net.toml` used to be read with a single `read` into a
    /// 4096-byte array -- one `async_fs::BLOCK_SIZE` -- and whatever came back
    /// was taken as the whole file. A larger config was cut at 4096 and the
    /// prefix parsed, which is the dangerous half: a prefix of a TOML file is
    /// usually still valid TOML. Reproduced with a 7715-byte config declaring a
    /// second device past the cut -- the device did not exist, and **nothing was
    /// logged at any level**; the machine booted looking healthy.
    ///
    /// The walk is what this pins. `BLOCK_SIZE` is not spelled as a literal, so
    /// the arithmetic is checked and not the constant.
    fn the_config_read_walks_whole_blocks() -> Result<(), String> {
        const B: usize = async_fs::BLOCK_SIZE;

        // A file inside one block is one read, ending at the file and not at
        // the block: asking past the end is not this function's job to allow.
        st_assert_eq!(chunk_end(0, 100), 100);
        st_assert_eq!(chunk_end(0, B), B);

        // Past one block, every read but the last ends *on* a boundary. A chunk
        // that overshot one would be refused outright -- `MotorFs::read` fails a
        // cross-block read rather than shortening it.
        st_assert_eq!(chunk_end(0, B + 1), B);
        st_assert_eq!(chunk_end(B, B + 1), B + 1);
        st_assert_eq!(chunk_end(0, 3 * B), B);
        st_assert_eq!(chunk_end(B, 3 * B), 2 * B);
        st_assert_eq!(chunk_end(2 * B, 3 * B), 3 * B);

        // And it always advances, which is what keeps `load`'s loop finite.
        for len in [1usize, B - 1, B, B + 1, 5 * B - 7] {
            let mut read = 0;
            let mut steps = 0;
            while read < len {
                let next = chunk_end(read, len);
                st_assert!(next > read);
                read = next;
                steps += 1;
                st_assert!(steps <= len / B + 2);
            }
            st_assert_eq!(read, len);
        }

        Ok(())
    }

    fn parses_echo_reply_policy() -> Result<(), String> {
        let config: NetConfig =
            toml::from_str("auto_icmp_echo_reply = true\nloopback = true\n[devices]\n").unwrap();
        st_assert!(config.auto_icmp_echo_reply);
        st_assert!(config.loopback);
        st_assert!(config.devices.is_empty());
        Ok(())
    }

    fn route_selection_handles_connected_and_default_routes() -> Result<(), String> {
        let net0 = device("192.168.4.2/24", &[("0.0.0.0/0", "192.168.4.1")]);
        let devices = [(0, &net0)];

        st_assert_eq!(
            find_route(devices.into_iter(), "192.168.4.99".parse().unwrap()),
            Some((0, "192.168.4.2".parse().unwrap()))
        );
        st_assert_eq!(
            find_route(devices.into_iter(), "1.1.1.1".parse().unwrap()),
            Some((0, "192.168.4.2".parse().unwrap()))
        );
        Ok(())
    }

    fn route_selection_prefers_the_longest_prefix() -> Result<(), String> {
        let net0 = device("192.168.4.2/24", &[("0.0.0.0/0", "192.168.4.1")]);
        let net1 = device("192.168.6.2/24", &[("203.0.113.0/24", "192.168.6.1")]);
        let devices = [(0, &net0), (1, &net1)];

        st_assert_eq!(
            find_route(devices.into_iter(), "203.0.113.7".parse().unwrap()),
            Some((1, "192.168.6.2".parse().unwrap()))
        );
        Ok(())
    }

    fn route_selection_rejects_wrong_family_and_off_link_gateway() -> Result<(), String> {
        let wrong_family = device("192.168.4.2/24", &[("::/0", "2001:db8::1")]);
        let off_link = device("192.168.4.2/24", &[("0.0.0.0/0", "10.0.0.1")]);

        st_assert_eq!(
            find_route(
                [(0, &wrong_family)].into_iter(),
                "2001:db8::7".parse().unwrap()
            ),
            None
        );
        st_assert_eq!(
            find_route([(0, &off_link)].into_iter(), "1.1.1.1".parse().unwrap()),
            None
        );
        Ok(())
    }

    fn route_selection_includes_loopback_cidr() -> Result<(), String> {
        let loopback = device("127.0.0.1/8", &[]);
        st_assert_eq!(
            find_route([(3, &loopback)].into_iter(), "127.0.0.2".parse().unwrap()),
            Some((3, "127.0.0.1".parse().unwrap()))
        );
        Ok(())
    }

    const MINIMAL: &str = "auto_icmp_echo_reply = true\nloopback = true\n";

    fn parse(config: &str) -> Result<NetConfig, String> {
        toml::from_str(&format!("{config}[devices]\n")).map_err(|err| err.to_string())
    }

    /// A config predating the caps must still load, on the defaults.
    fn defaults_the_half_open_caps() -> Result<(), String> {
        let config = parse(MINIMAL)?;
        st_assert_eq!(config.max_half_open_global, DEFAULT_MAX_HALF_OPEN_GLOBAL);
        st_assert_eq!(
            config.max_half_open_per_listener,
            DEFAULT_MAX_HALF_OPEN_PER_LISTENER
        );
        Ok(())
    }

    fn parses_the_half_open_caps() -> Result<(), String> {
        let config = parse(&format!(
            "{MINIMAL}max_half_open_global = 64\nmax_half_open_per_listener = 8\n"
        ))?;
        st_assert_eq!(config.max_half_open_global.get(), 64);
        st_assert_eq!(config.max_half_open_per_listener.get(), 8);

        // Zero must be refused here rather than reach the budget, where it
        // would hold the listening pool closed for the life of the process.
        st_assert!(parse(&format!("{MINIMAL}max_half_open_global = 0\n")).is_err());
        st_assert!(parse(&format!("{MINIMAL}max_half_open_per_listener = 0\n")).is_err());
        Ok(())
    }

    fn defaults_the_backlog_caps() -> Result<(), String> {
        let config = parse(MINIMAL)?;
        st_assert_eq!(config.max_backlog_global, DEFAULT_MAX_BACKLOG_GLOBAL);
        st_assert_eq!(
            config.max_backlog_per_listener,
            DEFAULT_MAX_BACKLOG_PER_LISTENER
        );
        Ok(())
    }

    fn parses_the_backlog_caps() -> Result<(), String> {
        let config = parse(&format!(
            "{MINIMAL}max_backlog_global = 16\nmax_backlog_per_listener = 8\n"
        ))?;
        st_assert_eq!(config.max_backlog_global.get(), 16);
        st_assert_eq!(config.max_backlog_per_listener.get(), 8);

        st_assert!(parse(&format!("{MINIMAL}max_backlog_global = 0\n")).is_err());
        st_assert!(parse(&format!("{MINIMAL}max_backlog_per_listener = 0\n")).is_err());
        Ok(())
    }

    fn defaults_the_egress_rate_limits() -> Result<(), String> {
        let config = parse(MINIMAL)?;
        st_assert_eq!(config.max_rst_rate, DEFAULT_MAX_RST_RATE);
        st_assert_eq!(config.max_syn_cookie_rate, DEFAULT_MAX_SYN_COOKIE_RATE);
        Ok(())
    }

    fn parses_the_egress_rate_limits() -> Result<(), String> {
        let config = parse(&format!(
            "{MINIMAL}max_rst_rate = 50\nmax_syn_cookie_rate = 4000\n"
        ))?;
        st_assert_eq!(config.max_rst_rate.get(), 50);
        st_assert_eq!(config.max_syn_cookie_rate.get(), 4000);

        // Zero is refused at the parse: "unlimited" and "never respond" are
        // different intents and neither should reach a device as a limit.
        st_assert!(parse(&format!("{MINIMAL}max_rst_rate = 0\n")).is_err());
        st_assert!(parse(&format!("{MINIMAL}max_syn_cookie_rate = 0\n")).is_err());
        Ok(())
    }
}
