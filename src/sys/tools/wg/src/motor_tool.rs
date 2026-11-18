//! Interactive configuration and sequential management of native daemons.
use crate::config::{self, Config, Peer};
use crate::control::{self, Interface};
use crate::motor_files::{self as files, CONFIG_DIR, Destination};
use crate::motor_ipc::{self as ipc, Connection};
use crate::prompt::{self, Prompt};
use crate::tool::{self, Command};
use base64::{Engine, engine::general_purpose::STANDARD};
use ipnetwork::IpNetwork;
use moto_sdk::rt::time::Instant;
use moto_sdk::sys::caps;
use std::collections::HashSet;
use std::io::{IsTerminal, Read, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::Path;

pub struct Error {
    pub code: i32,
    pub message: String,
}
impl From<&str> for Error {
    fn from(message: &str) -> Self {
        Self {
            code: 1,
            message: message.into(),
        }
    }
}
impl From<String> for Error {
    fn from(message: String) -> Self {
        Self { code: 1, message }
    }
}
impl From<prompt::Error> for Error {
    fn from(error: prompt::Error) -> Self {
        match error {
            prompt::Error::Cancelled => Self {
                code: 130,
                message: "cancelled".into(),
            },
            prompt::Error::Invalid(message) => message.into(),
            prompt::Error::Io => "prompt I/O failed".into(),
        }
    }
}
type Result<T> = std::result::Result<T, Error>;

fn pids(deadline: Instant) -> Result<Vec<u64>> {
    let mut service = moto_sdk::sys_io::stats::IoStatsService::connect()
        .map_err(|_| "cannot connect to sys-io discovery")?;
    service
        .list_external_net_device_pids(Some(deadline))
        .map_err(|_| "external device discovery failed".into())
}

fn open(pid: u64) -> Result<Option<Connection>> {
    Connection::open(&format!("wg-control-{pid}"), pid)
        .map(|opened| opened.map(|(connection, _)| connection))
        .map_err(Error::from)
}

fn interface(connection: &mut Connection, deadline: Instant) -> config::Result<Interface> {
    Interface::decode(&connection.rpc(control::GET_INTERFACE, &[], deadline)?)
}

struct LiveInterface {
    pid: u64,
    interface: Interface,
    peers: Vec<control::Peer>,
}

fn live(peers: bool) -> Result<(Vec<LiveInterface>, Vec<String>)> {
    let deadline = ipc::deadline();
    let mut found = Vec::new();
    let mut errors = Vec::new();
    for pid in pids(deadline)? {
        let result = (|| -> Result<_> {
            let Some(mut connection) = open(pid)? else {
                return Ok(None);
            };
            let interface = interface(&mut connection, deadline)?;
            let mut rows = Vec::new();
            if peers {
                for index in 0..interface.peer_count {
                    rows.push(control::Peer::decode(&connection.rpc(
                        control::GET_PEER,
                        &(index as u16).to_le_bytes(),
                        deadline,
                    )?)?);
                }
            }
            Ok(Some(LiveInterface {
                pid,
                interface,
                peers: rows,
            }))
        })();
        match result {
            Ok(Some(value)) => found.push(value),
            Ok(None) => (),
            Err(error) => errors.push(format!("pid={pid}: {}", error.message)),
        }
    }
    found.sort_by(|a, b| a.interface.name.cmp(&b.interface.name));
    Ok((found, errors))
}

pub fn execute(args: &[String]) -> Result<()> {
    let caps = ipc::require_interactive()?;
    let command = tool::parse(args).map_err(|message| Error {
        code: 2,
        message: message.into(),
    })?;
    let required = match command {
        Command::Help(_) => 0,
        Command::AddPeer(_) => caps::CAP_FS_WRITE,
        Command::New => caps::CAP_FS_WRITE | caps::CAP_NET,
        _ => caps::CAP_NET,
    };
    ipc::require(caps, required)?;
    let stdin = std::io::stdin();
    let mut prompt = Prompt::new(stdin.lock(), std::io::stderr().lock(), stdin.is_terminal());
    match command {
        Command::Help(help) => println!("{help}"),
        Command::New => new(&mut prompt)?,
        Command::AddPeer(path) => add_peer(&mut prompt, path.as_deref())?,
        Command::Up(path) => {
            let (pid, interface) = crate::launch::up(&path)?;
            println!(
                "{}: up (pid={pid}, peers={})",
                interface.name, interface.peer_count
            );
        }
        Command::Down(name) => down(&name)?,
        Command::Status => {
            let (found, errors) = live(true)?;
            if found.is_empty() && errors.is_empty() {
                println!("No WireGuard interfaces are running.");
            }
            for entry in found {
                print!(
                    "{}",
                    control::display(entry.pid, &entry.interface, &entry.peers)
                );
            }
            if !errors.is_empty() {
                return Err(errors.join("\n").into());
            }
        }
    }
    Ok(())
}

fn down(name: &str) -> Result<()> {
    let deadline = ipc::deadline();
    for pid in pids(deadline)? {
        let Some(mut connection) =
            open(pid).map_err(|error| format!("pid={pid}: {}", error.message))?
        else {
            continue;
        };
        let interface =
            interface(&mut connection, deadline).map_err(|error| format!("pid={pid}: {error}"))?;
        if interface.name == name {
            let reply = connection
                .rpc(control::STOP, &[], deadline)
                .map_err(|error| {
                    format!(
                        "{name} (pid={pid}): shutdown is not confirmed: {error}; use wg-tool status"
                    )
                })?;
            if !reply.is_empty() {
                return Err("invalid shutdown acknowledgment".into());
            }
            println!("{name}: down");
            return Ok(());
        }
    }
    println!("{name}: already down");
    Ok(())
}

fn cidrs(text: &str) -> config::Result<Vec<IpNetwork>> {
    if text.split(',').any(|value| !value.contains('/')) {
        return Err("CIDRs require explicit prefix lengths");
    }
    tool::list(text)
}

fn transport_default() -> String {
    for wildcard in ["0.0.0.0:0", "[::]:0"] {
        if let Ok(socket) = UdpSocket::bind(wildcard)
            && let Ok(address) = socket.local_addr()
        {
            let ip = address.ip();
            if config::unicast(ip)
                && !ip.is_loopback()
                && !matches!(ip, IpAddr::V6(ip) if ip.is_unicast_link_local())
            {
                return ip.to_string();
            }
        }
    }
    String::new()
}

fn new<R: Read, W: Write>(prompt: &mut Prompt<R, W>) -> Result<()> {
    let mut names = files::saved_names()?;
    let (interfaces, errors) = live(false)?;
    if !errors.is_empty() {
        return Err(errors.join("\n").into());
    }
    names.extend(interfaces.into_iter().map(|entry| entry.interface.name));
    let name = prompt.ask(
        "Interface name",
        &tool::unused_name(names),
        4096,
        false,
        |name| {
            config::validate_name(name)?;
            Ok(name.to_owned())
        },
    )?;
    let (path, destination) = prompt.ask(
        "Configuration file",
        &format!("{CONFIG_DIR}/{name}.toml"),
        4096,
        false,
        |value| {
            let path = files::absolute(Path::new(value))?;
            let destination = Destination::prepare(&path, None)?;
            Ok((path, destination))
        },
    )?;
    let port = prompt.ask("Listen port", "51820", 4096, false, |value| {
        value
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or("listen port must be 1–65535")
    })?;
    let addresses = prompt.ask("Tunnel CIDRs", "10.20.0.1/24", 4096, false, |value| {
        let values = cidrs(value)?;
        let mut seen = HashSet::new();
        if values.is_empty()
            || values.len() > config::MAX_ADDRESSES
            || values
                .iter()
                .any(|cidr| !config::unicast(cidr.ip()) || !seen.insert(cidr.ip()))
        {
            return Err("configure 1–16 unique unicast tunnel CIDRs");
        }
        Ok(values)
    })?;
    let transports = prompt.ask(
        "Physical transport addresses",
        &transport_default(),
        4096,
        false,
        |value| {
            let values: Vec<IpAddr> = tool::list(value)?;
            let mut families = HashSet::new();
            if values.is_empty()
                || values.len() > 2
                || values
                    .iter()
                    .any(|ip| !config::unicast(*ip) || !families.insert(ip.is_ipv4()))
            {
                return Err("configure one unicast physical address per enabled IP family");
            }
            Ok(values)
        },
    )?;
    prompt.say(&format!("Interface: {name}\nFile: {}\nListen port: {port}\nCIDRs: {}\nTransport addresses: {}\nPeers: 0", tool::escaped(&path), join(&addresses), join(&transports)))?;
    prompt.confirm("Create this configuration?")?;
    let mut private_key = [0; 32];
    moto_sdk::rt::fill_random_bytes(&mut private_key);
    let config = Config {
        name,
        private_key,
        listen_port: port,
        transport_addresses: transports,
        cidrs: addresses,
        peers: Vec::new(),
    };
    let text = crate::edit::serialize(&config)?;
    Config::parse(&text)?;
    destination.publish(&text)?;
    println!(
        "Created {}\nInterface: {}\nPublic key: {}\nNext: wg-tool add-peer {}",
        tool::escaped(&path),
        config.name,
        STANDARD.encode(config.public_key()),
        tool::quoted(&path)
    );
    Ok(())
}

fn join(values: &[impl ToString]) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn add_peer<R: Read, W: Write>(prompt: &mut Prompt<R, W>, path: Option<&str>) -> Result<()> {
    let path = match path {
        Some(path) => files::absolute(Path::new(path))?,
        None => prompt.ask(
            "Configuration file",
            &format!("{CONFIG_DIR}/wg0.toml"),
            4096,
            false,
            |path| files::absolute(Path::new(path)),
        )?,
    };
    let document = files::read(Path::new(&path))?;
    let config = Config::parse(&document.text)?;
    if config.peers.len() == config::MAX_PEERS {
        return Err("configuration already has 16 peers".into());
    }
    let destination = Destination::prepare(&path, Some(document.permissions))?;
    prompt.say(&format!(
        "Interface: {}\nPublic key: {}",
        config.name,
        STANDARD.encode(config.public_key())
    ))?;
    let name = prompt.ask("Peer name (optional comment)", "", 4096, false, |name| {
        crate::edit::peer_name(name).map(str::to_owned)
    })?;
    let public_key = prompt.ask("Peer public key", "", 128, false, |value| {
        let key = config::key(value)?;
        if key == config.public_key() {
            return Err("peer key is the interface's own key");
        }
        if config.peers.iter().any(|peer| peer.public_key == key) {
            return Err("duplicate peer public key");
        }
        Ok(key)
    })?;
    prompt.say("An empty endpoint waits for authenticated traffic; at least one side needs a reachable endpoint.")?;
    let endpoint = prompt.ask("Endpoint (optional)", "", 4096, false, |value| {
        if value.is_empty() {
            return Ok(None);
        }
        if value.contains('%') {
            return Err("endpoint scope IDs are unsupported");
        }
        let endpoint: SocketAddr = value
            .parse()
            .map_err(|_| "endpoint must be a numeric IP address and port")?;
        if endpoint.port() == 0 || !config::unicast(endpoint.ip()) {
            return Err("endpoint must be unicast with a nonzero port");
        }
        if !config
            .transport_addresses
            .iter()
            .any(|ip| ip.is_ipv4() == endpoint.is_ipv4())
        {
            return Err("endpoint family has no configured physical transport");
        }
        Ok(Some(endpoint))
    })?;
    let allowed_ips = prompt.ask("Allowed IPs", "", 8192, false, |value| {
        let mut prefixes: HashSet<_> = config
            .peers
            .iter()
            .flat_map(|peer| peer.allowed_ips.iter().copied())
            .collect();
        let mut values = cidrs(value)?;
        for prefix in &mut values {
            *prefix = IpNetwork::new(prefix.network(), prefix.prefix()).unwrap();
            if !config
                .cidrs
                .iter()
                .any(|cidr| cidr.is_ipv4() == prefix.is_ipv4())
            {
                return Err("allowed_ips family has no local tunnel address");
            }
            if !prefixes.insert(*prefix) {
                return Err("duplicate allowed_ips prefix");
            }
        }
        if prefixes.len() > config::MAX_PREFIXES {
            return Err("allowed_ips is limited to 128 prefixes in total");
        }
        Ok(values)
    })?;
    prompt.say("A keepalive of 25 seconds is often useful for maintaining a NAT mapping.")?;
    let keepalive = prompt.ask("Persistent keepalive, seconds", "0", 4096, false, |value| {
        value
            .parse::<u16>()
            .map_err(|_| "keepalive must be 0–65535")
    })?;
    let preshared_key = prompt.ask("Preshared key (optional; hidden)", "", 128, true, |value| {
        if value.is_empty() {
            Ok(None)
        } else {
            config::key(value).map(Some)
        }
    })?;
    let peer = Peer {
        public_key,
        endpoint,
        allowed_ips,
        persistent_keepalive: (keepalive != 0).then_some(keepalive),
        preshared_key,
    };
    prompt.say(&format!("Peer name: {}\nPublic key: {}\nEndpoint: {}\nAllowed IPs: {}\nKeepalive: {keepalive}s\nPreshared key: {}", name, STANDARD.encode(public_key), endpoint.map_or_else(|| "learn from traffic".into(), |value| value.to_string()), join(&peer.allowed_ips), if preshared_key.is_some() { "set" } else { "none" }))?;
    for prefix in &peer.allowed_ips {
        if prefix.prefix() == 0 {
            prompt.say(&format!(
                "{prefix} routes all destinations of this family through this peer."
            ))?;
        }
    }
    let text = crate::edit::add_peer(&document.text, peer, &name)?;
    prompt.confirm("Save this peer?")?;
    destination.publish(&text)?;
    println!(
        "Saved {}\nPeer public key: {}\nSaved configuration only. A running {} keeps its current peers.\nApply with: wg-tool down -- {}\n            wg-tool up {}",
        tool::escaped(&path),
        STANDARD.encode(public_key),
        config.name,
        config.name,
        tool::quoted(&path)
    );
    Ok(())
}
