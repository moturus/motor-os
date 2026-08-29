use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Applet {
    Ssh,
    Scp,
    Sftp,
    SshKeygen,
    SshCopyId,
}

impl Applet {
    pub fn name(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Scp => "scp",
            Self::Sftp => "sftp",
            Self::SshKeygen => "ssh-keygen",
            Self::SshCopyId => "ssh-copy-id",
        }
    }

    pub fn error_status(self) -> i32 {
        if self == Self::Ssh { 255 } else { 1 }
    }

    fn from_selector(value: &str) -> Option<Self> {
        match value {
            "ssh" => Some(Self::Ssh),
            "scp" => Some(Self::Scp),
            "sftp" => Some(Self::Sftp),
            "ssh-keygen" => Some(Self::SshKeygen),
            "ssh-copy-id" => Some(Self::SshCopyId),
            _ => None,
        }
    }
}

pub fn select_applet(args: &mut Vec<String>) -> Result<Applet, ParseError> {
    let Some(first) = args.get(1) else {
        return Ok(Applet::Ssh);
    };
    let Some(value) = first.strip_prefix("--motor-applet=") else {
        return Ok(Applet::Ssh);
    };
    let applet = Applet::from_selector(value)
        .ok_or_else(|| ParseError::new(format!("unknown internal applet '{value}'")))?;
    args.remove(1);
    Ok(applet)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseError(String);

impl ParseError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for ParseError {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum HostKeyPolicy {
    #[default]
    Ask,
    Yes,
    AcceptNew,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionOptions {
    pub port: u16,
    port_set: bool,
    pub identities: Vec<PathBuf>,
    pub identities_only: bool,
    identities_only_set: bool,
    pub host_key_policy: HostKeyPolicy,
    host_key_policy_set: bool,
    pub known_hosts: Option<PathBuf>,
    known_hosts_set: bool,
    pub batch_mode: bool,
    batch_mode_set: bool,
    pub connect_timeout: Option<Duration>,
    connect_timeout_set: bool,
    pub server_alive_interval: Option<Duration>,
    server_alive_interval_set: bool,
    pub server_alive_count_max: u32,
    server_alive_count_max_set: bool,
}

impl Default for ConnectionOptions {
    fn default() -> Self {
        Self {
            port: 22,
            port_set: false,
            identities: Vec::new(),
            identities_only: false,
            identities_only_set: false,
            host_key_policy: HostKeyPolicy::Ask,
            host_key_policy_set: false,
            known_hosts: default_known_hosts(),
            known_hosts_set: false,
            batch_mode: false,
            batch_mode_set: false,
            connect_timeout: None,
            connect_timeout_set: false,
            server_alive_interval: None,
            server_alive_interval_set: false,
            server_alive_count_max: 3,
            server_alive_count_max_set: false,
        }
    }
}

#[cfg(target_os = "motor")]
fn default_known_hosts() -> Option<PathBuf> {
    Some(PathBuf::from("/user/cfg/ssh/known_hosts"))
}

#[cfg(not(target_os = "motor"))]
fn default_known_hosts() -> Option<PathBuf> {
    None
}

impl ConnectionOptions {
    pub fn add_identity(&mut self, value: &str) -> Result<(), ParseError> {
        if value.is_empty() {
            return Err(ParseError::new("identity path must not be empty"));
        }
        self.identities.push(PathBuf::from(value));
        Ok(())
    }

    pub fn set_port(&mut self, value: &str) -> Result<(), ParseError> {
        let port = value
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| ParseError::new(format!("invalid port '{value}'")))?;
        if !self.port_set {
            self.port = port;
            self.port_set = true;
        }
        Ok(())
    }

    pub fn apply_o(&mut self, value: &str) -> Result<(), ParseError> {
        let (key, value) = value
            .split_once('=')
            .ok_or_else(|| ParseError::new("-o requires Key=Value"))?;
        if key.eq_ignore_ascii_case("IdentitiesOnly") {
            let parsed = parse_yes_no(key, value)?;
            set_first(
                &mut self.identities_only,
                &mut self.identities_only_set,
                parsed,
            );
        } else if key.eq_ignore_ascii_case("StrictHostKeyChecking") {
            let parsed = if value.eq_ignore_ascii_case("ask") {
                HostKeyPolicy::Ask
            } else if value.eq_ignore_ascii_case("yes") {
                HostKeyPolicy::Yes
            } else if value.eq_ignore_ascii_case("accept-new") {
                HostKeyPolicy::AcceptNew
            } else {
                return Err(ParseError::new(format!(
                    "unsupported StrictHostKeyChecking value '{value}'"
                )));
            };
            set_first(
                &mut self.host_key_policy,
                &mut self.host_key_policy_set,
                parsed,
            );
        } else if key.eq_ignore_ascii_case("UserKnownHostsFile") {
            if value.is_empty() {
                return Err(ParseError::new("UserKnownHostsFile must not be empty"));
            }
            if !self.known_hosts_set {
                self.known_hosts = Some(PathBuf::from(value));
                self.known_hosts_set = true;
            }
        } else if key.eq_ignore_ascii_case("BatchMode") {
            let parsed = parse_yes_no(key, value)?;
            set_first(&mut self.batch_mode, &mut self.batch_mode_set, parsed);
        } else if key.eq_ignore_ascii_case("ConnectTimeout") {
            let parsed = parse_seconds(key, value)?;
            set_first(
                &mut self.connect_timeout,
                &mut self.connect_timeout_set,
                parsed,
            );
        } else if key.eq_ignore_ascii_case("ServerAliveInterval") {
            let parsed = parse_seconds(key, value)?;
            set_first(
                &mut self.server_alive_interval,
                &mut self.server_alive_interval_set,
                parsed,
            );
        } else if key.eq_ignore_ascii_case("ServerAliveCountMax") {
            let parsed = value
                .parse::<u32>()
                .map_err(|_| ParseError::new(format!("invalid ServerAliveCountMax '{value}'")))?;
            set_first(
                &mut self.server_alive_count_max,
                &mut self.server_alive_count_max_set,
                parsed,
            );
        } else {
            return Err(ParseError::new(format!("unsupported -o option '{key}'")));
        }
        Ok(())
    }
}

fn set_first<T>(slot: &mut T, set: &mut bool, value: T) {
    if !*set {
        *slot = value;
        *set = true;
    }
}

fn parse_yes_no(key: &str, value: &str) -> Result<bool, ParseError> {
    if value.eq_ignore_ascii_case("yes") {
        Ok(true)
    } else if value.eq_ignore_ascii_case("no") {
        Ok(false)
    } else {
        Err(ParseError::new(format!("invalid {key} value '{value}'")))
    }
}

fn parse_seconds(key: &str, value: &str) -> Result<Option<Duration>, ParseError> {
    let seconds = value
        .parse::<u64>()
        .map_err(|_| ParseError::new(format!("invalid {key} value '{value}'")))?;
    Ok((seconds != 0).then(|| Duration::from_secs(seconds)))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Destination {
    pub user: String,
    pub host: String,
}

impl Destination {
    pub fn parse(value: &str) -> Result<Self, ParseError> {
        let default_user = std::env::var("USER")
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "motor".to_owned());
        Self::parse_with_default(value, &default_user)
    }

    pub fn parse_with_default(value: &str, default_user: &str) -> Result<Self, ParseError> {
        let (user, host) = match value.rsplit_once('@') {
            Some((user, host)) => (user, host),
            None => (default_user, value),
        };
        if user.is_empty() || host.is_empty() {
            return Err(ParseError::new(format!("invalid destination '{value}'")));
        }
        let host = if host.starts_with('[') && host.ends_with(']') {
            &host[1..host.len() - 1]
        } else {
            if host.contains(':') {
                return Err(ParseError::new("IPv6 destinations must be bracketed"));
            }
            host
        };
        if host.is_empty() || host.contains('[') || host.contains(']') {
            return Err(ParseError::new(format!("invalid destination '{value}'")));
        }
        Ok(Self {
            user: user.to_owned(),
            host: host.to_owned(),
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PtyMode {
    #[default]
    Auto,
    Force,
    Disable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshArgs {
    pub connection: ConnectionOptions,
    pub destination: Destination,
    pub command: Vec<String>,
    pub pty: PtyMode,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applet_selector_is_private_and_first() {
        let mut args = vec!["ssh".into(), "--motor-applet=scp".into(), "a".into()];
        assert_eq!(select_applet(&mut args).unwrap(), Applet::Scp);
        assert_eq!(args, ["ssh", "a"]);

        let mut args = vec!["ssh".into(), "host".into(), "--motor-applet=scp".into()];
        assert_eq!(select_applet(&mut args).unwrap(), Applet::Ssh);
    }

    #[test]
    fn destinations_cover_names_and_ip_addresses() {
        assert_eq!(
            Destination::parse_with_default("host", "motor").unwrap(),
            Destination {
                user: "motor".into(),
                host: "host".into()
            }
        );
        assert_eq!(
            Destination::parse_with_default("root@192.0.2.1", "motor").unwrap(),
            Destination {
                user: "root".into(),
                host: "192.0.2.1".into()
            }
        );
        assert_eq!(
            Destination::parse_with_default("root@[2001:db8::1]", "motor").unwrap(),
            Destination {
                user: "root".into(),
                host: "2001:db8::1".into()
            }
        );
        assert!(Destination::parse_with_default("2001:db8::1", "motor").is_err());
        assert!(Destination::parse_with_default("@host", "motor").is_err());
    }

    #[test]
    fn connection_options_are_strict_and_first_value_wins() {
        let mut options = ConnectionOptions::default();
        options.set_port("2222").unwrap();
        options.set_port("3333").unwrap();
        options.apply_o("IdentitiesOnly=yes").unwrap();
        options.apply_o("IdentitiesOnly=no").unwrap();
        options.apply_o("StrictHostKeyChecking=accept-new").unwrap();
        options.apply_o("BatchMode=yes").unwrap();
        options.apply_o("ConnectTimeout=7").unwrap();
        options.apply_o("ServerAliveInterval=9").unwrap();
        options.apply_o("ServerAliveCountMax=0").unwrap();
        options.apply_o("UserKnownHostsFile=/tmp/hosts").unwrap();
        options.add_identity("first").unwrap();
        options.add_identity("second").unwrap();

        assert_eq!(options.port, 2222);
        assert!(options.identities_only);
        assert_eq!(options.host_key_policy, HostKeyPolicy::AcceptNew);
        assert!(options.batch_mode);
        assert_eq!(options.connect_timeout, Some(Duration::from_secs(7)));
        assert_eq!(options.server_alive_interval, Some(Duration::from_secs(9)));
        assert_eq!(options.server_alive_count_max, 0);
        assert_eq!(options.known_hosts, Some(PathBuf::from("/tmp/hosts")));
        assert_eq!(
            options.identities,
            [PathBuf::from("first"), PathBuf::from("second")]
        );

        assert!(options.apply_o("StrictHostKeyChecking=no").is_err());
        assert!(options.apply_o("Compression=yes").is_err());
        assert!(options.apply_o("BatchMode=maybe").is_err());
        assert!(options.set_port("0").is_err());
    }
}
