//! TCP forwarding endpoints shared by command-line and configuration parsing.

use super::args::ParseError;

const MAX_HOST: usize = 255;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenAddress {
    /// None uses this forward's default; an explicit empty address or `*` is a wildcard.
    pub host: Option<String>,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetAddress {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalForward {
    pub listen: ListenAddress,
    /// No fixed target means a SOCKS listener.
    pub target: Option<TargetAddress>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteForward {
    pub listen: ListenAddress,
    pub target: TargetAddress,
}

impl ListenAddress {
    pub fn parse(value: &str) -> Result<Self, ParseError> {
        Self::parse_with_zero(value, false)
    }

    fn parse_with_zero(value: &str, allow_zero: bool) -> Result<Self, ParseError> {
        match fields(value)?.as_slice() {
            [listen_port] => Self::from_parts(None, listen_port, allow_zero),
            [host, listen_port] => Self::from_parts(Some(host), listen_port, allow_zero),
            _ => Err(invalid()),
        }
    }

    fn from_parts(
        bind: Option<&str>,
        listen_port: &str,
        allow_zero: bool,
    ) -> Result<Self, ParseError> {
        Ok(Self {
            host: bind.map(|value| host(value, true)).transpose()?,
            port: if allow_zero {
                listen_port.parse().map_err(|_| invalid())?
            } else {
                port(listen_port)?
            },
        })
    }
}

impl TargetAddress {
    pub fn parse(value: &str) -> Result<Self, ParseError> {
        match fields(value)?.as_slice() {
            [target_host, target_port] => Self::from_parts(target_host, target_port),
            _ => Err(invalid()),
        }
    }

    fn from_parts(target_host: &str, target_port: &str) -> Result<Self, ParseError> {
        Ok(Self {
            host: host(target_host, false)?,
            port: port(target_port)?,
        })
    }
}

impl LocalForward {
    pub fn parse_dynamic(value: &str) -> Result<Self, ParseError> {
        Ok(Self {
            listen: ListenAddress::parse(value)?,
            target: None,
        })
    }

    pub fn parse(value: &str) -> Result<Self, ParseError> {
        match fields(value)?.as_slice() {
            [listen_port, target_host, target_port] => Ok(Self {
                listen: ListenAddress::from_parts(None, listen_port, false)?,
                target: Some(TargetAddress::from_parts(target_host, target_port)?),
            }),
            [bind, listen_port, target_host, target_port] => Ok(Self {
                listen: ListenAddress::from_parts(Some(bind), listen_port, false)?,
                target: Some(TargetAddress::from_parts(target_host, target_port)?),
            }),
            _ => Err(invalid()),
        }
    }

    pub fn parse_config(listen: &str, target: &str) -> Result<Self, ParseError> {
        Ok(Self {
            listen: ListenAddress::parse(listen)?,
            target: Some(TargetAddress::parse(target)?),
        })
    }
}

impl RemoteForward {
    pub fn parse(value: &str) -> Result<Self, ParseError> {
        match fields(value)?.as_slice() {
            [listen_port, target_host, target_port] => Ok(Self {
                listen: ListenAddress::from_parts(None, listen_port, true)?,
                target: TargetAddress::from_parts(target_host, target_port)?,
            }),
            [bind, listen_port, target_host, target_port] => Ok(Self {
                listen: ListenAddress::from_parts(Some(bind), listen_port, true)?,
                target: TargetAddress::from_parts(target_host, target_port)?,
            }),
            _ => Err(invalid()),
        }
    }

    pub fn parse_config(listen: &str, target: &str) -> Result<Self, ParseError> {
        Ok(Self {
            listen: ListenAddress::parse_with_zero(listen, true)?,
            target: TargetAddress::parse(target)?,
        })
    }

    pub fn bind_address(&self) -> &str {
        self.listen.host.as_deref().unwrap_or("localhost")
    }
}

fn invalid() -> ParseError {
    ParseError::new("invalid TCP forwarding specification")
}

fn port(value: &str) -> Result<u16, ParseError> {
    value
        .parse()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(invalid)
}

fn host(value: &str, bind: bool) -> Result<String, ParseError> {
    let value = value
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(value);
    if bind && (value.is_empty() || value == "*") {
        return Ok(value.to_owned());
    }
    if value.is_empty()
        || value.len() > MAX_HOST
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(invalid());
    }
    Ok(value.to_owned())
}

/// Split only outside brackets, keeping allocation and field count bounded.
fn fields(value: &str) -> Result<Vec<&str>, ParseError> {
    if value.len() > 2 * MAX_HOST + 32 {
        return Err(invalid());
    }
    let mut fields = Vec::with_capacity(4);
    let mut start = 0;
    let mut bracketed = false;
    for (index, byte) in value.bytes().enumerate() {
        match byte {
            b'[' if index == start && !bracketed => bracketed = true,
            b'[' => return Err(invalid()),
            b']' if bracketed => {
                bracketed = false;
                if value
                    .as_bytes()
                    .get(index + 1)
                    .is_some_and(|byte| *byte != b':')
                {
                    return Err(invalid());
                }
            }
            b']' => return Err(invalid()),
            b':' if !bracketed => {
                if fields.len() == 3 {
                    return Err(invalid());
                }
                fields.push(&value[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    if bracketed {
        return Err(invalid());
    }
    fields.push(&value[start..]);
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_forwards_allow_allocation_only_for_the_listening_port() {
        for (argument, listen, target) in [
            ("0:localhost:80", "0", "localhost:80"),
            ("127.0.0.1:0:host:443", "127.0.0.1:0", "host:443"),
            ("[::1]:65535:[::2]:22", "[::1]:65535", "[::2]:22"),
            ("*:0:target:80", "*:0", "target:80"),
            (":0:target:80", ":0", "target:80"),
        ] {
            assert_eq!(
                RemoteForward::parse(argument).unwrap(),
                RemoteForward::parse_config(listen, target).unwrap()
            );
        }
        assert_eq!(
            RemoteForward::parse("0:host:80").unwrap().bind_address(),
            "localhost"
        );
        for argument in [
            "",
            "80:host",
            "65536:host:80",
            "0:host:0",
            "0:host:65536",
            "0:bad/host:80",
            "[::1]:0:[[::2]]:80",
        ] {
            assert!(
                RemoteForward::parse(argument).is_err(),
                "accepted {argument:?}"
            );
        }
        assert!(LocalForward::parse("0:host:80").is_err());
        assert!(LocalForward::parse_dynamic("0").is_err());
    }

    #[test]
    fn command_and_config_syntax_share_the_same_endpoints() {
        for (argument, bind, target) in [
            ("8080:localhost.:80", "8080", "localhost.:80"),
            ("127.0.0.1:8080:host:443", "127.0.0.1:8080", "host:443"),
            (
                "[::1]:8080:[2001:db8::2]:443",
                "[::1]:8080",
                "[2001:db8::2]:443",
            ),
            ("*:8080:[::1]:80", "*:8080", "[::1]:80"),
            (":8080:host:80", ":8080", "host:80"),
            ("8080:[host]:80", "8080", "host:80"),
        ] {
            assert_eq!(
                LocalForward::parse(argument).unwrap(),
                LocalForward::parse_config(bind, target).unwrap()
            );
        }
    }

    #[test]
    fn implicit_bind_empty_bind_and_wildcard_stay_distinct() {
        for (input, expected) in [
            ("8080", None),
            (":8080", Some("")),
            ("*:8080", Some("*")),
            ("[::1]:8080", Some("::1")),
        ] {
            let listen = ListenAddress::parse(input).unwrap();
            assert_eq!(listen.host.as_deref(), expected);
            assert_eq!(listen.port, 8080);
        }
        assert_eq!(
            TargetAddress::parse("[2001:0db8::1]:65535").unwrap().host,
            "2001:0db8::1"
        );
    }

    #[test]
    fn malformed_fields_and_ports_are_rejected() {
        for value in [
            "",
            "80:host",
            "0:host:80",
            "65536:host:80",
            "80:host:0",
            "80:host:65536",
            "80::80",
            "80:*:80",
            "80:::1:80",
            "[::1:80:host:80",
            "[::1]tail:80:host:80",
            "80:[::1]]:80",
            "80:[[::1]]:80",
            "80:host:80:extra:field",
            "80:host:service",
        ] {
            assert!(LocalForward::parse(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn hosts_are_bounded_ascii_and_preserved_for_the_far_end() {
        let name = "h".repeat(MAX_HOST);
        assert_eq!(
            TargetAddress::parse(&format!("{name}:80")).unwrap().host,
            name
        );
        assert!(TargetAddress::parse(&format!("{}:80", "h".repeat(MAX_HOST + 1))).is_err());
        for value in [
            "bad host:80",
            "bad\nhost:80",
            "bad/host:80",
            "ümlaut:80",
            "[fe80::1%eth0]:80",
        ] {
            assert!(TargetAddress::parse(value).is_err());
        }
        assert_eq!(
            TargetAddress::parse("MiXeD.Example.:80").unwrap().host,
            "MiXeD.Example."
        );
    }
}
