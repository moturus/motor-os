use std::{io, net::Ipv4Addr, net::Ipv6Addr, str::FromStr};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpsUrl {
    origin: Origin,
    request_url: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Origin {
    host: String,
    port: u16,
}

impl HttpsUrl {
    pub fn parse(value: &str) -> io::Result<HttpsUrl> {
        if !value.is_ascii()
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace() || byte == b'\\')
        {
            return Err(invalid(
                "contains non-ASCII, whitespace, control, or backslash characters",
            ));
        }
        let remainder = value
            .strip_prefix("https://")
            .ok_or_else(|| invalid("must use the exact `https://` scheme"))?;
        if remainder.contains('#') {
            return Err(invalid("must not contain a fragment"));
        }
        let authority_end = remainder.find(['/', '?']).unwrap_or(remainder.len());
        let authority = &remainder[..authority_end];
        if authority.is_empty() || authority.contains('@') {
            return Err(invalid("has an empty authority or user information"));
        }
        let origin = parse_authority(authority)?;
        let authority = if origin.port == 443 {
            origin.host.clone()
        } else {
            format!("{}:{}", origin.host, origin.port)
        };
        let suffix = match &remainder[authority_end..] {
            "" => "/".to_owned(),
            value if value.starts_with('?') => format!("/{value}"),
            value => value.to_owned(),
        };
        Ok(HttpsUrl {
            request_url: format!("https://{authority}{suffix}"),
            origin,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.request_url
    }

    pub fn same_origin_redirect(&self, value: &str) -> io::Result<HttpsUrl> {
        let next = Self::parse(value)?;
        if next.origin != self.origin {
            return Err(invalid("redirect changed the HTTPS origin"));
        }
        Ok(next)
    }
}

fn parse_authority(authority: &str) -> io::Result<Origin> {
    if let Some(value) = authority.strip_prefix('[') {
        let end = value
            .find(']')
            .ok_or_else(|| invalid("has an unterminated IPv6 address"))?;
        let address = Ipv6Addr::from_str(&value[..end])
            .map_err(|_| invalid("has an invalid IPv6 address"))?;
        return Ok(Origin {
            host: format!("[{address}]"),
            port: parse_ipv6_port(&value[end + 1..])?,
        });
    }
    if authority.matches(':').count() > 1 {
        return Err(invalid("must bracket an IPv6 address"));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, Ok(443)), |(host, port)| {
            (host, parse_explicit_port(port))
        });
    Ok(Origin {
        host: canonical_dns_host(host)?,
        port: port?,
    })
}

fn parse_ipv6_port(suffix: &str) -> io::Result<u16> {
    if suffix.is_empty() {
        Ok(443)
    } else {
        let value = suffix
            .strip_prefix(':')
            .ok_or_else(|| invalid("has bytes after its IPv6 address"))?;
        parse_explicit_port(value)
    }
}

fn parse_explicit_port(value: &str) -> io::Result<u16> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("has an invalid port"));
    }
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| invalid("has a port outside 1 through 65535"))
}

fn canonical_dns_host(host: &str) -> io::Result<String> {
    if let Ok(address) = Ipv4Addr::from_str(host) {
        return Ok(address.to_string());
    }
    if host.is_empty()
        || host.len() > 253
        || host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || host.starts_with('.')
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(invalid("has an invalid DNS host"));
    }
    Ok(host.to_ascii_lowercase())
}

fn invalid(reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid HTTPS URL: {reason}"),
    )
}
