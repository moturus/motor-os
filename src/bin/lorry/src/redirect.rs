use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::diagnostic::{Error, Result};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Site(String);

impl Site {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Site {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpsUrl {
    pub site: Site,
    pub request_url: String,
}

impl HttpsUrl {
    pub fn parse(value: &str) -> Result<Self> {
        if !value.is_ascii()
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b'\\')
        {
            return Err(invalid(
                "contains non-ASCII, control, or backslash characters",
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
        let (host, port) = parse_authority(authority)?;
        let site = if port == 443 {
            Site(host.clone())
        } else {
            Site(format!("{host}:{port}"))
        };
        let suffix = match &remainder[authority_end..] {
            "" => "/".to_owned(),
            value if value.starts_with('?') => format!("/{value}"),
            value => value.to_owned(),
        };
        Ok(Self {
            request_url: format!("https://{site}{suffix}"),
            site,
        })
    }
}

fn parse_authority(authority: &str) -> Result<(String, u16)> {
    if let Some(value) = authority.strip_prefix('[') {
        let end = value
            .find(']')
            .ok_or_else(|| invalid("has an unterminated IPv6 address"))?;
        let address = Ipv6Addr::from_str(&value[..end])
            .map_err(|_| invalid("has an invalid IPv6 address"))?;
        let port = parse_port(&value[end + 1..])?;
        return Ok((format!("[{address}]"), port));
    }
    if authority.matches(':').count() > 1 {
        return Err(invalid("must bracket an IPv6 address"));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, Ok(443)), |(host, port)| {
            (host, parse_explicit_port(port))
        });
    Ok((canonical_dns_host(host)?, port?))
}

fn parse_port(suffix: &str) -> Result<u16> {
    if suffix.is_empty() {
        Ok(443)
    } else {
        let value = suffix
            .strip_prefix(':')
            .ok_or_else(|| invalid("has bytes after its IPv6 address"))?;
        parse_explicit_port(value)
    }
}

fn parse_explicit_port(value: &str) -> Result<u16> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("has an invalid port"));
    }
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| invalid("has a port outside 1 through 65535"))
}

fn canonical_dns_host(host: &str) -> Result<String> {
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

fn invalid(reason: &str) -> Error {
    Error::failure(format!("invalid redirect URL: {reason}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_https_sites_and_request_urls() {
        let url = HttpsUrl::parse("https://EXAMPLE.com:443/path?q=1").unwrap();
        assert_eq!(url.site.as_str(), "example.com");
        assert_eq!(url.request_url, "https://example.com/path?q=1");

        let url = HttpsUrl::parse("https://[2001:0db8::1]:8443?q").unwrap();
        assert_eq!(url.site.as_str(), "[2001:db8::1]:8443");
        assert_eq!(url.request_url, "https://[2001:db8::1]:8443/?q");
    }

    #[test]
    fn rejects_ambiguous_or_unsafe_redirect_urls() {
        for value in [
            "http://example.com/",
            "HTTPS://example.com/",
            "https://user@example.com/",
            "https://example.com/#fragment",
            "https://example.com\\@other/",
            "https://example.com:0/",
            "https://example.com./",
            "https://-example.com/",
            "https://2001:db8::1/",
            "https://127.1/",
            "https://2130706433/",
            "https://exa_mple.com/",
        ] {
            assert!(HttpsUrl::parse(value).is_err(), "{value}");
        }
    }
}
