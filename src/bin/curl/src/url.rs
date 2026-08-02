use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{CurlError, CurlResult};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpsUrl {
    original: String,
    host: String,
    port: u16,
    explicit_port: bool,
    ipv6: bool,
    target: String,
}

impl HttpsUrl {
    pub fn parse(value: &str) -> CurlResult<Self> {
        if !value.is_ascii()
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b' ')
        {
            return Err(malformed("URL contains invalid characters"));
        }
        let rest = value
            .strip_prefix("https://")
            .ok_or_else(|| malformed("only HTTPS URLs are supported"))?;
        if rest.contains('#') {
            return Err(malformed("URL fragments are not supported"));
        }

        let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        let suffix = &rest[authority_end..];
        if authority.is_empty() {
            return Err(malformed("URL has no host"));
        }
        if authority.contains('@') {
            return Err(malformed("URL user information is not permitted"));
        }

        let (host, port, explicit_port, ipv6) = parse_authority(authority)?;
        let target = if suffix.is_empty() {
            "/".to_owned()
        } else if suffix.starts_with('?') {
            format!("/{suffix}")
        } else {
            suffix.to_owned()
        };

        Ok(Self {
            original: value.to_owned(),
            host,
            port,
            explicit_port,
            ipv6,
            target,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.original
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn request_target(&self) -> &str {
        &self.target
    }

    pub fn authority(&self) -> String {
        let host = if self.ipv6 {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.explicit_port {
            format!("{host}:{}", self.port)
        } else {
            host
        }
    }

    pub fn redirect(&self, location: &str) -> CurlResult<Self> {
        if location.starts_with("https://") {
            return Self::parse(location);
        }
        if location.starts_with("//") {
            return Self::parse(&format!("https:{location}"));
        }
        if location.is_empty()
            || !location.is_ascii()
            || location
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b' ')
            || location.contains('#')
        {
            return Err(malformed("invalid redirect URL"));
        }
        if location.contains("://") {
            return Err(malformed("redirect uses an unsupported protocol"));
        }

        let target = if location.starts_with('/') {
            normalize_target(location)
        } else if location.starts_with('?') {
            let path = self
                .target
                .split_once('?')
                .map_or(self.target.as_str(), |p| p.0);
            format!("{path}{location}")
        } else {
            let base_path = self
                .target
                .split_once('?')
                .map_or(self.target.as_str(), |p| p.0);
            let directory_end = base_path.rfind('/').unwrap_or(0) + 1;
            normalize_target(&format!("{}{location}", &base_path[..directory_end]))
        };
        Self::parse(&format!("https://{}{}", self.authority(), target))
    }
}

fn parse_authority(authority: &str) -> CurlResult<(String, u16, bool, bool)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest
            .find(']')
            .ok_or_else(|| malformed("unterminated IPv6 address"))?;
        let host = &rest[..close];
        host.parse::<Ipv6Addr>()
            .map_err(|_| malformed("invalid IPv6 address"))?;
        let tail = &rest[close + 1..];
        let (port, explicit) = parse_port_tail(tail)?;
        return Ok((host.to_ascii_lowercase(), port, explicit, true));
    }

    let (host, port, explicit) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, parse_port(port)?, true),
        None => (authority, 443, false),
    };
    if host.is_empty() || host.contains(':') {
        return Err(malformed("invalid host"));
    }
    validate_host(host)?;
    Ok((host.to_ascii_lowercase(), port, explicit, false))
}

fn parse_port_tail(tail: &str) -> CurlResult<(u16, bool)> {
    if tail.is_empty() {
        Ok((443, false))
    } else if let Some(port) = tail.strip_prefix(':') {
        Ok((parse_port(port)?, true))
    } else {
        Err(malformed("invalid characters after IPv6 address"))
    }
}

fn parse_port(value: &str) -> CurlResult<u16> {
    match value.parse::<u16>() {
        Ok(port) if port != 0 => Ok(port),
        _ => Err(malformed("invalid port")),
    }
}

fn validate_host(host: &str) -> CurlResult<()> {
    if host.parse::<Ipv4Addr>().is_ok() {
        return Ok(());
    }
    if host.len() > 253 {
        return Err(malformed("host name is too long"));
    }
    for label in host.split('.') {
        let valid = !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric);
        if !valid {
            return Err(malformed("invalid host name"));
        }
    }
    Ok(())
}

fn normalize_target(value: &str) -> String {
    let (path, query) = value
        .split_once('?')
        .map_or((value, None), |(p, q)| (p, Some(q)));
    let mut segments = Vec::new();
    for segment in path.split('/').skip(1) {
        match segment {
            "." => {}
            ".." => {
                segments.pop();
            }
            _ => segments.push(segment),
        }
    }
    let mut result = format!("/{}", segments.join("/"));
    if let Some(query) = query {
        result.push('?');
        result.push_str(query);
    }
    result
}

fn malformed(message: impl Into<String>) -> CurlError {
    CurlError::new(CurlError::MALFORMED_URL, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dns_ipv4_and_ipv6_urls() {
        let url = HttpsUrl::parse("https://Crates.IO/index?q=1").unwrap();
        assert_eq!(url.host(), "crates.io");
        assert_eq!(url.port(), 443);
        assert_eq!(url.authority(), "crates.io");
        assert_eq!(url.request_target(), "/index?q=1");

        let url = HttpsUrl::parse("https://127.0.0.1:8443").unwrap();
        assert_eq!(url.authority(), "127.0.0.1:8443");
        assert_eq!(url.request_target(), "/");

        let url = HttpsUrl::parse("https://[::1]:443/?x").unwrap();
        assert_eq!(url.host(), "::1");
        assert_eq!(url.authority(), "[::1]:443");
        assert_eq!(url.request_target(), "/?x");
    }

    #[test]
    fn rejects_unsafe_or_malformed_urls() {
        for value in [
            "http://example.test/",
            "https://",
            "https://user@example.test/",
            "https://example.test/#fragment",
            "https://example.test:0/",
            "https://bad_name.test/",
            "https://[::1/",
            "https://example.test/\n",
        ] {
            let error = HttpsUrl::parse(value).unwrap_err();
            assert_eq!(error.code(), CurlError::MALFORMED_URL, "{value}");
        }
    }

    #[test]
    fn resolves_redirect_references() {
        let base = HttpsUrl::parse("https://example.test/a/b?old").unwrap();
        assert_eq!(
            base.redirect("../c?new").unwrap().as_str(),
            "https://example.test/c?new"
        );
        assert_eq!(
            base.redirect("/root").unwrap().as_str(),
            "https://example.test/root"
        );
        assert_eq!(
            base.redirect("?new").unwrap().as_str(),
            "https://example.test/a/b?new"
        );
        assert_eq!(
            base.redirect("//other.test/x").unwrap().as_str(),
            "https://other.test/x"
        );
        assert!(base.redirect("http://other.test/").is_err());
    }
}
