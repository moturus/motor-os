use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{CurlError, CurlResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpUrl {
    original: String,
    scheme: Scheme,
    host: String,
    port: u16,
    explicit_port: bool,
    ipv6: bool,
    target: String,
}

impl HttpUrl {
    pub fn parse(value: &str) -> CurlResult<Self> {
        if !value.is_ascii()
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b' ')
        {
            return Err(malformed("URL contains invalid characters"));
        }
        let (scheme, rest) = split_scheme(value)
            .ok_or_else(|| malformed("only HTTP and HTTPS URLs are supported"))?;
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

        let (host, port, explicit_port, ipv6) = parse_authority(authority, scheme.default_port())?;
        let target = if suffix.is_empty() {
            "/".to_owned()
        } else if suffix.starts_with('?') {
            format!("/{suffix}")
        } else {
            suffix.to_owned()
        };

        Ok(Self {
            original: value.to_owned(),
            scheme,
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

    pub fn scheme(&self) -> Scheme {
        self.scheme
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
        if split_scheme(location).is_some() {
            return Self::parse(location);
        }
        if location.starts_with("//") {
            return Self::parse(&format!("{}:{location}", self.scheme.as_str()));
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
        Self::parse(&format!(
            "{}://{}{}",
            self.scheme.as_str(),
            self.authority(),
            target
        ))
    }
}

/// Schemes are case-insensitive (RFC 3986 §3.1); upstream curl accepts
/// `HTTP://` and Gears forwards the URL text as configured.
fn split_scheme(value: &str) -> Option<(Scheme, &str)> {
    let (scheme, rest) = value.split_once("://")?;
    if scheme.eq_ignore_ascii_case("http") {
        Some((Scheme::Http, rest))
    } else if scheme.eq_ignore_ascii_case("https") {
        Some((Scheme::Https, rest))
    } else {
        None
    }
}

fn parse_authority(authority: &str, default_port: u16) -> CurlResult<(String, u16, bool, bool)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest
            .find(']')
            .ok_or_else(|| malformed("unterminated IPv6 address"))?;
        let host = &rest[..close];
        host.parse::<Ipv6Addr>()
            .map_err(|_| malformed("invalid IPv6 address"))?;
        let tail = &rest[close + 1..];
        let (port, explicit) = parse_port_tail(tail, default_port)?;
        return Ok((host.to_ascii_lowercase(), port, explicit, true));
    }

    let (host, port, explicit) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, parse_port(port)?, true),
        None => (authority, default_port, false),
    };
    if host.is_empty() || host.contains(':') {
        return Err(malformed("invalid host"));
    }
    validate_host(host)?;
    Ok((host.to_ascii_lowercase(), port, explicit, false))
}

fn parse_port_tail(tail: &str, default_port: u16) -> CurlResult<(u16, bool)> {
    if tail.is_empty() {
        Ok((default_port, false))
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
        let url = HttpUrl::parse("https://Crates.IO/index?q=1").unwrap();
        assert_eq!(url.host(), "crates.io");
        assert_eq!(url.port(), 443);
        assert_eq!(url.authority(), "crates.io");
        assert_eq!(url.request_target(), "/index?q=1");

        let url = HttpUrl::parse("https://127.0.0.1:8443").unwrap();
        assert_eq!(url.authority(), "127.0.0.1:8443");
        assert_eq!(url.request_target(), "/");

        let url = HttpUrl::parse("https://[::1]:443/?x").unwrap();
        assert_eq!(url.host(), "::1");
        assert_eq!(url.authority(), "[::1]:443");
        assert_eq!(url.request_target(), "/?x");
    }

    #[test]
    fn rejects_unsafe_or_malformed_urls() {
        for value in [
            "ftp://example.test/",
            "http://user@example.test/",
            "http://example.test/#fragment",
            "http://example.test:0/",
            "https://",
            "https://user@example.test/",
            "https://example.test/#fragment",
            "https://example.test:0/",
            "https://bad_name.test/",
            "https://[::1/",
            "https://example.test/\n",
        ] {
            let error = HttpUrl::parse(value).unwrap_err();
            assert_eq!(error.code(), CurlError::MALFORMED_URL, "{value}");
        }
    }

    #[test]
    fn resolves_redirect_references() {
        let base = HttpUrl::parse("https://example.test/a/b?old").unwrap();
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
        assert_eq!(
            base.redirect("http://other.test/").unwrap().scheme(),
            Scheme::Http
        );
    }

    #[test]
    fn http_ports_and_relative_redirects_preserve_the_scheme() {
        for host in ["example.test", "192.168.4.1", "[::1]"] {
            let base = HttpUrl::parse(&format!("http://{host}/a/b")).unwrap();
            assert_eq!(base.scheme(), Scheme::Http);
            assert_eq!(base.port(), 80);
            assert_eq!(base.authority(), host);
            assert_eq!(
                base.redirect("../c").unwrap().as_str(),
                format!("http://{host}/c")
            );
            assert_eq!(
                base.redirect("//other.test/x").unwrap().as_str(),
                "http://other.test/x"
            );
            assert_eq!(base.redirect("https://other.test/x").unwrap().port(), 443);
        }
        let explicit = HttpUrl::parse("http://192.168.4.1:8080/v1").unwrap();
        assert_eq!(explicit.port(), 8080);
        assert_eq!(
            explicit.redirect("?new").unwrap().as_str(),
            "http://192.168.4.1:8080/v1?new"
        );
    }

    #[test]
    fn schemes_are_case_insensitive() {
        let url = HttpUrl::parse("HTTP://192.168.4.1:8080/v1").unwrap();
        assert_eq!(url.scheme(), Scheme::Http);
        assert_eq!(url.as_str(), "HTTP://192.168.4.1:8080/v1");
        let url = HttpUrl::parse("Https://Example.test/").unwrap();
        assert_eq!((url.scheme(), url.port()), (Scheme::Https, 443));
        assert_eq!(url.redirect("HTTP://other.test/x").unwrap().port(), 80);
        assert!(HttpUrl::parse("FTP://example.test/").is_err());
    }
}
