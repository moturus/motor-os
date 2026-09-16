use axum::Router;
use http::{header::LOCATION, HeaderValue, StatusCode, Uri};
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct RedirectUrl(HeaderValue);

impl FromStr for RedirectUrl {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        const INVALID: &str = "expected an absolute HTTPS URL without credentials";
        // Require escaped ASCII, excluding browser-specific backslash handling
        // and whitespace. Keep the original bytes for Location, including a fragment.
        if !value
            .bytes()
            .all(|b| (b'!'..=b'~').contains(&b) && b != b'\\')
        {
            return Err(INVALID);
        }
        for (index, byte) in value.bytes().enumerate() {
            if byte == b'%'
                && !value
                    .as_bytes()
                    .get(index + 1..index + 3)
                    .is_some_and(|s| s.iter().all(u8::is_ascii_hexdigit))
            {
                return Err(INVALID);
            }
        }
        let uri: Uri = value
            .split('#')
            .next()
            .unwrap()
            .parse()
            .map_err(|_| INVALID)?;
        if !uri
            .scheme_str()
            .is_some_and(|s| s.eq_ignore_ascii_case("https"))
        {
            return Err(INVALID);
        }
        let authority = uri.authority().ok_or(INVALID)?;
        let host = authority.host();
        if authority.as_str().contains('@') || host.is_empty() {
            return Err(INVALID);
        }
        if let Some(ip) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            ip.parse::<std::net::Ipv6Addr>().map_err(|_| INVALID)?;
        } else if !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        {
            return Err(INVALID);
        }
        let suffix = &authority.as_str()[host.len()..];
        if !suffix.is_empty()
            && (!suffix.starts_with(':') || authority.port_u16().is_none_or(|p| p == 0))
        {
            return Err(INVALID);
        }
        Ok(Self(HeaderValue::from_str(value).map_err(|_| INVALID)?))
    }
}

impl RedirectUrl {
    pub fn router(self) -> Router {
        // No request data enters Location, and redirects never touch the file cache.
        Router::new().fallback(move || {
            let location = self.0.clone();
            async move { (StatusCode::PERMANENT_REDIRECT, [(LOCATION, location)]) }
        })
    }
}
