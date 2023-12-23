use std::borrow::{Borrow, Cow};
use std::error::Error;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

/// An [HTTP method](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#methods) like `GET` or `POST`.
///
/// ```
/// use oxhttp::model::Method;
/// use std::str::FromStr;
///
/// assert_eq!(Method::from_str("get")?, Method::GET);
/// # Result::<_,Box<dyn std::error::Error>>::Ok(())
/// ```
#[derive(PartialEq, Eq, Debug, Clone, Hash)]
pub struct Method(Cow<'static, str>);

impl Method {
    /// Is the method [safe](https://httpwg.org/specs/rfc7231.html#safe.methods)
    pub(crate) fn is_safe(&self) -> bool {
        matches!(self.as_ref(), "GET" | "HEAD" | "OPTIONS" | "TRACE")
    }

    /// [CONNECT](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#CONNECT).
    pub const CONNECT: Method = Self(Cow::Borrowed("CONNECT"));
    /// [DELETE](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#DELETE).
    pub const DELETE: Method = Self(Cow::Borrowed("DELETE"));
    /// [GET](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#GET).
    pub const GET: Method = Self(Cow::Borrowed("GET"));
    /// [HEAD](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#HEAD).
    pub const HEAD: Method = Self(Cow::Borrowed("HEAD"));
    /// [OPTIONS](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#OPTIONS).
    pub const OPTIONS: Method = Self(Cow::Borrowed("OPTIONS"));
    /// [POST](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#POST).
    pub const POST: Method = Self(Cow::Borrowed("POST"));
    /// [PUT](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#PUT).
    pub const PUT: Method = Self(Cow::Borrowed("PUT"));
    /// [TRACE](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#TRACE).
    pub const TRACE: Method = Self(Cow::Borrowed("TRACE"));
}

impl Deref for Method {
    type Target = str;

    #[inline]
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Method {
    #[inline]
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for Method {
    #[inline]
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl FromStr for Method {
    type Err = InvalidMethod;

    #[inline]
    fn from_str(name: &str) -> Result<Self, InvalidMethod> {
        for method in STATIC_METHODS {
            if method.eq_ignore_ascii_case(name) {
                return Ok(method);
            }
        }
        name.to_owned().try_into()
    }
}

impl TryFrom<String> for Method {
    type Error = InvalidMethod;

    #[inline]
    fn try_from(name: String) -> Result<Self, InvalidMethod> {
        for method in STATIC_METHODS {
            if method.eq_ignore_ascii_case(&name) {
                return Ok(method);
            }
        }
        if name.is_empty() {
            Err(InvalidMethod(InvalidMethodAlt::Empty))
        } else {
            for c in name.chars() {
                if !matches!(c, '!' | '#' | '$' | '%' | '&' | '\'' | '*'
       | '+' | '-' | '.' | '^' | '_' | '`' | '|' | '~'
        | '0'..='9' | 'a'..='z' | 'A'..='Z')
                {
                    return Err(InvalidMethod(InvalidMethodAlt::InvalidChar {
                        name: name.to_owned(),
                        invalid_char: c,
                    }));
                }
            }
            Ok(Self(name.into()))
        }
    }
}

impl fmt::Display for Method {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

const STATIC_METHODS: [Method; 8] = [
    Method::CONNECT,
    Method::DELETE,
    Method::GET,
    Method::HEAD,
    Method::OPTIONS,
    Method::POST,
    Method::PUT,
    Method::TRACE,
];

/// Error returned by [`Method::try_from`].
#[derive(Debug, Clone)]
pub struct InvalidMethod(InvalidMethodAlt);

#[derive(Debug, Clone)]
enum InvalidMethodAlt {
    Empty,
    InvalidChar { name: String, invalid_char: char },
}

impl fmt::Display for InvalidMethod {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            InvalidMethodAlt::Empty => f.write_str("HTTP methods should not be empty"),
            InvalidMethodAlt::InvalidChar { name, invalid_char } => write!(
                f,
                "The character '{invalid_char}' is not valid inside of HTTP method '{name}'"
            ),
        }
    }
}

impl Error for InvalidMethod {}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_header_name() {
        assert!(Method::from_str("").is_err());
        assert!(Method::from_str("ffo bar").is_err());
        assert!(Method::from_str("ffo\tbar").is_err());
        assert!(Method::from_str("ffo\rbar").is_err());
        assert!(Method::from_str("ffo\nbar").is_err());
        assert!(Method::from_str("ffoébar").is_err());
        assert!(Method::from_str("foo-bar").is_ok());
    }
}
