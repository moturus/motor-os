use std::borrow::{Borrow, Cow};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fmt::Debug;
use std::ops::Deref;
use std::str;
use std::str::{FromStr, Utf8Error};

/// A list of headers aka [fields](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#fields).
///
/// ```
/// use oxhttp::model::{Headers, HeaderName, HeaderValue};
/// use std::str::FromStr;
///
/// let mut headers = Headers::new();
/// headers.append(HeaderName::ACCEPT_LANGUAGE, "en".parse()?);
/// headers.append(HeaderName::ACCEPT_LANGUAGE, "fr".parse()?);
/// assert_eq!(headers.get(&HeaderName::ACCEPT_LANGUAGE).unwrap().as_ref(), b"en, fr");
/// # Result::<_,Box<dyn std::error::Error>>::Ok(())
/// ```
#[derive(PartialEq, Eq, Debug, Clone, Hash, Default)]
pub struct Headers(BTreeMap<HeaderName, HeaderValue>);

impl Headers {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a header to the list.
    ///
    /// It does not override the existing value(s) for the same header.
    #[inline]
    pub fn append(&mut self, name: HeaderName, value: HeaderValue) {
        match self.0.entry(name) {
            Entry::Occupied(e) => {
                let val = &mut e.into_mut().0.to_mut();
                val.extend_from_slice(b", ");
                val.extend_from_slice(&value.0);
            }
            Entry::Vacant(e) => {
                e.insert(value);
            }
        }
    }

    /// Removes an header from the list.
    #[inline]
    pub fn remove(&mut self, name: &HeaderName) {
        self.0.remove(name);
    }

    /// Get an header value(s) from the list.
    #[inline]
    pub fn get(&self, name: &HeaderName) -> Option<&HeaderValue> {
        self.0.get(name)
    }

    #[inline]
    pub fn contains(&self, name: &HeaderName) -> bool {
        self.0.contains_key(name)
    }

    /// Sets a header it the list.
    ///
    /// It overrides the existing value(s) for the same header.
    #[inline]
    pub fn set(&mut self, name: HeaderName, value: HeaderValue) {
        self.0.insert(name, value);
    }

    #[inline]
    pub fn iter(&self) -> Iter<'_> {
        Iter(self.0.iter())
    }

    /// Number of distinct headers
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl IntoIterator for Headers {
    type Item = (HeaderName, HeaderValue);
    type IntoIter = IntoIter;

    #[inline]
    fn into_iter(self) -> IntoIter {
        IntoIter(self.0.into_iter())
    }
}

impl<'a> IntoIterator for &'a Headers {
    type Item = (&'a HeaderName, &'a HeaderValue);
    type IntoIter = Iter<'a>;

    #[inline]
    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

/// A [header/field name](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#fields.names).
///
/// It is also normalized to lower case to ease equality checks.
///
/// ```
/// use oxhttp::model::HeaderName;
/// use std::str::FromStr;
///
/// assert_eq!(HeaderName::from_str("content-Type")?, HeaderName::CONTENT_TYPE);
/// # Result::<_,Box<dyn std::error::Error>>::Ok(())
/// ```
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Hash)]
pub struct HeaderName(Cow<'static, str>);

impl HeaderName {
    #[inline]
    pub(crate) fn new_unchecked(name: impl Into<Cow<'static, str>>) -> Self {
        Self(name.into())
    }

    /// [`Accept`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.accept)
    pub const ACCEPT: Self = Self(Cow::Borrowed("accept"));
    /// [`Accept-Encoding`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.accept-encoding)
    pub const ACCEPT_ENCODING: Self = Self(Cow::Borrowed("accept-encoding"));
    /// [`Accept-Language`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.accept-language)
    pub const ACCEPT_LANGUAGE: Self = Self(Cow::Borrowed("accept-language"));
    /// [`Allow`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.allow)
    pub const ACCEPT_RANGES: Self = Self(Cow::Borrowed("accept-ranges"));
    /// [`Allow`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.allow)
    pub const ALLOW: Self = Self(Cow::Borrowed("allow"));
    /// [`Authentication-Info`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.authentication-info)
    pub const AUTHENTICATION_INFO: Self = Self(Cow::Borrowed("authentication-info"));
    /// [`Authorization`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.authorization)
    pub const AUTHORIZATION: Self = Self(Cow::Borrowed("authorization"));
    /// [`Connection`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.connection)
    pub const CONNECTION: Self = Self(Cow::Borrowed("connection"));
    /// [`Content-Encoding`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.content-encoding)
    pub const CONTENT_ENCODING: Self = Self(Cow::Borrowed("content-encoding"));
    /// [`Content-Language`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.content-language)
    pub const CONTENT_LANGUAGE: Self = Self(Cow::Borrowed("content-language"));
    /// [`Content-Length`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.content-length)
    pub const CONTENT_LENGTH: Self = Self(Cow::Borrowed("content-length"));
    /// [`Content-Location`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.content-location)
    pub const CONTENT_LOCATION: Self = Self(Cow::Borrowed("content-location"));
    /// [`Content-Range`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.content-range)
    pub const CONTENT_RANGE: Self = Self(Cow::Borrowed("content-range"));
    /// [`Content-Type`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.content-type)
    pub const CONTENT_TYPE: Self = Self(Cow::Borrowed("content-type"));
    /// [`Date`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.date)
    pub const DATE: Self = Self(Cow::Borrowed("date"));
    /// [`ETag`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.etag)
    pub const ETAG: Self = Self(Cow::Borrowed("etag"));
    /// [`Expect`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.expect)
    pub const EXPECT: Self = Self(Cow::Borrowed("expect"));
    /// [`From`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.from)
    pub const FROM: Self = Self(Cow::Borrowed("from"));
    /// [`Host`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.host)
    pub const HOST: Self = Self(Cow::Borrowed("host"));
    /// [`If-Match`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.if-match)
    pub const IF_MATCH: Self = Self(Cow::Borrowed("if-match"));
    /// [`If-Modified-Since`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.if-modified-since)
    pub const IF_MODIFIED_SINCE: Self = Self(Cow::Borrowed("if-modified-since"));
    /// [`If-None-Match`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.if-none-match)
    pub const IF_NONE_MATCH: Self = Self(Cow::Borrowed("if-none-match"));
    /// [`If-Range`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.if-range)
    pub const IF_RANGE: Self = Self(Cow::Borrowed("if-range"));
    /// [`If-Unmodified-Since`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.if-unmodified-since)
    pub const IF_UNMODIFIED_SINCE: Self = Self(Cow::Borrowed("if-unmodified-since"));
    /// [`Last-Modified`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.last-modified)
    pub const LAST_MODIFIED: Self = Self(Cow::Borrowed("last-modified"));
    /// [`Location`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.location)
    pub const LOCATION: Self = Self(Cow::Borrowed("location"));
    /// [`Max-Forwards`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.max-forwards)
    pub const MAX_FORWARDS: Self = Self(Cow::Borrowed("max-forwards"));
    /// [`Proxy-Authenticate`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.proxy-authenticate)
    pub const PROXY_AUTHENTICATE: Self = Self(Cow::Borrowed("proxy-authenticate"));
    /// [`Proxy-Authentication-Info`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.proxy-authentication-info)
    pub const PROXY_AUTHENTICATION_INFO: Self = Self(Cow::Borrowed("proxy-authentication-info"));
    /// [`Proxy-Authorization`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.proxy-authorization)
    pub const PROXY_AUTHORIZATION: Self = Self(Cow::Borrowed("proxy-authorization"));
    /// [`Range`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.range)
    pub const RANGE: Self = Self(Cow::Borrowed("range"));
    /// [`Referer`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.referer)
    pub const REFERER: Self = Self(Cow::Borrowed("referer"));
    /// [`Retry-After`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.retry-after)
    pub const RETRY_AFTER: Self = Self(Cow::Borrowed("retry-after"));
    /// [`Server`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.server)
    pub const SERVER: Self = Self(Cow::Borrowed("server"));
    /// [`TE`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.te)
    pub const TE: Self = Self(Cow::Borrowed("te"));
    /// [`Trailer`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.trailer)
    pub const TRAILER: Self = Self(Cow::Borrowed("trailer"));
    /// [`Transfer-Encoding`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.transfer-encoding)
    pub const TRANSFER_ENCODING: Self = Self(Cow::Borrowed("transfer-encoding"));
    /// [`Upgrade`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.upgrade)
    pub const UPGRADE: Self = Self(Cow::Borrowed("upgrade"));
    /// [`User-Agent`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.user-agent)
    pub const USER_AGENT: Self = Self(Cow::Borrowed("user-agent"));
    /// [`Vary`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.vary)
    pub const VARY: Self = Self(Cow::Borrowed("vary"));
    /// [`Via`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.via)
    pub const VIA: Self = Self(Cow::Borrowed("via"));
    /// [`WWW-Authenticate`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.www-authenticate)
    pub const WWW_AUTHENTICATE: Self = Self(Cow::Borrowed("www-authenticate"));
}

impl Deref for HeaderName {
    type Target = str;

    #[inline]
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for HeaderName {
    #[inline]
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for HeaderName {
    #[inline]
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl FromStr for HeaderName {
    type Err = InvalidHeader;

    #[inline]
    fn from_str(name: &str) -> Result<Self, InvalidHeader> {
        Self::try_from(name.to_owned())
    }
}

impl TryFrom<&'static str> for HeaderName {
    type Error = InvalidHeader;

    #[inline]
    fn try_from(value: &'static str) -> Result<Self, InvalidHeader> {
        Self::try_from(Cow::Borrowed(value))
    }
}

impl TryFrom<String> for HeaderName {
    type Error = InvalidHeader;

    #[inline]
    fn try_from(value: String) -> Result<Self, InvalidHeader> {
        Self::try_from(Cow::Owned(value))
    }
}

impl TryFrom<Cow<'static, str>> for HeaderName {
    type Error = InvalidHeader;

    #[inline]
    fn try_from(mut name: Cow<'static, str>) -> Result<Self, InvalidHeader> {
        if name.contains(|c: char| c.is_ascii_uppercase()) {
            name.to_mut().make_ascii_lowercase(); // We normalize to lowercase
        }
        if name.is_empty() {
            Err(InvalidHeader(InvalidHeaderAlt::EmptyName))
        } else {
            for c in name.chars() {
                if !matches!(c, '!' | '#' | '$' | '%' | '&' | '\'' | '*'
       | '+' | '-' | '.' | '^' | '_' | '`' | '|' | '~'
        | '0'..='9' | 'a'..='z')
                {
                    return Err(InvalidHeader(InvalidHeaderAlt::InvalidNameChar {
                        name,
                        invalid_char: c,
                    }));
                }
            }
            Ok(Self(name))
        }
    }
}

impl fmt::Display for HeaderName {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub trait IntoHeaderName {
    fn try_into(self) -> Result<HeaderName, InvalidHeader>;
}

impl IntoHeaderName for HeaderName {
    #[inline]
    fn try_into(self) -> Result<HeaderName, InvalidHeader> {
        Ok(self)
    }
}

impl<T: TryInto<HeaderName, Error = InvalidHeader>> IntoHeaderName for T {
    #[inline]
    fn try_into(self) -> Result<HeaderName, InvalidHeader> {
        self.try_into()
    }
}

/// A [header/field value](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#fields.values).
///
/// ```
/// use oxhttp::model::HeaderValue;
/// use std::str::FromStr;
///
/// assert_eq!(HeaderValue::from_str("foo")?.as_ref(), b"foo");
/// # Result::<_,Box<dyn std::error::Error>>::Ok(())
/// ```
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Hash, Default)]
pub struct HeaderValue(Cow<'static, [u8]>);

impl HeaderValue {
    #[inline]
    pub(crate) fn new_unchecked(value: impl Into<Cow<'static, [u8]>>) -> Self {
        Self(value.into())
    }

    #[inline]
    pub fn to_str(&self) -> Result<&str, Utf8Error> {
        str::from_utf8(self)
    }
}
impl Deref for HeaderValue {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for HeaderValue {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Borrow<[u8]> for HeaderValue {
    #[inline]
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl FromStr for HeaderValue {
    type Err = InvalidHeader;

    #[inline]
    fn from_str(value: &str) -> Result<Self, InvalidHeader> {
        Self::try_from(value.to_string().into_bytes())
    }
}

impl TryFrom<&'static str> for HeaderValue {
    type Error = InvalidHeader;

    #[inline]
    fn try_from(value: &str) -> Result<Self, InvalidHeader> {
        Self::try_from(value.to_owned())
    }
}

impl TryFrom<String> for HeaderValue {
    type Error = InvalidHeader;

    #[inline]
    fn try_from(value: String) -> Result<Self, InvalidHeader> {
        Self::try_from(value.into_bytes())
    }
}

impl TryFrom<Cow<'static, str>> for HeaderValue {
    type Error = InvalidHeader;

    #[inline]
    fn try_from(value: Cow<'static, str>) -> Result<Self, InvalidHeader> {
        Self::try_from(match value {
            Cow::Owned(value) => Cow::Owned(value.into_bytes()),
            Cow::Borrowed(value) => Cow::Borrowed(value.as_bytes()),
        })
    }
}

impl TryFrom<&'static [u8]> for HeaderValue {
    type Error = InvalidHeader;

    #[inline]
    fn try_from(value: &'static [u8]) -> Result<Self, InvalidHeader> {
        Cow::Borrowed(value).try_into()
    }
}

impl TryFrom<Vec<u8>> for HeaderValue {
    type Error = InvalidHeader;

    #[inline]
    fn try_from(value: Vec<u8>) -> Result<Self, InvalidHeader> {
        Cow::<'static, [u8]>::Owned(value).try_into()
    }
}

impl TryFrom<Cow<'static, [u8]>> for HeaderValue {
    type Error = InvalidHeader;

    #[inline]
    fn try_from(value: Cow<'static, [u8]>) -> Result<Self, InvalidHeader> {
        // no tab or space at the beginning
        if let Some(c) = value.first().cloned() {
            if matches!(c, b'\t' | b' ') {
                return Err(InvalidHeader(InvalidHeaderAlt::InvalidValueByte {
                    value,
                    invalid_byte: c,
                }));
            }
        }
        // no tab or space at the end
        if let Some(c) = value.last().cloned() {
            if matches!(c, b'\t' | b' ') {
                return Err(InvalidHeader(InvalidHeaderAlt::InvalidValueByte {
                    value,
                    invalid_byte: c,
                }));
            }
        }
        // no line jump
        for c in value.iter() {
            if matches!(*c, b'\r' | b'\n') {
                return Err(InvalidHeader(InvalidHeaderAlt::InvalidValueByte {
                    value: value.clone(),
                    invalid_byte: *c,
                }));
            }
        }
        Ok(HeaderValue(value))
    }
}

impl fmt::Display for HeaderValue {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}

#[derive(Debug)]
pub struct Iter<'a>(std::collections::btree_map::Iter<'a, HeaderName, HeaderValue>);

impl<'a> Iterator for Iter<'a> {
    type Item = (&'a HeaderName, &'a HeaderValue);

    #[inline]
    fn next(&mut self) -> Option<(&'a HeaderName, &'a HeaderValue)> {
        self.0.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }

    #[inline]
    fn last(self) -> Option<(&'a HeaderName, &'a HeaderValue)> {
        self.0.last()
    }
}

impl<'a> DoubleEndedIterator for Iter<'a> {
    #[inline]
    fn next_back(&mut self) -> Option<(&'a HeaderName, &'a HeaderValue)> {
        self.0.next_back()
    }
}

impl<'a> ExactSizeIterator for Iter<'a> {
    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Debug)]
pub struct IntoIter(std::collections::btree_map::IntoIter<HeaderName, HeaderValue>);

impl Iterator for IntoIter {
    type Item = (HeaderName, HeaderValue);

    #[inline]
    fn next(&mut self) -> Option<(HeaderName, HeaderValue)> {
        self.0.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }

    #[inline]
    fn last(self) -> Option<(HeaderName, HeaderValue)> {
        self.0.last()
    }
}

impl DoubleEndedIterator for IntoIter {
    #[inline]
    fn next_back(&mut self) -> Option<(HeaderName, HeaderValue)> {
        self.0.next_back()
    }
}

impl ExactSizeIterator for IntoIter {
    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }
}

/// Error returned by [`HeaderName::try_from`].
#[derive(Debug, Clone)]
pub struct InvalidHeader(InvalidHeaderAlt);

#[derive(Debug, Clone)]
enum InvalidHeaderAlt {
    EmptyName,
    InvalidNameChar {
        name: Cow<'static, str>,
        invalid_char: char,
    },
    InvalidValueByte {
        value: Cow<'static, [u8]>,
        invalid_byte: u8,
    },
}

impl fmt::Display for InvalidHeader {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            InvalidHeaderAlt::EmptyName => f.write_str("header names should not be empty"),
            InvalidHeaderAlt::InvalidNameChar { name, invalid_char } => write!(
                f,
                "The character '{invalid_char}' is not valid inside of header name '{name}'"
            ),
            InvalidHeaderAlt::InvalidValueByte {
                value,
                invalid_byte,
            } => write!(
                f,
                "The byte '{}' is not valid inside of header value '{}'",
                invalid_byte,
                String::from_utf8_lossy(value)
            ),
        }
    }
}

impl Error for InvalidHeader {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_header_name() {
        assert!(HeaderName::from_str("").is_err());
        assert!(HeaderName::from_str("ffo bar").is_err());
        assert!(HeaderName::from_str("ffo\tbar").is_err());
        assert!(HeaderName::from_str("ffo\rbar").is_err());
        assert!(HeaderName::from_str("ffo\nbar").is_err());
        assert!(HeaderName::from_str("ffoébar").is_err());
        assert!(HeaderName::from_str("foo-bar").is_ok());
    }

    #[test]
    fn validate_header_value() {
        assert!(HeaderValue::from_str("").is_ok());
        assert!(HeaderValue::from_str(" ffobar").is_err());
        assert!(HeaderValue::from_str("ffobar ").is_err());
        assert!(HeaderValue::from_str("ffo\rbar").is_err());
        assert!(HeaderValue::from_str("ffo\nbar").is_err());
        assert!(HeaderValue::from_str("ffoébar").is_ok());
    }
}
