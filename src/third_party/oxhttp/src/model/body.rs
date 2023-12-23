use crate::model::Headers;
#[cfg(feature = "flate2")]
use flate2::read::{DeflateDecoder, GzDecoder};
use std::fmt;
use std::io::{Cursor, Error, ErrorKind, Read, Result};

/// A request or response [body](https://httpwg.org/http-core/draft-ietf-httpbis-messaging-latest.html#message.body).
///
/// It implements the [`Read`] API.
pub struct Body(BodyAlt);

enum BodyAlt {
    SimpleOwned(Cursor<Vec<u8>>),
    SimpleBorrowed(&'static [u8]),
    Sized {
        content: Box<dyn Read>,
        total_len: u64,
        consumed_len: u64,
    },
    Chunked(Box<dyn ChunkedTransferPayload>),
    #[cfg(feature = "flate2")]
    DecodingDeflate(DeflateDecoder<Box<Body>>),
    #[cfg(feature = "flate2")]
    DecodingGzip(GzDecoder<Box<Body>>),
}

impl Body {
    /// Creates a new body from a [`Read`] implementation.
    ///
    /// If the body is sent as an HTTP request or response it will be streamed using [chunked transfer encoding](https://httpwg.org/http-core/draft-ietf-httpbis-messaging-latest.html#chunked.encoding).
    #[inline]
    pub fn from_read(read: impl Read + 'static) -> Self {
        Self::from_chunked_transfer_payload(SimpleChunkedTransferEncoding(read))
    }

    #[inline]
    pub(crate) fn from_read_and_len(read: impl Read + 'static, len: u64) -> Self {
        Self(BodyAlt::Sized {
            total_len: len,
            consumed_len: 0,
            content: Box::new(read.take(len)),
        })
    }

    /// Creates a [chunked transfer encoding](https://httpwg.org/http-core/draft-ietf-httpbis-messaging-latest.html#chunked.encoding) body with optional [trailers](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#trailer.fields).
    #[inline]
    pub fn from_chunked_transfer_payload(payload: impl ChunkedTransferPayload + 'static) -> Self {
        Self(BodyAlt::Chunked(Box::new(payload)))
    }

    #[cfg(feature = "flate2")]
    pub(crate) fn decode_gzip(self) -> Self {
        Self(BodyAlt::DecodingGzip(GzDecoder::new(Box::new(self))))
    }

    #[cfg(feature = "flate2")]
    pub(crate) fn decode_deflate(self) -> Self {
        Self(BodyAlt::DecodingDeflate(DeflateDecoder::new(Box::new(
            self,
        ))))
    }

    /// The number of bytes in the body (if known).
    #[allow(clippy::len_without_is_empty)]
    #[inline]
    pub fn len(&self) -> Option<u64> {
        match &self.0 {
            BodyAlt::SimpleOwned(d) => Some(d.get_ref().len().try_into().unwrap()),
            BodyAlt::SimpleBorrowed(d) => Some(d.len().try_into().unwrap()),
            BodyAlt::Sized { total_len, .. } => Some(*total_len),
            BodyAlt::Chunked(_) => None,
            #[cfg(feature = "flate2")]
            BodyAlt::DecodingDeflate(_) | BodyAlt::DecodingGzip(_) => None,
        }
    }

    /// Returns the chunked transfer encoding trailers if they exists and are already received.
    /// You should fully consume the body before attempting to fetch them.
    #[inline]
    pub fn trailers(&self) -> Option<&Headers> {
        match &self.0 {
            BodyAlt::SimpleOwned(_) | BodyAlt::SimpleBorrowed(_) | BodyAlt::Sized { .. } => None,
            BodyAlt::Chunked(c) => c.trailers(),
            #[cfg(feature = "flate2")]
            BodyAlt::DecodingDeflate(c) => c.get_ref().trailers(),
            #[cfg(feature = "flate2")]
            BodyAlt::DecodingGzip(c) => c.get_ref().trailers(),
        }
    }

    /// Reads the full body into a vector.
    ///
    /// <div class="warning">Beware of the body size!</div>
    ///
    /// ```
    /// use oxhttp::model::Body;
    /// use std::io::Cursor;
    ///
    /// let mut body = Body::from_read(b"foo".as_ref());
    /// assert_eq!(&body.to_vec()?, b"foo");
    /// # Result::<_,Box<dyn std::error::Error>>::Ok(())
    /// ```
    #[inline]
    pub fn to_vec(mut self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.read_to_end(&mut buf)?;
        Ok(buf)
    }

    /// Reads the full body into a string.
    ///
    /// <div class="warning">Beware of the body size!</div>    
    ///
    /// ```
    /// use oxhttp::model::Body;
    /// use std::io::Cursor;
    ///
    /// let mut body = Body::from_read(b"foo".as_ref());
    /// assert_eq!(&body.to_string()?, "foo");
    /// # Result::<_,Box<dyn std::error::Error>>::Ok(())
    /// ```
    #[inline]
    pub fn to_string(mut self) -> Result<String> {
        let mut buf = String::new();
        self.read_to_string(&mut buf)?;
        Ok(buf)
    }

    fn debug_fields<'a, 'b, 'c>(
        &'b self,
        s: &'c mut fmt::DebugStruct<'b, 'a>,
    ) -> &'c mut fmt::DebugStruct<'b, 'a> {
        match &self.0 {
            BodyAlt::SimpleOwned(d) => s.field("content-length", &d.get_ref().len()),
            BodyAlt::SimpleBorrowed(d) => s.field("content-length", &d.len()),
            BodyAlt::Sized { total_len, .. } => s.field("content-length", total_len),
            BodyAlt::Chunked(_) => s.field("transfer-encoding", &"chunked"),
            #[cfg(feature = "flate2")]
            BodyAlt::DecodingDeflate(inner) => inner
                .get_ref()
                .debug_fields(s.field("content-encoding", &"deflate")),
            #[cfg(feature = "flate2")]
            BodyAlt::DecodingGzip(inner) => inner
                .get_ref()
                .debug_fields(s.field("content-encoding", &"gzip")),
        }
    }
}

impl Read for Body {
    #[inline]
    fn read(&mut self, mut buf: &mut [u8]) -> Result<usize> {
        match &mut self.0 {
            BodyAlt::SimpleOwned(c) => c.read(buf),
            BodyAlt::SimpleBorrowed(c) => c.read(buf),
            BodyAlt::Sized {
                content,
                consumed_len,
                total_len,
            } => {
                let remaining_size = *total_len - *consumed_len;
                if remaining_size < u64::try_from(buf.len()).unwrap() {
                    buf = &mut buf[..usize::try_from(remaining_size).unwrap()];
                }
                if buf.is_empty() {
                    return Ok(0); // Nothing to read
                }
                let read = content.read(buf)?;
                *consumed_len += u64::try_from(read).unwrap();
                if read == 0 {
                    // We are missing some bytes
                    return Err(Error::new(ErrorKind::ConnectionAborted, format!("The body was expected to contain {total_len} bytes but we have been able to only read {consumed_len}")));
                }
                Ok(read)
            }
            BodyAlt::Chunked(inner) => inner.read(buf),
            #[cfg(feature = "flate2")]
            BodyAlt::DecodingDeflate(inner) => inner.read(buf),
            #[cfg(feature = "flate2")]
            BodyAlt::DecodingGzip(inner) => inner.read(buf),
        }
    }
}

impl Default for Body {
    #[inline]
    fn default() -> Self {
        b"".as_ref().into()
    }
}

impl From<Vec<u8>> for Body {
    #[inline]
    fn from(data: Vec<u8>) -> Self {
        Self(BodyAlt::SimpleOwned(Cursor::new(data)))
    }
}

impl From<String> for Body {
    #[inline]
    fn from(data: String) -> Self {
        data.into_bytes().into()
    }
}

impl From<&'static [u8]> for Body {
    #[inline]
    fn from(data: &'static [u8]) -> Self {
        Self(BodyAlt::SimpleBorrowed(data))
    }
}

impl From<&'static str> for Body {
    #[inline]
    fn from(data: &'static str) -> Self {
        data.as_bytes().into()
    }
}

impl fmt::Debug for Body {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.debug_fields(&mut f.debug_struct("Body")).finish()
    }
}

/// Trait to give to [`Body::from_chunked_transfer_payload`] a body to serialize
/// as [chunked transfer encoding](https://httpwg.org/http-core/draft-ietf-httpbis-messaging-latest.html#chunked.encoding).
///
/// It allows to provide [trailers](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#trailer.fields) to serialize.
pub trait ChunkedTransferPayload: Read {
    /// The [trailers](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#trailer.fields) to serialize.
    fn trailers(&self) -> Option<&Headers>;
}

struct SimpleChunkedTransferEncoding<R: Read>(R);

impl<R: Read> Read for SimpleChunkedTransferEncoding<R> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.0.read(buf)
    }
}

impl<R: Read> ChunkedTransferPayload for SimpleChunkedTransferEncoding<R> {
    #[inline]
    fn trailers(&self) -> Option<&Headers> {
        None
    }
}
