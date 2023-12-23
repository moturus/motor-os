use crate::model::header::IntoHeaderName;
use crate::model::{Body, HeaderName, HeaderValue, Headers, InvalidHeader, Method, Url};

/// A HTTP request.
///
/// ```
/// use oxhttp::model::{Request, Method, HeaderName, Body};
///
/// let request = Request::builder(Method::POST, "http://example.com:80/foo".parse()?)
///     .with_header(HeaderName::CONTENT_TYPE, "application/json")?
///     .with_body("{\"foo\": \"bar\"}");
///
/// assert_eq!(*request.method(), Method::POST);
/// assert_eq!(request.url().as_str(), "http://example.com/foo");
/// assert_eq!(request.header(&HeaderName::CONTENT_TYPE).unwrap().as_ref(), b"application/json");
/// assert_eq!(&request.into_body().to_vec()?, b"{\"foo\": \"bar\"}");
/// # Result::<_,Box<dyn std::error::Error>>::Ok(())
/// ```
#[derive(Debug)]
pub struct Request {
    method: Method,
    url: Url,
    headers: Headers,
    body: Body,
}

impl Request {
    #[inline]
    pub fn builder(method: Method, url: Url) -> RequestBuilder {
        RequestBuilder {
            method,
            url,
            headers: Headers::new(),
        }
    }

    #[inline]
    pub fn method(&self) -> &Method {
        &self.method
    }

    #[inline]
    pub fn url(&self) -> &Url {
        &self.url
    }

    #[inline]
    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    #[inline]
    pub fn headers_mut(&mut self) -> &mut Headers {
        &mut self.headers
    }

    #[inline]
    pub fn header(&self, name: &HeaderName) -> Option<&HeaderValue> {
        self.headers.get(name)
    }

    #[inline]
    pub fn append_header(
        &mut self,
        name: impl IntoHeaderName,
        value: impl TryInto<HeaderValue, Error = InvalidHeader>,
    ) -> Result<(), InvalidHeader> {
        self.headers_mut()
            .append(name.try_into()?, value.try_into()?);
        Ok(())
    }

    #[inline]
    pub fn body(&self) -> &Body {
        &self.body
    }

    #[inline]
    pub fn body_mut(&mut self) -> &mut Body {
        &mut self.body
    }

    #[inline]
    pub fn into_body(self) -> Body {
        self.body
    }
}

/// Builder for [`Request`]
pub struct RequestBuilder {
    method: Method,
    url: Url,
    headers: Headers,
}

impl RequestBuilder {
    #[inline]
    pub fn method(&self) -> &Method {
        &self.method
    }

    #[inline]
    pub fn url(&self) -> &Url {
        &self.url
    }

    #[inline]
    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    #[inline]
    pub fn headers_mut(&mut self) -> &mut Headers {
        &mut self.headers
    }

    #[inline]
    pub fn header(&self, name: &HeaderName) -> Option<&HeaderValue> {
        self.headers.get(name)
    }

    #[inline]
    pub fn with_header(
        mut self,
        name: impl IntoHeaderName,
        value: impl TryInto<HeaderValue, Error = InvalidHeader>,
    ) -> Result<Self, InvalidHeader> {
        self.headers_mut()
            .append(name.try_into()?, value.try_into()?);
        Ok(self)
    }

    #[inline]
    pub fn with_body(self, body: impl Into<Body>) -> Request {
        Request {
            method: self.method,
            url: self.url,
            headers: self.headers,
            body: body.into(),
        }
    }

    #[inline]
    pub fn build(self) -> Request {
        self.with_body(Body::default())
    }
}
