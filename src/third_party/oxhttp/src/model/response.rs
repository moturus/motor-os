use crate::model::header::IntoHeaderName;
use crate::model::{Body, HeaderName, HeaderValue, Headers, InvalidHeader, Status};

/// A HTTP response.
///
/// ```
/// use oxhttp::model::{HeaderName, Body, Response, Status};
///
/// let response = Response::builder(Status::OK)
///     .with_header(HeaderName::CONTENT_TYPE, "application/json")?
///     .with_header("X-Custom", "foo")?
///     .with_body("{\"foo\": \"bar\"}");
///
/// assert_eq!(response.status(), Status::OK);
/// assert_eq!(response.header(&HeaderName::CONTENT_TYPE).unwrap().as_ref(), b"application/json");
/// assert_eq!(&response.into_body().to_vec()?, b"{\"foo\": \"bar\"}");
/// # Result::<_,Box<dyn std::error::Error>>::Ok(())
/// ```
#[derive(Debug)]
pub struct Response {
    status: Status,
    headers: Headers,
    body: Body,
}

impl Response {
    #[inline]
    pub fn builder(status: Status) -> ResponseBuilder {
        ResponseBuilder {
            status,
            headers: Headers::new(),
        }
    }

    #[inline]
    pub fn status(&self) -> Status {
        self.status
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

/// Builder for [`Response`]
pub struct ResponseBuilder {
    status: Status,
    headers: Headers,
}

impl ResponseBuilder {
    #[inline]
    pub fn status(&self) -> Status {
        self.status
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
    pub fn with_body(self, body: impl Into<Body>) -> Response {
        Response {
            status: self.status,
            headers: self.headers,
            body: body.into(),
        }
    }

    #[inline]
    pub fn build(self) -> Response {
        self.with_body(Body::default())
    }
}
