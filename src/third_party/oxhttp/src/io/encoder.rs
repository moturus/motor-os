use crate::model::{Body, HeaderName, Headers, Method, Request, Response, Status};
use crate::utils::invalid_input_error;
use std::io::{copy, Read, Result, Write};

pub fn encode_request<W: Write>(request: &mut Request, mut writer: W) -> Result<W> {
    if !request.url().username().is_empty() || request.url().password().is_some() {
        return Err(invalid_input_error(
            "Username and password are not allowed in HTTP URLs",
        ));
    }
    let host = request
        .url()
        .host_str()
        .ok_or_else(|| invalid_input_error("No host provided"))?;

    if let Some(query) = request.url().query() {
        write!(
            &mut writer,
            "{} {}?{} HTTP/1.1\r\n",
            request.method(),
            request.url().path(),
            query
        )?;
    } else {
        write!(
            &mut writer,
            "{} {} HTTP/1.1\r\n",
            request.method(),
            request.url().path(),
        )?;
    }

    // host
    if let Some(port) = request.url().port() {
        write!(writer, "host: {host}:{port}\r\n")?;
    } else {
        write!(writer, "host: {host}\r\n")?;
    }

    // headers
    encode_headers(request.headers(), &mut writer)?;

    // body with content-length if existing
    let must_include_body = does_request_must_include_body(request.method());
    encode_body(request.body_mut(), &mut writer, must_include_body)?;

    Ok(writer)
}

pub fn encode_response<W: Write>(response: &mut Response, mut writer: W) -> Result<W> {
    write!(&mut writer, "HTTP/1.1 {}\r\n", response.status())?;
    encode_headers(response.headers(), &mut writer)?;
    let must_include_body = does_response_must_include_body(response.status());
    encode_body(response.body_mut(), &mut writer, must_include_body)?;
    Ok(writer)
}

fn encode_headers(headers: &Headers, writer: &mut impl Write) -> Result<()> {
    for (name, value) in headers {
        if !is_forbidden_name(name) {
            write!(writer, "{name}: ")?;
            writer.write_all(value)?;
            write!(writer, "\r\n")?;
        }
    }
    Ok(())
}

fn encode_body(body: &mut Body, writer: &mut impl Write, must_include_body: bool) -> Result<()> {
    if let Some(length) = body.len() {
        if must_include_body || length > 0 {
            write!(writer, "content-length: {length}\r\n\r\n")?;
            copy(body, writer)?;
        } else {
            write!(writer, "\r\n")?;
        }
    } else {
        write!(writer, "transfer-encoding: chunked\r\n\r\n")?;
        let mut buffer = vec![b'\0'; 4096];
        loop {
            let mut read = 0;
            while read < 1024 {
                // We try to avoid too small chunks
                let new_read = body.read(&mut buffer[read..])?;
                if new_read == 0 {
                    break; // EOF
                }
                read += new_read;
            }
            write!(writer, "{read:X}\r\n")?;
            writer.write_all(&buffer[..read])?;
            if read == 0 {
                break; // Done
            } else {
                write!(writer, "\r\n")?;
            }
        }
        if let Some(trailers) = body.trailers() {
            encode_headers(trailers, writer)?;
        }
        write!(writer, "\r\n")?;
    }
    Ok(())
}

/// Checks if it is a [forbidden header name](https://fetch.spec.whatwg.org/#forbidden-header-name)
///
/// We removed some of them not managed by this library (`Access-Control-Request-Headers`, `Access-Control-Request-Method`, `DNT`, `Cookie`, `Cookie2`, `Referer`, `Proxy-`, `Sec-`, `Via`...)
fn is_forbidden_name(header: &HeaderName) -> bool {
    header.as_ref() == "accept-charset"
        || *header == HeaderName::ACCEPT_ENCODING
        || header.as_ref() == "access-control-request-headers"
        || header.as_ref() == "access-control-request-method"
        || *header == HeaderName::CONNECTION
        || *header == HeaderName::CONTENT_LENGTH
        || *header == HeaderName::DATE
        || *header == HeaderName::EXPECT
        || *header == HeaderName::HOST
        || header.as_ref() == "keep-alive"
        || header.as_ref() == "origin"
        || *header == HeaderName::TE
        || *header == HeaderName::TRAILER
        || *header == HeaderName::TRANSFER_ENCODING
        || *header == HeaderName::UPGRADE
        || *header == HeaderName::VIA
}

fn does_request_must_include_body(method: &Method) -> bool {
    *method == Method::POST || *method == Method::PUT
}

fn does_response_must_include_body(status: Status) -> bool {
    !(status.is_informational() || status == Status::NO_CONTENT || status == Status::NOT_MODIFIED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ChunkedTransferPayload, Headers, Method, Status};
    use std::str;

    #[test]
    fn user_password_not_allowed_in_request() {
        let mut buffer = Vec::new();
        assert!(encode_request(
            &mut Request::builder(Method::GET, "http://foo@example.com/".parse().unwrap()).build(),
            &mut buffer
        )
        .is_err());
        assert!(encode_request(
            &mut Request::builder(Method::GET, "http://foo:bar@example.com/".parse().unwrap())
                .build(),
            &mut buffer
        )
        .is_err());
    }

    #[test]
    fn encode_get_request() -> Result<()> {
        let mut request = Request::builder(
            Method::GET,
            "http://example.com:81/foo/bar?query#fragment"
                .parse()
                .unwrap(),
        )
        .with_header(HeaderName::ACCEPT, "application/json")
        .unwrap()
        .build();
        let buffer = encode_request(&mut request, Vec::new())?;
        assert_eq!(
            str::from_utf8(&buffer).unwrap(),
            "GET /foo/bar?query HTTP/1.1\r\nhost: example.com:81\r\naccept: application/json\r\n\r\n"
        );
        Ok(())
    }

    #[test]
    fn encode_post_request() -> Result<()> {
        let mut request = Request::builder(
            Method::POST,
            "http://example.com/foo/bar?query#fragment".parse().unwrap(),
        )
        .with_header(HeaderName::ACCEPT, "application/json")
        .unwrap()
        .with_body(b"testbodybody".as_ref());
        let buffer = encode_request(&mut request, Vec::new())?;
        assert_eq!(
            str::from_utf8(&buffer).unwrap(),
            "POST /foo/bar?query HTTP/1.1\r\nhost: example.com\r\naccept: application/json\r\ncontent-length: 12\r\n\r\ntestbodybody"
        );
        Ok(())
    }

    #[test]
    fn encode_post_request_without_body() -> Result<()> {
        let mut request = Request::builder(
            Method::POST,
            "http://example.com/foo/bar?query#fragment".parse().unwrap(),
        )
        .build();
        let buffer = encode_request(&mut request, Vec::new())?;
        assert_eq!(
            str::from_utf8(&buffer).unwrap(),
            "POST /foo/bar?query HTTP/1.1\r\nhost: example.com\r\ncontent-length: 0\r\n\r\n"
        );
        Ok(())
    }

    #[test]
    fn encode_post_request_with_chunked() -> Result<()> {
        let mut trailers = Headers::new();
        trailers.append(HeaderName::CONTENT_LANGUAGE, "foo".parse().unwrap());

        let mut request = Request::builder(
            Method::POST,
            "http://example.com/foo/bar?query#fragment".parse().unwrap(),
        )
        .with_body(Body::from_chunked_transfer_payload(SimpleTrailers {
            read: b"testbodybody".as_slice(),
            trailers,
        }));
        let buffer = encode_request(&mut request, Vec::new())?;
        assert_eq!(
            str::from_utf8(&buffer).unwrap(),
            "POST /foo/bar?query HTTP/1.1\r\nhost: example.com\r\ntransfer-encoding: chunked\r\n\r\nC\r\ntestbodybody\r\n0\r\ncontent-language: foo\r\n\r\n"
        );
        Ok(())
    }

    #[test]
    fn encode_response_ok() -> Result<()> {
        let mut response = Response::builder(Status::OK)
            .with_header(HeaderName::ACCEPT, "application/json")
            .unwrap()
            .with_body("test test2");
        let buffer = encode_response(&mut response, Vec::new())?;
        assert_eq!(
            str::from_utf8(&buffer).unwrap(),
            "HTTP/1.1 200 OK\r\naccept: application/json\r\ncontent-length: 10\r\n\r\ntest test2"
        );
        Ok(())
    }

    #[test]
    fn encode_response_not_found() -> Result<()> {
        let mut response = Response::builder(Status::NOT_FOUND).build();
        let buffer = encode_response(&mut response, Vec::new())?;
        assert_eq!(
            str::from_utf8(&buffer).unwrap(),
            "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n"
        );
        Ok(())
    }

    #[test]
    fn encode_response_custom_code() -> Result<()> {
        let mut response = Response::builder(Status::try_from(499).unwrap()).build();
        let buffer = encode_response(&mut response, Vec::new())?;
        assert_eq!(
            str::from_utf8(&buffer).unwrap(),
            "HTTP/1.1 499 \r\ncontent-length: 0\r\n\r\n"
        );
        Ok(())
    }

    struct SimpleTrailers {
        read: &'static [u8],
        trailers: Headers,
    }

    impl Read for SimpleTrailers {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            self.read.read(buf)
        }
    }

    impl ChunkedTransferPayload for SimpleTrailers {
        fn trailers(&self) -> Option<&Headers> {
            Some(&self.trailers)
        }
    }
}
