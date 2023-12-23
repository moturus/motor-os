use crate::model::{
    Body, ChunkedTransferPayload, HeaderName, HeaderValue, Headers, Method, Request,
    RequestBuilder, Response, Status, Url,
};
use crate::utils::invalid_data_error;
use std::cmp::min;
use std::io::{BufRead, Error, ErrorKind, Read, Result};
use std::str::{self, FromStr};

const DEFAULT_SIZE: usize = 1024;
const MAX_HEADER_SIZE: u64 = 8 * 1024;

pub fn decode_request_headers(
    reader: &mut impl BufRead,
    is_connection_secure: bool,
) -> Result<RequestBuilder> {
    // Let's read the headers
    let buffer = read_header_bytes(reader)?;
    let mut headers = [httparse::EMPTY_HEADER; DEFAULT_SIZE];
    let mut parsed_request = httparse::Request::new(&mut headers);
    if parsed_request
        .parse(&buffer)
        .map_err(invalid_data_error)?
        .is_partial()
    {
        return Err(invalid_data_error(
            "Partial HTTP headers containing two line jumps",
        ));
    }

    let method = Method::from_str(
        parsed_request
            .method
            .ok_or_else(|| invalid_data_error("No method in the HTTP request"))?,
    )
    .map_err(invalid_data_error)?;

    let path = parsed_request
        .path
        .ok_or_else(|| invalid_data_error("No path in the HTTP request"))?;
    let url = if let Some(host) = parsed_request.headers.iter().find_map(|header| {
        if header.name.eq_ignore_ascii_case("host") {
            Some(header.value)
        } else {
            None
        }
    }) {
        let host = str::from_utf8(host)
            .map_err(|e| invalid_data_error(format!("Invalid host header value: {e}")))?;
        let base_url = Url::parse(&if is_connection_secure {
            format!("https://{host}")
        } else {
            format!("http://{host}")
        })
        .map_err(|e| invalid_data_error(format!("Invalid host header value '{host}': {e}")))?;
        if path == "*" {
            base_url
        } else {
            base_url
                .join(path)
                .map_err(|e| invalid_data_error(format!("Invalid request path '{path}': {e}")))?
        }
    } else {
        Url::parse(path).map_err(|e| {
            invalid_data_error(format!(
                "No host header in HTTP request and not absolute path '{path}': {e}"
            ))
        })?
    };

    // We validate that the URL is valid
    if !url.has_authority() {
        return Err(invalid_data_error("No host header in HTTP request"));
    }
    if is_connection_secure {
        if url.scheme() != "https" {
            return Err(invalid_data_error("The HTTPS URL scheme should be 'https"));
        }
    } else if url.scheme() != "http" {
        return Err(invalid_data_error("The HTTP URL scheme should be 'http"));
    }

    let mut request = Request::builder(method, url);
    for header in parsed_request.headers {
        request.headers_mut().append(
            HeaderName::new_unchecked(header.name.to_ascii_lowercase()),
            HeaderValue::new_unchecked(header.value.to_vec()),
        );
    }
    if parsed_request.version == Some(0) {
        // Hack to fallback to default HTTP 1.0 behavior of closing connections
        if !request.headers().contains(&HeaderName::CONNECTION) {
            request.headers_mut().append(
                HeaderName::CONNECTION,
                HeaderValue::new_unchecked("close".as_bytes()),
            )
        }
    }
    Ok(request)
}

pub fn decode_request_body(
    request: RequestBuilder,
    reader: impl BufRead + 'static,
) -> Result<Request> {
    let body = decode_body(request.headers(), reader)?;
    Ok(request.with_body(body))
}

pub fn decode_response(mut reader: impl BufRead + 'static) -> Result<Response> {
    // Let's read the headers
    let buffer = read_header_bytes(&mut reader)?;
    let mut headers = [httparse::EMPTY_HEADER; DEFAULT_SIZE];
    let mut parsed_response = httparse::Response::new(&mut headers);
    if parsed_response
        .parse(&buffer)
        .map_err(invalid_data_error)?
        .is_partial()
    {
        return Err(invalid_data_error(
            "Partial HTTP headers containing two line jumps",
        ));
    }

    let status = Status::try_from(
        parsed_response
            .code
            .ok_or_else(|| invalid_data_error("No status code in the HTTP response"))?,
    )
    .map_err(invalid_data_error)?;

    // Let's build the response
    let mut response = Response::builder(status);
    for header in parsed_response.headers {
        response.headers_mut().append(
            HeaderName::new_unchecked(header.name.to_ascii_lowercase()),
            HeaderValue::new_unchecked(header.value.to_vec()),
        );
    }

    let body = decode_body(response.headers(), reader)?;
    Ok(response.with_body(body))
}

fn read_header_bytes(reader: impl BufRead) -> Result<Vec<u8>> {
    let mut reader = reader.take(2 * MAX_HEADER_SIZE); // Makes sure we do not buffer too much
    let mut buffer = Vec::with_capacity(DEFAULT_SIZE);
    loop {
        if reader.read_until(b'\n', &mut buffer)? == 0 {
            return Err(Error::new(
                ErrorKind::ConnectionAborted,
                if buffer.is_empty() {
                    "Empty HTTP request"
                } else {
                    "Interrupted HTTP request"
                },
            ));
        }
        // We normalize line ends to plain \n
        if buffer.ends_with(b"\r\n") {
            buffer.pop();
            buffer.pop();
            buffer.push(b'\n')
        }
        if buffer.len() > (MAX_HEADER_SIZE as usize) {
            return Err(invalid_data_error("The headers size should fit in 8kb"));
        }
        if buffer.ends_with(b"\n\n") {
            break; //end of buffer
        }
    }
    Ok(buffer)
}

fn decode_body(headers: &Headers, reader: impl BufRead + 'static) -> Result<Body> {
    let content_length = headers.get(&HeaderName::CONTENT_LENGTH);
    let transfer_encoding = headers.get(&HeaderName::TRANSFER_ENCODING);
    if transfer_encoding.is_some() && content_length.is_some() {
        return Err(invalid_data_error(
            "Transfer-Encoding and Content-Length should not be set at the same time",
        ));
    }

    let body = if let Some(content_length) = content_length {
        let len = content_length
            .to_str()
            .map_err(invalid_data_error)?
            .parse::<u64>()
            .map_err(invalid_data_error)?;
        Body::from_read_and_len(reader, len)
    } else if let Some(transfer_encoding) = transfer_encoding {
        if transfer_encoding.as_ref().eq_ignore_ascii_case(b"chunked") {
            Body::from_chunked_transfer_payload(ChunkedDecoder {
                reader,
                buffer: Vec::with_capacity(DEFAULT_SIZE),
                is_start: true,
                chunk_position: 1,
                chunk_size: 1,
                trailers: None,
            })
        } else {
            return Err(invalid_data_error(format!(
                "Transfer-Encoding: {} is not supported",
                transfer_encoding.to_str().map_err(invalid_data_error)?
            )));
        }
    } else {
        Body::default()
    };

    decode_content_encoding(body, headers)
}

fn decode_content_encoding(body: Body, headers: &Headers) -> Result<Body> {
    let Some(content_encoding) = headers.get(&HeaderName::CONTENT_ENCODING) else {
        return Ok(body);
    };
    match content_encoding.as_ref() {
        b"identity" => Ok(body),
        #[cfg(feature = "flate2")]
        b"gzip" => Ok(body.decode_gzip()),
        #[cfg(feature = "flate2")]
        b"deflate" => Ok(body.decode_deflate()),
        _ => Ok(body),
    }
}

struct ChunkedDecoder<R: BufRead> {
    reader: R,
    buffer: Vec<u8>,
    is_start: bool,
    chunk_position: usize,
    chunk_size: usize,
    trailers: Option<Headers>,
}

impl<R: BufRead> Read for ChunkedDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        loop {
            // In case we still have data
            if self.chunk_position < self.chunk_size {
                let inner_buf = self.reader.fill_buf()?;
                if inner_buf.is_empty() {
                    return Err(invalid_data_error(
                        "Unexpected stream end in the middle of a chunked content",
                    ));
                }
                let size = min(
                    min(buf.len(), inner_buf.len()),
                    self.chunk_size - self.chunk_position,
                );
                buf[..size].copy_from_slice(&inner_buf[..size]);
                self.reader.consume(size);
                self.chunk_position += size;
                return Ok(size);
            }

            if self.is_start {
                self.is_start = false;
            } else {
                // chunk end
                self.buffer.clear();
                self.reader.read_until(b'\n', &mut self.buffer)?;
                if self.buffer != b"\r\n" && self.buffer != b"\n" {
                    return Err(invalid_data_error("Invalid chunked element end"));
                }
            }

            // We load a new chunk
            self.buffer.clear();
            self.reader.read_until(b'\n', &mut self.buffer)?;
            self.chunk_position = 0;
            let Ok(httparse::Status::Complete((read, chunk_size))) =
                httparse::parse_chunk_size(&self.buffer)
            else {
                return Err(invalid_data_error("Invalid chunked header"));
            };
            if read != self.buffer.len() {
                return Err(invalid_data_error("Chunked header containing a line jump"));
            }
            self.chunk_size = chunk_size.try_into().map_err(invalid_data_error)?;

            if self.chunk_size == 0 {
                // we read the trailers
                self.buffer.clear();
                self.buffer.push(b'\n');
                loop {
                    if self.reader.read_until(b'\n', &mut self.buffer)? == 0 {
                        return Err(invalid_data_error("Missing chunked encoding end"));
                    }
                    if self.buffer.len() > 8 * 1024 {
                        return Err(invalid_data_error("The trailers size should fit in 8kb"));
                    }

                    if self.buffer.ends_with(b"\r\n") {
                        self.buffer.pop();
                        self.buffer.pop();
                        self.buffer.push(b'\n')
                    }
                    if self.buffer.ends_with(b"\n\n") {
                        break; //end of buffer
                    }
                }
                let mut trailers = [httparse::EMPTY_HEADER; DEFAULT_SIZE];
                let httparse::Status::Complete((read, parsed_trailers)) =
                    httparse::parse_headers(&self.buffer[1..], &mut trailers)
                        .map_err(invalid_data_error)?
                else {
                    return Err(invalid_data_error(
                        "Partial HTTP headers containing two line jumps",
                    ));
                };
                if read != self.buffer.len() - 1 {
                    return Err(invalid_data_error(
                        "Invalid data at the end of the trailer section",
                    ));
                }
                let mut trailers = Headers::new();
                for trailer in parsed_trailers {
                    trailers.append(
                        HeaderName::new_unchecked(trailer.name.to_ascii_lowercase()),
                        HeaderValue::new_unchecked(trailer.value.to_vec()),
                    );
                }
                self.trailers = Some(trailers);

                return Ok(0);
            }
        }
    }
}

impl<R: BufRead> ChunkedTransferPayload for ChunkedDecoder<R> {
    fn trailers(&self) -> Option<&Headers> {
        self.trailers.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Deref;

    #[test]
    fn decode_request_target_origin_form() -> Result<()> {
        let request = decode_request_headers(
            &mut b"GET /where?q=now HTTP/1.1\nHost: www.example.org\n\n".as_slice(),
            false,
        )?;
        assert_eq!(request.url().as_str(), "http://www.example.org/where?q=now");
        Ok(())
    }

    #[test]
    fn decode_request_target_absolute_form_with_host() -> Result<()> {
        let request = decode_request_headers(
            &mut
              b"GET http://www.example.org/pub/WWW/TheProject.html HTTP/1.1\nHost: example.com\n\n".as_slice()
            ,
            false,
        )?;
        assert_eq!(
            request.url().as_str(),
            "http://www.example.org/pub/WWW/TheProject.html"
        );
        Ok(())
    }

    #[test]
    fn decode_request_target_absolute_form_without_host() -> Result<()> {
        let request = decode_request_headers(
            &mut b"GET http://www.example.org/pub/WWW/TheProject.html HTTP/1.1\n\n".as_slice(),
            false,
        )?;
        assert_eq!(
            request.url().as_str(),
            "http://www.example.org/pub/WWW/TheProject.html"
        );
        Ok(())
    }

    #[test]
    fn decode_request_target_relative_form_without_host() {
        assert!(decode_request_headers(
            &mut b"GET /pub/WWW/TheProject.html HTTP/1.1\n\n".as_slice(),
            false,
        )
        .is_err());
    }

    #[test]
    fn decode_request_target_absolute_form_wrong_scheme() {
        assert!(decode_request_headers(
            &mut b"GET https://www.example.org/pub/WWW/TheProject.html HTTP/1.1\n\n".as_slice(),
            false,
        )
        .is_err());
        assert!(decode_request_headers(
            &mut b"GET http://www.example.org/pub/WWW/TheProject.html HTTP/1.1\n\n".as_slice(),
            true,
        )
        .is_err());
    }

    #[test]
    fn decode_invalid_request_target_relative_form_with_host() {
        assert!(decode_request_headers(
            &mut b"GET /foo<bar HTTP/1.1\nhost: www.example.com\n\n".as_slice(),
            false,
        )
        .is_err());
    }

    #[test]
    fn decode_request_target_asterisk_form() -> Result<()> {
        let request = decode_request_headers(
            &mut b"OPTIONS * HTTP/1.1\nHost: www.example.org:8001\n\n".as_slice(),
            false,
        )?;
        assert_eq!(request.url().as_str(), "http://www.example.org:8001/"); //TODO: should be http://www.example.org:8001
        Ok(())
    }

    #[test]
    fn decode_request_with_header() -> Result<()> {
        let request = decode_request_headers(
            &mut b"GET / HTTP/1.1\nHost: www.example.org:8001\nFoo: v1\nbar: vbar\nfoo: v2\n\n"
                .as_slice(),
            true,
        )?;
        assert_eq!(request.url().as_str(), "https://www.example.org:8001/");
        assert_eq!(
            request
                .header(&HeaderName::from_str("foo").unwrap())
                .unwrap()
                .as_ref(),
            b"v1, v2".as_ref()
        );
        assert_eq!(
            request
                .header(&HeaderName::from_str("Bar").unwrap())
                .unwrap()
                .as_ref(),
            b"vbar".as_ref()
        );
        Ok(())
    }

    #[test]
    fn decode_request_with_body() -> Result<()> {
        let mut read =
            b"GET / HTTP/1.1\nHost: www.example.org:8001\ncontent-length: 9\n\nfoobarbar"
                .as_slice();
        let request = decode_request_body(decode_request_headers(&mut read, false)?, read)?;
        assert_eq!(request.into_body().to_string()?, "foobarbar");
        Ok(())
    }

    #[test]
    fn decode_request_empty_header_name() {
        assert!(decode_request_headers(
            &mut b"GET / HTTP/1.1\nHost: www.example.org:8001\n: foo".as_slice(),
            false
        )
        .is_err());
    }

    #[test]
    fn decode_request_invalid_header_name_char() {
        assert!(decode_request_headers(
            &mut b"GET / HTTP/1.1\nHost: www.example.org:8001\nCont\xE9: foo".as_slice(),
            false
        )
        .is_err());
    }

    #[test]
    fn decode_request_invalid_header_value_char() {
        assert!(decode_request_headers(
            &mut b"GET / HTTP/1.1\nHost: www.example.org:8001\nCont\t: foo\rbar\r\nTest: test"
                .as_slice(),
            false
        )
        .is_err());
    }

    #[test]
    fn decode_request_empty() {
        assert_eq!(
            decode_request_headers(&mut b"".as_slice(), false)
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::ConnectionAborted)
        );
    }

    #[test]
    fn decode_request_stop_in_header() {
        assert_eq!(
            decode_request_headers(&mut b"GET /\r\n".as_slice(), false)
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::ConnectionAborted)
        );
    }

    #[test]
    fn decode_request_stop_in_body() -> Result<()> {
        let mut read =
            b"POST / HTTP/1.1\r\nhost: example.com\r\ncontent-length: 12\r\n\r\nfoobar".as_slice();
        assert_eq!(
            decode_request_body(decode_request_headers(&mut read, false)?, read)?
                .into_body()
                .to_vec()
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::ConnectionAborted)
        );
        Ok(())
    }

    #[test]
    fn decode_request_http_1_0() -> Result<()> {
        let mut read =
            b"POST http://example.com/foo HTTP/1.0\r\ncontent-length: 12\r\n\r\nfoobar".as_slice();
        let request = decode_request_body(decode_request_headers(&mut read, false)?, read)?;
        assert_eq!(request.url().as_str(), "http://example.com/foo");
        assert_eq!(
            request.header(&HeaderName::CONNECTION).unwrap().deref(),
            b"close"
        );
        Ok(())
    }

    #[test]
    fn decode_request_unsupported_transfer_encoding() -> Result<()> {
        let mut read = b"POST / HTTP/1.1\r\nhost: example.com\r\ncontent-length: 12\r\ntransfer-encoding: foo\r\n\r\nfoobar".as_slice();
        assert!(decode_request_body(decode_request_headers(&mut read, false)?, read).is_err());
        Ok(())
    }

    #[test]
    fn decode_response_without_payload() -> Result<()> {
        let response = decode_response(b"HTTP/1.1 404 Not Found\r\n\r\n".as_slice())?;
        assert_eq!(response.status(), Status::NOT_FOUND);
        assert_eq!(response.body().len(), Some(0));
        Ok(())
    }

    #[test]
    fn decode_response_with_fixed_payload() -> Result<()> {
        let response = decode_response(
            b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length:12\r\n\r\ntestbodybody"
                .as_slice(),
        )?;
        assert_eq!(response.status(), Status::OK);
        assert_eq!(
            response
                .header(&HeaderName::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            "text/plain"
        );
        assert_eq!(response.into_body().to_string()?, "testbodybody");
        Ok(())
    }

    #[test]
    fn decode_response_with_chunked_payload() -> Result<()> {
        let response = decode_response(
            b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ntransfer-encoding:chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n".as_slice()
        )?;
        assert_eq!(response.status(), Status::OK);
        assert_eq!(
            response
                .header(&HeaderName::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            "text/plain"
        );
        assert_eq!(
            response.into_body().to_string()?,
            "Wikipedia in\r\n\r\nchunks."
        );
        Ok(())
    }

    #[test]
    fn decode_response_with_trailer() -> Result<()> {
        let response = decode_response(
            b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ntransfer-encoding:chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\ntest: foo\r\n\r\n".as_slice()
        )?;
        assert_eq!(response.status(), Status::OK);
        assert_eq!(
            response
                .header(&HeaderName::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            "text/plain"
        );
        let mut buf = String::new();
        let mut body = response.into_body();
        body.read_to_string(&mut buf)?;
        assert_eq!(buf, "Wikipedia in\r\n\r\nchunks.");
        assert_eq!(
            body.trailers()
                .unwrap()
                .get(&HeaderName::from_str("test").unwrap())
                .unwrap()
                .as_ref(),
            b"foo"
        );
        Ok(())
    }

    #[test]
    #[cfg(feature = "flate2")]
    fn decode_gzip_response() -> Result<()> {
        let response = decode_response(b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-encoding: gzip\r\ncontent-length: 23\r\n\r\n\x1f\x8b\x08\x00\xac\x94\xdfd\x02\xffK\xcb\xcf\x07\x00!es\x8c\x03\x00\x00\x00".as_slice())?;
        assert_eq!(response.into_body().to_string()?, "foo");
        Ok(())
    }

    #[test]
    #[cfg(feature = "flate2")]
    fn decode_deflate_response() -> Result<()> {
        let response = decode_response(b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-encoding: deflate\r\ncontent-length: 5\r\n\r\nK\xcb\xcf\x07\x00".as_slice())?;
        assert_eq!(response.into_body().to_string()?, "foo");
        Ok(())
    }

    #[test]
    fn decode_unknown_response() -> Result<()> {
        let response = decode_response(b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-encoding: foo\r\ncontent-length: 5\r\n\r\nfoooo".as_slice())?;
        assert_eq!(
            response.headers().get(&HeaderName::CONTENT_ENCODING),
            Some(&HeaderValue::new_unchecked("foo".as_bytes()))
        );
        assert_eq!(response.into_body().to_string()?, "foooo");
        Ok(())
    }

    #[test]
    fn decode_response_with_invalid_chunk_header() -> Result<()> {
        let response = decode_response(
            b"HTTP/1.1 200 OK\r\ntransfer-encoding:chunked\r\n\r\nh\r\nWiki\r\n0\r\n\r\n"
                .as_slice(),
        )?;
        assert!(response.into_body().to_string().is_err());
        Ok(())
    }

    #[test]
    fn decode_response_with_invalid_trailer() -> Result<()> {
        let response = decode_response(
            b"HTTP/1.1 200 OK\r\ntransfer-encoding:chunked\r\n\r\nf\r\nWiki\r\n0\r\ntest\n: foo\r\n\r\n"
        .as_slice())?;
        assert!(response.into_body().to_string().is_err());
        Ok(())
    }

    #[test]
    fn decode_response_with_not_ended_trailer() -> Result<()> {
        let response = decode_response(
            b"HTTP/1.1 200 OK\r\ntransfer-encoding:chunked\r\n\r\nf\r\nWiki".as_slice(),
        )?;
        assert!(response.into_body().to_string().is_err());
        Ok(())
    }

    #[test]
    fn decode_response_empty_header_name() {
        assert!(
            decode_response(b"HTTP/1.1 200 OK\nHost: www.example.org:8001\n: foo".as_slice())
                .is_err()
        );
    }

    #[test]
    fn decode_response_invalid_header_name_char() {
        assert!(decode_response(
            b"HTTP/1.1 200 OK\nHost: www.example.org:8001\nCont\xE9: foo".as_slice()
        )
        .is_err());
    }

    #[test]
    fn decode_response_invalid_header_value_char() {
        assert!(decode_response(
            b"HTTP/1.1 200 OK\nHost: www.example.org:8001\nCont\t: foo\rbar\r\nTest: test"
                .as_slice()
        )
        .is_err());
    }

    #[test]
    fn decode_response_empty() {
        assert!(decode_response(b"".as_slice()).is_err());
    }

    #[test]
    fn decode_response_stop_in_header() {
        assert!(decode_response(b"HTTP/1.1 404 Not Found\r\n".as_slice()).is_err());
    }

    #[test]
    fn decode_response_stop_in_body() -> Result<()> {
        assert!(decode_response(
            b"HTTP/1.1 200 OK\r\ncontent-length: 12\r\n\r\nfoobar".as_slice()
        )?
        .into_body()
        .to_vec()
        .is_err());
        Ok(())
    }

    #[test]
    fn decode_response_content_length_and_transfer_encoding() {
        assert!(decode_response( b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ntransfer-encoding:chunked\r\ncontent-length: 222\r\n\r\n".as_slice()).is_err());
    }
}
