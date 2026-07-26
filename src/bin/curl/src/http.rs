use std::io::{BufRead, BufReader, Read, Write};

use crate::{CurlError, CurlResult, HttpsUrl};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_HEADERS: usize = 200;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Response {
    pub status: u16,
    pub redirect_url: String,
    pub body_size: u64,
}

pub fn write_request(stream: &mut impl Write, url: &HttpsUrl, user_agent: &str) -> CurlResult<()> {
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\n\
         Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        url.request_target(),
        url.authority(),
        user_agent
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| CurlError::from_io(error, CurlError::SEND, "failed sending HTTP request"))
}

pub fn receive_response(
    stream: &mut impl Read,
    url: &HttpsUrl,
    output: &mut impl Write,
) -> CurlResult<Response> {
    let mut reader = BufReader::new(stream);
    let head = loop {
        let head = read_head(&mut reader)?;
        if (100..200).contains(&head.status) && head.status != 101 {
            continue;
        }
        break head;
    };

    let body_size = if (100..200).contains(&head.status) || head.status == 204 || head.status == 304
    {
        0
    } else if head.chunked {
        copy_chunked(&mut reader, output)?
    } else if let Some(length) = head.content_length {
        copy_exact(&mut reader, output, length)?
    } else {
        copy_to_end(&mut reader, output)?
    };
    let redirect_url = head
        .location
        .as_deref()
        .and_then(|location| url.redirect(location).ok())
        .map_or_else(String::new, |redirect| redirect.as_str().to_owned());
    Ok(Response {
        status: head.status,
        redirect_url,
        body_size,
    })
}

struct Head {
    status: u16,
    content_length: Option<u64>,
    chunked: bool,
    location: Option<String>,
}

fn read_head(reader: &mut impl BufRead) -> CurlResult<Head> {
    let mut consumed = 0;
    if reader
        .fill_buf()
        .map_err(|error| CurlError::from_io(error, CurlError::RECEIVE, "failed reading response"))?
        .is_empty()
    {
        return Err(CurlError::new(
            CurlError::EMPTY_REPLY,
            "server returned an empty response",
        ));
    }
    let status_line = read_line(reader, &mut consumed)?;
    let status = parse_status(&status_line)?;
    let mut content_length = None;
    let mut transfer_encoding = None;
    let mut location = None;

    for count in 0..=MAX_HEADERS {
        let line = read_line(reader, &mut consumed)?;
        if line.is_empty() {
            if transfer_encoding.is_some() && content_length.is_some() {
                return Err(receive_error(
                    "response has both Transfer-Encoding and Content-Length",
                ));
            }
            return Ok(Head {
                status,
                content_length,
                chunked: transfer_encoding.is_some(),
                location,
            });
        }
        if count == MAX_HEADERS {
            return Err(receive_error("response has too many headers"));
        }
        let (name, value) = parse_header(&line)?;
        match name.as_str() {
            "content-length" => {
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| receive_error("invalid Content-Length"))?;
                if content_length
                    .replace(parsed)
                    .is_some_and(|old| old != parsed)
                {
                    return Err(receive_error("conflicting Content-Length headers"));
                }
            }
            "transfer-encoding" => {
                if !value.eq_ignore_ascii_case("chunked") {
                    return Err(receive_error("unsupported Transfer-Encoding"));
                }
                if transfer_encoding.replace(value).is_some() {
                    return Err(receive_error("duplicate Transfer-Encoding header"));
                }
            }
            "location" if location.is_none() => location = Some(value),
            _ => {}
        }
    }
    unreachable!()
}

fn read_line(reader: &mut impl BufRead, consumed: &mut usize) -> CurlResult<Vec<u8>> {
    let mut line = Vec::new();
    let count = reader.read_until(b'\n', &mut line).map_err(|error| {
        CurlError::from_io(error, CurlError::RECEIVE, "failed reading response")
    })?;
    if count == 0 {
        return Err(receive_error("response ended before the header block"));
    }
    *consumed += count;
    if *consumed > MAX_HEADER_BYTES {
        return Err(receive_error("response headers are too large"));
    }
    if !line.ends_with(b"\r\n") {
        return Err(receive_error("response header line is not CRLF terminated"));
    }
    line.truncate(line.len() - 2);
    Ok(line)
}

fn parse_status(line: &[u8]) -> CurlResult<u16> {
    if line.len() < 12
        || (!line.starts_with(b"HTTP/1.1 ") && !line.starts_with(b"HTTP/1.0 "))
        || !line[9..12].iter().all(u8::is_ascii_digit)
        || line.get(12).is_some_and(|byte| *byte != b' ')
    {
        return Err(receive_error("invalid HTTP status line"));
    }
    Ok(u16::from(line[9] - b'0') * 100
        + u16::from(line[10] - b'0') * 10
        + u16::from(line[11] - b'0'))
}

fn parse_header(line: &[u8]) -> CurlResult<(String, String)> {
    let colon = line
        .iter()
        .position(|byte| *byte == b':')
        .ok_or_else(|| receive_error("malformed response header"))?;
    let name = &line[..colon];
    let value = &line[colon + 1..];
    if name.is_empty() || !name.iter().all(|byte| is_token(*byte)) {
        return Err(receive_error("invalid response header name"));
    }
    if value
        .iter()
        .any(|byte| (*byte < b' ' && *byte != b'\t') || *byte == 0x7f)
    {
        return Err(receive_error("invalid response header value"));
    }
    let value = std::str::from_utf8(value)
        .map_err(|_| receive_error("non-UTF-8 response header"))?
        .trim_matches([' ', '\t'])
        .to_owned();
    Ok((String::from_utf8_lossy(name).to_ascii_lowercase(), value))
}

fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn copy_exact(
    reader: &mut impl Read,
    output: &mut impl Write,
    mut remaining: u64,
) -> CurlResult<u64> {
    let total = remaining;
    let mut buffer = [0; 16 * 1024];
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64)).unwrap();
        let count = reader.read(&mut buffer[..wanted]).map_err(|error| {
            CurlError::from_io(error, CurlError::RECEIVE, "failed reading response body")
        })?;
        if count == 0 {
            return Err(receive_error("response body ended before Content-Length"));
        }
        write_body(output, &buffer[..count])?;
        remaining -= count as u64;
    }
    Ok(total)
}

fn copy_to_end(reader: &mut impl Read, output: &mut impl Write) -> CurlResult<u64> {
    let mut total = 0_u64;
    let mut buffer = [0; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer).map_err(|error| {
            CurlError::from_io(error, CurlError::RECEIVE, "failed reading response body")
        })?;
        if count == 0 {
            return Ok(total);
        }
        write_body(output, &buffer[..count])?;
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| receive_error("response body is too large"))?;
    }
}

fn copy_chunked(reader: &mut impl BufRead, output: &mut impl Write) -> CurlResult<u64> {
    let mut total = 0_u64;
    loop {
        let mut consumed = 0;
        let line = read_line(reader, &mut consumed)?;
        let size_text = line.split(|byte| *byte == b';').next().unwrap_or_default();
        let size_text = std::str::from_utf8(size_text)
            .map_err(|_| receive_error("invalid chunk size"))?
            .trim();
        let size =
            u64::from_str_radix(size_text, 16).map_err(|_| receive_error("invalid chunk size"))?;
        if size == 0 {
            read_trailers(reader)?;
            return Ok(total);
        }
        copy_exact(reader, output, size)?;
        let mut ending = [0; 2];
        reader.read_exact(&mut ending).map_err(|error| {
            CurlError::from_io(error, CurlError::RECEIVE, "failed reading chunk ending")
        })?;
        if ending != *b"\r\n" {
            return Err(receive_error("invalid chunk ending"));
        }
        total = total
            .checked_add(size)
            .ok_or_else(|| receive_error("response body is too large"))?;
    }
}

fn read_trailers(reader: &mut impl BufRead) -> CurlResult<()> {
    let mut consumed = 0;
    for count in 0..=MAX_HEADERS {
        let line = read_line(reader, &mut consumed)?;
        if line.is_empty() {
            return Ok(());
        }
        if count == MAX_HEADERS {
            return Err(receive_error("response has too many trailers"));
        }
        parse_header(&line)?;
    }
    unreachable!()
}

fn write_body(output: &mut impl Write, bytes: &[u8]) -> CurlResult<()> {
    output.write_all(bytes).map_err(|error| {
        CurlError::from_io(
            error,
            CurlError::LOCAL_WRITE,
            "failed writing response body",
        )
    })
}

fn receive_error(message: impl Into<String>) -> CurlError {
    CurlError::new(CurlError::RECEIVE, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receive(response: &[u8]) -> CurlResult<(Response, Vec<u8>)> {
        let url = HttpsUrl::parse("https://example.test/old/path").unwrap();
        let mut body = Vec::new();
        let response = receive_response(&mut &*response, &url, &mut body)?;
        Ok((response, body))
    }

    #[test]
    fn renders_fixed_get_request() {
        let url = HttpsUrl::parse("https://example.test:8443/a?q=1").unwrap();
        let mut request = Vec::new();
        write_request(&mut request, &url, "lorry/0.1.0").unwrap();
        assert_eq!(
            String::from_utf8(request).unwrap(),
            "GET /a?q=1 HTTP/1.1\r\nHost: example.test:8443\r\n\
             User-Agent: lorry/0.1.0\r\nAccept: */*\r\n\
             Accept-Encoding: identity\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn receives_content_length_and_redirect() {
        let (response, body) = receive(
            b"HTTP/1.1 302 Found\r\nContent-Length: 4\r\n\
              Location: ../new\r\n\r\nbody",
        )
        .unwrap();
        assert_eq!(response.status, 302);
        assert_eq!(response.redirect_url, "https://example.test/new");
        assert_eq!(response.body_size, 4);
        assert_eq!(body, b"body");
    }

    #[test]
    fn receives_chunked_and_close_delimited_bodies() {
        let (response, body) = receive(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
              3\r\nabc\r\n2;extension=x\r\nde\r\n0\r\nTrailer: yes\r\n\r\n",
        )
        .unwrap();
        assert_eq!(response.body_size, 5);
        assert_eq!(body, b"abcde");

        let (response, body) =
            receive(b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nclose body").unwrap();
        assert_eq!(response.body_size, 10);
        assert_eq!(body, b"close body");
    }

    #[test]
    fn handles_interim_and_bodyless_responses() {
        let (response, body) = receive(
            b"HTTP/1.1 100 Continue\r\nX-Test: yes\r\n\r\n\
              HTTP/1.1 204 No Content\r\nContent-Length: 12\r\n\r\n",
        )
        .unwrap();
        assert_eq!(response.status, 204);
        assert_eq!(response.body_size, 0);
        assert!(body.is_empty());
    }

    #[test]
    fn rejects_ambiguous_malformed_and_truncated_responses() {
        for response in [
            &b""[..],
            &b"NOT HTTP\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\n\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\
                Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nbody"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                2\r\na\r\n0\r\n\r\n"[..],
        ] {
            assert!(receive(response).is_err());
        }
    }
}
