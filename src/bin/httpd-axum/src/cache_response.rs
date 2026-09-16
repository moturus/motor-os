use crate::cache_store::CachedFile;
use axum::body::Body;
use axum::response::Response;
use http::{header, HeaderMap, Method, StatusCode};
use std::time::SystemTime;

fn date(headers: &HeaderMap, name: http::HeaderName) -> Option<SystemTime> {
    httpdate::parse_http_date(headers.get(name)?.to_str().ok()?).ok()
}

fn empty(status: StatusCode) -> Response {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .unwrap()
}

pub fn respond(file: &CachedFile, method: &Method, headers: &HeaderMap) -> Response {
    let conditional = headers.contains_key(header::IF_UNMODIFIED_SINCE)
        || headers.contains_key(header::IF_MODIFIED_SINCE);
    let modified = conditional
        .then(|| date(&file.headers, header::LAST_MODIFIED))
        .flatten();
    if let Some(since) = date(headers, header::IF_UNMODIFIED_SINCE) {
        if modified.is_none_or(|modified| modified > since) {
            return empty(StatusCode::PRECONDITION_FAILED);
        }
    }
    if let Some(since) = date(headers, header::IF_MODIFIED_SINCE) {
        if modified.is_some_and(|modified| modified <= since) {
            return empty(StatusCode::NOT_MODIFIED);
        }
    }

    let mut response = Response::new(Body::empty());
    *response.headers_mut() = file.headers.clone();
    let size = file.body.len();
    if let Some(range) = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
    {
        let ranges = http_range_header::parse_range_header(range)
            .and_then(|range| range.validate(size as u64));
        // Match ServeDir: single ranges are supported; multipart ranges are 416.
        if let Ok(ranges) = &ranges {
            if ranges.len() == 1 {
                let range = &ranges[0];
                let bytes = if size == 0 {
                    file.body.clone()
                } else {
                    file.body
                        .slice(*range.start() as usize..=*range.end() as usize)
                };
                *response.status_mut() = StatusCode::PARTIAL_CONTENT;
                response.headers_mut().insert(
                    header::CONTENT_RANGE,
                    format!("bytes {}-{}/{size}", range.start(), range.end())
                        .parse()
                        .unwrap(),
                );
                response
                    .headers_mut()
                    .insert(header::CONTENT_LENGTH, bytes.len().into());
                if method != Method::HEAD {
                    *response.body_mut() = Body::from(bytes);
                }
                return response;
            }
        }
        *response.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
        response.headers_mut().remove(header::CONTENT_LENGTH);
        response.headers_mut().insert(
            header::CONTENT_RANGE,
            format!("bytes */{size}").parse().unwrap(),
        );
        if ranges.is_ok_and(|ranges| ranges.len() > 1) {
            *response.body_mut() = Body::from("Cannot serve multipart range requests");
        }
        return response;
    }
    if method != Method::HEAD {
        *response.body_mut() = Body::from(file.body.clone());
    }
    response
}
