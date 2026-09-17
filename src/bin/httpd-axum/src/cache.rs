use crate::cache_response;
use crate::cache_store::{CacheStore, CachedFile, MAX_FILE_SIZE};
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use http::{header, HeaderMap, Method, StatusCode};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

pub struct Cache {
    files: Mutex<CacheStore>,
    ttl: Duration,
    fills: Semaphore,
}

impl Cache {
    pub fn new(budget: usize, ttl: Duration) -> Self {
        Self {
            files: Mutex::new(CacheStore::new(budget)),
            ttl,
            // Concurrent misses must not each allocate an unbounded file body.
            fills: Semaphore::new((budget / MAX_FILE_SIZE).clamp(1, 8)),
        }
    }

    pub async fn serve(State(cache): State<Arc<Self>>, req: Request, next: Next) -> Response {
        if !matches!(*req.method(), Method::GET | Method::HEAD)
            || req.uri().path().len() > 4096
            || bypass(req.headers())
        {
            return next.run(req).await;
        }
        let started = Instant::now();
        let hit = cache.files.lock().unwrap().get(req.uri().path(), started);
        if let Some(file) = hit {
            return cache_response::respond(&file, req.method(), req.headers(), started);
        }
        // Cache whole representations; a range or conditional miss retains
        // ServeDir's streaming and validation behavior without a second fetch.
        if req.method() != Method::GET
            || [
                header::RANGE,
                header::IF_MODIFIED_SINCE,
                header::IF_UNMODIFIED_SINCE,
            ]
            .iter()
            .any(|name| req.headers().contains_key(name))
        {
            return next.run(req).await;
        }
        let Ok(_permit) = cache.fills.try_acquire() else {
            return next.run(req).await;
        };
        let path = req.uri().path().to_owned();
        let response = next.run(req).await;
        let length = response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());
        let Some(length) = length.filter(|length| *length <= MAX_FILE_SIZE) else {
            return response;
        };
        if response.status() != StatusCode::OK {
            return response;
        }

        let (parts, body) = response.into_parts();
        let body = match crate::cache_body::collect(body, length).await {
            Ok(body) => body,
            Err(body) => return Response::from_parts(parts, body),
        };
        cache.files.lock().unwrap().insert(
            path,
            CachedFile {
                headers: parts.headers.clone(),
                body: body.clone(),
                loaded: started,
                expires: started + cache.ttl,
            },
            Instant::now(),
        );
        Response::from_parts(parts, body.into())
    }
}

fn bypass(headers: &HeaderMap) -> bool {
    [header::CACHE_CONTROL, header::PRAGMA]
        .iter()
        .any(|header| {
            headers
                .get_all(header)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .flat_map(|value| value.split(','))
                .any(|directive| {
                    let (name, value) = directive.split_once('=').unwrap_or((directive, ""));
                    let name = name.trim();
                    name.eq_ignore_ascii_case("no-cache")
                        || (*header == header::CACHE_CONTROL
                            && (name.eq_ignore_ascii_case("no-store")
                                || (name.eq_ignore_ascii_case("max-age")
                                    && value.trim().trim_matches('"').parse::<u64>() == Ok(0))))
                })
        })
}
