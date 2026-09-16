use crate::cache_response;
use crate::cache_store::{CacheStore, CachedFile, MAX_FILE_SIZE};
use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::{header, Method, StatusCode};
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
        if !matches!(*req.method(), Method::GET | Method::HEAD) || req.uri().path().len() > 4096 {
            return next.run(req).await;
        }
        let started = Instant::now();
        let hit = cache.files.lock().unwrap().get(req.uri().path(), started);
        if let Some(file) = hit {
            return cache_response::respond(&file, req.method(), req.headers());
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
        let body = match to_bytes(body, MAX_FILE_SIZE).await {
            Ok(body) if body.len() == length => body,
            _ => {
                tracing::warn!("file changed size or could not be read during cache fill");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        cache.files.lock().unwrap().insert(
            path,
            CachedFile {
                headers: parts.headers.clone(),
                body: body.clone(),
                expires: started + cache.ttl,
            },
            Instant::now(),
        );
        Response::from_parts(parts, body.into())
    }
}
