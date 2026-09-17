#[path = "../src/cache_response.rs"]
mod cache_response;
#[path = "../src/cache_store.rs"]
mod cache_store;

use axum::body::{to_bytes, Body};
use cache_store::{CacheStore, CachedFile};
use http::{header, Method, Request};
use std::time::{Duration, Instant};
#[path = "common/fixture.rs"]
mod fixture;
use tower::ServiceExt;
use tower_http::services::ServeDir;

#[tokio::main]
async fn main() {
    let fixture = fixture::Fixture::new("response");
    let dir = &fixture.0;
    let service = ServeDir::new(dir);
    for content in [b"0123456789".as_slice(), b""] {
        std::fs::write(dir.join("file.txt"), content).unwrap();
        let response = service
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/file.txt")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let headers = response.headers().clone();
        let modified = headers[header::LAST_MODIFIED].to_str().unwrap().to_owned();
        let body = to_bytes(Body::new(response.into_body()), 1024)
            .await
            .unwrap();
        let now = Instant::now();
        let mut store = CacheStore::new(4096);
        store.insert(
            "/file.txt".into(),
            CachedFile {
                headers,
                body,
                loaded: now,
                expires: now + Duration::from_secs(10),
            },
            now,
        );
        let file = store.get("/file.txt", now).unwrap();
        for method in [Method::GET, Method::HEAD] {
            let cases = [
                (header::RANGE, "bytes=1-3"),
                (header::RANGE, "bytes=-3"),
                (header::RANGE, "bytes=3-"),
                (header::RANGE, "bytes=999-"),
                (header::RANGE, "bytes=0-1,3-4"),
                (header::RANGE, "invalid"),
                (header::IF_MODIFIED_SINCE, modified.as_str()),
                (header::IF_MODIFIED_SINCE, "Thu, 01 Jan 1970 00:00:00 GMT"),
                (header::IF_UNMODIFIED_SINCE, modified.as_str()),
                (header::IF_UNMODIFIED_SINCE, "Thu, 01 Jan 1970 00:00:00 GMT"),
                (header::IF_MODIFIED_SINCE, "invalid"),
                (header::ACCEPT, "*/*"),
            ];
            for (name, value) in cases {
                let request = Request::builder()
                    .method(method.clone())
                    .uri("/file.txt")
                    .header(name, value)
                    .body(Body::empty())
                    .unwrap();
                let mut cached = cache_response::respond(
                    &file,
                    &method,
                    request.headers(),
                    now + Duration::from_secs(2),
                );
                assert_eq!(cached.headers_mut().remove(header::AGE).unwrap(), "2");
                let original = service.clone().oneshot(request).await.unwrap();
                assert_eq!(cached.status(), original.status(), "{method} {value}");
                assert_eq!(cached.headers(), original.headers(), "{method} {value}");
                let cached = to_bytes(cached.into_body(), 1024).await.unwrap();
                let original = to_bytes(Body::new(original.into_body()), 1024)
                    .await
                    .unwrap();
                assert_eq!(cached, original, "{method} {value}");
            }
        }
    }
    println!("httpd-axum cached responses match ServeDir");
}
