#[path = "../src/cache.rs"]
mod cache;
#[path = "../src/cache_body.rs"]
mod cache_body;
#[path = "../src/cache_response.rs"]
mod cache_response;
#[path = "../src/cache_store.rs"]
mod cache_store;
#[path = "common/fixture.rs"]
mod fixture;

use axum::{
    body::{to_bytes, Body, Bytes},
    Router,
};
use http::{header, Request, StatusCode};
use http_body::{Body as HttpBody, Frame};
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::task::{Context, Poll};
use std::time::Duration;
use tower::{service_fn, ServiceExt};
use tower_http::services::ServeDir;

#[tokio::main]
async fn main() {
    for changed in [
        vec![b'b'; 200],
        vec![b'b'; 10],
        vec![b'b'; cache_store::MAX_FILE_SIZE + 1],
    ] {
        let fixture = fixture::Fixture::new("fill");
        let path = fixture.0.join("file");
        std::fs::write(&path, vec![b'a'; 100]).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let served = calls.clone();
        let service = ServeDir::new(&fixture.0);
        let expected = changed.clone();
        let service = service_fn(move |request| {
            let service = service.clone();
            let path = path.clone();
            let changed = changed.clone();
            let first = served.fetch_add(1, Ordering::Relaxed) == 0;
            async move {
                let response = service.oneshot(request).await;
                if first {
                    // Metadata is fixed, but ServeDir has not read the body.
                    if changed.len() > 100 {
                        use std::io::Write;
                        std::fs::OpenOptions::new()
                            .append(true)
                            .open(path)
                            .unwrap()
                            .write_all(&changed[100..])
                            .unwrap();
                    } else {
                        std::fs::write(path, &changed).unwrap();
                    }
                }
                response
            }
        });
        let app =
            Router::new()
                .fallback_service(service)
                .layer(axum::middleware::from_fn_with_state(
                    Arc::new(cache::Cache::new(1024 * 1024, Duration::from_secs(10))),
                    cache::Cache::serve,
                ));
        let mut expected = expected;
        if expected.len() > 100 {
            expected[..100].fill(b'a');
        }
        for index in 0..2 {
            let response = app
                .clone()
                .oneshot(Request::builder().uri("/file").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers()[header::CONTENT_LENGTH],
                if index == 0 { 100 } else { expected.len() }.to_string()
            );
            let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
            assert_eq!(body.as_ref(), expected);
        }
        assert_eq!(
            calls.load(Ordering::Relaxed),
            2,
            "a changed body must not populate the cache"
        );
    }
    let body = Body::new(Broken(false));
    let mut fallback = cache_body::collect(body, 4)
        .await
        .expect_err("read error must bypass caching");
    use http_body_util::BodyExt;
    assert_eq!(
        fallback
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        "abc"
    );
    assert!(fallback
        .frame()
        .await
        .unwrap()
        .unwrap_err()
        .to_string()
        .contains("test read failure"));
    println!("httpd-axum changing-file and read-error cache-fill tests passed");
}

struct Broken(bool);

impl HttpBody for Broken {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let frame = if std::mem::replace(&mut self.0, true) {
            Err(std::io::Error::other("test read failure"))
        } else {
            Ok(Frame::data(Bytes::from_static(b"abc")))
        };
        Poll::Ready(Some(frame))
    }
}
