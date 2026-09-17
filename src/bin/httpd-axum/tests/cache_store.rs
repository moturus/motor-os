#[path = "../src/cache_store.rs"]
mod cache_store;

use axum::body::Bytes;
use cache_store::{CacheStore, CachedFile, MAX_FILE_SIZE};
use http::HeaderMap;
use std::time::{Duration, Instant};

fn file(body: &'static str, expires: Instant) -> CachedFile {
    CachedFile {
        headers: HeaderMap::new(),
        body: Bytes::from_static(body.as_bytes()),
        loaded: expires - Duration::from_secs(10),
        expires,
    }
}

fn main() {
    let now = Instant::now();
    let later = now + Duration::from_secs(10);
    let mut cache = CacheStore::new(1200);
    cache.insert("/a".into(), file("a", later), now);
    cache.insert("/b".into(), file("b", later), now);
    let retained = cache.get("/a", now).unwrap();
    cache.insert("/c".into(), file("c", later), now);
    assert!(cache.get("/a", now).is_none());
    assert_eq!(retained.body, "a");
    assert_eq!(retained.loaded, now);
    assert!(cache.get("/b", now).is_some());
    assert!(cache.get("/c", later).is_none());
    cache.insert(
        "/b".into(),
        file("new", later + Duration::from_secs(1)),
        now,
    );
    cache.insert("/b".into(), file("stale fill", later), now);
    assert_eq!(cache.get("/b", later).unwrap().body, "new");
    cache.insert("/expired".into(), file("old", now), now);
    assert!(cache.get("/expired", now).is_none());

    let mut bounded = CacheStore::new(4 * 1024 * 1024);
    for i in 0..1025 {
        bounded.insert(format!("/{i}"), file("", later), now);
    }
    assert!(bounded.get("/0", now).is_none());
    assert!(bounded.get("/1024", now).is_some());
    bounded.insert(
        "/large".into(),
        CachedFile {
            headers: HeaderMap::new(),
            body: Bytes::from(vec![0; MAX_FILE_SIZE + 1]),
            loaded: now,
            expires: later,
        },
        now,
    );
    assert!(bounded.get("/large", now).is_none());

    let mut empty = CacheStore::new(0);
    empty.insert("/empty".into(), file("", later), now);
    assert!(empty.get("/empty", now).is_none());
    let mut header_heavy = file("", later);
    header_heavy
        .headers
        .insert("x-padding", "x".repeat(1200).parse().unwrap());
    cache.insert("/headers".into(), header_heavy, now);
    assert!(cache.get("/headers", now).is_none());
    println!("httpd-axum cache storage tests passed");
}
