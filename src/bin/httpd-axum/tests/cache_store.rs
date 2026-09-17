#[path = "../src/cache_store.rs"]
mod cache_store;

use axum::body::Bytes;
use cache_store::{CacheStore, CachedFile, MAX_FILE_SIZE};
use http::HeaderMap;
use std::time::{Duration, Instant};

fn file(body: &'static str, loaded: Instant, expires: Instant) -> CachedFile {
    CachedFile {
        headers: HeaderMap::new(),
        body: Bytes::from_static(body.as_bytes()),
        loaded,
        expires,
    }
}

fn main() {
    let now = Instant::now();
    let later = now + Duration::from_secs(10);
    let mut cache = CacheStore::new(1200);
    cache.insert("/a".into(), file("a", now, later), now);
    cache.insert("/b".into(), file("b", now, later), now);
    let retained = cache.get("/a", now).unwrap();
    cache.insert("/c".into(), file("c", now, later), now);
    assert!(cache.get("/a", now).is_none());
    assert_eq!(retained.body, "a");
    assert_eq!(retained.loaded, now);
    assert!(cache.get("/b", now).is_some());
    assert!(cache.get("/c", later).is_none());
    cache.insert(
        "/b".into(),
        file("new", now, later + Duration::from_secs(1)),
        now,
    );
    cache.insert("/b".into(), file("stale fill", now, later), now);
    assert_eq!(cache.get("/b", later).unwrap().body, "new");
    cache.insert("/expired".into(), file("old", now, now), now);
    assert!(cache.get("/expired", now).is_none());

    let mut bounded = CacheStore::new(4 * 1024 * 1024);
    for i in 0..1025 {
        bounded.insert(format!("/{i}"), file("", now, later), now);
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
    empty.insert("/empty".into(), file("", now, later), now);
    assert!(empty.get("/empty", now).is_none());
    let mut header_heavy = file("", now, later);
    header_heavy
        .headers
        .insert("x-padding", "x".repeat(1200).parse().unwrap());
    cache.insert("/headers".into(), header_heavy, now);
    assert!(cache.get("/headers", now).is_none());
    churn(now);
    println!("httpd-axum cache storage tests passed");
}

fn churn(now: Instant) {
    let later = now + Duration::from_secs(10);
    let mut cache = CacheStore::new(MAX_FILE_SIZE + 1024);
    for _ in 0..3 {
        for i in 0..400 {
            cache.insert(format!("/{i:03}"), file("", now, later), now);
        }
        cache.insert(
            "/large".into(),
            CachedFile {
                headers: HeaderMap::new(),
                body: Bytes::from(vec![0; MAX_FILE_SIZE]),
                loaded: now,
                expires: later,
            },
            now,
        );
        for i in 0..400 {
            assert!(cache.get(&format!("/{i:03}"), now).is_none());
        }
        assert!(cache.get("/large", now).is_some());
        assert!(cache.get("/large", later).is_none());
    }
    let mut cache = CacheStore::new(1200);
    cache.insert("/stay".into(), file("stay", now, later), now);
    for i in 0..4096 {
        let expires = now + Duration::from_micros(i + 1);
        cache.insert("/churn".into(), file("churn", now, expires), now);
        assert!(cache.get("/churn", expires).is_none());
    }
    assert!(cache.get("/stay", now).is_some());
    cache.insert("/new".into(), file("new", now, later), now);
    // Replacement is a new insertion and becomes newest in FIFO order.
    cache.insert(
        "/stay".into(),
        file("replaced", now, later + Duration::from_secs(1)),
        now,
    );
    cache.insert("/third".into(), file("third", now, later), now);
    assert!(cache.get("/new", now).is_none());
    assert_eq!(cache.get("/stay", now).unwrap().body, "replaced");
}
