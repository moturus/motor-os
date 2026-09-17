#[path = "../src/rejections.rs"]
mod rejections;

use rejections::Rejections;
use std::time::{Duration, Instant};

fn main() {
    let now = Instant::now();
    let mut rejections = Rejections::default();
    assert_eq!(rejections.record(now), Some((1, 1)));
    for _ in 0..1000 {
        assert_eq!(rejections.record(now + Duration::from_secs(4)), None);
    }
    assert_eq!(
        rejections.record(now + Duration::from_secs(5)),
        Some((1001, 1002))
    );
    assert_eq!(rejections.record(now + Duration::from_secs(5)), None);
    assert_eq!(
        rejections.record(now + Duration::from_secs(15)),
        Some((2, 1004))
    );
    let mut other_listener = Rejections::default();
    assert_eq!(other_listener.record(now), Some((1, 1)));
    println!("httpd-axum rejection accounting and rate limiting tests passed");
}
