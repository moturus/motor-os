use axum::{body::Body, Router};
use std::time::{Duration, Instant};
#[path = "common/fixture.rs"]
mod fixture;
#[path = "common/report.rs"]
mod report;
use fixture::Fixture;
use report::report;
use tokio::io::AsyncReadExt;
use tower::ServiceExt;
use tower_http::services::ServeDir;

const SAMPLES: usize = 64;
const CONTENT: &[u8] = &[b'x'; 256];

async fn pace(sparse: bool) {
    if sparse {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::main]
async fn main() {
    let fixture = Fixture::new("fs");
    std::fs::write(fixture.0.join("index.html"), CONTENT).unwrap();
    let path = fixture.0.join("index.html");
    let app = Router::new().fallback_service(ServeDir::new(&fixture.0));

    for sparse in [false, true] {
        let label = if sparse { "sparse" } else { "burst" };
        let mut stages: [Vec<Duration>; 5] = std::array::from_fn(|_| Vec::new());
        // These reproduce ServeDir's three sequential filesystem operations,
        // followed by its deferred body read. Warm-up samples are excluded.
        for i in 0..SAMPLES + 4 {
            pace(sparse).await;
            let start = Instant::now();
            assert!(!tokio::fs::metadata(&path).await.unwrap().is_dir());
            let stat = Instant::now();
            let mut file = tokio::fs::File::open(&path).await.unwrap();
            let open = Instant::now();
            assert_eq!(file.metadata().await.unwrap().len(), CONTENT.len() as u64);
            let metadata = Instant::now();
            let mut body = Vec::new();
            file.read_to_end(&mut body).await.unwrap();
            let read = Instant::now();
            assert_eq!(body, CONTENT);
            if i >= 4 {
                for (samples, duration) in stages.iter_mut().zip([
                    stat - start,
                    open - stat,
                    metadata - open,
                    metadata - start,
                    read - metadata,
                ]) {
                    samples.push(duration);
                }
            }
        }
        for (name, samples) in ["path-stat", "open", "file-stat", "prepare-fs", "read"]
            .iter()
            .zip(&stages)
        {
            report(&format!("{label} {name}"), samples);
        }

        let mut preparation = Vec::new();
        let mut complete = Vec::new();
        for i in 0..SAMPLES + 4 {
            pace(sparse).await;
            let request = http::Request::builder()
                .uri("/index.html")
                .body(Body::empty())
                .unwrap();
            let start = Instant::now();
            let response = app.clone().oneshot(request).await.unwrap();
            let prepared = start.elapsed();
            assert_eq!(response.status(), http::StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), CONTENT.len())
                .await
                .unwrap();
            let finished = start.elapsed();
            assert_eq!(&body[..], CONTENT);
            if i >= 4 {
                preparation.push(prepared);
                complete.push(finished);
            }
        }
        report(&format!("{label} ServeDir prepare"), &preparation);
        report(
            &format!("{label} ServeDir with body (no network)"),
            &complete,
        );

        let mut batched = Vec::new();
        for i in 0..SAMPLES + 4 {
            pace(sparse).await;
            let path = path.clone();
            let start = Instant::now();
            tokio::task::spawn_blocking(move || {
                assert!(!std::fs::metadata(&path).unwrap().is_dir());
                let file = std::fs::File::open(path).unwrap();
                assert_eq!(file.metadata().unwrap().len(), CONTENT.len() as u64);
            })
            .await
            .unwrap();
            if i >= 4 {
                batched.push(start.elapsed());
            }
        }
        report(&format!("{label} batched prepare-fs"), &batched);
    }
    println!("httpd-axum filesystem path tests passed; timings are diagnostic, not thresholds");
}
