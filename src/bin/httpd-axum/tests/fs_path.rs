use axum::{body::Body, Router};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tower::ServiceExt;
use tower_http::services::ServeDir;

const SAMPLES: usize = 64;
const CONTENT: &[u8] = &[b'x'; 256];

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("httpd-fs-{nonce}"));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("index.html"), CONTENT).unwrap();
        Self(dir)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn report(label: &str, samples: &[Duration]) {
    let mut nanos: Vec<_> = samples.iter().map(Duration::as_nanos).collect();
    nanos.sort_unstable();
    println!(
        "{label}: n={} mean={:.2}us p50={:.2}us p95={:.2}us",
        nanos.len(),
        nanos.iter().sum::<u128>() as f64 / nanos.len() as f64 / 1000.0,
        nanos[nanos.len() / 2] as f64 / 1000.0,
        nanos[nanos.len() * 95 / 100] as f64 / 1000.0,
    );
}

async fn pace(sparse: bool) {
    if sparse {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::main]
async fn main() {
    let fixture = Fixture::new();
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
