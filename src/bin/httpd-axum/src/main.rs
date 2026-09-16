use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use tower_http::services::ServeDir;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod cache;
mod cache_response;
mod cache_store;
mod connections;

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CacheMode {
    On,
    Off,
}

#[cfg(target_os = "motor")]
fn motor_getrandom(dest: &mut [u8]) -> Result<(), getrandom::Error> {
    moto_rt::fill_random_bytes(dest);
    Ok(())
}

#[cfg(target_os = "motor")]
getrandom::register_custom_getrandom!(motor_getrandom);

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    addr: std::net::SocketAddr,
    #[arg(short, long)]
    dir: String, // The directory to serve content from.

    #[arg(long, requires = "ssl_key")]
    ssl_cert: Option<String>,
    #[arg(long, requires = "ssl_cert")]
    ssl_key: Option<String>,

    /// Maximum admitted TCP connections, including TLS handshakes and idle clients.
    #[arg(long, default_value = "128")]
    max_active_connections: std::num::NonZeroU32,

    /// HTTP/1.1 header and initial protocol-detection deadlines, in seconds.
    #[arg(long, default_value = "10")]
    max_header_deadline_sec: std::num::NonZeroU32,

    /// Cache small file responses in memory; use --cache=off for immediate freshness.
    #[arg(long, value_enum, default_value = "on")]
    cache: CacheMode,
    /// Maximum age of a cached representation, measured from the start of its load.
    #[arg(long, default_value = "10")]
    cache_timeout_sec: std::num::NonZeroU32,
    /// Cache budget in MiB, including keys and response metadata.
    #[arg(long, default_value = "4")]
    cache_size_mb: std::num::NonZeroU32,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut app = Router::new().fallback_service(ServeDir::new(&args.dir));
    if args.cache == CacheMode::On {
        let budget = usize::try_from(u64::from(args.cache_size_mb.get()) * 1024 * 1024)
            .expect("cache budget exceeds address space");
        let cache = std::sync::Arc::new(cache::Cache::new(
            budget,
            std::time::Duration::from_secs(args.cache_timeout_sec.get().into()),
        ));
        app = app.layer(axum::middleware::from_fn_with_state(
            cache,
            cache::Cache::serve,
        ));
    }
    let app = app.layer(axum::middleware::from_fn(
        |req: axum::extract::Request, next: axum::middleware::Next| async move {
            if !tracing::enabled!(tracing::Level::DEBUG) {
                return next.run(req).await;
            }
            let uri = req.uri().clone();
            let method = req.method().clone();
            let start = std::time::Instant::now();
            let res = next.run(req).await;
            let latency = start.elapsed();
            // Cache fills include body reads; streamed bodies and transmission
            // happen after response preparation.
            tracing::debug!(
                %method,
                %uri,
                status = res.status().as_u16(),
                prepare_us = latency.as_micros(),
                "response prepared"
            );
            res
        },
    ));

    let admission = connections::ConnectionLimit::new(args.max_active_connections.get());
    let deadline = std::time::Duration::from_secs(args.max_header_deadline_sec.get().into());
    if let Some(ssl_cert) = args.ssl_cert.as_ref() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .unwrap();
        let config = RustlsConfig::from_pem_file(
            PathBuf::from(ssl_cert),
            PathBuf::from(args.ssl_key.as_ref().unwrap()),
        )
        .await
        .unwrap();

        let listener = std::net::TcpListener::bind(args.addr).unwrap();
        tracing::info!("listening on {}", listener.local_addr().unwrap());
        let mut server = axum_server::from_tcp_rustls(listener, config).map(|acceptor| {
            connections::HeaderDeadline::new(acceptor.acceptor(admission), deadline)
        });
        configure_headers(&mut server, deadline);
        server.serve(app.into_make_service()).await.unwrap();
    } else {
        let listener = std::net::TcpListener::bind(args.addr).unwrap();
        tracing::info!("listening on {}", listener.local_addr().unwrap());
        let mut server = axum_server::from_tcp(listener)
            .acceptor(connections::HeaderDeadline::new(admission, deadline));
        configure_headers(&mut server, deadline);
        server.serve(app.into_make_service()).await.unwrap();
    };
}

fn configure_headers<A>(server: &mut axum_server::Server<A>, deadline: std::time::Duration) {
    server
        .http_builder()
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(deadline);
}
