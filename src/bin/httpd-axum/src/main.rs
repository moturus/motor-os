use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use std::path::PathBuf;
use tower_http::services::ServeDir;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod connections;

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

    let app = Router::new()
        .fallback_service(ServeDir::new(&args.dir))
        .layer(axum::middleware::from_fn(
            |req: axum::extract::Request, next: axum::middleware::Next| async move {
                if !tracing::enabled!(tracing::Level::DEBUG) {
                    return next.run(req).await;
                }
                let uri = req.uri().clone();
                let method = req.method().clone();
                let start = std::time::Instant::now();
                let res = next.run(req).await;
                let latency = start.elapsed();
                // The streaming body has not been read or transmitted yet.
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
        axum_server::from_tcp_rustls(listener, config)
            .map(|acceptor| acceptor.acceptor(admission))
            .serve(app.into_make_service())
            .await
            .unwrap();
    } else {
        let listener = std::net::TcpListener::bind(args.addr).unwrap();
        tracing::info!("listening on {}", listener.local_addr().unwrap());
        axum_server::from_tcp(listener)
            .acceptor(admission)
            .serve(app.into_make_service())
            .await
            .unwrap();
    };
}
