use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use clap::{CommandFactory, Parser, ValueEnum};
use std::path::PathBuf;
use tower_http::services::ServeDir;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod cache;
mod cache_body;
mod cache_response;
mod cache_store;
mod connections;
mod redirect;
mod rejections;

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

    /// Listen on HTTP port 80 and redirect to this exact HTTPS URL; requires TLS on 443.
    #[arg(long, requires = "ssl_cert")]
    http_redirect_url: Option<redirect::RedirectUrl>,

    /// Disable request logs on stdout (enabled by default).
    #[arg(long)]
    no_request_log: bool,

    /// Maximum TCP connections per listener, including TLS handshakes and idle clients.
    #[arg(long, default_value = "128")]
    max_active_connections: std::num::NonZeroU32,

    /// First request head/HTTP/1 idle timeout and HTTP/2 PING interval/ACK timeout, in seconds.
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
async fn main() -> std::io::Result<()> {
    let args = Args::parse();
    if args.http_redirect_url.is_some() && args.addr.port() != 443 {
        Args::command()
            .error(
                clap::error::ErrorKind::ArgumentConflict,
                "--http-redirect-url requires --addr on port 443",
            )
            .exit();
    }

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
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
    if !args.no_request_log {
        app = app.layer(axum::middleware::from_fn(log_request));
    }

    let admission = connections::ConnectionLimit::new(args.max_active_connections.get(), "content");
    let deadline = std::time::Duration::from_secs(args.max_header_deadline_sec.get().into());
    if let Some(ssl_cert) = args.ssl_cert.as_ref() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .unwrap();
        let config = RustlsConfig::from_pem_file(
            PathBuf::from(ssl_cert),
            PathBuf::from(args.ssl_key.as_ref().unwrap()),
        )
        .await?;

        let listener = std::net::TcpListener::bind(args.addr)?;
        // Bind both sockets before reporting readiness. A required redirect
        // listener must not silently disappear when its port is unavailable.
        let redirect_server = if let Some(url) = args.http_redirect_url {
            let mut address = args.addr;
            address.set_port(80);
            let redirect_listener = std::net::TcpListener::bind(address).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!("cannot bind HTTP redirect listener at {address}: {error}"),
                )
            })?;
            let mut server = axum_server::from_tcp(redirect_listener).acceptor(
                connections::HeaderDeadline::new(
                    connections::ConnectionLimit::new(
                        args.max_active_connections.get(),
                        "redirect",
                    ),
                    deadline,
                ),
            );
            configure_timeouts(&mut server, deadline);
            let mut redirect_app = url.router();
            if !args.no_request_log {
                redirect_app = redirect_app.layer(axum::middleware::from_fn(log_request));
            }
            Some((server, redirect_app, address))
        } else {
            None
        };
        tracing::info!("listening on {}", listener.local_addr()?);
        let mut server = axum_server::from_tcp_rustls(listener, config).map(|acceptor| {
            connections::HeaderDeadline::new(acceptor.acceptor(admission), deadline)
        });
        configure_timeouts(&mut server, deadline);
        if let Some((redirect_server, redirect_app, address)) = redirect_server {
            tracing::info!("HTTP redirect on {address}");
            tokio::try_join!(
                server.serve(app.into_make_service()),
                redirect_server.serve(redirect_app.into_make_service()),
            )?;
        } else {
            server.serve(app.into_make_service()).await?;
        }
    } else {
        let listener = std::net::TcpListener::bind(args.addr)?;
        tracing::info!("listening on {}", listener.local_addr()?);
        let mut server = axum_server::from_tcp(listener)
            .acceptor(connections::HeaderDeadline::new(admission, deadline));
        configure_timeouts(&mut server, deadline);
        server.serve(app.into_make_service()).await?;
    };
    Ok(())
}

fn configure_timeouts<A>(server: &mut axum_server::Server<A>, deadline: std::time::Duration) {
    server
        .http_builder()
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(deadline);
    // Hyper probes idle HTTP/2 connections too. A completed request must not
    // let an unresponsive peer retain an admission permit indefinitely.
    server
        .http_builder()
        .http2()
        .timer(hyper_util::rt::TokioTimer::new())
        .keep_alive_interval(deadline)
        .keep_alive_timeout(deadline);
}

async fn log_request(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if !tracing::enabled!(tracing::Level::INFO) {
        return next.run(req).await;
    }
    let uri = req.uri().clone();
    let method = req.method().clone();
    let start = std::time::Instant::now();
    let response = next.run(req).await;
    // Preparation includes cache fills, but not streamed reads or transmission.
    tracing::info!(
        %method, %uri, status = response.status().as_u16(),
        prepare_us = start.elapsed().as_micros(), "response prepared"
    );
    response
}
