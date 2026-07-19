use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use std::path::PathBuf;
use tower_http::services::ServeDir;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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

    #[arg(long)]
    ssl_cert: Option<String>,
    #[arg(long)]
    ssl_key: Option<String>,
}

// Intercept Ctrl+C ourselves if the OS does not do it for us.
fn input_listener() {
    use std::io::Read;

    loop {
        let mut input = [0_u8; 16];
        let sz = std::io::stdin().read(&mut input).unwrap();
        for b in &input[0..sz] {
            if *b == 3 {
                println!("\ncaught ^C: exiting.");
                std::process::exit(0);
            }
        }
    }
}

#[tokio::main]
async fn main() {
    std::thread::spawn(input_listener);
    let args = Args::parse();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let app = Router::new()
        .fallback_service(ServeDir::new(&args.dir))
        .layer(axum::middleware::from_fn(
            |req: axum::extract::Request, next: axum::middleware::Next| async move {
                let uri = req.uri().clone();
                let method = req.method().clone();
                let start = std::time::Instant::now();
                let res = next.run(req).await;
                let latency = start.elapsed();
                tracing::info!("{} {} {} ({}us)", method, uri, res.status().as_u16(), latency.as_micros());
                res
            },
        ));

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

        tracing::debug!("listening on {}", args.addr);
        axum_server::bind_rustls(args.addr, config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    } else {
        tracing::debug!("listening on {}", args.addr);
        let listener = tokio::net::TcpListener::bind(args.addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    };
}
