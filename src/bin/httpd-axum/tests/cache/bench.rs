#[path = "../common/report.rs"]
mod report;
use crate::common::{request, Server};
use report::report;
use std::io::BufReader;
use std::time::{Duration, Instant};

pub fn run() {
    for cached in [false, true] {
        let args: &[&str] = if cached { &[] } else { &["--cache=off"] };
        let mut server = Server::start(Some("httpd_axum=debug"), args);
        let content = vec![b'x'; 256];
        std::fs::write(server.directory.join("index.html"), &content).unwrap();
        let mut io = BufReader::new(server.connect());
        for sparse in [false, true] {
            let mut prepared = Vec::new();
            let mut complete = Vec::new();
            for i in 0..68 {
                if sparse {
                    std::thread::sleep(Duration::from_millis(20));
                }
                let start = Instant::now();
                let response = request(&mut io, "GET", "/index.html", "");
                let elapsed = start.elapsed();
                assert_eq!(response.status, 200);
                assert_eq!(response.body, content);
                // Drain each log event so the diagnostic itself cannot fill the
                // child's stdout pipe and block a request worker.
                let line = server.next_log();
                let time = line
                    .split_once("prepare_us=")
                    .unwrap()
                    .1
                    .split_whitespace()
                    .next()
                    .unwrap()
                    .parse::<u64>()
                    .unwrap();
                if i >= 4 {
                    prepared.push(Duration::from_micros(time));
                    complete.push(elapsed);
                }
            }
            let label = format!(
                "cache={} {}",
                if cached { "on" } else { "off" },
                if sparse { "sparse" } else { "burst" }
            );
            report(&format!("{label} prepare"), &prepared);
            report(&format!("{label} client"), &complete);
        }
        drop(io);
        server.stop();
    }
}
