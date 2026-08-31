use std::env;
use std::io::{self, Write};
use std::thread;

use rust_analyzer_smoke::process::MAX_STDERR_LEN;
use rust_analyzer_smoke::transport::write_frame;
use serde_json::json;

fn main() {
    let mut args = env::args();
    let _program = args.next();
    if args.next().as_deref() != Some("--fake-child") {
        eprintln!("rust-analyzer smoke harness is not implemented yet");
        std::process::exit(2);
    }
    match args.next().as_deref() {
        Some("message") => write_frame(io::stdout(), &json!({"ready": true})).unwrap(),
        Some("partial") => {
            io::stdout()
                .write_all(b"Content-Length: 2\r\n\r\n{")
                .unwrap();
        }
        Some("stderr") => {
            let mut stderr = io::stderr().lock();
            stderr.write_all(&vec![b'x'; MAX_STDERR_LEN * 2]).unwrap();
            stderr.write_all(b"stderr-tail-marker").unwrap();
            drop(stderr);
            write_frame(io::stdout(), &json!({"ready": true})).unwrap();
        }
        Some("hang") => loop {
            thread::park();
        },
        _ => std::process::exit(2),
    }
}
