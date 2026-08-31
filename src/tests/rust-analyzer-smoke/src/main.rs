use std::env;
use std::io::{self, Write};
use std::thread;

use rust_analyzer_smoke::process::MAX_STDERR_LEN;
use rust_analyzer_smoke::transport::{FrameReader, write_frame};
use serde_json::{Value, json};

fn main() {
    let mut args = env::args();
    let _program = args.next();
    match args.next().as_deref() {
        Some("--fake-child") => fake_child(args.next().as_deref()),
        None => {
            if let Err(error) = rust_analyzer_smoke::smoke::run() {
                eprintln!("rust-analyzer-smoke: {error}");
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("usage: rust-analyzer-smoke");
            std::process::exit(2);
        }
    }
}

fn fake_child(mode: Option<&str>) {
    match mode {
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
        Some("lifecycle") => lifecycle(0),
        Some("lifecycle-error") => lifecycle(9),
        _ => std::process::exit(2),
    }
}

fn lifecycle(exit_code: i32) {
    let mut input = FrameReader::new(io::stdin());
    let mut output = io::stdout().lock();
    let initialize = input.read().unwrap().unwrap();
    write_frame(
        &mut output,
        &json!({
            "jsonrpc": "2.0",
            "id": "server-request",
            "method": "window/workDoneProgress/create"
        }),
    )
    .unwrap();
    let reply = input.read().unwrap().unwrap();
    if reply["id"] != "server-request" || reply["result"] != Value::Null {
        std::process::exit(3);
    }
    for method in [
        "textDocument/publishDiagnostics",
        "$/progress",
        "experimental/serverStatus",
    ] {
        write_frame(
            &mut output,
            &json!({"jsonrpc": "2.0", "method": method, "params": {}}),
        )
        .unwrap();
    }
    write_frame(
        &mut output,
        &json!({"jsonrpc": "2.0", "id": initialize["id"], "result": {"ready": true}}),
    )
    .unwrap();

    let shutdown = input.read().unwrap().unwrap();
    if shutdown["method"] != "shutdown" {
        std::process::exit(4);
    }
    write_frame(
        &mut output,
        &json!({"jsonrpc": "2.0", "id": shutdown["id"], "result": null}),
    )
    .unwrap();
    if input.read().unwrap().unwrap()["method"] != "exit" {
        std::process::exit(5);
    }
    if exit_code != 0 {
        eprintln!("fake lifecycle failure marker");
        std::process::exit(exit_code);
    }
}
