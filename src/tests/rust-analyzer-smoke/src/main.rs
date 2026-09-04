use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use rust_analyzer_smoke::process::MAX_STDERR_LEN;
use rust_analyzer_smoke::transport::{FrameReader, write_frame};
use serde_json::{Value, json};

fn main() {
    if let Some((lorry, log)) = wrapper_paths() {
        cargo_wrapper(&lorry, &log);
    }
    let mut args = env::args();
    let _program = args.next();
    match args.next().as_deref() {
        Some("--fake-child") => fake_child(args.next().as_deref()),
        Some("--lorry") => {
            let Some(lorry) = args.next() else {
                eprintln!("usage: rust-analyzer-smoke --lorry PATH");
                std::process::exit(2);
            };
            if args.next().is_some() {
                eprintln!("usage: rust-analyzer-smoke --lorry PATH");
                std::process::exit(2);
            }
            if let Err(error) = rust_analyzer_smoke::lorry::run(Path::new(&lorry)) {
                eprintln!("rust-analyzer-smoke: {error}");
                std::process::exit(1);
            }
        }
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

fn wrapper_paths() -> Option<(PathBuf, PathBuf)> {
    let program = env::args_os().next()?;
    let directory = Path::new(&program).parent()?;
    (Path::new(&program).file_name()? == "cargo").then(|| {
        let lorry = fs::read_to_string(directory.join("lorry-path")).unwrap();
        (PathBuf::from(lorry.trim()), directory.join("invocations"))
    })
}

fn cargo_wrapper(lorry: &Path, log: &Path) -> ! {
    let arguments = env::args_os().skip(1).collect::<Vec<OsString>>();
    let environment = [
        "RUSTUP_TOOLCHAIN",
        "RUSTUP_AUTO_INSTALL",
        "CARGO_NET_OFFLINE",
        "CARGO_LOG",
        "__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS",
        "RUSTC_BOOTSTRAP",
    ]
    .into_iter()
    .filter_map(|name| env::var(name).ok().map(|value| (name, value)))
    .collect::<BTreeMap<_, _>>();
    let record = json!({
        "argv": arguments.iter().map(|value| value.to_string_lossy()).collect::<Vec<_>>(),
        "cwd": env::current_dir().unwrap().to_string_lossy(),
        "environment": environment,
    });
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    fs::write(
        log.join(format!("{}-{nonce:x}.json", std::process::id())),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    let status = Command::new(lorry).args(arguments).status().unwrap();
    std::process::exit(status.code().unwrap_or(1));
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
