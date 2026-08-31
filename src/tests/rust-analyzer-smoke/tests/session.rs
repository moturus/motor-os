use std::process::Command;
use std::time::{Duration, Instant};

use rust_analyzer_smoke::session::LspSession;
use serde_json::json;

fn spawn(mode: &str) -> LspSession {
    LspSession::spawn(
        Command::new(env!("CARGO_BIN_EXE_rust-analyzer-smoke"))
            .arg("--fake-child")
            .arg(mode),
    )
    .unwrap()
}

#[test]
fn handles_requests_notifications_and_clean_shutdown() {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut session = spawn("lifecycle");
    let response = session.request("initialize", json!({}), deadline).unwrap();
    assert_eq!(response["result"]["ready"], true);
    let methods: Vec<_> = session
        .notifications()
        .map(|notification| notification.method.as_str())
        .collect();
    assert_eq!(
        methods,
        [
            "textDocument/publishDiagnostics",
            "$/progress",
            "experimental/serverStatus"
        ]
    );
    session.shutdown(deadline).unwrap();
}

#[test]
fn rejects_nonzero_exit_and_reports_stderr() {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut session = spawn("lifecycle-error");
    session.request("initialize", json!({}), deadline).unwrap();
    let error = session.shutdown(deadline).unwrap_err().to_string();
    assert!(error.contains("fake lifecycle failure marker"), "{error}");
}
