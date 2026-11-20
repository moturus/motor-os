use std::process::Command;
use std::time::{Duration, Instant};

use crate::session::LspSession;
use serde_json::json;

fn spawn(mode: &str) -> LspSession {
    LspSession::spawn(
        Command::new(std::env::current_exe().unwrap())
            .arg("--fake-child")
            .arg(mode),
    )
    .unwrap()
}

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
    session.clear_notifications();
    assert_eq!(session.notifications().count(), 0);
    session.shutdown(deadline).unwrap();
}

fn rejects_nonzero_exit_and_reports_stderr() {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut session = spawn("lifecycle-error");
    session.request("initialize", json!({}), deadline).unwrap();
    let error = session.shutdown(deadline).unwrap_err().to_string();
    assert!(error.contains("fake lifecycle failure marker"), "{error}");
}

pub fn run() {
    handles_requests_notifications_and_clean_shutdown();
    rejects_nonzero_exit_and_reports_stderr();
}
