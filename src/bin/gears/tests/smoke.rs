#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

use gears::mock::{MockServer, sse_response};

fn fixture(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("gears-smoke-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn config(root: &Path, server: &MockServer) -> PathBuf {
    let path = root.join("gears.toml");
    std::fs::write(
        &path,
        format!(
            r#"version = 1
[net]
egress_allowlist = ["127.0.0.1"]
allow_plain_http_loopback = true
[provider]
base_url = "{}"
model = "test/model"
"#,
            server.url("/v1")
        ),
    )
    .unwrap();
    path
}

fn gears(root: &Path, workspace: &Path, config: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gears"));
    command
        .env("HOME", root)
        .env("OPENROUTER_API_KEY", "test-key")
        .args(["--ui", "line", "--ephemeral", "--config"])
        .arg(config)
        .arg("--workspace")
        .arg(workspace);
    command
}

#[test]
fn help_version_and_bad_arguments_need_no_configuration() {
    let version = Command::new(env!("CARGO_BIN_EXE_gears"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(version.status.success());
    assert!(
        String::from_utf8(version.stdout)
            .unwrap()
            .starts_with("gears ")
    );

    let help = Command::new(env!("CARGO_BIN_EXE_gears"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(
        String::from_utf8(help.stdout)
            .unwrap()
            .contains("--ephemeral")
    );

    let bad = Command::new(env!("CARGO_BIN_EXE_gears"))
        .arg("--removed-flag")
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(2));
}

#[test]
fn one_shot_streams_from_the_hermetic_backend() {
    let root = fixture("stream");
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let server = MockServer::start_one(sse_response(&[
        r#"{"choices":[{"index":0,"delta":{"content":"hello "}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"content":"mock"}}]}"#,
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
    ]))
    .unwrap();
    let config = config(&root, &server);
    let output = gears(&root, &workspace, &config)
        .args(["-p", "hello"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("hello mock")
    );
    assert_eq!(server.requests().len(), 1);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn unattended_sh_is_denied_and_the_turn_continues() {
    let root = fixture("deny");
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let call = r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"sh","arguments":"{\"command\":\"touch denied-file\"}"}}]},"finish_reason":"tool_calls"}]}"#;
    let server = MockServer::start(vec![
        sse_response(&[call]),
        sse_response(&[
            r#"{"choices":[{"index":0,"delta":{"content":"denied safely"}}]}"#,
            r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
        ]),
    ])
    .unwrap();
    let config = config(&root, &server);
    let output = gears(&root, &workspace, &config)
        .args(["-p", "try it"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!workspace.join("denied-file").exists());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("denied safely")
    );
    assert_eq!(server.requests().len(), 2);
    std::fs::remove_dir_all(root).unwrap();
}
