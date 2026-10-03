#![cfg(unix)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

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
plain_http_allowlist = ["127.0.0.1"]
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
fn a_second_gears_is_refused_while_the_first_holds_the_directory_lock() {
    let root = fixture("directory-lock");
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let other_workspace = root.join("other-workspace");
    std::fs::create_dir(&other_workspace).unwrap();
    let server = MockServer::start_one(sse_response(&[])).unwrap();
    let config = config(&root, &server);
    std::fs::create_dir_all(root.join(".gears")).unwrap();
    std::fs::write(root.join(".gears/.gears-tmp-crashed"), "partial").unwrap();
    let mut first = gears(&root, &workspace, &config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = first.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut prompt = [0_u8; 7];
        let result = stdout.read_exact(&mut prompt).map(|()| prompt);
        let _ = sender.send(result);
    });
    let prompt = match receiver.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(prompt)) => prompt,
        other => {
            let _ = first.kill();
            let _ = first.wait();
            panic!("first Gears did not reach its prompt: {other:?}");
        }
    };
    assert_eq!(&prompt, b"gears> ");
    assert!(!root.join(".gears/.gears-tmp-crashed").exists());

    let second = gears(&root, &other_workspace, &config)
        .args(["-p", "hello"])
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert!(
        String::from_utf8_lossy(&second.stderr)
            .contains(&format!("locked by process {}", first.id()))
    );
    first.stdin.take().unwrap().write_all(b"/quit\n").unwrap();
    assert!(first.wait().unwrap().success());
    assert!(!root.join(".gears/gears.lock").exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn one_shot_streams_from_the_hermetic_backend() {
    let root = fixture("stream");
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    std::fs::create_dir_all(root.join(".gears")).unwrap();
    std::fs::write(root.join(".gears/gears.lock"), "0\n").unwrap();
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
    assert!(!root.join(".gears/gears.lock").exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn configured_tools_are_validated_before_a_provider_request() {
    let root = fixture("tool-validation");
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let server = MockServer::start_one(sse_response(&[])).unwrap();
    let config = config(&root, &server);
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str("\n[[tools]]\ndirectory = 'tools/missing'\nenabled = false\n");
    std::fs::write(&config, text).unwrap();
    let output = gears(&root, &workspace, &config)
        .args(["-p", "hello"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("tools/missing"));
    assert!(server.requests().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn malformed_line_commands_report_errors_and_keep_the_session_open() {
    let root = fixture("line-command-errors");
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let server = MockServer::start_one(sse_response(&[
        r#"{"choices":[{"index":0,"delta":{"content":"still open"},"finish_reason":"stop"}]}"#,
    ]))
    .unwrap();
    let config = config(&root, &server);
    let mut child = gears(&root, &workspace, &config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            b"/tool enable\n/tool enable missing\n/permission revoke sh --unknown\nhello\n/quit\n",
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("still open"));
    let errors = String::from_utf8_lossy(&output.stderr);
    assert!(errors.contains("usage: /tool"), "{errors}");
    assert!(errors.contains("unknown directory tool"), "{errors}");
    assert!(errors.contains("usage: /permission"), "{errors}");
    assert_eq!(server.requests().len(), 1);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn one_shot_uses_the_selected_named_provider() {
    let root = fixture("named-provider");
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let server = MockServer::start_one(sse_response(&[
        r#"{"choices":[{"index":0,"delta":{"content":"named answer"}}]}"#,
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
    ]))
    .unwrap();
    let config = root.join("gears.toml");
    std::fs::write(
        &config,
        format!(
            "version = 1\ndefault_provider = 'local'\ndefault_model = 'test/model'\n[net]\negress_allowlist = ['127.0.0.1']\nplain_http_allowlist = ['127.0.0.1']\n[providers.local]\nbase_url = '{}'\n",
            server.url("/v1")
        ),
    )
    .unwrap();
    let output = gears(&root, &workspace, &config)
        .args(["--provider", "local", "-p", "hello"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("named answer"));
    assert_eq!(server.requests().len(), 1);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn continued_session_uses_its_recorded_provider() {
    let root = fixture("continued-provider");
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let response = || {
        sse_response(&[
            r#"{"choices":[{"index":0,"delta":{"content":"local answer"}}]}"#,
            r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
        ])
    };
    let local = MockServer::start(vec![response(), response()]).unwrap();
    let remote = MockServer::start_one(sse_response(&[])).unwrap();
    let config = root.join("gears.toml");
    std::fs::write(
        &config,
        format!(
            "version = 1\ndefault_provider = 'remote'\ndefault_model = 'test/model'\n[net]\negress_allowlist = ['127.0.0.1']\nplain_http_allowlist = ['127.0.0.1']\n[providers.local]\nbase_url = '{}'\n[providers.remote]\nbase_url = '{}'\n",
            local.url("/v1"),
            remote.url("/v1")
        ),
    )
    .unwrap();
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gears"));
        command
            .env("HOME", &root)
            .env("OPENROUTER_API_KEY", "test-key")
            .args(["--ui", "line", "--config"])
            .arg(&config)
            .arg("--workspace")
            .arg(&workspace);
        command
    };
    let first = command()
        .args(["--provider", "local", "-p", "one"])
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let second = command()
        .args(["--continue", "-p", "two"])
        .output()
        .unwrap();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(local.requests().len(), 2);
    assert!(remote.requests().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn line_command_switches_provider_before_the_next_turn() {
    let root = fixture("line-provider-switch");
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let local = MockServer::start_one(sse_response(&[
        r#"{"choices":[{"index":0,"delta":{"content":"from local"}}]}"#,
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
    ]))
    .unwrap();
    let remote = MockServer::start_one(sse_response(&[])).unwrap();
    let config = root.join("gears.toml");
    std::fs::write(
        &config,
        format!(
            "version = 1\ndefault_provider = 'remote'\ndefault_model = 'test/model'\n[net]\negress_allowlist = ['127.0.0.1']\nplain_http_allowlist = ['127.0.0.1']\n[providers.local]\nbase_url = '{}'\n[providers.remote]\nbase_url = '{}'\n",
            local.url("/v1"),
            remote.url("/v1")
        ),
    )
    .unwrap();
    let mut child = gears(&root, &workspace, &config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"/provider local\nhello\n/quit\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("from local"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("provider: local"));
    assert_eq!(local.requests().len(), 1);
    assert!(remote.requests().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn line_commands_save_provider_and_model_defaults() {
    let root = fixture("saved-provider-choice");
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let local = MockServer::start_one(sse_response(&[
        r#"{"choices":[{"index":0,"delta":{"content":"saved choice"}}]}"#,
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
    ]))
    .unwrap();
    let remote = MockServer::start_one(sse_response(&[])).unwrap();
    let config = root.join("custom-config.toml");
    std::fs::write(
        &config,
        format!(
            "version = 1\ndefault_provider = 'remote'\ndefault_model = 'old/model'\n[net]\negress_allowlist = ['127.0.0.1']\nplain_http_allowlist = ['127.0.0.1']\n[providers.local]\nbase_url = '{}'\n[providers.remote]\nbase_url = '{}'\n",
            local.url("/v1"),
            remote.url("/v1")
        ),
    )
    .unwrap();
    let mut child = gears(&root, &workspace, &config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"/provider local --default\n/model chosen/model --default\n/quit\n")
        .unwrap();
    assert!(child.wait().unwrap().success());
    assert!(root.join(".gears/provider.toml").exists());

    let output = gears(&root, &workspace, &config)
        .args(["-p", "hello"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("saved choice"));
    let requests = local.requests();
    assert_eq!(requests.len(), 1);
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["model"], "chosen/model");
    assert!(remote.requests().is_empty());
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

#[test]
fn http_refuses_implicit_credentials_and_preserves_explicit_precedence() {
    let root = fixture("http-keys");
    let key_dir = root.join(".config/gears");
    std::fs::create_dir_all(&key_dir).unwrap();
    let default_key = key_dir.join("openrouter.key");
    std::fs::write(&default_key, "fixture-default-key").unwrap();
    let explicit_key = root.join("local.key");
    std::fs::write(&explicit_key, "fixture-local-key").unwrap();
    for (key_file, env_key, expected) in [
        (None, None, None),
        (Some(&explicit_key), None, Some("fixture-local-key")),
        (
            Some(&explicit_key),
            Some("fixture-env-key"),
            Some("fixture-env-key"),
        ),
        (None, Some("fixture-env-key"), Some("fixture-env-key")),
        (Some(&default_key), None, Some("fixture-default-key")),
    ] {
        let server = MockServer::start_one(sse_response(&[
            r#"{"choices":[{"index":0,"delta":{"content":"hello"},"finish_reason":"stop"}]}"#,
        ]))
        .unwrap();
        let config_path = config(&root, &server);
        if let Some(path) = key_file {
            let mut text = std::fs::read_to_string(&config_path).unwrap();
            text.push_str(&format!("key_file = {:?}\n", path.to_str().unwrap()));
            std::fs::write(&config_path, text).unwrap();
        }
        let mut command = Command::new(env!("CARGO_BIN_EXE_gears"));
        command
            .env("HOME", &root)
            .env_remove("OPENROUTER_API_KEY")
            .arg("--config")
            .arg(&config_path)
            .args(["ask", "hello"]);
        if let Some(key) = env_key {
            command.env("OPENROUTER_API_KEY", key);
        }
        let output = command.output().unwrap();
        if let Some(key) = expected {
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(server.requests().len(), 1);
            assert_eq!(
                server.requests()[0].header("Authorization"),
                Some(format!("Bearer {key}").as_str())
            );
            assert_eq!(output.stdout, b"hello\n");
        } else {
            assert!(!output.status.success());
            let error = String::from_utf8(output.stderr).unwrap();
            assert!(error.contains("implicit default key file"), "{error}");
            assert!(error.contains("provider.api_key_file"));
            assert!(error.contains("OPENROUTER_API_KEY"));
            assert!(server.requests().is_empty());
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}
