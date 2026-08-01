//! `gears ask` end to end: the built binary against a scripted endpoint, with
//! a fake key — and then a search for that key in everything gears wrote.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use gears::mock::{MockServer, plain_response, sse_response};

const KEY: &str = "sk-fake-key-9f3c2a";

fn workdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gears-ask-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A config pointing gears at the mock endpoint. The loopback carve-out is
/// what lets the binary speak plain HTTP to it at all.
fn write_config(dir: &Path, server: &MockServer, key_file: Option<&Path>, model: bool) -> PathBuf {
    let mut text = format!(
        "version = 1\n\
         [net]\n\
         egress_allowlist = [\"127.0.0.1\"]\n\
         allow_plain_http_loopback = true\n\
         [provider]\n\
         base_url = \"{}/v1\"\n",
        server.base_url()
    );
    if model {
        text.push_str("model = \"test/model\"\n");
    }
    if let Some(path) = key_file {
        text.push_str(&format!("key_file = \"{}\"\n", path.display()));
    }
    text.push_str("[trace]\nlevel = \"debug\"\n");
    let path = dir.join("gears.toml");
    std::fs::write(&path, text).unwrap();
    path
}

fn write_key(dir: &Path, key: &str) -> PathBuf {
    let path = dir.join("openrouter.key");
    std::fs::write(&path, format!("{key}\n")).unwrap();
    path
}

fn gears(config: &Path, log: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gears"));
    command
        .arg("--config")
        .arg(config)
        .arg("--log-file")
        .arg(log)
        // The developer's own key must not decide what this test exercises.
        .env_remove("OPENROUTER_API_KEY");
    command
}

fn completion(text: &str) -> Vec<String> {
    vec![
        format!(r#"{{"choices":[{{"index":0,"delta":{{"content":"{text}"}}}}]}}"#),
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#.to_string(),
        r#"{"choices":[],"usage":{"prompt_tokens":7,"completion_tokens":2,"cost":0.0002}}"#
            .to_string(),
    ]
}

fn as_refs(payloads: &[String]) -> Vec<&str> {
    payloads.iter().map(String::as_str).collect()
}

/// Everything gears wrote under `dir`, plus what it printed.
fn artifacts(dir: &Path, out: &Output, ours: &[&Path]) -> Vec<(String, String)> {
    let mut found = vec![
        (
            "stdout".to_string(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        ),
        (
            "stderr".to_string(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ),
    ];
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if ours.contains(&path.as_path()) {
            continue; // The key file and the config are the user's, not ours.
        }
        let bytes = std::fs::read(&path).unwrap();
        found.push((
            path.display().to_string(),
            String::from_utf8_lossy(&bytes).into_owned(),
        ));
    }
    found
}

#[test]
fn an_ask_prints_the_answer_and_writes_no_key_anywhere() {
    let dir = workdir("answer");
    let payloads = completion("Hello, world");
    let server = MockServer::start_one(sse_response(&as_refs(&payloads))).unwrap();
    let key_file = write_key(&dir, KEY);
    let config = write_config(&dir, &server, Some(&key_file), true);
    let log = dir.join("gears.log");

    let out = gears(&config, &log).arg("ask").arg("hi").output().unwrap();

    assert!(out.status.success(), "{:?}", out);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "Hello, world\n");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("1 completions, 7 + 2 tokens, $0.0002"),
        "{stderr}"
    );

    // The key really did reach the endpoint: the search below is not passing
    // because nothing was sent.
    let sent = &server.requests()[0];
    assert_eq!(
        sent.header("authorization"),
        Some(format!("Bearer {KEY}").as_str())
    );
    let body: serde_json::Value = serde_json::from_slice(&sent.body).unwrap();
    assert_eq!(body["model"], serde_json::json!("test/model"));
    assert_eq!(body["messages"][0]["content"], serde_json::json!("hi"));

    // And the wire log really did record the exchange.
    let written = artifacts(&dir, &out, &[&key_file, &config]);
    let log_text = &written
        .iter()
        .find(|(name, _)| name.ends_with("gears.log"))
        .expect("a log file")
        .1;
    assert!(log_text.contains("-> POST"), "{log_text}");
    assert!(log_text.contains("<- 200"), "{log_text}");

    for (name, text) in &written {
        assert!(!text.contains(KEY), "the key appears in {name}");
        assert!(!text.contains("sk-fake"), "a key prefix appears in {name}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The realistic leak: an endpoint quoting the key back in an error. It must
/// survive neither to the terminal nor into the log.
#[test]
fn a_key_echoed_by_the_endpoint_is_redacted() {
    let dir = workdir("echo");
    let server = MockServer::start_one(plain_response(
        401,
        "Unauthorized",
        "application/json",
        &format!(r#"{{"error":{{"message":"Invalid API key: {KEY}","code":401}}}}"#),
    ))
    .unwrap();
    let key_file = write_key(&dir, KEY);
    let config = write_config(&dir, &server, Some(&key_file), true);
    let log = dir.join("gears.log");

    let out = gears(&config, &log).arg("ask").arg("hi").output().unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("authentication failed"), "{stderr}");
    assert!(stderr.contains("[redacted]"), "{stderr}");

    for (name, text) in artifacts(&dir, &out, &[&key_file, &config]) {
        assert!(!text.contains(KEY), "the key appears in {name}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_environment_overrides_the_key_file() {
    let dir = workdir("env");
    let payloads = completion("from the env");
    let server = MockServer::start_one(sse_response(&as_refs(&payloads))).unwrap();
    let key_file = write_key(&dir, "sk-file-key-should-lose");
    let config = write_config(&dir, &server, Some(&key_file), false);
    let log = dir.join("gears.log");

    let out = gears(&config, &log)
        .env("OPENROUTER_API_KEY", "sk-env-key-wins")
        .args(["ask", "-m", "test/other-model", "hi"])
        .output()
        .unwrap();

    assert!(out.status.success(), "{:?}", out);
    let sent = &server.requests()[0];
    assert_eq!(sent.header("authorization"), Some("Bearer sk-env-key-wins"));
    let body: serde_json::Value = serde_json::from_slice(&sent.body).unwrap();
    assert_eq!(body["model"], serde_json::json!("test/other-model"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_missing_model_or_key_is_reported_before_anything_is_sent() {
    let dir = workdir("missing");
    let server = MockServer::start(Vec::new()).unwrap();
    let log = dir.join("gears.log");

    // No -m and no provider.model: gears cannot guess one.
    let config = write_config(&dir, &server, None, false);
    let out = gears(&config, &log).arg("ask").arg("hi").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr.contains("provider.model"), "{stderr}");

    // A key file that is not there names itself.
    let missing = dir.join("absent.key");
    let config = write_config(&dir, &server, Some(&missing), true);
    let out = gears(&config, &log).arg("ask").arg("hi").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr.contains("absent.key"), "{stderr}");

    assert!(server.requests().is_empty(), "a request went out anyway");
    std::fs::remove_dir_all(&dir).unwrap();
}
