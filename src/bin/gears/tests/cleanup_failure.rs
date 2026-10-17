#![cfg(unix)]
//! Deliberately escape ownership to verify the fail-closed cleanup boundary.
//! This has its own test process because an uncertain cleanup is permanent.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use gears::config::{Config, ToolDirectory};
use gears::mock::{MockServer, sse_response};
use gears::net::{EgressPolicy, host_curl::HostCurl};
use gears::process::{Cancellation, sh};
use gears::provider::{Endpoint, OpenAiCompat};
use gears::runtime::{Approval, Event, Options, Permission, Runtime};
use gears::session::Store;

struct Escaped(PathBuf);

impl Drop for Escaped {
    fn drop(&mut self) {
        if let Some(pid) = std::fs::read_to_string(&self.0)
            .ok()
            .and_then(|text| text.trim().parse::<i32>().ok())
            .filter(|pid| *pid > 1)
        {
            unsafe {
                libc::killpg(pid, libc::SIGKILL);
            }
        }
    }
}

#[test]
fn unconfirmed_cleanup_blocks_another_turn_and_session_mutation() {
    let base = std::env::temp_dir().join(format!("gears-cleanup-failure-{}", std::process::id()));
    std::fs::create_dir(&base).unwrap();
    let escaped = Escaped(base.join("escaped.pid"));
    // A new session alone is still found through its parent; the subshell
    // also orphans it, so neither its group nor its ancestry leads back.
    let command = "(/usr/bin/setsid /bin/sh -c 'echo $$ > escaped.pid; printf escaped-ready; sleep 30' &); sleep 30";
    let arguments = serde_json::json!({"command": command}).to_string();
    let call = serde_json::json!({"choices": [{"index": 0, "delta": {"tool_calls": [{
        "index": 0, "id": "escaped-call", "function": {"name": "sh", "arguments": arguments}
    }]}, "finish_reason": "tool_calls"}]})
    .to_string();
    let server = MockServer::start_one(sse_response(&[&call])).unwrap();
    let http = HostCurl::new(
        EgressPolicy::new(&["127.0.0.1".into()]).with_plain_http_allowlist(&["127.0.0.1".into()]),
    )
    .unwrap();
    let provider = Arc::new(OpenAiCompat::new(
        http.with_secret("OPENROUTER_API_KEY", "fixture-cleanup-key"),
        Endpoint::new(&server.url("/v1")).unwrap(),
    ));
    let store = Store::with_root(&base, base.join("state")).unwrap();
    let session = store.create(false, None).unwrap();
    let config = Config {
        tools: vec![ToolDirectory {
            directory: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/sh"),
            enabled: true,
        }],
        ..Config::default()
    };
    let mut runtime = Runtime::with_options(
        provider,
        store,
        session,
        &config,
        "test/model".into(),
        Options {
            tools: Some(gears::tools::Registry::load_config(&config).unwrap()),
            tool_state_directory: Some(base.join("global")),
        },
    )
    .unwrap();
    let cancellation = runtime.cancellation();
    let mut started = false;
    let original = runtime.turn(
        "work".into(),
        &mut |_: &Permission| Approval::Once,
        &mut |event| {
            if let Event::ToolOutput { text, .. } = event
                && text.contains("escaped-ready")
            {
                started = true;
                cancellation.cancel();
            }
            Ok(())
        },
    );
    // The fixture escaped the owned group deliberately. Stop it even if an
    // assertion below fails, before inspecting the permanent blocked state.
    drop(escaped);
    assert!(
        started,
        "turn ended before child output: {original:?}; requests={}",
        server.requests().len()
    );
    assert!(
        original
            .unwrap_err()
            .contains("cleanup could not be confirmed")
    );
    let path = runtime.session().path().unwrap().to_path_buf();
    let before = std::fs::read(&path).unwrap();
    let entries = runtime.session().entries().len();
    let next = runtime.turn(
        "next".into(),
        &mut |_: &Permission| Approval::Once,
        &mut |_| Ok(()),
    );
    assert!(next.unwrap_err().contains("further work is blocked"));
    assert_eq!(runtime.session().entries().len(), entries);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(runtime.new_session(false, None).is_err());
    assert!(runtime.set_name("changed").is_err());
    assert!(runtime.set_model("other".into(), &mut |_| Ok(())).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let marker = base.join("must-not-run");
    let error = sh(
        base.clone(),
        "printf wrong > must-not-run",
        Duration::from_secs(1),
        1024,
        &Cancellation::new(),
        &mut |_, _| {},
    )
    .unwrap_err();
    assert!(!error.started);
    assert!(!marker.exists());
    assert_eq!(server.requests().len(), 1);
    drop(runtime);
    std::fs::remove_dir_all(base).unwrap();
}
