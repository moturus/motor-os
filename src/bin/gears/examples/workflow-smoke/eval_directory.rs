//! Real hook and CLI processes keep learning data within the selected directory.

use gears::batteries::{
    memory_format::{Document, Entry, Target},
    paths::ToolContext,
    pending::Proposal,
};
use gears::{
    mock::{MockServer, sse_response},
    process::{Cancellation, Request, run},
};
use serde_json::{Value, json};
use std::{
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

fn entry(id: &str, text: &str, kind: &str) -> Entry {
    serde_json::from_value(
        json!({"metadata": {"id": id, "kind": kind, "scope": "global",
        "source": {"session": "source", "entries": ["e1"]}, "date_ms": 1}, "text": text}),
    )
    .unwrap()
}

pub fn run_fixture(
    binary: &Path,
    gears: &Path,
    workspace: &Path,
    root: &Path,
) -> Result<(), String> {
    let selected = root.join("selected");
    let inherited = root.join("inherited");
    let context = ToolContext::new(workspace.into(), selected.clone(), "source".into(), None)?;
    let old = ToolContext::new(workspace.into(), inherited.clone(), "source".into(), None)?;
    for (context, text) in [
        (&context, "Selected evaluation guideline."),
        (&old, "Inherited guideline must stay outside this run."),
    ] {
        let document = Document {
            entries: vec![entry("guideline", text, "user")],
        }
        .encode(Target::User, 1375)?;
        context
            .state
            .replace_file(Target::User.relative(), document.as_bytes())?;
    }
    let old_bytes =
        std::fs::read(old.state.file(Target::User.relative())?).map_err(|e| e.to_string())?;
    let server = MockServer::start_one(sse_response(&[
        r#"{"choices":[{"index":0,"delta":{"content":"Scoped learning is isolated."},"finish_reason":"stop"}]}"#
    ])).map_err(|e| e.to_string())?;
    let key = root.join("key");
    std::fs::write(&key, "fixture").map_err(|e| e.to_string())?;
    let config = root.join("gears.toml");
    let hook = json!([binary, "hook"]);
    std::fs::write(&config, format!("version=1\n[provider]\nbase_url={:?}\napi_key_file={:?}\nmodel='fixture'\n[net]\negress_allowlist=['127.0.0.1']\nplain_http_allowlist=['127.0.0.1']\n[[hooks]]\nname='batteries'\nevents=['initialize','permission','tool_execute','turn_start','entry','context','turn_end']\ncommand={hook}\n", server.url("/v1"), key)).map_err(|e| e.to_string())?;
    let request = Request {
        program: gears.to_str().ok_or("binary is not UTF-8")?.into(),
        args: vec![
            "--config".into(),
            config.display().to_string(),
            "--gears-dir".into(),
            selected.display().to_string(),
            "--ephemeral".into(),
            "-p".into(),
            "Use only selected learning.".into(),
            "--output".into(),
            "jsonl".into(),
        ],
        cwd: workspace.into(),
        stdin: None,
        timeout: Duration::from_secs(30),
        max_output_bytes: 65536,
        env: vec![(
            gears::directory::ENV.into(),
            inherited.display().to_string(),
        )],
        remove_env: vec!["GEARS_LOCK_OWNER".into(), gears::provider::KEY_ENV.into()],
    };
    let output = run(&request, &Cancellation::new(), &mut |_, _| {}).map_err(|e| e.to_string())?;
    assert!(output.success(), "{output:?}");
    let body: Value =
        serde_json::from_slice(&server.requests()[0].body).map_err(|e| e.to_string())?;
    let messages = body["messages"].to_string();
    assert!(messages.contains("Selected evaluation guideline."));
    assert!(!messages.contains("Inherited guideline must stay outside this run."));
    assert!(selected.join("batteries/snapshots").is_dir());
    assert!(selected.join("batteries/sessions").is_dir());
    assert!(!inherited.join("batteries/snapshots").exists());
    assert!(!inherited.join("batteries/sessions").exists());
    let draft = entry("draft", "Selected pending evidence.", "observed");
    gears::batteries::memory::propose(
        &context,
        &Proposal {
            version: 1,
            target: Target::Global,
            before: None,
            after: Some(draft.clone()),
            source: draft.metadata.source,
            date_ms: 1,
        },
    )?;
    let pending = Command::new(binary)
        .args(["pending", "--list"])
        .arg("--workspace")
        .arg(workspace)
        .env(gears::directory::ENV, &selected)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    assert!(pending.status.success());
    assert!(String::from_utf8_lossy(&pending.stdout).contains("Selected pending evidence."));
    assert_eq!(
        std::fs::read(old.state.file(Target::User.relative())?).unwrap(),
        old_bytes
    );
    std::fs::remove_dir_all(root).map_err(|e| e.to_string())
}
