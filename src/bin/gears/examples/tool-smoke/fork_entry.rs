//! The actual CLI selects an old entry while its parent remains writable.

use std::path::Path;
use std::time::Duration;

use gears::mock::{MockServer, sse_response};
use gears::process::{Cancellation, Request, run};
use gears::provider::Message;
use gears::session::{Compaction, HookState, Store};

pub fn smoke(gears: &Path) -> Result<(), String> {
    let root = std::env::temp_dir().join(format!("gears-fork-entry-{}", std::process::id()));
    std::fs::create_dir(&root).map_err(|error| error.to_string())?;
    // The children use this directory instead of the user's Gears directory.
    let directory = root.join(".gears");
    let store = Store::with_root(&root, directory.join("sessions"))?;
    let mut parent = store.create(false, None)?;
    parent.append_hook_state(&HookState {
        hook: "fixture".into(),
        state: serde_json::json!({"role":"parent", "retained":"source"}),
        context: None,
    })?;
    parent.append_hook_state(&HookState {
        hook: "other".into(),
        state: serde_json::json!({"private":"other hook"}),
        context: None,
    })?;
    parent.append_hook_state(&HookState {
        hook: "fixture".into(),
        state: serde_json::json!({"role":"parent", "retained":"current"}),
        context: None,
    })?;
    parent.append_message(&Message::user("Saved original task"))?;
    let entry = parent.append_message(&Message::assistant("Saved original answer"))?;
    parent.append_compaction(&Compaction {
        summary: "Later compacted summary".into(),
        retained_tail: Vec::new(),
        tokens_before: 100,
    })?;
    parent.append_message(&Message::user("Later task"))?;
    let path = parent.path().unwrap().to_path_buf();
    let before = std::fs::read(&path).map_err(|error| error.to_string())?;
    let server = MockServer::start_one(sse_response(&[
        r#"{"choices":[{"index":0,"delta":{"content":"Nothing to save."},"finish_reason":"stop"}]}"#,
    ])).map_err(|error| error.to_string())?;
    let config = root.join("gears.toml");
    let key = root.join("key");
    std::fs::write(&key, "fixture").map_err(|error| error.to_string())?;
    std::fs::write(&config, format!(
        "version=1\n[provider]\nbase_url={:?}\napi_key_file={:?}\nmodel='fixture'\n[net]\negress_allowlist=['127.0.0.1']\nplain_http_allowlist=['127.0.0.1']\n",
        server.url("/v1"), key,
    )).map_err(|error| error.to_string())?;
    let mut request = Request {
        program: gears.display().to_string(),
        args: vec![
            "--config".into(),
            config.display().to_string(),
            "--workspace".into(),
            root.display().to_string(),
            "--fork".into(),
            path.display().to_string(),
            "--fork-entry".into(),
            entry,
            "--ephemeral".into(),
            "--ui".into(),
            "line".into(),
        ],
        cwd: root.clone(),
        stdin: Some(b"/session\n/quit\n".to_vec()),
        timeout: Duration::from_secs(10),
        max_output_bytes: 65536,
        env: vec![
            ("HOME".into(), root.display().to_string()),
            (
                gears::directory::ENV.into(),
                directory.display().to_string(),
            ),
        ],
        remove_env: vec![gears::provider::KEY_ENV.into()],
    };
    let output =
        run(&request, &Cancellation::new(), &mut |_, _| {}).map_err(|error| error.to_string())?;
    assert!(output.success(), "{output:?}");
    assert!(output.stdout.contains("Saved original task"), "{output:?}");
    assert!(
        output.stdout.contains("Saved original answer"),
        "{output:?}"
    );
    assert!(!output.stdout.contains("Later"), "{output:?}");
    assert!(server.requests().is_empty());
    #[cfg(unix)]
    let shell = "/bin/sh";
    #[cfg(not(unix))]
    let shell = "/system/bin/rush";
    let event_path = root.join("initialized.json");
    let mut text = std::fs::read_to_string(&config).map_err(|error| error.to_string())?;
    text.push_str(&format!(
        "[[hooks]]\nname='fixture'\nevents=['initialize']\ncommand={}\n",
        serde_json::json!([
            shell,
            "-c",
            "cat > \"$1\"; printf '{}'",
            "fixture",
            event_path
        ]),
    ));
    std::fs::write(&config, text).map_err(|error| error.to_string())?;
    request.args.extend([
        "-p".into(),
        "Continue the saved task".into(),
        "--output".into(),
        "jsonl".into(),
    ]);
    let output =
        run(&request, &Cancellation::new(), &mut |_, _| {}).map_err(|error| error.to_string())?;
    assert!(output.success(), "{output:?}");
    let event: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&event_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    // The fork inherits the hook state saved before its entry, and only its own.
    assert_eq!(event["session"]["state"]["role"], "parent");
    assert_eq!(event["session"]["state"]["retained"], "current");
    assert!(!event.to_string().contains("other hook"));
    assert_ne!(event["session"]["id"], parent.id());
    assert_eq!(server.requests().len(), 1);
    assert_eq!(
        std::fs::read(&path).map_err(|error| error.to_string())?,
        before
    );
    parent.append_message(&Message::assistant("Parent continued"))?;
    drop(parent);
    std::fs::remove_dir_all(root).map_err(|error| error.to_string())?;
    println!("gears CLI saved-entry fork ALL PASS");
    Ok(())
}
