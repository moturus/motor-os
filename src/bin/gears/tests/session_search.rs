#![cfg(unix)]

use std::io::Write;
use std::process::{Command, Stdio};

use gears::provider::Message;
use gears::session::Store;
use serde_json::{Value, json};

#[test]
fn real_tool_command_pages_saved_sessions_and_loads_every_shipped_manifest() {
    let tools = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tools");
    let directories: Vec<_> = std::fs::read_dir(&tools)
        .unwrap()
        .map(|entry| gears::config::ToolDirectory {
            directory: entry.unwrap().path(),
            enabled: true,
        })
        .collect();
    let registry = gears::tools::Registry::load(&directories, &tools).unwrap();
    assert_eq!(registry.tools().len(), directories.len());
    let root = std::env::temp_dir().join(format!("batteries-search-cli-{}", std::process::id()));
    std::fs::create_dir_all(root.join("workspace")).unwrap();
    let store = Store::with_root(&root.join("workspace"), root.join(".gears")).unwrap();
    let mut session = store.create(false, None).unwrap();
    session
        .append_message(&Message::user("needle question"))
        .unwrap();
    session
        .append_message(&Message::assistant("needle answer"))
        .unwrap();
    let invoke = |arguments: Value| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_gears-batteries"))
            .args(["tool", "session_search"])
            .env("HOME", &root)
            .env("GEARS_WORKSPACE", root.join("workspace"))
            .env("GEARS_SESSION_ID", session.id())
            .env("GEARS_SESSION_PATH", session.path().unwrap())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(arguments.to_string().as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    };
    let result = invoke(json!({"query": "needle", "limit": 1}));
    assert!(result.status.success(), "{result:?}");
    let page: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(page["total_matches"], 2);
    assert_eq!(page["next_offset"], 1);
    assert_eq!(page["hits"][0]["session_id"], session.id());
    assert_eq!(page["hits"][0]["off_current_branch"], false);
    for invalid in [
        json!({"query": "needle", "offset": -1}),
        json!({"query": "needle", "limit": 0}),
        json!({"query": "needle", "unknown": true}),
    ] {
        let refused = invoke(invalid);
        assert!(!refused.status.success());
        assert!(refused.stdout.is_empty());
    }
    drop(session);
    std::fs::remove_dir_all(root).unwrap();
}
