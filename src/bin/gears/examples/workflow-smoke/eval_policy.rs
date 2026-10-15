//! Evaluation grants cannot escape the copy, change learning, or substitute checks.

use gears::batteries::{eval_policy, paths::ToolContext};
use gears::provider::ToolCall;
use serde_json::json;
use std::path::Path;

pub fn run_fixture(root: &Path) -> Result<(), String> {
    std::fs::create_dir_all(root.join("workspace")).unwrap();
    let context = ToolContext::new(
        root.join("workspace"),
        root.join("state"),
        "eval".into(),
        None,
    )?;
    let mut event = gears::batteries::Event {
        protocol_version: 1,
        event: "permission".into(),
        workspace: context.workspace.clone(),
        session: gears::batteries::Session {
            id: "eval".into(),
            path: None,
            state: None,
        },
        payload: json!({}),
    };
    assert!(eval_policy::permission(&event, &context)?.is_none());
    eval_policy::install(&context, &["rustc".into(), "literal file*".into()])?;
    assert!(eval_policy::install(&context, &["other".into()]).is_err());
    for (name, args, decision) in [
        ("write_file", json!({"path":"src/lib.rs"}), "allow"),
        ("patch", json!({"path":"a file*"}), "allow"),
        ("read_file", json!({"path":"AGENTS.md"}), "allow"),
        ("search_files", json!({"pattern":"value"}), "allow"),
        ("skill_view", json!({"name":"curated"}), "allow"),
        ("todo", json!({}), "allow"),
        ("write_file", json!({"path":"../original"}), "deny"),
        ("patch", json!({"path":".gears/MEMORY.md"}), "deny"),
        ("write_file", json!({"path":"AGENTS.md"}), "deny"),
        ("write_file", json!({"path":".gears.md"}), "deny"),
        ("read_file", json!({"path":"../original"}), "deny"),
        ("memory", json!({}), "deny"),
        ("skill_manage", json!({}), "deny"),
        ("sh", json!({"command":"true"}), "deny"),
        ("gix", json!({"action":"push"}), "deny"),
        ("session_search", json!({}), "deny"),
        ("external", json!({}), "deny"),
    ] {
        event.payload = json!({"tool_call":ToolCall::new("call",name,args.to_string())});
        assert_eq!(
            eval_policy::permission(&event, &context)?.unwrap()["decision"],
            decision,
            "{name}"
        );
    }
    event.payload = json!({"tool_call":ToolCall::new("check","check","{}")});
    let response = eval_policy::permission(&event, &context)?.unwrap();
    assert_eq!(response["decision"], "allow");
    assert!(!response["state"]["pending_check"].is_null());
    std::fs::write(
        context.workspace.join(".gears/batteries.toml"),
        "check=['replacement']",
    )
    .unwrap();
    assert!(eval_policy::permission(&event, &context).is_err());
    std::fs::remove_dir_all(root).map_err(|e| e.to_string())
}
