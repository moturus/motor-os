//! Review calls cannot use ordinary command, writer or check authority.

use std::path::Path;

use gears::batteries::{Event, Session, paths::ToolContext, policy};
use gears::hooks::Decision;
use gears::provider::ToolCall;
use serde_json::json;

pub fn run(workspace: &Path, root: &Path) -> Result<(), String> {
    let context = ToolContext::new(workspace.into(), root.into(), "review".into(), None)?;
    let mut event = Event {
        protocol_version: 1,
        event: "permission".into(),
        workspace: workspace.into(),
        session: Session {
            id: "review".into(),
            path: None,
            state: Some(json!({"run_kind": "review"})),
        },
        payload: json!({}),
    };
    for name in [
        "sh",
        "check",
        "todo",
        "write_file",
        "patch",
        "gix",
        "unknown",
    ] {
        event.payload = json!({"tool_call": ToolCall::new("call", name, "{}")});
        // Denial comes before check setup or access to any default state root.
        assert_eq!(
            policy::permission(&event),
            json!({"decision": "deny"}),
            "{name}"
        );
    }
    for name in ["sh", "check", "todo", "write_file", "patch"] {
        event.payload = json!({"tool_call": ToolCall::new("call", name, "{}"),
            "tool": {"read_only": true}});
        assert_eq!(
            policy::permission(&event),
            json!({"decision": "deny"}),
            "{name}"
        );
    }
    for name in ["memory", "skill_manage", "skill_view", "session_search"] {
        event.payload = json!({"tool_call": ToolCall::new("call", name, "{}")});
        assert_eq!(policy::decide(&event, &context)?, Decision::Allow, "{name}");
    }
    for name in ["read_file", "search_files", "cat", "ls", "rg"] {
        event.payload = json!({"tool_call": ToolCall::new("call", name,
            json!({"path": "file"}).to_string()), "tool": {"read_only": true}});
        assert_eq!(policy::decide(&event, &context)?, Decision::Allow, "{name}");
        event.payload["tool"]["read_only"] = json!(false);
    }
    event.payload = json!({"tool_call": ToolCall::new("call", "read_file",
        json!({"path": "../outside"}).to_string()), "tool": {"read_only": true}});
    assert_eq!(policy::decide(&event, &context)?, Decision::Ask);
    event.payload["tool_call"] = json!(ToolCall::new(
        "call",
        "read_file",
        json!({"path": root.join("key")}).to_string()
    ));
    assert!(policy::decide(&event, &context).is_err());
    event.payload = json!({"tool_call": ToolCall::new("call", "write_file",
        json!({"path": "file", "content": "example"}).to_string())});
    for state in [None, Some(json!({})), Some(json!({"run_kind": "worker"}))] {
        event.session.state = state;
        assert_eq!(policy::decide(&event, &context)?, Decision::Ask);
    }
    event.session.state = Some(json!({"run_kind": "review"}));
    assert_eq!(policy::permission(&event), json!({"decision": "deny"}));
    assert!(!root.exists(), "policy checks must not create review data");
    println!("gears batteries review policy ALL PASS");
    Ok(())
}
