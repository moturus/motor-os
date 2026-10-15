//! Check grants bind to the vector actually run, never a denied request.

use crate::provider::ToolOutcome;
use serde_json::{Value, json};

use crate::batteries::{Event, check::Receipt, paths::ToolContext};

fn signature(argv: &[String], system: &str) -> Value {
    json!({"version": 1, "argv": argv, "system": system})
}

pub fn prepare(event: &Event, context: &ToolContext) -> Result<Value, String> {
    let system = crate::batteries::check_config::system();
    let argv = crate::batteries::check_config::load(context, system)?
        .ok_or("no check declared for this platform")?;
    let pending = signature(&argv, system);
    let mut state = crate::batteries::hook_state(event)?;
    let decision = if state.get("approved_check") == Some(&pending) {
        "ask"
    } else {
        "confirm"
    };
    let mut response = json!({"decision": decision,
        "permission_detail": format!("declared check: {}", serde_json::to_string(&argv).unwrap())});
    if state.get("pending_check") != Some(&pending) {
        state["pending_check"] = pending;
        response["state"] = state;
    }
    Ok(response)
}

pub fn completed(event: &Event, state: &mut Value) -> Result<Option<Receipt>, String> {
    let pending = state.as_object_mut().unwrap().remove("pending_check");
    if event.payload["outcome"] != serde_json::to_value(ToolOutcome::Completed).unwrap()
        || event.payload["tool_result"]["is_error"] != false
        || event.payload["tool_result_truncated"] == true
    {
        return Ok(None);
    }
    let Some(content) = event.payload["tool_result"]["content"].as_str() else {
        return Ok(None);
    };
    let Ok(receipt) = serde_json::from_str::<Receipt>(content) else {
        return Ok(None);
    };
    if receipt.version != 1
        || receipt.kind != "check"
        || receipt.passed != (receipt.exit_status == Some(0))
    {
        return Err("invalid check receipt".into());
    }
    let actual = signature(&receipt.argv, &receipt.system);
    if pending.as_ref() != Some(&actual) {
        return Err("check receipt differs from the approval request".into());
    }
    state["approved_check"] = actual;
    Ok(Some(receipt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_denied_vector_is_not_approved_and_rewritten_declarations_require_confirmation() {
        let root =
            std::env::temp_dir().join(format!("batteries-check-approval-{}", std::process::id()));
        std::fs::create_dir_all(root.join("workspace/.gears")).unwrap();
        let context = ToolContext::new(
            root.join("workspace"),
            root.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        let config = context.workspace.join(".gears/batteries.toml");
        std::fs::write(&config, "check = ['program', 'first']").unwrap();
        let mut event = Event {
            protocol_version: 1,
            event: "permission".into(),
            workspace: context.workspace.clone(),
            session: crate::batteries::Session {
                id: "s1".into(),
                path: None,
                state: None,
            },
            payload: json!({}),
        };
        let response = prepare(&event, &context).unwrap();
        assert_eq!(response["decision"], "confirm");
        assert!(
            response["permission_detail"]
                .as_str()
                .unwrap()
                .contains("first")
        );
        let mut state = response["state"].clone();
        event.payload = json!({"outcome": "not_started", "tool_result": {"content": "denied", "is_error": true}});
        assert!(completed(&event, &mut state).unwrap().is_none());
        assert!(state.get("approved_check").is_none());
        event.session.state = Some(state);
        let response = prepare(&event, &context).unwrap();
        let mut state = response["state"].clone();
        let receipt = Receipt {
            version: 1,
            kind: "check".into(),
            argv: vec!["program".into(), "first".into()],
            system: crate::batteries::check_config::system().into(),
            exit_status: Some(1),
            duration_ms: 1,
            passed: false,
            stdout: String::new(),
            stderr: "failed".into(),
            output_truncated: false,
            output_file: None,
        };
        event.payload = json!({"outcome": "completed", "tool_result": {
            "content": serde_json::to_string(&receipt).unwrap(), "is_error": false}});
        assert!(!completed(&event, &mut state).unwrap().unwrap().passed);
        event.session.state = Some(state.clone());
        assert_eq!(prepare(&event, &context).unwrap()["decision"], "ask");
        std::fs::write(&config, "check = ['program', 'changed']").unwrap();
        assert_eq!(prepare(&event, &context).unwrap()["decision"], "confirm");
        // A receipt for an unapproved replacement cannot establish evidence.
        state["pending_check"] = signature(
            &["program".into(), "changed".into()],
            crate::batteries::check_config::system(),
        );
        assert!(completed(&event, &mut state).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
