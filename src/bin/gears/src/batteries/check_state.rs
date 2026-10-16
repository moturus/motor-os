//! Current/stale evidence and bounded feedback, without judging acceptance.

use crate::provider::{ToolCall, ToolOutcome};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::batteries::{Event, check::Receipt, paths::ToolContext};

#[derive(Serialize, Deserialize)]
struct Latest {
    version: u32,
    entry_id: String,
    receipt: Receipt,
    current: bool,
}

pub fn observe(event: &Event, context: &ToolContext) -> Result<Value, String> {
    let mut state = crate::batteries::hook_state(event)?;
    let mut response = json!({});
    match event.event.as_str() {
        "turn_start" => {
            response["hint"] = json!("");
            state["workspace_changed"] = json!(false);
            state["check_reminders"] = json!(0);
            state.as_object_mut().unwrap().remove("pending_check");
        }
        "entry" if event.payload["role"] == "tool" => {
            let call: ToolCall = serde_json::from_value(event.payload["tool_call"].clone())
                .map_err(|error| error.to_string())?;
            let outcome: ToolOutcome = serde_json::from_value(event.payload["outcome"].clone())
                .map_err(|error| error.to_string())?;
            if !matches!(call.name.as_str(), "todo" | "memory" | "skill_view")
                && event.payload["tool"]["read_only"] != true
            {
                if let Some(mut latest) = latest(&state)? {
                    latest.current = false;
                    state["last_check"] = serde_json::to_value(latest).unwrap();
                }
                if outcome != ToolOutcome::NotStarted {
                    state["workspace_changed"] = json!(true);
                }
            }
            if call.name == "check" {
                match crate::batteries::check_approval::completed(event, &mut state) {
                    Ok(Some(receipt)) => {
                        let entry_id = event.payload["id"]
                            .as_str()
                            .ok_or("check result has no entry id")?
                            .into();
                        state["last_check"] = serde_json::to_value(Latest {
                            version: 1,
                            entry_id,
                            receipt,
                            current: true,
                        })
                        .unwrap();
                    }
                    Ok(None) => {}
                    Err(error) => {
                        response["notice"] = json!(format!("check evidence unavailable: {error}"))
                    }
                }
            }
        }
        "before_stop" => {
            if state["workspace_changed"] != true
                || latest(&state)?.is_some_and(|latest| latest.current && latest.receipt.passed)
                || crate::batteries::check_config::load(
                    context,
                    crate::batteries::check_config::system(),
                )?
                .is_none()
            {
                return Ok(response);
            }
            let count = state["check_reminders"].as_u64().unwrap_or(0);
            if count >= 3 {
                return Ok(response);
            }
            state["check_reminders"] = json!(count + 1);
            response["message"] = json!(
                "The workspace changed and no current passing check exists. Run the declared check before finishing; checks provide development evidence, not task acceptance."
            );
        }
        "turn_end" if state["workspace_changed"] == true => {
            response["hint"] =
                json!("Workspace changed; check results provide development evidence.");
        }
        _ => return Ok(response),
    }
    if event.session.state.as_ref() != Some(&state) {
        response["state"] = state;
    }
    Ok(response)
}

fn latest(state: &Value) -> Result<Option<Latest>, String> {
    let Some(value) = state.get("last_check") else {
        return Ok(None);
    };
    let latest: Latest = serde_json::from_value(value.clone())
        .map_err(|error| format!("invalid check state: {error}"))?;
    if latest.version != 1
        || latest.receipt.version != 1
        || latest.receipt.kind != "check"
        || latest.receipt.passed != (latest.receipt.exit_status == Some(0))
    {
        return Err("unsupported check-state version".into());
    }
    Ok(Some(latest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_or_stale_checks_remind_at_most_three_times_and_readers_keep_evidence_current() {
        let root =
            std::env::temp_dir().join(format!("batteries-check-state-{}", std::process::id()));
        std::fs::create_dir_all(root.join("workspace/.gears")).unwrap();
        let context = ToolContext::new(
            root.join("workspace"),
            root.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        std::fs::write(
            context.workspace.join(".gears/batteries.toml"),
            "check = ['program']",
        )
        .unwrap();
        let mut event = Event {
            protocol_version: 1,
            event: "turn_start".into(),
            workspace: context.workspace.clone(),
            session: crate::batteries::Session {
                id: "s1".into(),
                path: None,
                state: None,
            },
            payload: json!({}),
        };
        event.session.state = Some(observe(&event, &context).unwrap()["state"].clone());
        event.event = "entry".into();
        event.payload = json!({"id": "w1", "role": "tool", "tool_call": ToolCall::new("c1", "write_file", "{}"), "outcome": "completed"});
        event.session.state = Some(observe(&event, &context).unwrap()["state"].clone());
        event.event = "before_stop".into();
        for _ in 0..3 {
            let response = observe(&event, &context).unwrap();
            assert!(
                response["message"]
                    .as_str()
                    .unwrap()
                    .contains("no current passing check")
            );
            event.session.state = Some(response["state"].clone());
        }
        assert!(observe(&event, &context).unwrap().get("message").is_none());
        event.session.state.as_mut().unwrap()["check_reminders"] = json!(0);
        let mut receipt = Receipt {
            version: 1,
            kind: "check".into(),
            argv: vec!["program".into()],
            system: crate::batteries::check_config::system().into(),
            exit_status: Some(0),
            duration_ms: 3,
            passed: true,
            stdout: String::new(),
            stderr: String::new(),
            output_truncated: false,
            output_file: None,
        };
        for passed in [false, true] {
            let approval = crate::batteries::check_approval::prepare(&event, &context).unwrap();
            event.session.state = Some(approval["state"].clone());
            receipt.passed = passed;
            receipt.exit_status = Some(if passed { 0 } else { 1 });
            event.event = "entry".into();
            event.payload = json!({"id": if passed { "check1" } else { "failed-check" }, "role": "tool",
                "tool_call": ToolCall::new("c2", "check", "{}"), "outcome": "completed",
                "tool_result": {"content": serde_json::to_string(&receipt).unwrap(), "is_error": false}});
            event.session.state = Some(observe(&event, &context).unwrap()["state"].clone());
            event.event = "before_stop".into();
            assert_eq!(
                observe(&event, &context).unwrap().get("message").is_some(),
                !passed
            );
        }
        event.event = "entry".into();
        event.payload = json!({"id": "r1", "role": "tool", "tool_call": ToolCall::new("c3", "read_file", "{}"), "outcome": "completed", "tool": {"read_only": true}});
        assert!(observe(&event, &context).unwrap().get("state").is_none());
        for name in ["memory", "skill_view"] {
            event.event = "entry".into();
            event.payload = json!({"id": "state-call", "role": "tool", "tool_call": ToolCall::new("state-caller", name, "{}"), "outcome": "completed"});
            assert!(
                observe(&event, &context).unwrap().get("state").is_none(),
                "{name} must preserve check evidence"
            );
        }
        event.event = "before_stop".into();
        assert!(observe(&event, &context).unwrap().get("message").is_none());
        event.event = "entry".into();
        event.payload = json!({"id": "s1", "role": "tool", "tool_call": ToolCall::new("c4", "external", "{}"), "outcome": "not_started"});
        event.session.state = Some(observe(&event, &context).unwrap()["state"].clone());
        assert_eq!(
            event.session.state.as_ref().unwrap()["last_check"]["current"],
            false
        );
        event.event = "before_stop".into();
        assert!(observe(&event, &context).unwrap().get("message").is_some());
        std::fs::remove_dir_all(root).unwrap();
    }
}
