//! Mechanical summaries tied to Gears' saved entry ids and runtime outcomes.

use std::collections::BTreeSet;

use gears::hooks::ToolResult;
use gears::provider::{ToolCall, ToolOutcome};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Event, paths::ToolContext};

#[derive(Default, Serialize, Deserialize)]
pub struct Turn {
    pub version: u32,
    pub number: u64,
    pub last_entry_id: Option<String>,
    pub tool_calls: u32,
    pub execution_errors: u32,
    pub not_started: u32,
    pub repeated_calls: u32,
    pub failing_tools: BTreeSet<String>,
    pub files_written: BTreeSet<std::path::PathBuf>,
    pub checks: Vec<Value>,
    pub compacted: bool,
    pub interrupted: bool,
    pub events: Vec<SavedTool>,
}

#[derive(Serialize, Deserialize)]
pub struct SavedTool {
    pub entry_id: String,
    pub call_id: String,
    pub name: String,
    pub outcome: ToolOutcome,
    pub is_error: bool,
    pub read_only: bool,
    pub repeated: bool,
}

pub fn observe(event: &Event, context: &ToolContext) -> Result<Value, String> {
    let mut state = crate::hook_state(event)?;
    if event.event == "turn_start" {
        let number = state
            .get("turn_number")
            .map(|value| value.as_u64().ok_or("invalid turn number"))
            .transpose()?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or("turn number overflow")?;
        state["turn_number"] = json!(number);
        state["turn_record"] = serde_json::to_value(Turn {
            version: 1,
            number,
            ..Turn::default()
        })
        .unwrap();
        return Ok(json!({"state": state}));
    }
    let Some(active) = state.get("turn_record") else {
        return Ok(json!({}));
    };
    let mut turn: Turn =
        serde_json::from_value(active.clone()).map_err(|error| error.to_string())?;
    if turn.version != 1 {
        return Err("unsupported turn-record version".into());
    }
    match event.event.as_str() {
        "entry" => {
            turn.last_entry_id = event.payload["id"].as_str().map(String::from);
            turn.compacted |= event.payload["type"] == "compaction";
            if event.payload["role"] == "tool" {
                record_tool(event, &mut state, &mut turn)?;
            }
            state["turn_record"] = serde_json::to_value(turn).unwrap();
        }
        "turn_end" => {
            turn.last_entry_id = event.payload["last_entry_id"].as_str().map(String::from);
            turn.interrupted = event.payload["status"] == "cancelled";
            crate::journal::append(context, "turns.jsonl", &turn)?;
            state.as_object_mut().unwrap().remove("turn_record");
        }
        _ => return Ok(json!({})),
    }
    Ok(json!({"state": state}))
}

fn record_tool(event: &Event, state: &mut Value, turn: &mut Turn) -> Result<(), String> {
    if turn.events.len() >= 512 {
        return Err("turn record exceeds 512 tool calls".into());
    }
    let call: ToolCall = serde_json::from_value(event.payload["tool_call"].clone())
        .map_err(|error| error.to_string())?;
    let result: ToolResult = serde_json::from_value(event.payload["tool_result"].clone())
        .map_err(|error| error.to_string())?;
    let outcome: ToolOutcome = serde_json::from_value(event.payload["outcome"].clone())
        .map_err(|error| error.to_string())?;
    let entry = event.payload["id"].as_str().ok_or("tool entry has no id")?;
    let arguments =
        serde_json::from_str::<Value>(&call.arguments).unwrap_or_else(|_| json!(call.arguments));
    let fingerprint = crate::snapshot::digest(json!([call.name, arguments]).to_string().as_bytes());
    let mut recent: Vec<String> = state
        .get("recent_calls")
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()
        .map_err(|error| error.to_string())?
        .unwrap_or_default();
    let repeated = recent.contains(&fingerprint);
    recent.push(fingerprint);
    if recent.len() > 2 {
        recent.drain(..recent.len() - 2);
    }
    state["recent_calls"] = json!(recent);
    turn.tool_calls += 1;
    turn.repeated_calls += u32::from(repeated);
    turn.not_started += u32::from(outcome == ToolOutcome::NotStarted);
    turn.execution_errors += u32::from(outcome != ToolOutcome::NotStarted && result.is_error);
    if result.is_error {
        turn.failing_tools.insert(call.name.clone());
    }
    if outcome == ToolOutcome::Completed
        && matches!(call.name.as_str(), "write_file" | "patch")
        && event.payload["tool_result_truncated"] != true
        && let Ok(receipt) = serde_json::from_str::<Value>(&result.content)
        && receipt["written"] == true
        && let Some(path) = receipt["path"].as_str()
    {
        turn.files_written.insert(path.into());
    }
    turn.events.push(SavedTool {
        entry_id: entry.into(),
        call_id: call.id,
        name: call.name,
        outcome,
        is_error: result.is_error,
        read_only: event.payload["tool"]["read_only"] == true,
        repeated,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send(context: &ToolContext, state: &mut Option<Value>, name: &str, payload: Value) {
        let response = observe(
            &Event {
                protocol_version: 1,
                event: name.into(),
                workspace: context.workspace.clone(),
                session: crate::Session {
                    id: context.session.clone(),
                    path: None,
                    state: state.clone(),
                },
                payload,
            },
            context,
        )
        .unwrap();
        if let Some(updated) = response.get("state") {
            *state = Some(updated.clone());
        }
    }

    #[test]
    fn records_failures_repetition_mutations_compaction_and_interruption_without_judging_success() {
        let root = std::env::temp_dir().join(format!("batteries-turns-{}", std::process::id()));
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        let context = ToolContext::new(
            root.join("workspace"),
            root.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        let mut state = Some(json!({"tasks": {"version": 1, "items": []}}));
        send(&context, &mut state, "turn_start", json!({}));
        for (id, name, arguments, error, outcome, content) in [
            ("e1", "sh", "{\"a\":1,\"b\":2}", true, "completed", "failed"),
            (
                "e2",
                "sh",
                "{\"b\":2,\"a\":1}",
                false,
                "completed",
                "passed",
            ),
            (
                "e3",
                "write_file",
                "{}",
                false,
                "completed",
                "{\"written\":true,\"path\":\"src/file\"}",
            ),
            ("e4", "write_file", "{}", true, "not_started", "denied"),
        ] {
            send(
                &context,
                &mut state,
                "entry",
                json!({"id": id, "role": "tool",
                "tool_call": ToolCall::new(id, name, arguments), "outcome": outcome,
                "tool_result": {"content": content, "is_error": error}, "tool": {"read_only": false}}),
            );
        }
        send(
            &context,
            &mut state,
            "entry",
            json!({"id": "compact", "type": "compaction"}),
        );
        send(
            &context,
            &mut state,
            "turn_end",
            json!({"last_entry_id": "final", "status": "cancelled"}),
        );
        let text = std::fs::read_to_string(context.data_file("turns.jsonl").unwrap()).unwrap();
        let turn: Turn = serde_json::from_str(text.trim_end()).unwrap();
        assert_eq!(
            (
                turn.number,
                turn.tool_calls,
                turn.execution_errors,
                turn.not_started,
                turn.repeated_calls
            ),
            (1, 4, 1, 1, 2)
        );
        assert_eq!(turn.last_entry_id.as_deref(), Some("final"));
        assert!(turn.compacted && turn.interrupted);
        assert_eq!(turn.files_written, BTreeSet::from(["src/file".into()]));
        assert_eq!(turn.events[3].outcome, ToolOutcome::NotStarted);
        assert_eq!(turn.events[0].entry_id, "e1");
        assert!(state.as_ref().unwrap().get("turn_record").is_none());
        assert!(state.as_ref().unwrap().get("tasks").is_some());
        send(&context, &mut state, "turn_start", json!({}));
        assert_eq!(state.as_ref().unwrap()["turn_record"]["number"], 2);
        std::fs::remove_dir_all(root).unwrap();
    }
}
