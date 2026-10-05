//! Interactive admission uses Gears' existing hook question/answer lifecycle.

use gears::provider::Message;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::Event;
use crate::memory_format::Target;
use crate::paths::ToolContext;
use crate::pending::Decision;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Awaiting {
    version: u32,
    id: String,
    target: Target,
}

pub fn after_result(event: &Event, context: &ToolContext) -> Result<Value, String> {
    if event.payload["tool_call"]["name"] != "memory"
        || event.payload["tool_result"]["is_error"] != false
    {
        return Ok(json!({}));
    }
    let content = event.payload["tool_result"]["content"]
        .as_str()
        .ok_or("memory result has no content")?;
    let result: Value = serde_json::from_str(content).map_err(|error| error.to_string())?;
    if result["status"] != "pending" {
        return Ok(json!({}));
    }
    let state = crate::hook_state(event)?;
    let awaiting: Awaiting = serde_json::from_value(state["awaiting_memory"].clone())
        .map_err(|error| format!("invalid pending memory question: {error}"))?;
    if awaiting.version != 1 || result["proposal_id"] != awaiting.id {
        return Err("memory result does not match the pending question".into());
    }
    let proposal = crate::pending::load(context, awaiting.target, &awaiting.id)?;
    let other = crate::pending::list(context, Target::Global).and_then(|global| {
        crate::pending::list(context, Target::Workspace)
            .map(|workspace| global.len() + workspace.len() - 1)
    });
    let count = match &other {
        Ok(count) => count.to_string(),
        Err(_) => "an unknown number of".into(),
    };
    let mut notice = format!(
        "Memory proposal {}:\n{}",
        awaiting.id,
        serde_json::to_string_pretty(&proposal).map_err(|error| error.to_string())?
    );
    if let Err(error) = other {
        notice.push_str(&format!("\nPending count unavailable: {error}"));
    }
    Ok(json!({"notice": notice, "question": {"id": awaiting.id,
        "text": format!("Approve this memory change? {count} other memory changes are waiting."),
        "choices": [{"value": "approve", "label": "Approve"}, {"value": "deny", "label": "Deny"},
            {"value": "postpone", "label": "Postpone"}]}}))
}

pub fn answer(event: &Event, context: &ToolContext) -> Result<Value, String> {
    let mut state = crate::hook_state(event)?;
    let Some(value) = state.get("awaiting_memory") else {
        return Ok(json!({}));
    };
    let awaiting: Awaiting =
        serde_json::from_value(value.clone()).map_err(|error| error.to_string())?;
    if awaiting.version != 1 || event.payload["id"] != awaiting.id {
        return Err("memory answer does not match the pending question".into());
    }
    let decision = decision(event)?;
    if let Err(error) = crate::memory::decide(context, awaiting.target, &awaiting.id, decision) {
        let text = format!(
            "Memory proposal {} decision failed: {error}. It remains pending.",
            awaiting.id
        );
        return Ok(json!({"notice": text, "context": Message::user(text)}));
    }
    state.as_object_mut().unwrap().remove("awaiting_memory");
    let action = match decision {
        Decision::Approve => "approved",
        Decision::Deny => "denied",
        Decision::Postpone => "postponed; still pending",
    };
    let text = format!(
        "Memory proposal {}: {action}. Approval admits future use and does not prove usefulness.",
        awaiting.id
    );
    Ok(json!({"state": state, "notice": text, "context": Message::user(text)}))
}

pub(crate) fn decision(event: &Event) -> Result<Decision, String> {
    Ok(
        if event.payload["attended"] != true || event.payload["cancelled"] == true {
            Decision::Postpone
        } else {
            match event.payload["answer"].as_str() {
                Some("approve") => Decision::Approve,
                Some("deny") => Decision::Deny,
                None | Some("postpone") => Decision::Postpone,
                _ => return Err("invalid memory approval answer".into()),
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use gears::provider::ToolCall;

    #[test]
    fn questions_show_proposals_and_deliver_attended_or_unattended_outcomes() {
        for (choice, attended, count, pending) in [
            ("approve", true, 1, 0),
            ("deny", true, 0, 0),
            ("postpone", true, 0, 1),
            ("approve", false, 0, 1),
        ] {
            let path = std::env::temp_dir().join(format!(
                "batteries-memory-question-{choice}-{attended}-{}",
                std::process::id()
            ));
            std::fs::create_dir_all(path.join("workspace")).unwrap();
            let context = ToolContext::new(
                path.join("workspace"),
                path.join("state"),
                "s1".into(),
                None,
            )
            .unwrap();
            let mut event = Event {
                protocol_version: 1,
                event: "tool_execute".into(),
                workspace: context.workspace.clone(),
                session: crate::Session {
                    id: "s1".into(),
                    path: None,
                    state: Some(json!({"prompt_snapshot": "keep",
                    "turn_record": {"last_entry_id": "e-call"}})),
                },
                payload: json!({"tool_call":
                    ToolCall::new("c1", "memory", json!({"action": "add", "target": "user", "text": "Prefer Rust."}).to_string())}),
            };
            let response = crate::memory_tool::execute(&event, &context).unwrap();
            event.session.state = Some(response["state"].clone());
            event.payload["tool_result"] = response["tool_result"].clone();
            event.event = "tool_result".into();
            let question = after_result(&event, &context).unwrap();
            assert!(
                question["notice"]
                    .as_str()
                    .unwrap()
                    .contains("Prefer Rust.")
            );
            assert!(question["notice"].as_str().unwrap().contains("e-call"));
            assert_eq!(question["question"]["choices"].as_array().unwrap().len(), 3);
            assert!(
                question["question"]["text"]
                    .as_str()
                    .unwrap()
                    .contains("0 other")
            );
            event.event = "answer".into();
            event.payload = json!({"id": question["question"]["id"], "answer": choice, "attended": attended, "cancelled": false});
            let answered = answer(&event, &context).unwrap();
            assert_eq!(answered["state"]["prompt_snapshot"], "keep");
            assert!(answered["state"].get("awaiting_memory").is_none());
            let outcome = if !attended {
                "postponed"
            } else if choice == "deny" {
                "denied"
            } else {
                choice
            };
            assert!(answered["context"].to_string().contains(outcome));
            assert_eq!(
                crate::memory::load(&context, Target::User)
                    .unwrap()
                    .entries
                    .len(),
                count
            );
            assert_eq!(
                crate::pending::list(&context, Target::User).unwrap().len(),
                pending
            );
            std::fs::remove_dir_all(path).unwrap();
        }
    }
}
