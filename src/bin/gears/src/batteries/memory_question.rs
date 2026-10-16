//! The yes/no question for a proposed memory change, through Gears' hook questions.

use crate::provider::Message;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::batteries::Event;
use crate::batteries::memory::{Action, Change};
use crate::batteries::paths::ToolContext;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Awaiting {
    version: u32,
    question: String,
    change: Change,
}

fn awaiting(state: &Value) -> Result<Awaiting, String> {
    let awaiting: Awaiting = serde_json::from_value(state["awaiting_memory"].clone())
        .map_err(|error| format!("invalid waiting memory change: {error}"))?;
    if awaiting.version != 2 {
        return Err("unsupported waiting memory change".into());
    }
    awaiting.change.validate()?;
    Ok(awaiting)
}

pub fn after_result(event: &Event, _: &ToolContext) -> Result<Value, String> {
    if event.payload["tool_call"]["name"] != "memory"
        || event.payload["tool_result"]["is_error"] != false
    {
        return Ok(json!({}));
    }
    let content = event.payload["tool_result"]["content"]
        .as_str()
        .ok_or("memory result has no content")?;
    let result: Value = serde_json::from_str(content).map_err(|error| error.to_string())?;
    if result["status"] != "proposed" {
        return Ok(json!({}));
    }
    let awaiting = awaiting(&crate::batteries::hook_state(event)?)?;
    let change = &awaiting.change;
    let title = change.target.title().to_lowercase();
    let subject = change.subject();
    let (notice, text) = match change.action {
        Action::Add => (
            format!("Proposed {title} entry:\n{}", subject.text),
            "Remember this?",
        ),
        Action::Replace => (
            format!(
                "Proposed {title} replacement of [{}]:\n{}\nReplacing:\n{}",
                subject.id,
                subject.text,
                change.before.as_ref().unwrap().text
            ),
            "Replace this memory entry?",
        ),
        Action::Remove => (
            format!(
                "Proposed {title} removal of [{}]:\n{}",
                subject.id, subject.text
            ),
            "Forget this memory entry?",
        ),
    };
    Ok(
        json!({"notice": notice, "question": {"id": awaiting.question, "text": text,
        "choices": [{"value": "yes", "label": "Yes"}, {"value": "no", "label": "No"}]}}),
    )
}

pub fn answer(event: &Event, context: &ToolContext) -> Result<Value, String> {
    let mut state = crate::batteries::hook_state(event)?;
    if state.get("awaiting_memory").is_none() {
        return Ok(json!({}));
    }
    let awaiting = awaiting(&state)?;
    if event.payload["id"] != awaiting.question {
        return Err("memory answer does not match the waiting question".into());
    }
    state.as_object_mut().unwrap().remove("awaiting_memory");
    let change = &awaiting.change;
    let attended = event.payload["attended"] == true && event.payload["cancelled"] != true;
    let answer = event.payload["answer"].as_str().filter(|_| attended);
    let text = match answer {
        Some("yes") => match crate::batteries::memory::apply(context, change) {
            Ok(()) => {
                let verb = match change.action {
                    Action::Add => "remembered in",
                    Action::Replace => "replaced in",
                    Action::Remove => "forgotten from",
                };
                let mut text = format!(
                    "Memory entry [{}] {verb} {}.",
                    change.subject().id,
                    change.target.title().to_lowercase()
                );
                if let Err(error) = crate::batteries::memory::log(context, change, true) {
                    text.push_str(&format!(" The change log could not be written: {error}"));
                }
                text
            }
            Err(error) => format!("Memory change could not be applied: {error}."),
        },
        Some("no") => {
            let mut text = "Memory change declined.".to_string();
            if let Err(error) = crate::batteries::memory::log(context, change, false) {
                text.push_str(&format!(" The change log could not be written: {error}"));
            }
            text
        }
        None => "Memory change dropped: nobody answered.".to_string(),
        Some(_) => return Err("invalid memory answer".into()),
    };
    Ok(json!({"state": state, "notice": text, "context": Message::user(text)}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batteries::memory_format::Target;
    use crate::provider::ToolCall;

    #[test]
    fn questions_show_the_entry_and_only_yes_writes_it() {
        for (choice, attended, written, logged) in [
            (Some("yes"), true, 1, 1),
            (Some("no"), true, 0, 1),
            (None, true, 0, 0),
            (Some("yes"), false, 0, 0),
        ] {
            let path = std::env::temp_dir().join(format!(
                "batteries-memory-question-{}-{attended}-{}",
                choice.unwrap_or("skip"),
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
                session: crate::batteries::Session {
                    id: "s1".into(),
                    path: None,
                    state: Some(json!({"prompt_snapshot": "keep"})),
                },
                payload: json!({"tool_call":
                    ToolCall::new("c1", "memory", json!({"action": "add", "target": "user", "text": "Prefer Rust."}).to_string())}),
            };
            let response = crate::batteries::memory_tool::execute(&event, &context).unwrap();
            event.session.state = Some(response["state"].clone());
            event.payload["tool_result"] = response["tool_result"].clone();
            event.event = "tool_result".into();
            let question = after_result(&event, &context).unwrap();
            assert_eq!(
                question["notice"],
                "Proposed user memory entry:\nPrefer Rust."
            );
            assert_eq!(question["question"]["text"], "Remember this?");
            assert_eq!(question["question"]["choices"].as_array().unwrap().len(), 2);
            event.event = "answer".into();
            event.payload = json!({"id": question["question"]["id"], "answer": choice, "attended": attended, "cancelled": false});
            let answered = answer(&event, &context).unwrap();
            assert_eq!(answered["state"]["prompt_snapshot"], "keep");
            assert!(answered["state"].get("awaiting_memory").is_none());
            let outcome = match (choice, attended) {
                (Some("yes"), true) => "remembered in user memory",
                (Some("no"), true) => "declined",
                _ => "nobody answered",
            };
            assert!(answered["notice"].as_str().unwrap().contains(outcome));
            assert!(answered["context"].to_string().contains(outcome));
            assert_eq!(
                crate::batteries::memory::load(&context, Target::User)
                    .unwrap()
                    .entries
                    .len(),
                written
            );
            assert_eq!(
                crate::batteries::memory_history::history(&context, 0, 10).unwrap()["total"],
                logged
            );
            std::fs::remove_dir_all(path).unwrap();
        }
    }
}
