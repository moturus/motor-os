//! Loads one of the user's skills; a session may load at most three.

use crate::provider::ToolCall;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::batteries::Event;
use crate::batteries::paths::ToolContext;

const MAX_LOADED: usize = 3;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments {
    name: Option<String>,
}

pub fn specification() -> Value {
    json!({"name": "skill_view", "description": "Load one skill and its notes by name, or omit name to list the available skills. Load at most three skills per session. Current instructions take precedence over a skill.",
        "parameters": {"type": "object", "additionalProperties": false, "properties": {"name": {"type": "string"}}}})
}

pub fn execute(event: &Event, context: &ToolContext) -> Result<Value, String> {
    let call: ToolCall = serde_json::from_value(event.payload["tool_call"].clone())
        .map_err(|error| error.to_string())?;
    if call.name != "skill_view" {
        return Err("unknown skill view tool".into());
    }
    let arguments: Arguments = serde_json::from_str(&call.arguments)
        .map_err(|error| format!("invalid skill_view arguments: {error}"))?;
    let (catalog, _) =
        crate::batteries::skill_catalog::load(context, crate::batteries::skill_catalog::platform());
    let Some(name) = arguments.name else {
        return Ok(result(json!({"version": 1, "skills": catalog})));
    };
    if !catalog.iter().any(|skill| skill.name == name) {
        return Err("skill is unavailable".into());
    }
    let mut state = crate::batteries::hook_state(event)?;
    let mut loaded: Vec<String> = match state.get("skills_loaded") {
        None | Some(Value::Null) => Vec::new(),
        Some(value) => serde_json::from_value(value.clone())
            .map_err(|_| "invalid loaded skill list in hook state")?,
    };
    if !loaded.contains(&name) {
        if loaded.len() >= MAX_LOADED {
            return Err(
                "at most three skills may be loaded in a session; start a new session for others"
                    .into(),
            );
        }
        loaded.push(name.clone());
    }
    let content =
        crate::batteries::skill_store::current(context, &name)?.ok_or("skill is unavailable")?;
    state["skills_loaded"] = json!(loaded);
    let mut response = result(json!({"version": 1, "name": name, "content": content}));
    response["state"] = state;
    Ok(response)
}

fn result(content: Value) -> Value {
    json!({"tool_result": {"content": content.to_string(), "is_error": false}})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batteries::skill_format::Content;

    #[test]
    fn loads_listed_skills_and_refuses_a_fourth_or_an_unknown_one() {
        let root =
            std::env::temp_dir().join(format!("batteries-skill-view-{}", std::process::id()));
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        let context = ToolContext::new(
            root.join("workspace"),
            root.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        for name in ["a", "b", "c", "d"] {
            let content = Content {
                skill_md: format!(
                    "---\nname: {name}\ndescription: Skill {name}.\nmetadata: {{platforms: motor linux}}\n---\nSteps.\n"
                ),
                notes_md: Some(format!("Notes {name}.")),
            };
            crate::batteries::skill_store::write(&context, name, Some(&content)).unwrap();
        }
        let mut event = Event {
            protocol_version: 1,
            event: "tool_execute".into(),
            workspace: context.workspace.clone(),
            session: crate::batteries::Session {
                id: "s1".into(),
                path: None,
                state: Some(json!({"tasks": ["keep"]})),
            },
            payload: json!({}),
        };
        let view = |event: &mut Event, arguments: Value| {
            event.payload =
                json!({"tool_call": ToolCall::new("c", "skill_view", arguments.to_string())});
            let response = execute(event, &context)?;
            if let Some(state) = response.get("state") {
                event.session.state = Some(state.clone());
            }
            Ok::<Value, String>(response)
        };
        let listing = view(&mut event, json!({})).unwrap();
        assert!(
            listing["tool_result"]["content"]
                .as_str()
                .unwrap()
                .contains("\"name\":\"d\"")
        );
        for name in ["a", "b", "c", "a"] {
            let response = view(&mut event, json!({"name": name})).unwrap();
            assert!(
                response["tool_result"]["content"]
                    .as_str()
                    .unwrap()
                    .contains(&format!("Notes {name}."))
            );
        }
        assert_eq!(
            event.session.state.as_ref().unwrap()["skills_loaded"],
            json!(["a", "b", "c"])
        );
        assert_eq!(
            event.session.state.as_ref().unwrap()["tasks"],
            json!(["keep"])
        );
        assert!(
            view(&mut event, json!({"name": "d"}))
                .unwrap_err()
                .contains("at most three")
        );
        assert!(
            view(&mut event, json!({"name": "missing"}))
                .unwrap_err()
                .contains("unavailable")
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
