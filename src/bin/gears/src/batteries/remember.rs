//! `/remember` and `/remember-host` write the user's own words to memory at once.

use serde_json::{Value, json};

use crate::batteries::Event;
use crate::batteries::memory::{Action, Change};
use crate::batteries::memory_format::{Entry, Target};
use crate::batteries::paths::ToolContext;

pub fn specifications() -> Value {
    json!([
        {"name": "remember", "help": "Remember TEXT in this workspace's memory"},
        {"name": "remember-host", "help": "Remember TEXT in this computer's memory"}
    ])
}

/// Commands are registered only when the hook receives them.
pub fn subscribed(event: &Event) -> bool {
    match &event.payload["subscribed_events"] {
        Value::Array(events) => events.iter().any(|event| event == "command"),
        _ => true,
    }
}

pub fn command(event: &Event, context: &ToolContext) -> Result<Value, String> {
    let name = event.payload["name"].as_str().unwrap_or_default();
    let target = match name {
        "remember" => Target::Workspace,
        "remember-host" => Target::Global,
        _ => return Err(format!("unknown batteries command /{name}")),
    };
    let text = event.payload["argument"]
        .as_str()
        .ok_or("command has no argument")?
        .trim();
    if text.is_empty() {
        return Ok(json!({"notice": format!("Usage: /{name} TEXT")}));
    }
    let document = crate::batteries::memory::load(context, target)?;
    let (date, time_ms) = crate::batteries::memory_format::today()?;
    let entry = Entry {
        id: crate::batteries::memory::new_id(
            &document,
            &format!("{}:{name}:{time_ms}:{text}", context.session),
        ),
        date,
        session: context.session.clone(),
        text: text.to_string(),
    };
    let change = Change {
        version: 2,
        target,
        action: Action::Add,
        before: None,
        after: Some(entry),
    };
    let title = target.title().to_lowercase();
    if !crate::batteries::memory::propose(context, &change)? {
        return Ok(json!({"notice": format!("Already remembered in {title}.")}));
    }
    crate::batteries::memory::apply(context, &change)?;
    let mut notice = format!("Remembered [{}] in {title}.", change.subject().id);
    if let Err(error) = crate::batteries::memory::log(context, &change, true) {
        notice.push_str(&format!(" The change log could not be written: {error}"));
    }
    Ok(json!({"notice": notice}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(context: &ToolContext, name: &str, argument: &str) -> Event {
        Event {
            protocol_version: 1,
            event: "command".into(),
            workspace: context.workspace.clone(),
            session: crate::batteries::Session {
                id: context.session.clone(),
                path: None,
                state: None,
            },
            payload: json!({"name": name, "argument": argument}),
        }
    }

    #[test]
    fn commands_write_the_users_words_to_workspace_or_host_memory_and_log_them() {
        let root = std::env::temp_dir().join(format!("batteries-remember-{}", std::process::id()));
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        let context = ToolContext::new(
            root.join("workspace"),
            root.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        let response = command(
            &event(&context, "remember", "  Run `lorry test` here.\n"),
            &context,
        )
        .unwrap();
        assert!(
            response["notice"]
                .as_str()
                .unwrap()
                .ends_with("in workspace memory."),
            "{response}"
        );
        let workspace = crate::batteries::memory::load(&context, Target::Workspace).unwrap();
        assert_eq!(workspace.entries.len(), 1);
        assert_eq!(workspace.entries[0].text, "Run `lorry test` here.");
        assert_eq!(workspace.entries[0].session, "s1");
        let again = command(
            &event(&context, "remember", "Run `lorry test` here."),
            &context,
        )
        .unwrap();
        assert_eq!(again["notice"], "Already remembered in workspace memory.");
        command(
            &event(&context, "remember-host", "This VM has no network."),
            &context,
        )
        .unwrap();
        let host = crate::batteries::memory::load(&context, Target::Global).unwrap();
        assert_eq!(host.entries[0].text, "This VM has no network.");
        let history = crate::batteries::memory_history::history(&context, 0, 10).unwrap();
        assert_eq!(history["total"], 2);
        assert_eq!(
            command(&event(&context, "remember", " \n"), &context).unwrap()["notice"],
            "Usage: /remember TEXT"
        );
        assert!(command(&event(&context, "forget", "x"), &context).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn commands_are_registered_only_for_a_hook_that_receives_them() {
        let mut initialize = Event {
            protocol_version: 1,
            event: "initialize".into(),
            workspace: "/work".into(),
            session: crate::batteries::Session {
                id: "s1".into(),
                path: None,
                state: None,
            },
            payload: json!({"subscribed_events": ["initialize", "command"]}),
        };
        assert!(subscribed(&initialize));
        initialize.payload = json!({"subscribed_events": ["initialize"]});
        assert!(!subscribed(&initialize));
        initialize.payload = json!({"subscribed_events": null});
        assert!(subscribed(&initialize));
    }
}
