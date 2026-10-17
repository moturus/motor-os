//! Batteries authority is composed with Gears' saved grants and prompts.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::hooks::Decision;
use crate::provider::ToolCall;
use crate::state::StateRoot;
use serde_json::{Value, json};

use crate::batteries::{Event, paths::ToolContext};

pub fn permission(event: &Event) -> Value {
    let decision = ToolContext::for_event(event).and_then(|context| {
        if event.payload["tool_call"]["name"] == "check" {
            let call: ToolCall = serde_json::from_value(event.payload["tool_call"].clone())
                .map_err(|error| error.to_string())?;
            let arguments: Value =
                serde_json::from_str(&call.arguments).map_err(|error| error.to_string())?;
            if arguments != json!({}) {
                return Err("check takes an empty argument object".into());
            }
            crate::batteries::check_approval::prepare(event, &context)
        } else {
            decide(event, &context).map(|decision| json!({"decision": decision}))
        }
    });
    match decision {
        Ok(response) => response,
        Err(error) => {
            json!({"decision": "deny", "notice": format!("approval policy denied the call: {error}")})
        }
    }
}

pub fn decide(event: &Event, context: &ToolContext) -> Result<Decision, String> {
    let call: ToolCall = serde_json::from_value(event.payload["tool_call"].clone())
        .map_err(|error| format!("invalid permission call: {error}"))?;
    let arguments: Value =
        serde_json::from_str(&call.arguments).map_err(|error| error.to_string())?;
    if !arguments.is_object() {
        return Err("tool arguments must be an object".into());
    }
    match call.name.as_str() {
        "todo" | "session_search" | "skill_view" | "memory" => Ok(Decision::Allow),
        "read_file" | "search_files" => {
            let input = arguments["path"]
                .as_str()
                .or_else(|| (call.name == "search_files").then_some("."))
                .ok_or("reading tool has no path")?;
            let path = context.resolve(input, false)?;
            if call.name == "search_files" && context.state.path().starts_with(&path) {
                return Err("search path contains the Gears directory".into());
            }
            Ok(
                if path.starts_with(&context.workspace) || path.starts_with(context.state.path()) {
                    Decision::Allow
                } else {
                    Decision::Ask
                },
            )
        }
        "ls" | "head" | "tail" | "cat" | "wc" | "find" | "rg"
            if event.payload["tool"]["read_only"] == true =>
        {
            let path = context.resolve(
                arguments["path"]
                    .as_str()
                    .ok_or("reading tool has no path")?,
                false,
            )?;
            Ok(if path.starts_with(&context.workspace) {
                Decision::Allow
            } else {
                Decision::Ask
            })
        }
        "diff" if event.payload["tool"]["read_only"] == true => {
            let mut inside = true;
            for field in ["left", "right"] {
                let path = context.resolve(
                    arguments[field].as_str().ok_or("diff has no file path")?,
                    false,
                )?;
                inside &= path.starts_with(&context.workspace);
            }
            Ok(if inside {
                Decision::Allow
            } else {
                Decision::Ask
            })
        }
        "gix"
            if matches!(
                arguments["action"].as_str(),
                Some("push" | "checkout" | "restore")
            ) =>
        {
            Ok(Decision::Confirm)
        }
        "write_file" | "patch" => {
            context.resolve(
                arguments["path"]
                    .as_str()
                    .ok_or("writing tool has no path")?,
                true,
            )?;
            Ok(Decision::Ask)
        }
        "sh" => {
            let command = arguments["command"].as_str().ok_or("sh has no command")?;
            let cwd = shell_cwd(event, &context.workspace)?;
            crate::batteries::command_policy::inspect(command, &cwd, context.state.path())
        }
        "check" => Ok(Decision::Confirm),
        _ => Ok(Decision::Ask),
    }
}

fn shell_cwd(event: &Event, workspace: &Path) -> Result<PathBuf, String> {
    let Some(directory) = event.payload["tool"]["shell_state_directory"].as_str() else {
        return Ok(workspace.into());
    };
    if !Path::new(directory).is_absolute() {
        return Err("shell state path is not absolute".into());
    }
    let root = StateRoot::new(directory.into())?;
    let Some(path) = root.existing_file(Path::new("cwd"))? else {
        return Ok(workspace.into());
    };
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|error| error.to_string())?
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 4096 {
        return Err("saved shell directory exceeds 4096 bytes".into());
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "saved shell directory is not UTF-8")?
        .trim_end_matches(['\r', '\n']);
    if text.contains(['\n', '\r', '\0']) || !Path::new(text).is_absolute() {
        return Err("invalid saved shell directory".into());
    }
    Ok(if Path::new(text).is_dir() {
        text.into()
    } else {
        workspace.into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(context: &ToolContext, name: &str, arguments: Value) -> Event {
        Event {
            protocol_version: 1,
            event: "permission".into(),
            workspace: context.workspace.clone(),
            session: crate::batteries::Session {
                id: context.session.clone(),
                path: None,
                state: None,
            },
            payload: json!({"tool_call": ToolCall::new("c1", name, arguments.to_string())}),
        }
    }

    #[test]
    fn automatic_reads_are_scoped_and_writers_or_unknown_tools_need_user_authority() {
        let root = std::env::temp_dir().join(format!("batteries-policy-{}", std::process::id()));
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        let context = ToolContext::new(
            root.join("workspace"),
            root.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        for (name, args, expected) in [
            ("read_file", json!({"path": "file"}), Decision::Allow),
            ("read_file", json!({"path": "../outside"}), Decision::Ask),
            ("search_files", json!({"pattern": "text"}), Decision::Allow),
            (
                "write_file",
                json!({"path": "file", "content": "text"}),
                Decision::Ask,
            ),
            ("todo", json!({}), Decision::Allow),
            ("check", json!({}), Decision::Confirm),
            ("external", json!({}), Decision::Ask),
            ("cat", json!({"path": "file"}), Decision::Ask),
            ("sh", json!({"command": "rm -rf /user"}), Decision::Deny),
        ] {
            assert_eq!(
                decide(&event(&context, name, args), &context).unwrap(),
                expected,
                "{name}"
            );
        }
        assert!(
            decide(
                &event(&context, "read_file", json!({"path": "../state/key"})),
                &context
            )
            .is_err()
        );
        let mut read = event(&context, "cat", json!({"path": "file"}));
        read.payload["tool"] = json!({"read_only": true});
        assert_eq!(decide(&read, &context).unwrap(), Decision::Allow);
        read.payload["tool_call"] = json!(ToolCall::new(
            "c2",
            "diff",
            json!({"left": "file", "right": "other"}).to_string()
        ));
        assert_eq!(decide(&read, &context).unwrap(), Decision::Allow);
        read.payload["tool_call"] = json!(ToolCall::new(
            "c3",
            "diff",
            json!({"left": "file", "right": "../outside"}).to_string()
        ));
        assert_eq!(decide(&read, &context).unwrap(), Decision::Ask);
        read.payload["tool_call"] = json!(ToolCall::new(
            "c4",
            "rg",
            json!({"path": "file", "pattern": "text"}).to_string()
        ));
        assert_eq!(decide(&read, &context).unwrap(), Decision::Allow);
        assert_eq!(
            decide(&event(&context, "gix", json!({"action": "push"})), &context).unwrap(),
            Decision::Confirm
        );
        let directory = context.state.directory(Path::new("shell")).unwrap();
        std::fs::write(
            directory.join("cwd"),
            format!("{}\n", context.state.path().display()),
        )
        .unwrap();
        let mut shell = event(&context, "sh", json!({"command": "rm key"}));
        shell.payload["tool"] = json!({"shell_state_directory": directory});
        assert_eq!(decide(&shell, &context).unwrap(), Decision::Deny);
        std::fs::write(context.state.path().join("shell/cwd"), "bad\nvalue\n").unwrap();
        assert!(decide(&shell, &context).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
