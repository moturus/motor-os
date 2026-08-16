//! Root-agent operations over the durable task model.

use serde_json::{Value, json};

use super::{Tool, schema, string_arg};
use crate::agent::task::{ItemState, Mode};
use crate::provider::ToolSpec;

pub const NAME: &str = "task";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    Add {
        text: String,
    },
    Transition {
        id: u64,
        from: ItemState,
        to: ItemState,
        text: Option<String>,
    },
    Wait {
        question: String,
    },
    Mode {
        from: Mode,
        to: Mode,
    },
}

pub fn tool() -> Box<dyn Tool> {
    Box::new(TaskTool)
}

pub fn parse(args: &Value) -> Result<Operation, String> {
    let object = args
        .as_object()
        .ok_or_else(|| "task arguments must be an object".to_string())?;
    const NAMES: &[&str] = &[
        "action",
        "id",
        "from",
        "to",
        "text",
        "question",
        "from_mode",
        "to_mode",
    ];
    if let Some(name) = object.keys().find(|name| !NAMES.contains(&name.as_str())) {
        return Err(format!("unknown argument '{name}'"));
    }

    match string_arg(args, "action")?.as_str() {
        "add" => {
            reject(
                args,
                &["id", "from", "to", "question", "from_mode", "to_mode"],
                "add",
            )?;
            Ok(Operation::Add {
                text: string_arg(args, "text")?,
            })
        }
        "transition" => {
            reject(args, &["question", "from_mode", "to_mode"], "transition")?;
            Ok(Operation::Transition {
                id: positive(args, "id")?,
                from: state(args, "from")?,
                to: state(args, "to")?,
                text: super::opt_string(args, "text")?,
            })
        }
        "wait" => {
            reject(
                args,
                &["id", "from", "to", "text", "from_mode", "to_mode"],
                "wait",
            )?;
            Ok(Operation::Wait {
                question: string_arg(args, "question")?,
            })
        }
        "mode" => {
            reject(args, &["id", "from", "to", "text", "question"], "mode")?;
            Ok(Operation::Mode {
                from: mode(args, "from_mode")?,
                to: mode(args, "to_mode")?,
            })
        }
        action => Err(format!(
            "unknown action '{action}' (expected 'add', 'transition', 'wait', or 'mode')"
        )),
    }
}

struct TaskTool;

impl Tool for TaskTool {
    fn name(&self) -> &'static str {
        NAME
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            NAME,
            "Update the durable task: append work, make an explicit item-state or mode transition, or return a question to the user. Use the exact IDs, states, and mode shown in task state. Entering code may require user approval.",
            schema(
                json!({
                    "action": {"type": "string", "enum": ["add", "transition", "wait", "mode"]},
                    "id": {"type": "integer", "minimum": 1},
                    "from": {"type": "string", "enum": ["pending", "active", "completed", "blocked"]},
                    "to": {"type": "string", "enum": ["pending", "active", "completed", "blocked"]},
                    "text": {"type": "string", "description": "Required base wording for add; optional model refinement for transition."},
                    "question": {"type": "string", "description": "Required only for wait."},
                    "from_mode": {"type": "string", "enum": ["ask", "plan", "code", "review"]},
                    "to_mode": {"type": "string", "enum": ["ask", "plan", "code", "review"]},
                }),
                &["action"],
            ),
        )
    }

    fn mutates(&self) -> bool {
        false
    }

    fn call(&self, args: &Value) -> Result<String, String> {
        parse(args)?;
        Err("task operations are handled by the root agent".to_string())
    }
}

fn positive(args: &Value, name: &str) -> Result<u64, String> {
    match &args[name] {
        Value::Number(value) => value
            .as_u64()
            .filter(|value| *value > 0)
            .ok_or_else(|| format!("argument '{name}' must be a positive whole number")),
        Value::Null => Err(format!("missing required argument '{name}'")),
        _ => Err(format!("argument '{name}' must be a positive whole number")),
    }
}

fn state(args: &Value, name: &str) -> Result<ItemState, String> {
    match string_arg(args, name)?.as_str() {
        "pending" => Ok(ItemState::Pending),
        "active" => Ok(ItemState::Active),
        "completed" => Ok(ItemState::Completed),
        "blocked" => Ok(ItemState::Blocked),
        value => Err(format!("unknown task item state '{value}'")),
    }
}

fn mode(args: &Value, name: &str) -> Result<Mode, String> {
    let value = string_arg(args, name)?;
    crate::agent::mode::from_name(&value).ok_or_else(|| format!("unknown task mode '{value}'"))
}

fn reject(args: &Value, names: &[&str], action: &str) -> Result<(), String> {
    match names.iter().find(|name| !args[**name].is_null()) {
        Some(name) => Err(format!(
            "argument '{name}' does not apply to action '{action}'"
        )),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_operation() {
        assert_eq!(
            parse(&json!({"action": "add", "text": "verify"})).unwrap(),
            Operation::Add {
                text: "verify".into()
            }
        );
        assert_eq!(
            parse(&json!({
                "action": "transition", "id": 2,
                "from": "pending", "to": "active", "text": "run checks"
            }))
            .unwrap(),
            Operation::Transition {
                id: 2,
                from: ItemState::Pending,
                to: ItemState::Active,
                text: Some("run checks".into()),
            }
        );
        assert_eq!(
            parse(&json!({"action": "wait", "question": "which parser?"})).unwrap(),
            Operation::Wait {
                question: "which parser?".into()
            }
        );
        assert_eq!(
            parse(&json!({"action": "mode", "from_mode": "code", "to_mode": "review"})).unwrap(),
            Operation::Mode {
                from: Mode::Code,
                to: Mode::Review,
            }
        );
    }

    #[test]
    fn the_task_tool_contract_is_a_reviewable_fixture() {
        assert_eq!(crate::tools::SPEC_VERSION, 4);
        let spec = tool().spec();
        assert_eq!(
            spec.function.description,
            "Update the durable task: append work, make an explicit item-state or mode transition, or return a question to the user. Use the exact IDs, states, and mode shown in task state. Entering code may require user approval."
        );
        assert_eq!(
            spec.function.parameters["properties"]["action"]["enum"],
            json!(["add", "transition", "wait", "mode"])
        );
        assert_eq!(
            spec.function.parameters["properties"]["from_mode"]["enum"],
            json!(["ask", "plan", "code", "review"])
        );
        assert_eq!(
            spec.function.parameters["properties"]["to_mode"]["enum"],
            json!(["ask", "plan", "code", "review"])
        );
    }

    #[test]
    fn rejects_inapplicable_and_invalid_arguments() {
        assert!(parse(&json!({"action": "add", "text": "x", "id": 1})).is_err());
        assert!(
            parse(&json!({"action": "transition", "id": 0, "from": "pending", "to": "active"}))
                .is_err()
        );
        assert!(
            parse(&json!({"action": "transition", "id": 1, "from": "new", "to": "active"}))
                .is_err()
        );
        assert!(parse(&json!({"action": "wait", "question": "x", "extra": true})).is_err());
        assert!(parse(&json!({"action": "mode", "from_mode": "ask", "to_mode": "write"})).is_err());
    }
}
