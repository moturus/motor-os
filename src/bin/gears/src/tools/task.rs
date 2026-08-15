//! Root-agent operations over the durable task model.

use serde_json::{Value, json};

use super::{Tool, schema, string_arg};
use crate::agent::task::ItemState;
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
}

pub fn tool() -> Box<dyn Tool> {
    Box::new(TaskTool)
}

pub fn parse(args: &Value) -> Result<Operation, String> {
    let object = args
        .as_object()
        .ok_or_else(|| "task arguments must be an object".to_string())?;
    const NAMES: &[&str] = &["action", "id", "from", "to", "text", "question"];
    if let Some(name) = object.keys().find(|name| !NAMES.contains(&name.as_str())) {
        return Err(format!("unknown argument '{name}'"));
    }

    match string_arg(args, "action")?.as_str() {
        "add" => {
            reject(args, &["id", "from", "to", "question"], "add")?;
            Ok(Operation::Add {
                text: string_arg(args, "text")?,
            })
        }
        "transition" => {
            reject(args, &["question"], "transition")?;
            Ok(Operation::Transition {
                id: positive(args, "id")?,
                from: state(args, "from")?,
                to: state(args, "to")?,
                text: super::opt_string(args, "text")?,
            })
        }
        "wait" => {
            reject(args, &["id", "from", "to", "text"], "wait")?;
            Ok(Operation::Wait {
                question: string_arg(args, "question")?,
            })
        }
        action => Err(format!(
            "unknown action '{action}' (expected 'add', 'transition', or 'wait')"
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
            "Update the durable task: append ordered work, make one explicit item-state transition, or return a question to the user. Use the exact item IDs and current states shown in task state.",
            schema(
                json!({
                    "action": {"type": "string", "enum": ["add", "transition", "wait"]},
                    "id": {"type": "integer", "minimum": 1},
                    "from": {"type": "string", "enum": ["pending", "active", "completed", "blocked"]},
                    "to": {"type": "string", "enum": ["pending", "active", "completed", "blocked"]},
                    "text": {"type": "string", "description": "Required base wording for add; optional model refinement for transition."},
                    "question": {"type": "string", "description": "Required only for wait."},
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
    }
}
