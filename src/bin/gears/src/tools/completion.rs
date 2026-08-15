//! Structured verification skips for reviewed candidates.

use serde_json::{Value, json};

use super::{Tool, schema, string_arg, string_list};
use crate::provider::ToolSpec;

pub const NAME: &str = "completion";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    Skip {
        program: String,
        args: Vec<String>,
        cwd: String,
        source: String,
        reason: String,
    },
}

pub fn tool() -> Box<dyn Tool> {
    Box::new(CompletionTool)
}

pub fn parse(args: &Value) -> Result<Operation, String> {
    let object = args
        .as_object()
        .ok_or_else(|| "completion arguments must be an object".to_string())?;
    const NAMES: &[&str] = &["action", "program", "args", "cwd", "source", "reason"];
    if let Some(name) = object.keys().find(|name| !NAMES.contains(&name.as_str())) {
        return Err(format!("unknown argument '{name}'"));
    }
    match string_arg(args, "action")?.as_str() {
        "skip" => {
            let program = string_arg(args, "program")?;
            native_program(&program)?;
            Ok(Operation::Skip {
                program,
                args: string_list(args, "args")?,
                cwd: string_arg(args, "cwd")?,
                source: string_arg(args, "source")?,
                reason: string_arg(args, "reason")?,
            })
        }
        action => Err(format!("unknown action '{action}' (expected 'skip')")),
    }
}

fn native_program(program: &str) -> Result<(), String> {
    if program.is_empty() {
        return Err("argument 'program' must not be empty".to_string());
    }
    if cfg!(target_os = "motor") && program == "cargo" {
        return Err("Motor OS verification uses lorry, not cargo".to_string());
    }
    if cfg!(not(target_os = "motor")) && program == "lorry" {
        return Err("Linux Rust verification uses cargo, not lorry".to_string());
    }
    Ok(())
}

struct CompletionTool;

impl Tool for CompletionTool {
    fn name(&self) -> &'static str {
        NAME
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            NAME,
            "Record an explicit reason a reviewed check candidate was not run. The candidate and reason become typed task evidence rather than an unverified prose claim.",
            schema(
                json!({
                    "action": {"type": "string", "enum": ["skip"]},
                    "program": {"type": "string", "description": "For skip: candidate program, or 'none' when no executable check applies."},
                    "args": {"type": "array", "items": {"type": "string"}, "description": "For skip: candidate arguments."},
                    "cwd": {"type": "string", "description": "For skip: candidate workspace-relative directory."},
                    "source": {"type": "string", "description": "For skip: manifest, instruction, or task evidence supporting the candidate."},
                    "reason": {"type": "string", "description": "For skip: why this candidate was not run."},
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
        Err("completion operations are handled by the root agent".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_reviewed_skip() {
        assert_eq!(crate::tools::SPEC_VERSION, 2);
        assert_eq!(
            tool().spec().function.parameters["properties"]["action"]["enum"],
            json!(["skip"])
        );
        assert!(matches!(
            parse(&json!({
                "action": "skip", "program": "none", "args": [], "cwd": ".",
                "source": "task inspection", "reason": "documentation only"
            }))
            .unwrap(),
            Operation::Skip { .. }
        ));
        assert!(parse(&json!({"action": "report"})).is_err());
        let wrong_backend = if cfg!(target_os = "motor") {
            "cargo"
        } else {
            "lorry"
        };
        assert!(native_program(wrong_backend).is_err());
    }
}
