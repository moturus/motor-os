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
    Report {
        evidence: Vec<u64>,
        assumptions: Vec<String>,
    },
}

pub fn tool() -> Box<dyn Tool> {
    Box::new(CompletionTool)
}

pub fn parse(args: &Value) -> Result<Operation, String> {
    let object = args
        .as_object()
        .ok_or_else(|| "completion arguments must be an object".to_string())?;
    const NAMES: &[&str] = &[
        "action",
        "program",
        "args",
        "cwd",
        "source",
        "reason",
        "evidence",
        "assumptions",
    ];
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
        "report" => Ok(Operation::Report {
            evidence: evidence_list(args)?,
            assumptions: assumptions(args)?,
        }),
        action => Err(format!(
            "unknown action '{action}' (expected 'skip' or 'report')"
        )),
    }
}

fn evidence_list(args: &Value) -> Result<Vec<u64>, String> {
    let Some(values) = args["evidence"].as_array() else {
        return Err("argument 'evidence' must be a list of positive integers".to_string());
    };
    if values.is_empty() || values.len() > 256 {
        return Err("argument 'evidence' must contain 1..=256 ids".to_string());
    }
    let mut ids = Vec::with_capacity(values.len());
    for value in values {
        let Some(id) = value.as_u64().filter(|id| *id > 0) else {
            return Err("argument 'evidence' must contain positive integers".to_string());
        };
        if ids.contains(&id) {
            return Err("argument 'evidence' contains a duplicate id".to_string());
        }
        ids.push(id);
    }
    Ok(ids)
}

fn assumptions(args: &Value) -> Result<Vec<String>, String> {
    let assumptions = string_list(args, "assumptions")?;
    if assumptions.len() > 16
        || assumptions
            .iter()
            .any(|text| text.trim().is_empty() || text.len() > 256 || text.contains('\0'))
    {
        return Err(
            "argument 'assumptions' must contain at most 16 non-empty 256-byte strings".to_string(),
        );
    }
    Ok(assumptions)
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
            "Record a reviewed check skip, or emit the authoritative completion report from current task and verification state.",
            schema(
                json!({
                    "action": {"type": "string", "enum": ["skip", "report"]},
                    "program": {"type": "string", "description": "For skip: candidate program, or 'none' when no executable check applies."},
                    "args": {"type": "array", "items": {"type": "string"}, "description": "For skip: candidate arguments."},
                    "cwd": {"type": "string", "description": "For skip: candidate workspace-relative directory."},
                    "source": {"type": "string", "description": "For skip: manifest, instruction, or task evidence supporting the candidate."},
                    "reason": {"type": "string", "description": "For skip: why this candidate was not run."},
                    "evidence": {"type": "array", "items": {"type": "integer", "minimum": 1}, "description": "For report: every evidence id attached to the current task, in order."},
                    "assumptions": {"type": "array", "items": {"type": "string"}, "description": "For report: unverified assumptions; use an empty list when there are none."},
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
        assert_eq!(crate::tools::SPEC_VERSION, 4);
        assert_eq!(
            tool().spec().function.parameters["properties"]["action"]["enum"],
            json!(["skip", "report"])
        );
        assert!(matches!(
            parse(&json!({
                "action": "skip", "program": "none", "args": [], "cwd": ".",
                "source": "task inspection", "reason": "documentation only"
            }))
            .unwrap(),
            Operation::Skip { .. }
        ));
        assert_eq!(
            parse(&json!({
                "action": "report", "evidence": [2, 5], "assumptions": []
            }))
            .unwrap(),
            Operation::Report {
                evidence: vec![2, 5],
                assumptions: Vec::new(),
            }
        );
        assert!(
            parse(&json!({
                "action": "report", "evidence": [2, 2], "assumptions": []
            }))
            .is_err()
        );
        let wrong_backend = if cfg!(target_os = "motor") {
            "cargo"
        } else {
            "lorry"
        };
        assert!(native_program(wrong_backend).is_err());
    }
}
