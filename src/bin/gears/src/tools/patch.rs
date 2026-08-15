//! Versioned model-facing grammar for atomic workspace patches.

use serde_json::{Map, Value, json};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub version: u64,
    pub operations: Vec<Operation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    Create {
        path: String,
        content: String,
        executable: Option<bool>,
    },
    Edit {
        path: String,
        expected_identity: Option<String>,
        hunks: Vec<Hunk>,
        executable: Option<bool>,
    },
    Delete {
        path: String,
        expected_identity: Option<String>,
    },
    Rename {
        path: String,
        to: String,
        expected_identity: Option<String>,
        hunks: Vec<Hunk>,
        executable: Option<bool>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hunk {
    pub old: String,
    pub new: String,
}

impl Request {
    pub fn parse(value: &Value) -> Result<Request, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "patch request must be an object".to_string())?;
        exact_keys(object, &["version", "operations"], "patch request")?;
        let version = object
            .get("version")
            .and_then(Value::as_u64)
            .ok_or_else(|| "patch version must be the integer 1".to_string())?;
        if version != 1 {
            return Err(format!("unsupported patch version {version}; expected 1"));
        }
        let items = object
            .get("operations")
            .and_then(Value::as_array)
            .ok_or_else(|| "patch operations must be an array".to_string())?;
        if items.is_empty() {
            return Err("patch operations must not be empty".to_string());
        }
        let operations = items
            .iter()
            .enumerate()
            .map(|(index, value)| parse_operation(index, value))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Request {
            version,
            operations,
        })
    }
}

/// Deliberately one simple operation object rather than provider-specific
/// unions. Runtime validation below enforces which fields belong to each kind.
pub fn schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "version": {"type": "integer", "enum": [1]},
            "operations": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "properties": {
                        "kind": {"type": "string", "enum": ["create", "edit", "delete", "rename"]},
                        "path": {"type": "string", "description": "Workspace-relative source path."},
                        "to": {"type": "string", "description": "Workspace-relative rename destination."},
                        "content": {"type": "string", "description": "Complete contents for a created file."},
                        "expected_identity": {"type": "string", "description": "Optional identity returned by read_file."},
                        "hunks": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "old": {"type": "string"},
                                    "new": {"type": "string"}
                                },
                                "required": ["old", "new"],
                                "additionalProperties": false
                            }
                        },
                        "executable": {"type": "boolean", "description": "Set or clear the Unix executable bits; Linux only."}
                    },
                    "required": ["kind", "path"],
                    "additionalProperties": false
                }
            }
        },
        "required": ["version", "operations"],
        "additionalProperties": false
    })
}

fn parse_operation(index: usize, value: &Value) -> Result<Operation, String> {
    let what = format!("operation {index}");
    let object = value
        .as_object()
        .ok_or_else(|| format!("{what} must be an object"))?;
    let kind = text(object, "kind", &what)?;
    let path = nonempty(text(object, "path", &what)?, &format!("{what} path"))?;
    match kind.as_str() {
        "create" => {
            exact_keys(object, &["kind", "path", "content", "executable"], &what)?;
            Ok(Operation::Create {
                path,
                content: text(object, "content", &what)?,
                executable: optional_bool(object, "executable", &what)?,
            })
        }
        "edit" => {
            exact_keys(
                object,
                &["kind", "path", "expected_identity", "hunks", "executable"],
                &what,
            )?;
            let hunks = hunks(object, true, &what)?;
            let executable = optional_bool(object, "executable", &what)?;
            if hunks.is_empty() && executable.is_none() {
                return Err(format!(
                    "{what} edit must contain a hunk or an executable-bit change"
                ));
            }
            Ok(Operation::Edit {
                path,
                expected_identity: optional_text(object, "expected_identity", &what)?,
                hunks,
                executable,
            })
        }
        "delete" => {
            exact_keys(object, &["kind", "path", "expected_identity"], &what)?;
            Ok(Operation::Delete {
                path,
                expected_identity: optional_text(object, "expected_identity", &what)?,
            })
        }
        "rename" => {
            exact_keys(
                object,
                &[
                    "kind",
                    "path",
                    "to",
                    "expected_identity",
                    "hunks",
                    "executable",
                ],
                &what,
            )?;
            Ok(Operation::Rename {
                path,
                to: nonempty(
                    text(object, "to", &what)?,
                    &format!("{what} rename destination"),
                )?,
                expected_identity: optional_text(object, "expected_identity", &what)?,
                hunks: hunks(object, false, &what)?,
                executable: optional_bool(object, "executable", &what)?,
            })
        }
        _ => Err(format!(
            "{what} kind must be create, edit, delete, or rename"
        )),
    }
}

fn hunks(object: &Map<String, Value>, required: bool, what: &str) -> Result<Vec<Hunk>, String> {
    let Some(value) = object.get("hunks") else {
        return if required {
            Err(format!("{what} is missing 'hunks'"))
        } else {
            Ok(Vec::new())
        };
    };
    let items = value
        .as_array()
        .ok_or_else(|| format!("{what} hunks must be an array"))?;
    items
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let hunk = value
                .as_object()
                .ok_or_else(|| format!("{what} hunk {index} must be an object"))?;
            exact_keys(hunk, &["old", "new"], &format!("{what} hunk {index}"))?;
            let old = text(hunk, "old", &format!("{what} hunk {index}"))?;
            if old.is_empty() {
                return Err(format!("{what} hunk {index} 'old' must not be empty"));
            }
            Ok(Hunk {
                old,
                new: text(hunk, "new", &format!("{what} hunk {index}"))?,
            })
        })
        .collect()
}

fn exact_keys(object: &Map<String, Value>, allowed: &[&str], what: &str) -> Result<(), String> {
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(format!("{what} has unknown field '{key}'"));
    }
    Ok(())
}

fn text(object: &Map<String, Value>, key: &str, what: &str) -> Result<String, String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("{what} '{key}' must be a string"))
}

fn optional_text(
    object: &Map<String, Value>,
    key: &str,
    what: &str,
) -> Result<Option<String>, String> {
    object.get(key).map(|_| text(object, key, what)).transpose()
}

fn optional_bool(
    object: &Map<String, Value>,
    key: &str,
    what: &str,
) -> Result<Option<bool>, String> {
    object
        .get(key)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| format!("{what} '{key}' must be a boolean"))
        })
        .transpose()
}

fn nonempty(value: String, what: &str) -> Result<String, String> {
    if value.is_empty() {
        Err(format!("{what} must not be empty"))
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_operation_and_mode_only_edit() {
        let request = Request::parse(&json!({"version": 1, "operations": [
            {"kind": "create", "path": "new", "content": "hello"},
            {"kind": "edit", "path": "old", "hunks": [{"old": "a", "new": "b"}]},
            {"kind": "edit", "path": "script", "hunks": [], "executable": true},
            {"kind": "delete", "path": "gone", "expected_identity": "sha256:a"},
            {"kind": "rename", "path": "from", "to": "to"}
        ]}))
        .unwrap();
        assert_eq!(request.version, 1);
        assert_eq!(request.operations.len(), 5);
    }

    #[test]
    fn rejects_unknown_fields_and_ambiguous_empty_edits() {
        let unknown = json!({"version": 1, "operations": [
            {"kind": "delete", "path": "gone", "force": true}
        ]});
        assert!(
            Request::parse(&unknown)
                .unwrap_err()
                .contains("unknown field 'force'")
        );

        let empty = json!({"version": 1, "operations": [
            {"kind": "edit", "path": "file", "hunks": []}
        ]});
        assert!(
            Request::parse(&empty)
                .unwrap_err()
                .contains("must contain a hunk")
        );
    }

    #[test]
    fn rejects_wrong_versions_and_empty_hunk_matches() {
        let version = json!({"version": 2, "operations": [{"kind": "delete", "path": "x"}]});
        assert!(
            Request::parse(&version)
                .unwrap_err()
                .contains("unsupported patch version")
        );

        let hunk = json!({"version": 1, "operations": [
            {"kind": "edit", "path": "x", "hunks": [{"old": "", "new": "x"}]}
        ]});
        assert!(
            Request::parse(&hunk)
                .unwrap_err()
                .contains("must not be empty")
        );
    }
}
