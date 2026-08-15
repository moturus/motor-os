//! Versioned model-facing grammar for atomic workspace patches.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{Map, Value, json};

use super::mutation::{Final, Prepared, Snapshot};
use super::{Tool, Workspace};
use crate::provider::ToolSpec;

pub struct PatchTool {
    workspace: Arc<Workspace>,
}

pub fn tool(workspace: Arc<Workspace>) -> Box<dyn Tool> {
    Box::new(PatchTool { workspace })
}

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

    /// Resolve and validate the complete request without changing the
    /// workspace, then bind its exact final states into one approval digest.
    pub fn prepare(&self, workspace: &Workspace) -> Result<Prepared, String> {
        let paths = self.resolve_paths(workspace)?;
        refuse_unsupported_modes(&self.operations)?;
        let mut changes = Vec::new();
        let mut renames = Vec::new();
        for (operation, (source_path, destination_path)) in self.operations.iter().zip(paths) {
            let source = Snapshot::at(workspace, operation.path().to_string(), source_path)?;
            match operation {
                Operation::Create {
                    content,
                    executable,
                    ..
                } => {
                    if !source.missing() {
                        return Err(format!(
                            "{}: create target already exists",
                            operation.path()
                        ));
                    }
                    changes.push((
                        source,
                        Final::File {
                            bytes: content.as_bytes().to_vec(),
                            mode: final_mode(None, *executable, false),
                        },
                    ));
                }
                Operation::Edit {
                    expected_identity,
                    hunks,
                    executable,
                    ..
                } => {
                    let (bytes, identity, mode) = source.file()?;
                    check_identity(operation.path(), expected_identity, identity)?;
                    let after = apply_hunks(operation.path(), bytes, hunks)?;
                    changes.push((
                        source,
                        Final::File {
                            bytes: after,
                            mode: final_mode(mode, *executable, false),
                        },
                    ));
                }
                Operation::Delete {
                    expected_identity, ..
                } => {
                    let (_, identity, _) = source.file()?;
                    check_identity(operation.path(), expected_identity, identity)?;
                    changes.push((source, Final::Missing));
                }
                Operation::Rename {
                    to,
                    expected_identity,
                    hunks,
                    executable,
                    ..
                } => {
                    let (bytes, identity, mode) = source.file()?;
                    check_identity(operation.path(), expected_identity, identity)?;
                    let after = apply_hunks(operation.path(), bytes, hunks)?;
                    let destination_path = destination_path
                        .ok_or_else(|| "rename destination was not resolved".to_string())?;
                    let destination = Snapshot::at(workspace, to.clone(), destination_path)?;
                    if !destination.missing() {
                        return Err(format!("{to}: rename destination already exists"));
                    }
                    changes.push((source, Final::Missing));
                    renames.push((operation.path().to_string(), to.clone()));
                    changes.push((
                        destination,
                        Final::File {
                            bytes: after,
                            mode: final_mode(mode, *executable, true),
                        },
                    ));
                }
            }
        }
        Prepared::from_snapshots("patch", "patch".to_string(), changes)
            .with_renames(workspace, renames)
    }

    fn resolve_paths(
        &self,
        workspace: &Workspace,
    ) -> Result<Vec<(PathBuf, Option<PathBuf>)>, String> {
        let mut seen = HashSet::new();
        self.operations
            .iter()
            .map(|operation| {
                let source = workspace.resolve(operation.path())?;
                unique_target(workspace, &mut seen, &source)?;
                let destination = operation
                    .destination()
                    .map(|path| {
                        let path = workspace.resolve(path)?;
                        unique_target(workspace, &mut seen, &path)?;
                        Ok::<PathBuf, String>(path)
                    })
                    .transpose()?;
                Ok((source, destination))
            })
            .collect()
    }
}

impl Operation {
    fn path(&self) -> &str {
        match self {
            Operation::Create { path, .. }
            | Operation::Edit { path, .. }
            | Operation::Delete { path, .. }
            | Operation::Rename { path, .. } => path,
        }
    }

    fn destination(&self) -> Option<&str> {
        match self {
            Operation::Rename { to, .. } => Some(to),
            _ => None,
        }
    }
}

impl Tool for PatchTool {
    fn name(&self) -> &'static str {
        "patch"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            self.name(),
            "Atomically create, edit, delete, or rename multiple workspace files. Exact text \
             hunks must each match once. The complete diff is shown for approval before any \
             file changes; expected_identity detects stale inputs.",
            schema(),
        )
    }

    fn mutates(&self) -> bool {
        true
    }

    fn prepare_mutation(&self, args: &Value) -> Result<Option<Prepared>, String> {
        Ok(Some(Request::parse(args)?.prepare(&self.workspace)?))
    }

    fn apply_mutation(&self, prepared: &Prepared) -> Result<String, String> {
        if prepared.tool() != self.name() {
            return Err(format!(
                "prepared for {}, not {}",
                prepared.tool(),
                self.name()
            ));
        }
        let applied = prepared.apply(&self.workspace)?;
        Ok(format!(
            "applied {} file states and wrote {} bytes{}",
            applied.paths.len(),
            applied.bytes,
            if applied.recovery_pending {
                "; transaction cleanup is pending until the next Gears start"
            } else {
                ""
            }
        ))
    }

    fn call(&self, args: &Value) -> Result<String, String> {
        let prepared = Request::parse(args)?.prepare(&self.workspace)?;
        self.apply_mutation(&prepared)
    }
}

fn unique_target(
    workspace: &Workspace,
    seen: &mut HashSet<PathBuf>,
    path: &Path,
) -> Result<(), String> {
    if seen.insert(path.to_path_buf()) {
        Ok(())
    } else {
        Err(format!(
            "duplicate or overlapping patch target '{}'",
            workspace.display(path)
        ))
    }
}

fn check_identity(path: &str, expected: &Option<String>, actual: &str) -> Result<(), String> {
    match expected {
        Some(expected) if expected != actual => Err(format!(
            "{path}: expected identity {expected}, got {actual}; inspect the file again"
        )),
        _ => Ok(()),
    }
}

fn apply_hunks(path: &str, bytes: &[u8], hunks: &[Hunk]) -> Result<Vec<u8>, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| format!("{path}: exact text hunks require a UTF-8 file"))?;
    let mut ranges = Vec::with_capacity(hunks.len());
    for (index, hunk) in hunks.iter().enumerate() {
        let mut found = text.match_indices(&hunk.old);
        let Some((start, _)) = found.next() else {
            return Err(format!("{path}: hunk {index} old text was not found"));
        };
        if found.next().is_some() {
            return Err(format!("{path}: hunk {index} old text is not unique"));
        }
        ranges.push((start, start + hunk.old.len(), hunk.new.as_str(), index));
    }
    ranges.sort_by_key(|range| range.0);
    for pair in ranges.windows(2) {
        if pair[1].0 < pair[0].1 {
            return Err(format!(
                "{path}: hunks {} and {} overlap",
                pair[0].3, pair[1].3
            ));
        }
    }
    let mut output = String::with_capacity(text.len());
    let mut cursor = 0;
    for (start, end, replacement, _) in ranges {
        output.push_str(&text[cursor..start]);
        output.push_str(replacement);
        cursor = end;
    }
    output.push_str(&text[cursor..]);
    Ok(output.into_bytes())
}

#[cfg(target_os = "linux")]
fn final_mode(current: Option<u32>, requested: Option<bool>, preserve: bool) -> Option<u32> {
    let requested = requested.map(|executable| {
        let mode = current.unwrap_or(0o644);
        if executable {
            mode | 0o111
        } else {
            mode & !0o111
        }
    });
    requested.or(if preserve { current } else { None })
}

#[cfg(not(target_os = "linux"))]
fn final_mode(_current: Option<u32>, _requested: Option<bool>, _preserve: bool) -> Option<u32> {
    None
}

#[cfg(not(target_os = "linux"))]
fn refuse_unsupported_modes(operations: &[Operation]) -> Result<(), String> {
    if operations.iter().any(|operation| match operation {
        Operation::Create { executable, .. }
        | Operation::Edit { executable, .. }
        | Operation::Rename { executable, .. } => executable.is_some(),
        Operation::Delete { .. } => false,
    }) {
        Err("executable-bit changes are unsupported on Motor OS until a reviewed portable API exists".to_string())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn refuse_unsupported_modes(_operations: &[Operation]) -> Result<(), String> {
    Ok(())
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

    fn workspace(name: &str) -> (PathBuf, Workspace) {
        let root = std::env::temp_dir().join(format!("gears-patch-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let workspace = Workspace::new(&root).unwrap();
        (root, workspace)
    }

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

    #[test]
    fn prepares_create_edit_delete_and_rename_as_one_set() {
        let (root, workspace) = workspace("complete");
        std::fs::write(root.join("edit"), "one two three\n").unwrap();
        std::fs::write(root.join("delete"), "gone\n").unwrap();
        std::fs::write(root.join("source"), "move me\n").unwrap();
        let request = Request::parse(&json!({"version": 1, "operations": [
            {"kind": "create", "path": "created", "content": "new\n"},
            {"kind": "edit", "path": "edit", "hunks": [
                {"old": "one", "new": "ONE"}, {"old": "three", "new": "THREE"}]},
            {"kind": "delete", "path": "delete"},
            {"kind": "rename", "path": "source", "to": "destination",
                "hunks": [{"old": "move", "new": "moved"}]}
        ]}))
        .unwrap();

        let prepared = request.prepare(&workspace).unwrap();
        let changes = prepared.changes();
        assert_eq!(changes.len(), 5);
        assert_eq!(
            changes
                .iter()
                .map(|change| change.path.as_str())
                .collect::<Vec<_>>(),
            ["created", "edit", "delete", "source", "destination"]
        );
        assert!(prepared.preview().contains("+ONE two THREE"));
        assert!(prepared.preview().contains("+moved me"));
        assert_eq!(
            std::fs::read(root.join("edit")).unwrap(),
            b"one two three\n"
        );
        assert!(!root.join("created").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_ambiguous_overlapping_and_duplicate_targets_without_changes() {
        let (root, workspace) = workspace("invalid");
        std::fs::write(root.join("file"), "abc abcdef\n").unwrap();
        let ambiguous = Request::parse(&json!({"version": 1, "operations": [
            {"kind": "edit", "path": "file", "hunks": [{"old": "abc", "new": "x"}]}
        ]}))
        .unwrap();
        assert!(
            ambiguous
                .prepare(&workspace)
                .unwrap_err()
                .contains("not unique")
        );

        let overlap = apply_hunks(
            "file",
            b"abcdef",
            &[
                Hunk {
                    old: "abc".into(),
                    new: "x".into(),
                },
                Hunk {
                    old: "cde".into(),
                    new: "y".into(),
                },
            ],
        )
        .unwrap_err();
        assert!(overlap.contains("overlap"), "{overlap}");

        let duplicate = Request::parse(&json!({"version": 1, "operations": [
            {"kind": "delete", "path": "file"},
            {"kind": "rename", "path": "file", "to": "other"}
        ]}))
        .unwrap();
        assert!(
            duplicate
                .prepare(&workspace)
                .unwrap_err()
                .contains("duplicate")
        );
        assert_eq!(std::fs::read(root.join("file")).unwrap(), b"abc abcdef\n");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_stale_identities_and_occupied_destinations() {
        let (root, workspace) = workspace("state");
        std::fs::write(root.join("source"), "source\n").unwrap();
        std::fs::write(root.join("destination"), "occupied\n").unwrap();
        let stale = Request::parse(&json!({"version": 1, "operations": [
            {"kind": "delete", "path": "source", "expected_identity": "sha256:stale"}
        ]}))
        .unwrap();
        assert!(
            stale
                .prepare(&workspace)
                .unwrap_err()
                .contains("expected identity")
        );
        let occupied = Request::parse(&json!({"version": 1, "operations": [
            {"kind": "rename", "path": "source", "to": "destination"}
        ]}))
        .unwrap();
        assert!(
            occupied
                .prepare(&workspace)
                .unwrap_err()
                .contains("already exists")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prepares_an_exact_executable_bit_change() {
        use std::os::unix::fs::PermissionsExt;

        let (root, workspace) = workspace("mode");
        let path = root.join("script");
        std::fs::write(&path, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let request = Request::parse(&json!({"version": 1, "operations": [
            {"kind": "edit", "path": "script", "hunks": [], "executable": true}
        ]}))
        .unwrap();

        let prepared = request.prepare(&workspace).unwrap();
        let change = prepared.changes().remove(0);
        assert_eq!(
            (change.before_mode, change.after_mode),
            (Some(0o644), Some(0o755))
        );
        assert!(
            prepared
                .preview()
                .contains("old mode 100644\nnew mode 100755")
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn arbitrary_exact_hunks_match_a_reference_layout() {
        for (case, bytes) in crate::property::byte_cases(0x0070_6174_6368, 512, 2048).enumerate() {
            let replacement = String::from_utf8_lossy(&bytes);
            let first = format!("<first-{case}>");
            let second = format!("<second-{case}>");
            let input = format!("prefix\n{first}\nmiddle\n{second}\nsuffix\n");
            let hunks = [
                Hunk {
                    old: second,
                    new: replacement.to_string(),
                },
                Hunk {
                    old: first,
                    new: replacement.to_string(),
                },
            ];
            let output = apply_hunks("property", input.as_bytes(), &hunks).unwrap();
            let expected = format!("prefix\n{replacement}\nmiddle\n{replacement}\nsuffix\n");
            assert_eq!(output, expected.as_bytes());
            assert!(output.len() <= input.len() + replacement.len() * 2);

            if std::str::from_utf8(&bytes).is_err() {
                assert!(apply_hunks("property", &bytes, &hunks).is_err());
            }
        }
    }

    #[test]
    fn arbitrary_patch_arguments_are_safely_validated() {
        for (case, bytes) in
            crate::property::byte_cases(0x7061_7463_682d_6172, 512, 4096).enumerate()
        {
            let text = String::from_utf8_lossy(&bytes);
            let mut values = vec![
                Value::String(text.to_string()),
                json!({"version": case as u64, "operations": text}),
                json!({"version": 1, "operations": [{
                    "kind": text, "path": text, "unknown": text
                }]}),
            ];
            if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                values.push(value);
            }
            for value in values {
                if let Ok(request) = Request::parse(&value) {
                    assert_eq!(request.version, 1);
                    assert!(!request.operations.is_empty());
                    for operation in request.operations {
                        assert!(!operation.path().is_empty());
                        match operation {
                            Operation::Edit { hunks, .. } | Operation::Rename { hunks, .. } => {
                                assert!(hunks.iter().all(|hunk| !hunk.old.is_empty()));
                            }
                            Operation::Create { .. } | Operation::Delete { .. } => {}
                        }
                    }
                }
            }
        }
    }
}
