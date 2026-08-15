//! Model access to named workspace checkpoints.

use std::sync::Arc;

use serde_json::{Value, json};

use super::{DEFAULT_CAP, Tool, clamp, schema, string_arg};
use crate::agent::artifact::{CHECKPOINT_DIFF, LazyStore, Origin, complete_reference};
use crate::provider::ToolSpec;

const DEFAULT_LIST_RESULTS: usize = 20;
const MAX_LIST_RESULTS: usize = 100;

pub struct CheckpointTool {
    workspace: Arc<super::Workspace>,
    artifacts: Arc<LazyStore>,
}

pub fn tool(workspace: Arc<super::Workspace>, artifacts: Arc<LazyStore>) -> Box<dyn Tool> {
    Box::new(CheckpointTool {
        workspace,
        artifacts,
    })
}

impl Tool for CheckpointTool {
    fn name(&self) -> &'static str {
        "checkpoints"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            self.name(),
            "Create and list named workspace checkpoints, or inspect the exact change that would restore one. Checkpoint creation does not scan the workspace; each file's prior state is captured on its first later mutation.",
            schema(
                json!({
                    "action": {"type": "string", "enum": ["create", "list", "inspect"]},
                    "name": {"type": "string", "description": "Checkpoint name; required for create."},
                    "id": {"type": "integer", "minimum": 1, "description": "Checkpoint ID; required for inspect."},
                    "after_id": {"type": "integer", "minimum": 0, "description": "For list, return IDs greater than this value (default 0)."},
                    "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIST_RESULTS, "description": "For list, maximum records (default 20)."},
                }),
                &["action"],
            ),
        )
    }

    fn mutates(&self) -> bool {
        false
    }

    fn call(&self, args: &Value) -> Result<String, String> {
        match string_arg(args, "action")?.as_str() {
            "create" => self.create(args),
            "list" => self.list(args),
            "inspect" => self.inspect(args),
            other => Err(format!(
                "unknown action '{other}' (expected 'create', 'list', or 'inspect')"
            )),
        }
    }
}

impl CheckpointTool {
    fn create(&self, args: &Value) -> Result<String, String> {
        reject(args, &["id", "after_id", "limit"], "create")?;
        let metadata = self
            .workspace
            .create_checkpoint(&string_arg(args, "name")?, 0, 0)?;
        serde_json::to_string_pretty(&metadata).map_err(|error| error.to_string())
    }

    fn list(&self, args: &Value) -> Result<String, String> {
        reject(args, &["name", "id"], "list")?;
        let after = number(args, "after_id")?.unwrap_or(0);
        let limit = number(args, "limit")?.unwrap_or(DEFAULT_LIST_RESULTS as u64);
        let limit = usize::try_from(limit)
            .map_err(|_| "argument 'limit' is too large for this system".to_string())?;
        if limit == 0 || limit > MAX_LIST_RESULTS {
            return Err(format!(
                "argument 'limit' must be between 1 and {MAX_LIST_RESULTS}"
            ));
        }
        let (checkpoints, more) = self.workspace.checkpoints_after(after, limit)?;
        let next_after_id = more.then(|| checkpoints.last().unwrap().id);
        serde_json::to_string_pretty(&json!({
            "checkpoints": checkpoints,
            "next_after_id": next_after_id,
        }))
        .map_err(|error| error.to_string())
    }

    fn inspect(&self, args: &Value) -> Result<String, String> {
        reject(args, &["name", "after_id", "limit"], "inspect")?;
        let id = positive(args, "id")?;
        let Some(prepared) = super::mutation::Prepared::restore_checkpoint(&self.workspace, id)?
        else {
            return Ok(format!("checkpoint {id} matches the workspace"));
        };
        let preview = prepared.preview();
        if preview.len() <= DEFAULT_CAP {
            return Ok(preview);
        }
        let metadata = self.artifacts.put_text(
            CHECKPOINT_DIFF,
            Origin {
                producer: self.name().to_string(),
                reference: format!("checkpoint {id} diff"),
            },
            &preview,
        )?;
        let reference = complete_reference("checkpoint diff", &metadata);
        let head = clamp(
            &preview,
            DEFAULT_CAP.saturating_sub(reference.len().saturating_add(1)),
        );
        Ok(format!("{head}\n{reference}"))
    }
}

fn number(args: &Value, name: &str) -> Result<Option<u64>, String> {
    match &args[name] {
        Value::Null => Ok(None),
        Value::Number(number) => number
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("argument '{name}' must be a non-negative whole number")),
        _ => Err(format!("argument '{name}' must be a number")),
    }
}

fn positive(args: &Value, name: &str) -> Result<u64, String> {
    number(args, name)?
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("argument '{name}' must be a positive whole number"))
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
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn fixture() -> (
        PathBuf,
        Arc<super::super::Workspace>,
        Arc<LazyStore>,
        Box<dyn Tool>,
    ) {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "gears-checkpoint-tool-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let checkpoints = Arc::new(
            crate::agent::checkpoint::LazyStore::new(
                root.clone(),
                "18-1".to_string(),
                100_000,
                200_000,
                false,
            )
            .unwrap(),
        );
        let workspace = Arc::new(
            super::super::Workspace::new(&root)
                .unwrap()
                .with_checkpoints(checkpoints),
        );
        let artifacts =
            Arc::new(LazyStore::new(root.clone(), "18-1".to_string(), 100_000, 200_000).unwrap());
        let tool = super::tool(workspace.clone(), artifacts.clone());
        (root, workspace, artifacts, tool)
    }

    #[test]
    fn create_list_and_inspect_are_exact_and_bounded() {
        let (root, workspace, artifacts, tool) = fixture();
        let source = root.join("main.rs");
        let original = format!("one\n{}", "old line\n".repeat(2_000));
        let changed = format!("two\n{}", "new line\n".repeat(2_000));
        std::fs::write(&source, &original).unwrap();
        assert!(!tool.mutates());
        let created = tool
            .call(&json!({"action": "create", "name": "before refactor"}))
            .unwrap();
        assert!(created.contains("before refactor"), "{created}");
        let prepared = super::super::mutation::Prepared::one_file(
            &workspace,
            "test",
            "test".to_string(),
            "main.rs".to_string(),
            changed.into_bytes(),
        )
        .unwrap();
        prepared.apply(&workspace).unwrap();

        let listed = tool.call(&json!({"action": "list"})).unwrap();
        assert!(listed.contains("session start"), "{listed}");
        assert!(listed.contains("before refactor"), "{listed}");
        let inspected = tool.call(&json!({"action": "inspect", "id": 2})).unwrap();
        assert!(
            inspected.contains("complete output is artifact"),
            "{inspected}"
        );
        let store = artifacts.get().unwrap();
        let metadata = store.list().pop().unwrap();
        assert_eq!(metadata.artifact_type, CHECKPOINT_DIFF);
        let complete = String::from_utf8(store.read(metadata.id).unwrap()).unwrap();
        assert!(complete.contains("-two\n"), "{complete}");
        assert!(complete.contains("+one\n"), "{complete}");

        assert!(tool.call(&json!({"action": "inspect"})).is_err());
        assert!(
            tool.call(&json!({"action": "list", "name": "bad"}))
                .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
