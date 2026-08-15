//! Exact, approved restoration of one named workspace checkpoint.

use std::sync::Arc;

use serde_json::{Value, json};

use super::{Tool, schema};
use crate::provider::ToolSpec;

pub struct RestoreCheckpoint {
    workspace: Arc<super::Workspace>,
}

pub fn tool(workspace: Arc<super::Workspace>) -> Box<dyn Tool> {
    Box::new(RestoreCheckpoint { workspace })
}

impl Tool for RestoreCheckpoint {
    fn name(&self) -> &'static str {
        "restore_checkpoint"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            self.name(),
            "Restore every path changed since a named checkpoint. The exact current-to-checkpoint diff is prepared and shown for approval, then every input is revalidated and the whole restore is applied atomically.",
            schema(
                json!({
                    "id": {"type": "integer", "minimum": 1, "description": "Checkpoint ID."},
                }),
                &["id"],
            ),
        )
    }

    fn mutates(&self) -> bool {
        true
    }

    fn prepare_mutation(&self, args: &Value) -> Result<Option<super::mutation::Prepared>, String> {
        super::mutation::Prepared::restore_checkpoint(&self.workspace, positive_id(args)?)
    }

    fn apply_mutation(&self, prepared: &super::mutation::Prepared) -> Result<String, String> {
        if prepared.tool() != self.name() {
            return Err(format!(
                "prepared for {}, not {}",
                prepared.tool(),
                self.name()
            ));
        }
        let applied = prepared.apply(&self.workspace)?;
        Ok(format!(
            "restored {} file states and wrote {} bytes{}",
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
        let id = positive_id(args)?;
        let Some(prepared) = super::mutation::Prepared::restore_checkpoint(&self.workspace, id)?
        else {
            return Ok(format!("checkpoint {id} already matches the workspace"));
        };
        self.apply_mutation(&prepared)
    }
}

fn positive_id(args: &Value) -> Result<u64, String> {
    args["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .ok_or_else(|| "argument 'id' must be a positive whole number".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_is_prepared_exactly_and_revalidates_before_apply() {
        let root =
            std::env::temp_dir().join(format!("gears-restore-checkpoint-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("main.rs");
        std::fs::write(&source, "one\n").unwrap();
        let checkpoints = Arc::new(
            crate::agent::checkpoint::LazyStore::new(
                root.clone(),
                "18-1".to_string(),
                4096,
                16384,
                false,
            )
            .unwrap(),
        );
        let workspace = Arc::new(
            super::super::Workspace::new(&root)
                .unwrap()
                .with_checkpoints(checkpoints),
        );
        workspace.create_checkpoint("before", 0, 0).unwrap();
        let edit = super::super::mutation::Prepared::one_file(
            &workspace,
            "test",
            "test".to_string(),
            "main.rs".to_string(),
            b"two\n".to_vec(),
        )
        .unwrap();
        edit.apply(&workspace).unwrap();

        let tool = super::tool(workspace.clone());
        let prepared = tool.prepare_mutation(&json!({"id": 2})).unwrap().unwrap();
        assert!(prepared.preview().contains("-two\n+one\n"));
        std::fs::write(&source, "external\n").unwrap();
        assert!(
            tool.apply_mutation(&prepared)
                .unwrap_err()
                .contains("conflict")
        );
        let prepared = tool.prepare_mutation(&json!({"id": 2})).unwrap().unwrap();
        tool.apply_mutation(&prepared).unwrap();
        assert_eq!(std::fs::read_to_string(&source).unwrap(), "one\n");
        assert!(tool.prepare_mutation(&json!({"id": 1})).unwrap().is_none());
        std::fs::remove_dir_all(root).unwrap();
    }
}
