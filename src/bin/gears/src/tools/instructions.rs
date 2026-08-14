//! Applicable repository instructions, loaded on demand from root to leaf.

use std::io::Read;
use std::path::{Component, Path};
use std::sync::Arc;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{Tool, Workspace, opt_string, schema};
use crate::provider::ToolSpec;

pub const PROJECT_DOCS: [&str; 2] = ["AGENTS.md", "CLAUDE.md"];
const DOC_CAP: usize = 24 * 1024;

pub struct Document {
    pub source: String,
    pub identity: String,
    pub content: String,
}

pub fn tool(workspace: Arc<Workspace>) -> Box<dyn Tool> {
    Box::new(InstructionTool { workspace })
}

struct InstructionTool {
    workspace: Arc<Workspace>,
}

impl Tool for InstructionTool {
    fn name(&self) -> &'static str {
        "project_instructions"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            self.name(),
            "Load project instructions applicable to one file or directory. Sources are returned \
             in deterministic workspace-root-to-leaf order with current content identities. Call \
             this again before acting if an instruction file may have changed.",
            schema(
                json!({"path": {"type": "string", "description":
                    "Workspace-relative file or directory (default: the workspace root)."}}),
                &[],
            ),
        )
    }

    fn mutates(&self) -> bool {
        false
    }

    fn call(&self, args: &Value) -> Result<String, String> {
        let given = opt_string(args, "path")?.unwrap_or_else(|| ".".to_string());
        let target = self.workspace.resolve(&given)?;
        let documents = load_at(self.workspace.root(), &target);
        if documents.is_empty() {
            return Ok(format!("no project instructions apply to {given}"));
        }
        let mut output = format!("project instructions applicable to {given}, root to leaf:\n");
        for document in documents {
            output.push_str(&format!(
                "\n--- {}; identity {} ---\n{}\n--- end of {} ---\n",
                document.source, document.identity, document.content, document.source
            ));
        }
        Ok(output)
    }
}

/// Load current instructions for `target`. Missing, unreadable, empty,
/// non-UTF-8, changing, and symlinked documents are not instructions.
pub fn load_at(root: &Path, target: &Path) -> Vec<Document> {
    let scope = if target.is_dir() {
        target
    } else {
        target.parent().unwrap_or(root)
    };
    let Ok(relative) = scope.strip_prefix(root) else {
        return Vec::new();
    };
    let mut directory = root.to_path_buf();
    let mut result = read_directory(root, &directory);
    for component in relative.components() {
        if let Component::Normal(name) = component {
            directory.push(name);
            result.extend(read_directory(root, &directory));
        }
    }
    result
}

fn read_directory(root: &Path, directory: &Path) -> Vec<Document> {
    PROJECT_DOCS
        .iter()
        .filter_map(|name| read_document(root, &directory.join(name)))
        .collect()
}

fn read_document(root: &Path, path: &Path) -> Option<Document> {
    let before = path.symlink_metadata().ok()?;
    if !before.file_type().is_file() {
        return None;
    }
    let mut input = std::fs::File::open(path).ok()?;
    let mut digest = Sha256::new();
    let mut prefix = Vec::new();
    let mut utf8_tail = Vec::new();
    let mut total = 0usize;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = input.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        let bytes = &buffer[..read];
        digest.update(bytes);
        total = total.checked_add(read)?;
        let retained = (DOC_CAP - prefix.len()).min(read);
        prefix.extend_from_slice(&bytes[..retained]);

        utf8_tail.extend_from_slice(bytes);
        match std::str::from_utf8(&utf8_tail) {
            Ok(_) => utf8_tail.clear(),
            Err(error) if error.error_len().is_some() => return None,
            Err(error) => {
                utf8_tail = utf8_tail.split_off(error.valid_up_to());
            }
        }
    }
    if !utf8_tail.is_empty() {
        return None;
    }
    let after = path.symlink_metadata().ok()?;
    if !after.file_type().is_file()
        || before.len() != total as u64
        || after.len() != total as u64
        || before.modified().ok() != after.modified().ok()
    {
        return None;
    }
    let end = std::str::from_utf8(&prefix)
        .map(|_| prefix.len())
        .unwrap_or_else(|error| error.valid_up_to());
    let mut content = String::from_utf8(prefix[..end].to_vec()).ok()?;
    if content.trim().is_empty() {
        return None;
    }
    if total > end {
        content.push_str(&format!("\n[{} bytes elided]", total - end));
    }
    Some(Document {
        source: path.strip_prefix(root).ok()?.display().to_string(),
        identity: format!("sha256:{}", super::hex(&digest.finalize())),
        content,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_instructions_are_ordered_scoped_and_refreshed() {
        let base = std::env::temp_dir().join(format!("gears-instructions-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("crate/src")).unwrap();
        std::fs::create_dir_all(base.join("other")).unwrap();
        std::fs::write(base.join("AGENTS.md"), "root agents").unwrap();
        std::fs::write(base.join("CLAUDE.md"), "root claude").unwrap();
        std::fs::write(base.join("crate/AGENTS.md"), "crate agents v1").unwrap();
        std::fs::write(base.join("crate/src/CLAUDE.md"), "source claude").unwrap();
        std::fs::write(base.join("other/AGENTS.md"), "wrong branch").unwrap();

        let target = base.join("crate/src/lib.rs");
        let first = load_at(&base, &target);
        assert_eq!(
            first
                .iter()
                .map(|doc| doc.source.as_str())
                .collect::<Vec<_>>(),
            [
                "AGENTS.md",
                "CLAUDE.md",
                "crate/AGENTS.md",
                "crate/src/CLAUDE.md"
            ]
        );
        assert!(!first.iter().any(|doc| doc.content == "wrong branch"));
        let old_identity = first[2].identity.clone();

        std::fs::write(base.join("crate/AGENTS.md"), "crate agents v2").unwrap();
        let refreshed = load_at(&base, &target);
        assert_eq!(refreshed[2].content, "crate agents v2");
        assert_ne!(refreshed[2].identity, old_identity);
        assert_eq!(load_at(&base, &base)[0].source, "AGENTS.md");
        assert_eq!(load_at(&base, &base).len(), 2);

        let workspace = Arc::new(Workspace::new(&base).unwrap());
        let output = tool(workspace)
            .call(&json!({"path": "crate/src/lib.rs"}))
            .unwrap();
        assert!(
            output.contains("crate/AGENTS.md; identity sha256:"),
            "{output}"
        );
        assert!(output.contains("crate agents v2"), "{output}");
        std::fs::remove_dir_all(base).unwrap();
    }
}
