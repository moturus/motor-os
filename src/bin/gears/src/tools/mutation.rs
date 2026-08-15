//! Immutable file changes: prepared without writes, then revalidated and
//! applied through the workspace and undo boundaries.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::Workspace;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Before {
    Missing,
    File { bytes: Vec<u8>, identity: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileChange {
    given: String,
    path: PathBuf,
    display: String,
    before: Before,
    after: Vec<u8>,
}

/// An exact, immutable change set. Fields stay private so approval and apply
/// cannot accidentally describe different bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    tool: &'static str,
    permission_key: String,
    changes: Vec<FileChange>,
    digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub paths: Vec<String>,
    pub bytes: usize,
}

/// Content identities and sizes retained in the session audit record. The
/// bounded preview supplies the human-readable form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub path: String,
    pub before_identity: String,
    pub before_bytes: Option<usize>,
    pub after_identity: String,
    pub after_bytes: usize,
}

impl Prepared {
    pub fn one_file(
        workspace: &Workspace,
        tool: &'static str,
        permission_key: String,
        given: String,
        after: Vec<u8>,
    ) -> Result<Prepared, String> {
        let path = workspace.resolve(&given)?;
        let before = read_before(&path, &given)?;
        Ok(Self::from_file(
            workspace,
            tool,
            permission_key,
            given,
            path,
            before,
            after,
        ))
    }

    /// Prepare an edit from the same byte snapshot whose identity will later
    /// be revalidated. This avoids a second read becoming a silent overwrite.
    pub fn transform_file(
        workspace: &Workspace,
        tool: &'static str,
        permission_key: String,
        given: String,
        transform: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>,
    ) -> Result<Prepared, String> {
        let path = workspace.resolve(&given)?;
        let bytes = std::fs::read(&path).map_err(|error| format!("{given}: {error}"))?;
        let after = transform(&bytes)?;
        let before = Before::File {
            identity: identity(&bytes),
            bytes,
        };
        Ok(Self::from_file(
            workspace,
            tool,
            permission_key,
            given,
            path,
            before,
            after,
        ))
    }

    fn from_file(
        workspace: &Workspace,
        tool: &'static str,
        permission_key: String,
        given: String,
        path: PathBuf,
        before: Before,
        after: Vec<u8>,
    ) -> Prepared {
        let display = workspace.display(&path);
        let changes = vec![FileChange {
            given,
            path,
            display,
            before,
            after,
        }];
        let digest = digest(tool, &permission_key, &changes);
        Prepared {
            tool,
            permission_key,
            changes,
            digest,
        }
    }

    pub fn tool(&self) -> &'static str {
        self.tool
    }

    pub fn permission_key(&self) -> &str {
        &self.permission_key
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn changes(&self) -> Vec<Change> {
        self.changes
            .iter()
            .map(|change| {
                let (before_identity, before_bytes) = match &change.before {
                    Before::Missing => ("missing".to_string(), None),
                    Before::File { bytes, identity } => (identity.clone(), Some(bytes.len())),
                };
                Change {
                    path: change.display.clone(),
                    before_identity,
                    before_bytes,
                    after_identity: identity(&change.after),
                    after_bytes: change.after.len(),
                }
            })
            .collect()
    }

    pub fn preview(&self) -> String {
        let mut out = format!("prepared {}\ndigest: {}\n", self.tool, self.digest);
        for change in &self.changes {
            let before = match &change.before {
                Before::Missing => "missing".to_string(),
                Before::File { bytes, identity } => {
                    format!("{} bytes, {identity}", bytes.len())
                }
            };
            out.push_str(&format!(
                "path: {}\nbefore: {before}\nafter: {} bytes, {}\n",
                change.display,
                change.after.len(),
                identity(&change.after)
            ));
            out.push_str(&diff(change));
        }
        out
    }

    /// Re-resolve and hash every input before touching the undo log or disk.
    pub fn apply(&self, workspace: &Workspace) -> Result<Applied, String> {
        for change in &self.changes {
            let resolved = workspace.resolve(&change.given)?;
            if resolved != change.path {
                return Err(conflict(&change.display, "the resolved target changed"));
            }
            let current = read_before(&resolved, &change.given)?;
            if !same_input(&change.before, &current) {
                return Err(conflict(&change.display, "the input identity changed"));
            }
        }

        let mut bytes = 0usize;
        let mut paths = Vec::with_capacity(self.changes.len());
        for change in &self.changes {
            workspace.before_write(&change.path)?;
            if let Some(parent) = change.path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|error| format!("{}: {error}", change.given))?;
            }
            std::fs::write(&change.path, &change.after)
                .map_err(|error| format!("{}: {error}", change.given))?;
            bytes = bytes.saturating_add(change.after.len());
            paths.push(change.display.clone());
        }
        Ok(Applied { paths, bytes })
    }
}

fn read_before(path: &Path, given: &str) -> Result<Before, String> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let identity = identity(&bytes);
            Ok(Before::File { bytes, identity })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Before::Missing),
        Err(error) => Err(format!("{given}: {error}")),
    }
}

fn same_input(expected: &Before, current: &Before) -> bool {
    match (expected, current) {
        (Before::Missing, Before::Missing) => true,
        (Before::File { identity: a, .. }, Before::File { identity: b, .. }) => a == b,
        _ => false,
    }
}

fn conflict(path: &str, reason: &str) -> String {
    format!("conflict: {path}: {reason}; prepare the mutation again")
}

fn identity(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(bytes);
    format!("sha256:{}", super::hex(&hash.finalize()))
}

fn digest(tool: &str, permission_key: &str, changes: &[FileChange]) -> String {
    let mut hash = Sha256::new();
    field(&mut hash, b"gears-prepared-mutation-v1");
    field(&mut hash, tool.as_bytes());
    field(&mut hash, permission_key.as_bytes());
    field(&mut hash, &(changes.len() as u64).to_be_bytes());
    for change in changes {
        field(&mut hash, change.given.as_bytes());
        field(&mut hash, change.path.as_os_str().as_encoded_bytes());
        match &change.before {
            Before::Missing => field(&mut hash, b"missing"),
            Before::File { identity, .. } => field(&mut hash, identity.as_bytes()),
        }
        field(&mut hash, &change.after);
    }
    format!("sha256:{}", super::hex(&hash.finalize()))
}

fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn diff(change: &FileChange) -> String {
    let old_name = match change.before {
        Before::Missing => "/dev/null".to_string(),
        Before::File { .. } => format!("a/{}", change.display),
    };
    let mut out = format!("--- {old_name}\n+++ b/{}\n", change.display);
    let old = match &change.before {
        Before::Missing => &[][..],
        Before::File { bytes, .. } => bytes,
    };
    if let (Some(old), Some(new)) = (safe_text(old), safe_text(&change.after)) {
        let old_lines = old.lines().count();
        let new_lines = new.lines().count();
        out.push_str(&format!("@@ -1,{old_lines} +1,{new_lines} @@\n"));
        for line in old.lines() {
            out.push_str(&format!("-{line}\n"));
        }
        for line in new.lines() {
            out.push_str(&format!("+{line}\n"));
        }
        if (!old.is_empty() && !old.ends_with('\n')) || (!new.is_empty() && !new.ends_with('\n')) {
            out.push_str("\\ No newline at end of file\n");
        }
    } else {
        out.push_str("@@ binary replacement @@\n");
        out.push_str(&format!(
            "-{}\n+{}\n",
            super::hex(old),
            super::hex(&change.after)
        ));
    }
    out
}

fn safe_text(bytes: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(bytes).ok()?;
    text.chars()
        .all(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn workspace(name: &str) -> (PathBuf, Workspace) {
        let root =
            std::env::temp_dir().join(format!("gears-mutation-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let workspace = Workspace::new(&root).unwrap();
        (root, workspace)
    }

    #[test]
    fn prepared_bytes_and_preview_are_exact() {
        let (root, workspace) = workspace("exact");
        let prepared = Prepared::one_file(
            &workspace,
            "write_file",
            "write_file".to_string(),
            "new.txt".to_string(),
            b"hello\n".to_vec(),
        )
        .unwrap();
        let preview = prepared.preview();
        assert!(preview.contains("before: missing"), "{preview}");
        assert!(
            preview.contains("--- /dev/null\n+++ b/new.txt"),
            "{preview}"
        );
        assert!(preview.contains("+hello\n"), "{preview}");
        assert!(preview.contains(prepared.digest()), "{preview}");

        let applied = prepared.apply(&workspace).unwrap();
        assert_eq!(applied.paths, ["new.txt"]);
        assert_eq!(applied.bytes, 6);
        assert_eq!(std::fs::read(root.join("new.txt")).unwrap(), b"hello\n");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn changed_input_conflicts_before_undo_or_write() {
        let (root, workspace) = workspace("conflict");
        std::fs::write(root.join("file"), "old\n").unwrap();
        let undo = Arc::new(crate::agent::undo::UndoLog::new(&root, "s1").unwrap());
        let workspace = workspace.with_undo(undo.clone());
        let prepared = Prepared::one_file(
            &workspace,
            "edit_file",
            "edit_file".to_string(),
            "file".to_string(),
            b"new\n".to_vec(),
        )
        .unwrap();
        std::fs::write(root.join("file"), "other\n").unwrap();

        let error = prepared.apply(&workspace).unwrap_err();
        assert!(error.contains("conflict"), "{error}");
        assert_eq!(std::fs::read(root.join("file")).unwrap(), b"other\n");
        assert!(undo.files().is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replacement_diffs_are_exact_and_control_bytes_are_encoded() {
        let (root, workspace) = workspace("replace");
        std::fs::write(root.join("file"), "old\n").unwrap();
        let prepared = Prepared::transform_file(
            &workspace,
            "edit_file",
            "edit_file".to_string(),
            "file".to_string(),
            |_| Ok(b"new\n".to_vec()),
        )
        .unwrap();
        let preview = prepared.preview();
        assert!(preview.contains("--- a/file\n+++ b/file"), "{preview}");
        assert!(preview.contains("-old\n+new\n"), "{preview}");

        let encoded = Prepared::one_file(
            &workspace,
            "write_file",
            "write_file".to_string(),
            "control".to_string(),
            b"safe\x1b[31m".to_vec(),
        )
        .unwrap()
        .preview();
        assert!(encoded.contains("@@ binary replacement @@"), "{encoded}");
        assert!(!encoded.contains('\x1b'));
        std::fs::remove_dir_all(root).unwrap();
    }
}
