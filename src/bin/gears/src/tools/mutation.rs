//! Immutable file changes: prepared without writes, then revalidated and
//! applied through the workspace and undo boundaries.

mod transaction;

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::Workspace;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Before {
    Missing,
    File {
        bytes: Vec<u8>,
        identity: String,
        mode: Option<u32>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Final {
    Missing,
    File { bytes: Vec<u8>, mode: Option<u32> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Snapshot {
    given: String,
    path: PathBuf,
    display: String,
    before: Before,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileChange {
    given: String,
    path: PathBuf,
    display: String,
    before: Before,
    after: Final,
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
    pub recovery_pending: bool,
}

pub fn recover(workspace: &Workspace) -> Result<usize, String> {
    transaction::recover(workspace)
}

/// Content identities and sizes retained in the session audit record. The
/// bounded preview supplies the human-readable form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub path: String,
    pub before_identity: String,
    pub before_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_mode: Option<u32>,
    pub after_identity: String,
    pub after_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_mode: Option<u32>,
}

impl Snapshot {
    pub(super) fn read(workspace: &Workspace, given: String) -> Result<Snapshot, String> {
        let path = workspace.resolve(&given)?;
        Self::at(workspace, given, path)
    }

    pub(super) fn at(
        workspace: &Workspace,
        given: String,
        path: PathBuf,
    ) -> Result<Snapshot, String> {
        let before = read_before(&path, &given)?;
        Ok(Snapshot {
            display: workspace.display(&path),
            given,
            path,
            before,
        })
    }

    pub(super) fn missing(&self) -> bool {
        matches!(self.before, Before::Missing)
    }

    pub(super) fn bytes(&self) -> Result<&[u8], String> {
        match &self.before {
            Before::Missing => Err(format!("{}: no such file", self.given)),
            Before::File { bytes, .. } => Ok(bytes),
        }
    }

    pub(super) fn file(&self) -> Result<(&[u8], &str, Option<u32>), String> {
        match &self.before {
            Before::Missing => Err(format!("{}: no such file", self.given)),
            Before::File {
                bytes,
                identity,
                mode,
            } => Ok((bytes, identity, *mode)),
        }
    }
}

impl Prepared {
    pub fn one_file(
        workspace: &Workspace,
        tool: &'static str,
        permission_key: String,
        given: String,
        after: Vec<u8>,
    ) -> Result<Prepared, String> {
        let snapshot = Snapshot::read(workspace, given)?;
        Ok(Self::from_snapshots(
            tool,
            permission_key,
            vec![(
                snapshot,
                Final::File {
                    bytes: after,
                    mode: None,
                },
            )],
        ))
    }

    pub fn delete_file(
        workspace: &Workspace,
        tool: &'static str,
        permission_key: String,
        given: String,
    ) -> Result<Prepared, String> {
        let snapshot = Snapshot::read(workspace, given)?;
        if snapshot.missing() {
            return Err(format!("{}: no such file", snapshot.given));
        }
        Ok(Self::from_snapshots(
            tool,
            permission_key,
            vec![(snapshot, Final::Missing)],
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
        let snapshot = Snapshot::read(workspace, given)?;
        let after = transform(snapshot.bytes()?)?;
        Ok(Self::from_snapshots(
            tool,
            permission_key,
            vec![(
                snapshot,
                Final::File {
                    bytes: after,
                    mode: None,
                },
            )],
        ))
    }

    pub(super) fn from_snapshots(
        tool: &'static str,
        permission_key: String,
        snapshots: Vec<(Snapshot, Final)>,
    ) -> Prepared {
        let changes: Vec<FileChange> = snapshots
            .into_iter()
            .map(|(snapshot, after)| FileChange {
                given: snapshot.given,
                path: snapshot.path,
                display: snapshot.display,
                before: snapshot.before,
                after,
            })
            .collect();
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
                let (before_identity, before_bytes, before_mode) = match &change.before {
                    Before::Missing => ("missing".to_string(), None, None),
                    Before::File {
                        bytes,
                        identity,
                        mode,
                    } => (identity.clone(), Some(bytes.len()), *mode),
                };
                let (after_identity, after_bytes, after_mode) = match &change.after {
                    Final::Missing => ("missing".to_string(), 0, None),
                    Final::File { bytes, mode } => {
                        (identity(bytes), bytes.len(), (*mode).or(before_mode))
                    }
                };
                Change {
                    path: change.display.clone(),
                    before_identity,
                    before_bytes,
                    before_mode,
                    after_identity,
                    after_bytes,
                    after_mode,
                }
            })
            .collect()
    }

    pub fn preview(&self) -> String {
        let mut out = format!("prepared {}\ndigest: {}\n", self.tool, self.digest);
        for change in &self.changes {
            let before = match &change.before {
                Before::Missing => "missing".to_string(),
                Before::File {
                    bytes, identity, ..
                } => {
                    format!("{} bytes, {identity}", bytes.len())
                }
            };
            let after = match &change.after {
                Final::Missing => "missing".to_string(),
                Final::File { bytes, .. } => {
                    format!("{} bytes, {}", bytes.len(), identity(bytes))
                }
            };
            out.push_str(&format!(
                "path: {}\nbefore: {before}\nafter: {after}\n",
                change.display
            ));
            out.push_str(&diff(change));
        }
        out
    }

    /// Re-resolve and hash every input before touching the undo log or disk.
    pub fn apply(&self, workspace: &Workspace) -> Result<Applied, String> {
        let _mutation = workspace.mutation()?;
        #[cfg(not(target_os = "linux"))]
        if self
            .changes
            .iter()
            .any(|change| matches!(&change.after, Final::File { mode: Some(_), .. }))
        {
            return Err(
                "executable-bit changes are unsupported on Motor OS until a reviewed portable API exists"
                    .to_string(),
            );
        }
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

        transaction::apply(workspace, &self.changes, &self.digest)
    }

    #[cfg(test)]
    pub(crate) fn leave_applying_after(
        &self,
        workspace: &Workspace,
        count: usize,
    ) -> Result<(), String> {
        transaction::leave_applying_after(workspace, &self.changes, &self.digest, count)
    }
}

fn read_before(path: &Path, given: &str) -> Result<Before, String> {
    match std::fs::File::open(path) {
        Ok(mut file) => {
            let metadata = file
                .metadata()
                .map_err(|error| format!("{given}: {error}"))?;
            if !metadata.is_file() {
                return Err(format!("{given}: not a regular file"));
            }
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .map_err(|error| format!("{given}: {error}"))?;
            let identity = identity(&bytes);
            Ok(Before::File {
                bytes,
                identity,
                mode: file_mode(&metadata),
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Before::Missing),
        Err(error) => Err(format!("{given}: {error}")),
    }
}

fn same_input(expected: &Before, current: &Before) -> bool {
    match (expected, current) {
        (Before::Missing, Before::Missing) => true,
        (
            Before::File {
                identity: a,
                mode: mode_a,
                ..
            },
            Before::File {
                identity: b,
                mode: mode_b,
                ..
            },
        ) => a == b && mode_a == mode_b,
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
    field(&mut hash, b"gears-prepared-mutation-v2");
    field(&mut hash, tool.as_bytes());
    field(&mut hash, permission_key.as_bytes());
    field(&mut hash, &(changes.len() as u64).to_be_bytes());
    for change in changes {
        field(&mut hash, change.given.as_bytes());
        field(&mut hash, change.path.as_os_str().as_encoded_bytes());
        match &change.before {
            Before::Missing => field(&mut hash, b"missing"),
            Before::File { identity, mode, .. } => {
                field(&mut hash, identity.as_bytes());
                field(&mut hash, &mode.unwrap_or(u32::MAX).to_be_bytes());
            }
        }
        match &change.after {
            Final::Missing => field(&mut hash, b"missing"),
            Final::File { bytes, mode } => {
                field(&mut hash, bytes);
                field(&mut hash, &mode.unwrap_or(u32::MAX).to_be_bytes());
            }
        }
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
    let new_name = match change.after {
        Final::Missing => "/dev/null".to_string(),
        Final::File { .. } => format!("b/{}", change.display),
    };
    let (old_mode, new_mode) = modes(change);
    let mut out = match (old_mode, new_mode) {
        (Some(old), None) => format!("deleted file mode {}\n", shown_mode(old)),
        (None, Some(new)) => format!("new file mode {}\n", shown_mode(new)),
        (Some(old), Some(new)) if old != new => format!(
            "old mode {}\nnew mode {}\n",
            shown_mode(old),
            shown_mode(new)
        ),
        _ => String::new(),
    };
    out.push_str(&format!("--- {old_name}\n+++ {new_name}\n"));
    let old = match &change.before {
        Before::Missing => &[][..],
        Before::File { bytes, .. } => bytes,
    };
    let new = match &change.after {
        Final::Missing => &[][..],
        Final::File { bytes, .. } => bytes,
    };
    if let (Some(old), Some(new)) = (safe_text(old), safe_text(new)) {
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
        out.push_str(&format!("-{}\n+{}\n", super::hex(old), super::hex(new)));
    }
    out
}

fn modes(change: &FileChange) -> (Option<u32>, Option<u32>) {
    let before = match change.before {
        Before::Missing => None,
        Before::File { mode, .. } => mode,
    };
    let after = match change.after {
        Final::Missing => None,
        Final::File { mode, .. } => mode.or(before),
    };
    (before, after)
}

fn shown_mode(mode: u32) -> String {
    format!("{:06o}", 0o100000 | mode)
}

#[cfg(target_os = "linux")]
fn file_mode(metadata: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(metadata.permissions().mode() & 0o7777)
}

#[cfg(not(target_os = "linux"))]
fn file_mode(_metadata: &std::fs::Metadata) -> Option<u32> {
    None
}

#[cfg(target_os = "linux")]
fn set_mode(path: &Path, mode: u32, given: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|error| format!("{given}: {error}"))
}

#[cfg(not(target_os = "linux"))]
fn set_mode(_path: &Path, _mode: u32, _given: &str) -> Result<(), String> {
    Err(
        "executable-bit changes are unsupported on Motor OS until a reviewed portable API exists"
            .to_string(),
    )
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
    fn deletion_is_previewed_applied_and_undoable() {
        let (root, workspace) = workspace("delete");
        std::fs::write(root.join("file"), "old\n").unwrap();
        let undo = Arc::new(crate::agent::undo::UndoLog::new(&root, "s1").unwrap());
        let workspace = workspace.with_undo(undo.clone());
        let prepared =
            Prepared::delete_file(&workspace, "patch", "patch".to_string(), "file".to_string())
                .unwrap();

        let preview = prepared.preview();
        assert!(preview.contains("after: missing"), "{preview}");
        assert!(preview.contains("--- a/file\n+++ /dev/null"), "{preview}");
        prepared.apply(&workspace).unwrap();
        assert!(!root.join("file").exists());
        undo.restore().unwrap();
        assert_eq!(std::fs::read(root.join("file")).unwrap(), b"old\n");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn multiple_snapshots_keep_one_ordered_digest_and_audit_set() {
        let (root, workspace) = workspace("multiple");
        std::fs::write(root.join("old"), "old\n").unwrap();
        let old = Snapshot::read(&workspace, "old".to_string()).unwrap();
        let new = Snapshot::read(&workspace, "new".to_string()).unwrap();
        let prepared = Prepared::from_snapshots(
            "patch",
            "patch".to_string(),
            vec![
                (old, Final::Missing),
                (
                    new,
                    Final::File {
                        bytes: b"new\n".to_vec(),
                        mode: None,
                    },
                ),
            ],
        );

        let changes = prepared.changes();
        assert_eq!(
            changes
                .iter()
                .map(|change| &change.path)
                .collect::<Vec<_>>(),
            ["old", "new"]
        );
        assert_eq!(changes[0].after_identity, "missing");
        assert_eq!(changes[1].before_identity, "missing");
        assert_eq!(prepared.preview().matches("path: ").count(), 2);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_multi_file_set_applies_from_staging_and_cleans_up() {
        let (root, workspace) = workspace("transaction-success");
        std::fs::write(root.join("old"), "old\n").unwrap();
        let old = Snapshot::read(&workspace, "old".to_string()).unwrap();
        let new = Snapshot::read(&workspace, "new".to_string()).unwrap();
        let prepared = Prepared::from_snapshots(
            "patch",
            "patch".to_string(),
            vec![
                (old, Final::Missing),
                (
                    new,
                    Final::File {
                        bytes: b"new\n".to_vec(),
                        mode: None,
                    },
                ),
            ],
        );

        let applied = prepared.apply(&workspace).unwrap();
        assert_eq!(applied.paths, ["old", "new"]);
        assert!(!root.join("old").exists());
        assert_eq!(std::fs::read(root.join("new")).unwrap(), b"new\n");
        assert!(transactions_empty(&root));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_mid_apply_failure_restores_files_and_created_directories() {
        let (root, workspace) = workspace("transaction-rollback");
        std::fs::write(root.join("edit"), "old\n").unwrap();
        let edit = Snapshot::read(&workspace, "edit".to_string()).unwrap();
        let create = Snapshot::read(&workspace, "nested/deeper/new".to_string()).unwrap();
        let untouched = Snapshot::read(&workspace, "untouched".to_string()).unwrap();
        let prepared = Prepared::from_snapshots(
            "patch",
            "patch".to_string(),
            vec![
                (
                    edit,
                    Final::File {
                        bytes: b"changed\n".to_vec(),
                        mode: None,
                    },
                ),
                (
                    create,
                    Final::File {
                        bytes: b"created\n".to_vec(),
                        mode: None,
                    },
                ),
                (
                    untouched,
                    Final::File {
                        bytes: b"never\n".to_vec(),
                        mode: None,
                    },
                ),
            ],
        );

        let error =
            transaction::apply_failing_before(&workspace, &prepared.changes, &prepared.digest, 2)
                .unwrap_err();
        assert!(error.contains("injected failure"), "{error}");
        assert_eq!(std::fs::read(root.join("edit")).unwrap(), b"old\n");
        assert!(!root.join("nested").exists());
        assert!(!root.join("untouched").exists());
        assert!(transactions_empty(&root));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_recovery_restores_an_interrupted_file_set() {
        let (root, workspace) = workspace("transaction-recovery");
        std::fs::write(root.join("edit"), "old\n").unwrap();
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.join("edit"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        let edit = Snapshot::read(&workspace, "edit".to_string()).unwrap();
        let create = Snapshot::read(&workspace, "nested/deeper/new".to_string()).unwrap();
        #[cfg(target_os = "linux")]
        let changed_mode = Some(0o600);
        #[cfg(not(target_os = "linux"))]
        let changed_mode = None;
        let prepared = Prepared::from_snapshots(
            "patch",
            "patch".to_string(),
            vec![
                (
                    edit,
                    Final::File {
                        bytes: b"changed\n".to_vec(),
                        mode: changed_mode,
                    },
                ),
                (
                    create,
                    Final::File {
                        bytes: b"created\n".to_vec(),
                        mode: None,
                    },
                ),
            ],
        );

        prepared.leave_applying_after(&workspace, 2).unwrap();
        assert_eq!(std::fs::read(root.join("edit")).unwrap(), b"changed\n");
        assert!(root.join("nested/deeper/new").is_file());
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(root.join("edit"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        assert_eq!(recover(&workspace).unwrap(), 1);
        assert_eq!(std::fs::read(root.join("edit")).unwrap(), b"old\n");
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(root.join("edit"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o755
            );
        }
        assert!(!root.join("nested").exists());
        assert!(transactions_empty(&root));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsafe_recovery_metadata_is_refused_without_touching_the_workspace() {
        let (root, workspace) = workspace("transaction-unsafe-recovery");
        std::fs::write(root.join("sentinel"), "safe\n").unwrap();
        let directory = root.join(".gears/transactions/v1").join("0".repeat(64));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join("manifest.json"),
            format!(
                r#"{{"version":1,"phase":"applying","digest":"sha256:{}","changes":[{{"path":"../sentinel","before_exists":false,"before_mode":null,"after_exists":false,"after_mode":null}}],"created_dirs":[]}}"#,
                "0".repeat(64)
            ),
        )
        .unwrap();

        let error = recover(&workspace).unwrap_err();
        assert!(error.contains("invalid mutation recovery path"), "{error}");
        assert_eq!(std::fs::read(root.join("sentinel")).unwrap(), b"safe\n");
        assert!(directory.is_dir());
        std::fs::remove_dir_all(root).unwrap();
    }

    fn transactions_empty(root: &Path) -> bool {
        let path = root.join(".gears/transactions/v1");
        path.is_dir() && std::fs::read_dir(path).unwrap().next().is_none()
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

    #[test]
    fn concurrent_prepared_writers_cannot_both_apply() {
        let (root, workspace) = workspace("serialized");
        std::fs::write(root.join("file"), "old\n").unwrap();
        let prepare = |after: &[u8]| {
            Prepared::one_file(
                &workspace,
                "write_file",
                "write_file".to_string(),
                "file".to_string(),
                after.to_vec(),
            )
            .unwrap()
        };
        let first = prepare(b"first\n");
        let second = prepare(b"second\n");

        let (first, second) = std::thread::scope(|scope| {
            let first = scope.spawn(|| first.apply(&workspace));
            let second = scope.spawn(|| second.apply(&workspace));
            (first.join().unwrap(), second.join().unwrap())
        });

        assert_ne!(first.is_ok(), second.is_ok());
        let error = first.err().or_else(|| second.err()).unwrap();
        assert!(error.contains("conflict"), "{error}");
        let final_bytes = std::fs::read(root.join("file")).unwrap();
        assert!(final_bytes == b"first\n" || final_bytes == b"second\n");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn changed_input_mode_conflicts_before_write() {
        use std::os::unix::fs::PermissionsExt;

        let (root, workspace) = workspace("mode-conflict");
        let path = root.join("file");
        std::fs::write(&path, "old\n").unwrap();
        let prepared = Prepared::one_file(
            &workspace,
            "write_file",
            "write_file".to_string(),
            "file".to_string(),
            b"new\n".to_vec(),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();

        let error = prepared.apply(&workspace).unwrap_err();
        assert!(error.contains("conflict"), "{error}");
        assert_eq!(std::fs::read(&path).unwrap(), b"old\n");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exact_mode_change_is_previewed_audited_and_applied() {
        use std::os::unix::fs::PermissionsExt;

        let (root, workspace) = workspace("mode-change");
        let path = root.join("script");
        std::fs::write(&path, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let snapshot = Snapshot::read(&workspace, "script".to_string()).unwrap();
        let bytes = snapshot.bytes().unwrap().to_vec();
        let prepared = Prepared::from_snapshots(
            "patch",
            "patch".to_string(),
            vec![(
                snapshot,
                Final::File {
                    bytes,
                    mode: Some(0o755),
                },
            )],
        );

        let preview = prepared.preview();
        assert!(preview.contains("old mode 100644\nnew mode 100755"));
        let change = prepared.changes().remove(0);
        assert_eq!(
            (change.before_mode, change.after_mode),
            (Some(0o644), Some(0o755))
        );
        prepared.apply(&workspace).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o755
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
