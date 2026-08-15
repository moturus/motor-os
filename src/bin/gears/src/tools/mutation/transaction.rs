//! Private staging and rollback for one prepared file-state set.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::{Applied, Before, FileChange, Final, modes, set_mode};
use crate::state::StateDir;
use crate::tools::Workspace;

const ROOT: &str = "transactions/v1";

#[derive(Serialize)]
struct Manifest<'a> {
    version: u32,
    phase: &'a str,
    digest: &'a str,
    changes: Vec<Record>,
}

#[derive(Clone, Serialize)]
struct Record {
    path: String,
    before_exists: bool,
    before_mode: Option<u32>,
    after_exists: bool,
    after_mode: Option<u32>,
}

pub(super) fn apply(
    workspace: &Workspace,
    changes: &[FileChange],
    digest: &str,
) -> Result<Applied, String> {
    apply_inner(workspace, changes, digest, |_| Ok(()))
}

fn apply_inner(
    workspace: &Workspace,
    changes: &[FileChange],
    digest: &str,
    mut before_change: impl FnMut(usize) -> Result<(), String>,
) -> Result<Applied, String> {
    let state = StateDir::new(workspace.root())?;
    let relative = Path::new(ROOT).join(
        digest
            .strip_prefix("sha256:")
            .ok_or_else(|| "prepared mutation has an invalid digest".to_string())?,
    );
    if state.existing_directory(&relative)?.is_some() {
        return Err(format!(
            "pending mutation recovery exists for {digest}; restart gears before applying it again"
        ));
    }
    let directory = state.directory(&relative)?;
    let records = match stage(&state, &relative, changes, digest) {
        Ok(records) => records,
        Err(error) => return cleanup_error(&directory, error),
    };
    for change in changes {
        if let Err(error) = workspace.before_write(&change.path) {
            return cleanup_error(&directory, error);
        }
    }
    if let Err(error) = write_manifest(&state, &relative, digest, "applying", records) {
        return cleanup_error(&directory, error);
    }
    let mut created = Vec::new();
    match apply_changes(
        workspace,
        &directory,
        changes,
        &mut created,
        &mut before_change,
    ) {
        Ok(applied) => {
            remove_transaction(&directory)?;
            Ok(applied)
        }
        Err(error) => {
            match restore(workspace, &directory, changes).and_then(|()| remove_created(&created)) {
                Ok(()) => {
                    remove_transaction(&directory)?;
                    Err(error)
                }
                Err(restore) => Err(format!(
                    "{error}; rollback failed: {restore}; recovery metadata remains at {}",
                    directory.display()
                )),
            }
        }
    }
}

fn stage(
    state: &StateDir,
    relative: &Path,
    changes: &[FileChange],
    digest: &str,
) -> Result<Vec<Record>, String> {
    let mut records = Vec::with_capacity(changes.len());
    for (index, change) in changes.iter().enumerate() {
        if let Before::File { bytes, .. } = &change.before {
            write_synced(
                &state.file(&relative.join("old").join(index.to_string()))?,
                bytes,
            )?;
        }
        if let Final::File { bytes, .. } = &change.after {
            write_synced(
                &state.file(&relative.join("new").join(index.to_string()))?,
                bytes,
            )?;
        }
        let (before_mode, after_mode) = modes(change);
        records.push(Record {
            path: change.display.clone(),
            before_exists: matches!(change.before, Before::File { .. }),
            before_mode,
            after_exists: matches!(change.after, Final::File { .. }),
            after_mode,
        });
    }
    write_manifest(state, relative, digest, "prepared", records.clone())?;
    Ok(records)
}

fn write_manifest(
    state: &StateDir,
    relative: &Path,
    digest: &str,
    phase: &str,
    changes: Vec<Record>,
) -> Result<(), String> {
    let bytes = serde_json::to_vec(&Manifest {
        version: 1,
        phase,
        digest,
        changes,
    })
    .map_err(|error| format!("mutation manifest: {error}"))?;
    let temporary = state.file(&relative.join("manifest.new"))?;
    write_synced(&temporary, &bytes)?;
    let manifest = state.file(&relative.join("manifest.json"))?;
    std::fs::rename(&temporary, &manifest)
        .map_err(|error| format!("{}: {error}", manifest.display()))
}

fn apply_changes(
    workspace: &Workspace,
    directory: &Path,
    changes: &[FileChange],
    created: &mut Vec<PathBuf>,
    before_change: &mut impl FnMut(usize) -> Result<(), String>,
) -> Result<Applied, String> {
    let mut bytes = 0usize;
    for (index, change) in changes.iter().enumerate() {
        before_change(index)?;
        match &change.after {
            Final::Missing => remove_file(&change.path, &change.given)?,
            Final::File { bytes: after, .. } => {
                create_parents(workspace.root(), &change.path, created)?;
                std::fs::copy(directory.join("new").join(index.to_string()), &change.path)
                    .map_err(|error| format!("{}: {error}", change.given))?;
                if let Some(mode) = modes(change).1 {
                    set_mode(&change.path, mode, &change.given)?;
                }
                bytes = bytes.saturating_add(after.len());
            }
        }
    }
    Ok(Applied {
        paths: changes
            .iter()
            .map(|change| change.display.clone())
            .collect(),
        bytes,
    })
}

fn restore(workspace: &Workspace, directory: &Path, changes: &[FileChange]) -> Result<(), String> {
    for (index, change) in changes.iter().enumerate().rev() {
        match &change.before {
            Before::Missing => remove_file_if_present(&change.path)?,
            Before::File { mode, .. } => {
                let mut ignored = Vec::new();
                create_parents(workspace.root(), &change.path, &mut ignored)?;
                std::fs::copy(directory.join("old").join(index.to_string()), &change.path)
                    .map_err(|error| format!("{}: {error}", change.given))?;
                if let Some(mode) = mode {
                    set_mode(&change.path, *mode, &change.given)?;
                }
            }
        }
    }
    Ok(())
}

fn create_parents(root: &Path, path: &Path, created: &mut Vec<PathBuf>) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{}: path has no parent", path.display()))?;
    let relative = parent
        .strip_prefix(root)
        .map_err(|_| format!("{}: outside workspace", path.display()))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => return Err(format!("{}: parent is not a directory", current.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current)
                    .map_err(|error| format!("{}: {error}", current.display()))?;
                created.push(current.clone());
            }
            Err(error) => return Err(format!("{}: {error}", current.display())),
        }
    }
    Ok(())
}

fn remove_file(path: &Path, given: &str) -> Result<(), String> {
    std::fs::remove_file(path).map_err(|error| format!("{given}: {error}"))
}

fn remove_file_if_present(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file =
        std::fs::File::create(path).map_err(|error| format!("{}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn remove_transaction(directory: &Path) -> Result<(), String> {
    std::fs::remove_dir_all(directory).map_err(|error| format!("{}: {error}", directory.display()))
}

fn remove_created(created: &[PathBuf]) -> Result<(), String> {
    for path in created.iter().rev() {
        match std::fs::remove_dir(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("{}: {error}", path.display())),
        }
    }
    Ok(())
}

fn cleanup_error<T>(directory: &Path, error: String) -> Result<T, String> {
    match remove_transaction(directory) {
        Ok(()) => Err(error),
        Err(cleanup) => Err(format!("{error}; transaction cleanup failed: {cleanup}")),
    }
}

#[cfg(test)]
pub(super) fn apply_failing_before(
    workspace: &Workspace,
    changes: &[FileChange],
    digest: &str,
    index: usize,
) -> Result<Applied, String> {
    apply_inner(workspace, changes, digest, |at| {
        if at == index {
            Err(format!("injected failure before change {at}"))
        } else {
            Ok(())
        }
    })
}
