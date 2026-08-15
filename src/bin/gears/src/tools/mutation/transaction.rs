//! Private staging and rollback for one prepared file-state set.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{Applied, Before, FileChange, Final, modes, set_mode};
use crate::state::StateDir;
use crate::tools::Workspace;

const ROOT: &str = "transactions/v1";

const MANIFEST_LIMIT: u64 = 1024 * 1024;
const TRANSACTION_LIMIT: usize = 64;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    phase: Phase,
    digest: String,
    changes: Vec<Record>,
    created_dirs: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Prepared,
    Applying,
    Committed,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    path: String,
    before_exists: bool,
    before_mode: Option<u32>,
    after_exists: bool,
    after_mode: Option<u32>,
}

struct Recovery {
    record: Record,
    path: PathBuf,
    old: Option<PathBuf>,
}

struct Location<'a> {
    state: &'a StateDir,
    relative: &'a Path,
    directory: &'a Path,
    digest: &'a str,
}

pub(super) fn recover(workspace: &Workspace) -> Result<usize, String> {
    let _mutation = workspace.mutation()?;
    let state = StateDir::new(workspace.root())?;
    let Some(root) = state.existing_directory(Path::new(ROOT))? else {
        return Ok(0);
    };
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(&root).map_err(|error| format!("{}: {error}", root.display()))? {
        entries.push(entry.map_err(|error| format!("{}: {error}", root.display()))?);
        if entries.len() > TRANSACTION_LIMIT {
            return Err(format!(
                "{}: more than {TRANSACTION_LIMIT} pending mutations",
                root.display()
            ));
        }
    }
    entries.sort_by_key(std::fs::DirEntry::file_name);

    for entry in &entries {
        recover_one(workspace, &state, entry)?;
    }
    Ok(entries.len())
}

fn recover_one(
    workspace: &Workspace,
    state: &StateDir,
    entry: &std::fs::DirEntry,
) -> Result<(), String> {
    let name = entry
        .file_name()
        .into_string()
        .map_err(|_| "mutation recovery directory name is not UTF-8".to_string())?;
    if name.len() != 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!(
            "{}: invalid mutation recovery directory name",
            entry.path().display()
        ));
    }
    let metadata = std::fs::symlink_metadata(entry.path())
        .map_err(|error| format!("{}: {error}", entry.path().display()))?;
    if !metadata.file_type().is_dir() {
        return Err(format!(
            "{}: unsafe mutation recovery entry (expected a directory)",
            entry.path().display()
        ));
    }
    let relative = Path::new(ROOT).join(&name);
    let Some(manifest_path) = state.existing_file(&relative.join("manifest.json"))? else {
        // The initial manifest is published before any workspace mutation.
        return remove_transaction(&entry.path());
    };
    let manifest = read_manifest(&manifest_path)?;
    if manifest.version != 1 || manifest.digest != format!("sha256:{name}") {
        return Err(format!(
            "{}: invalid mutation recovery version or digest",
            manifest_path.display()
        ));
    }
    match manifest.phase {
        Phase::Prepared | Phase::Committed => remove_transaction(&entry.path()),
        Phase::Applying => {
            let (changes, created) =
                validate_recovery(workspace, state, &relative, manifest.clone())?;
            restore_recovery(&changes)?;
            remove_created(&created)?;
            write_manifest(
                state,
                &relative,
                &manifest.digest,
                Phase::Prepared,
                manifest.changes,
                Vec::new(),
            )?;
            remove_transaction(&entry.path())
        }
    }
}

fn read_manifest(path: &Path) -> Result<Manifest, String> {
    let file = std::fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MANIFEST_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if bytes.len() as u64 > MANIFEST_LIMIT {
        return Err(format!(
            "{}: mutation manifest is too large",
            path.display()
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("{}: invalid mutation manifest: {error}", path.display()))
}

fn validate_recovery(
    workspace: &Workspace,
    state: &StateDir,
    relative: &Path,
    manifest: Manifest,
) -> Result<(Vec<Recovery>, Vec<PathBuf>), String> {
    if manifest.changes.is_empty() {
        return Err("mutation recovery manifest has no changes".to_string());
    }
    let mut seen = HashSet::new();
    let mut changes = Vec::with_capacity(manifest.changes.len());
    for (index, record) in manifest.changes.into_iter().enumerate() {
        let path = recovery_path(workspace, &record.path)?;
        if !seen.insert(path.clone()) {
            return Err(format!("{}: duplicate mutation recovery path", record.path));
        }
        let old = state.existing_file(&relative.join("old").join(index.to_string()))?;
        let new = state.existing_file(&relative.join("new").join(index.to_string()))?;
        if record.before_exists != old.is_some() || record.after_exists != new.is_some() {
            return Err(format!(
                "{}: incomplete mutation recovery staging",
                record.path
            ));
        }
        changes.push(Recovery { record, path, old });
    }

    let changed_paths: Vec<&Path> = changes.iter().map(|change| change.path.as_path()).collect();
    let mut seen_dirs = HashSet::new();
    let mut created = Vec::with_capacity(manifest.created_dirs.len());
    for given in manifest.created_dirs {
        let path = recovery_path(workspace, &given)?;
        if path == workspace.root()
            || !seen_dirs.insert(path.clone())
            || !changed_paths
                .iter()
                .any(|changed| changed != &path && changed.starts_with(&path))
        {
            return Err(format!(
                "{given}: invalid created directory in mutation recovery"
            ));
        }
        created.push(path);
    }
    created.sort_by_key(|path| path.components().count());
    Ok((changes, created))
}

fn recovery_path(workspace: &Workspace, given: &str) -> Result<PathBuf, String> {
    let relative = Path::new(given);
    if relative.is_absolute()
        || relative.as_os_str().is_empty()
        || !relative
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!("{given}: invalid mutation recovery path"));
    }
    let path = workspace.resolve(given)?;
    if workspace.display(&path) != given {
        return Err(format!("{given}: mutation recovery path was redirected"));
    }
    Ok(path)
}

fn restore_recovery(changes: &[Recovery]) -> Result<(), String> {
    for change in changes.iter().rev() {
        if change.record.before_exists {
            let old = change
                .old
                .as_ref()
                .ok_or_else(|| format!("{}: missing recovery backup", change.record.path))?;
            std::fs::copy(old, &change.path)
                .map_err(|error| format!("{}: {error}", change.record.path))?;
            if let Some(mode) = change.record.before_mode {
                set_mode(&change.path, mode, &change.record.path)?;
            }
        } else {
            remove_file_if_present(&change.path)?;
        }
    }
    Ok(())
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
    let created_dirs = match missing_parents(workspace, changes) {
        Ok(created) => created,
        Err(error) => return cleanup_error(&directory, error),
    };
    if let Err(error) = write_manifest(
        &state,
        &relative,
        digest,
        Phase::Applying,
        records.clone(),
        created_dirs.clone(),
    ) {
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
        Ok(mut applied) => match write_manifest(
            &state,
            &relative,
            digest,
            Phase::Committed,
            records.clone(),
            created_dirs.clone(),
        ) {
            Ok(()) => {
                applied.recovery_pending = remove_transaction(&directory).is_err();
                Ok(applied)
            }
            Err(error) => rollback_error(
                workspace,
                Location {
                    state: &state,
                    relative: &relative,
                    directory: &directory,
                    digest,
                },
                changes,
                &created,
                records,
                error,
            ),
        },
        Err(error) => rollback_error(
            workspace,
            Location {
                state: &state,
                relative: &relative,
                directory: &directory,
                digest,
            },
            changes,
            &created,
            records,
            error,
        ),
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
    write_manifest(
        state,
        relative,
        digest,
        Phase::Prepared,
        records.clone(),
        Vec::new(),
    )?;
    Ok(records)
}

fn write_manifest(
    state: &StateDir,
    relative: &Path,
    digest: &str,
    phase: Phase,
    changes: Vec<Record>,
    created_dirs: Vec<String>,
) -> Result<(), String> {
    let bytes = serde_json::to_vec(&Manifest {
        version: 1,
        phase,
        digest: digest.to_string(),
        changes,
        created_dirs,
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
        recovery_pending: false,
    })
}

fn missing_parents(workspace: &Workspace, changes: &[FileChange]) -> Result<Vec<String>, String> {
    let mut seen = HashSet::new();
    let mut created = Vec::new();
    for change in changes {
        if !matches!(change.after, Final::File { .. }) {
            continue;
        }
        let parent = change
            .path
            .parent()
            .ok_or_else(|| format!("{}: path has no parent", change.given))?;
        let relative = parent
            .strip_prefix(workspace.root())
            .map_err(|_| format!("{}: outside workspace", change.given))?;
        let mut current = workspace.root().to_path_buf();
        for component in relative.components() {
            current.push(component);
            match std::fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_dir() => {}
                Ok(_) => return Err(format!("{}: parent is not a directory", current.display())),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let display = workspace.display(&current);
                    if seen.insert(display.clone()) {
                        created.push(display);
                    }
                }
                Err(error) => return Err(format!("{}: {error}", current.display())),
            }
        }
    }
    Ok(created)
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
    remove_tree(directory)
}

fn remove_tree(directory: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?;
    if !metadata.file_type().is_dir() {
        return Err(format!(
            "{}: unsafe transaction cleanup entry",
            directory.display()
        ));
    }
    for entry in
        std::fs::read_dir(directory).map_err(|error| format!("{}: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| format!("{}: {error}", directory.display()))?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if metadata.file_type().is_dir() {
            remove_tree(&path)?;
        } else if metadata.file_type().is_file() {
            std::fs::remove_file(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        } else {
            return Err(format!(
                "{}: unsafe transaction cleanup entry",
                path.display()
            ));
        }
    }
    std::fs::remove_dir(directory).map_err(|error| format!("{}: {error}", directory.display()))
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

fn rollback_error<T>(
    workspace: &Workspace,
    location: Location<'_>,
    changes: &[FileChange],
    created: &[PathBuf],
    records: Vec<Record>,
    error: String,
) -> Result<T, String> {
    match restore(workspace, location.directory, changes).and_then(|()| remove_created(created)) {
        Ok(()) => match write_manifest(
            location.state,
            location.relative,
            location.digest,
            Phase::Prepared,
            records,
            Vec::new(),
        ) {
            Ok(()) => cleanup_error(location.directory, error),
            Err(marker) => Err(format!(
                "{error}; rollback completed but its cleanup marker failed: {marker}; recovery metadata remains at {}",
                location.directory.display()
            )),
        },
        Err(restore) => Err(format!(
            "{error}; rollback failed: {restore}; recovery metadata remains at {}",
            location.directory.display()
        )),
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

#[cfg(test)]
pub(super) fn leave_applying_after(
    workspace: &Workspace,
    changes: &[FileChange],
    digest: &str,
    count: usize,
) -> Result<(), String> {
    let state = StateDir::new(workspace.root())?;
    let relative = Path::new(ROOT).join(
        digest
            .strip_prefix("sha256:")
            .ok_or_else(|| "prepared mutation has an invalid digest".to_string())?,
    );
    let directory = state.directory(&relative)?;
    let records = stage(&state, &relative, changes, digest)?;
    for change in changes {
        workspace.before_write(&change.path)?;
    }
    let created_dirs = missing_parents(workspace, changes)?;
    write_manifest(
        &state,
        &relative,
        digest,
        Phase::Applying,
        records,
        created_dirs,
    )?;
    let partial = changes
        .get(..count)
        .ok_or_else(|| "interruption index is outside the change set".to_string())?;
    apply_changes(workspace, &directory, partial, &mut Vec::new(), &mut |_| {
        Ok(())
    })?;
    Ok(())
}
