//! Durable, session-owned named workspace checkpoints.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::state::StateDir;

const VERSION: u32 = 1;
const ROOT: &str = "checkpoints/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub version: u32,
    pub id: u64,
    pub name: String,
    pub created_unix_seconds: u64,
    pub task_generation: u64,
    pub mutation_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileState {
    pub version: u32,
    pub path: String,
    pub identity: String,
    pub content_bytes: Option<u64>,
    pub mode: Option<u32>,
}

struct Item {
    metadata: Metadata,
    files: BTreeMap<String, FileState>,
    used: usize,
    next_file: u64,
}

struct Catalog {
    next: u64,
    used: usize,
    entries: BTreeMap<u64, Item>,
}

pub struct Store {
    root: PathBuf,
    state: StateDir,
    relative: PathBuf,
    max_checkpoint_bytes: usize,
    max_session_bytes: usize,
    catalog: Mutex<Catalog>,
}

impl Store {
    pub fn open(
        workspace: &Path,
        session: &str,
        max_checkpoint_bytes: usize,
        max_session_bytes: usize,
    ) -> Result<Store, String> {
        crate::agent::session::validate_id(session)?;
        validate_limits(max_checkpoint_bytes, max_session_bytes)?;
        let root = workspace
            .canonicalize()
            .map_err(|error| format!("workspace {}: {error}", workspace.display()))?;
        let state = StateDir::new(&root)?;
        let relative = Path::new(ROOT).join(session);
        let catalog = scan(&state, &relative, max_checkpoint_bytes, max_session_bytes)?;
        Ok(Store {
            root,
            state,
            relative,
            max_checkpoint_bytes,
            max_session_bytes,
            catalog: Mutex::new(catalog),
        })
    }

    pub fn list(&self) -> Vec<Metadata> {
        self.catalog
            .lock()
            .unwrap()
            .entries
            .values()
            .map(|item| item.metadata.clone())
            .collect()
    }

    pub fn metadata(&self, id: u64) -> Result<Metadata, String> {
        self.catalog
            .lock()
            .unwrap()
            .entries
            .get(&id)
            .map(|item| item.metadata.clone())
            .ok_or_else(|| format!("there is no checkpoint {id}"))
    }

    pub fn files(&self, id: u64) -> Result<Vec<FileState>, String> {
        self.catalog
            .lock()
            .unwrap()
            .entries
            .get(&id)
            .map(|item| item.files.values().cloned().collect())
            .ok_or_else(|| format!("there is no checkpoint {id}"))
    }

    pub fn create(
        &self,
        name: &str,
        task_generation: u64,
        mutation_generation: u64,
    ) -> Result<Metadata, String> {
        validate_name(name)?;
        let mut catalog = self.catalog.lock().unwrap();
        if catalog
            .entries
            .values()
            .any(|item| item.metadata.name == name)
        {
            return Err(format!("a checkpoint named {name:?} already exists"));
        }
        let id = catalog.next;
        let next = id
            .checked_add(1)
            .ok_or("checkpoint id space is exhausted")?;
        let metadata = Metadata {
            version: VERSION,
            id,
            name: name.to_string(),
            created_unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or_default(),
            task_generation,
            mutation_generation,
        };
        let encoded = serde_json::to_vec(&metadata).map_err(|error| error.to_string())?;
        if encoded.len() > self.max_checkpoint_bytes {
            return Err(format!(
                "checkpoint metadata has {} bytes; limit is {}",
                encoded.len(),
                self.max_checkpoint_bytes
            ));
        }
        let used = catalog
            .used
            .checked_add(encoded.len())
            .ok_or("checkpoint quota overflow")?;
        if used > self.max_session_bytes {
            return Err(format!(
                "session checkpoints would use {used} bytes; limit is {}",
                self.max_session_bytes
            ));
        }

        let parent = self.state.directory(&self.relative)?;
        let staging = parent.join(format!(".new-{id}"));
        std::fs::create_dir(&staging).map_err(|error| format!("{}: {error}", staging.display()))?;
        write_new(&staging.join("metadata.json"), &encoded)?;
        let destination = parent.join(id.to_string());
        match std::fs::symlink_metadata(&destination) {
            Ok(_) => {
                return Err(format!(
                    "{}: checkpoint already exists",
                    destination.display()
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("{}: {error}", destination.display())),
        }
        std::fs::rename(&staging, &destination)
            .map_err(|error| format!("{}: {error}", destination.display()))?;

        catalog.next = next;
        catalog.used = used;
        catalog.entries.insert(
            id,
            Item {
                metadata: metadata.clone(),
                files: BTreeMap::new(),
                used: encoded.len(),
                next_file: 1,
            },
        );
        Ok(metadata)
    }

    /// Record a file's current state once for every checkpoint that predates
    /// its next change. Callers must pass a path already resolved by the
    /// workspace confinement boundary.
    pub fn note(&self, path: &Path) -> Result<(), String> {
        let relative = path
            .strip_prefix(&self.root)
            .map_err(|_| format!("{}: outside the checkpoint workspace", path.display()))?;
        let given = relative
            .to_str()
            .filter(|given| safe_relative(given))
            .ok_or_else(|| format!("{}: path is not safely representable", path.display()))?
            .to_string();
        let mut catalog = self.catalog.lock().unwrap();
        if !catalog
            .entries
            .values()
            .any(|item| !item.files.contains_key(&given))
        {
            return Ok(());
        }

        let (file, content) = read_state(path, given.clone(), self.max_checkpoint_bytes)?;
        let encoded = serde_json::to_vec(&file).map_err(|error| error.to_string())?;
        let added = encoded
            .len()
            .checked_add(content.as_ref().map_or(0, Vec::len))
            .ok_or("checkpoint quota overflow")?;
        let affected = catalog
            .entries
            .values()
            .filter(|item| !item.files.contains_key(&given))
            .count();
        for item in catalog
            .entries
            .values()
            .filter(|item| !item.files.contains_key(&given))
        {
            let used = item
                .used
                .checked_add(added)
                .ok_or("checkpoint quota overflow")?;
            if used > self.max_checkpoint_bytes {
                return Err(format!(
                    "checkpoint {} would use {used} bytes; limit is {}",
                    item.metadata.id, self.max_checkpoint_bytes
                ));
            }
        }
        let total_added = added
            .checked_mul(affected)
            .ok_or("checkpoint quota overflow")?;
        let session_used = catalog
            .used
            .checked_add(total_added)
            .ok_or("checkpoint quota overflow")?;
        if session_used > self.max_session_bytes {
            return Err(format!(
                "session checkpoints would use {session_used} bytes; limit is {}",
                self.max_session_bytes
            ));
        }

        let Catalog { used, entries, .. } = &mut *catalog;
        for item in entries
            .values_mut()
            .filter(|item| !item.files.contains_key(&given))
        {
            let next = item
                .next_file
                .checked_add(1)
                .ok_or("checkpoint file id space is exhausted")?;
            publish_file(
                &self.state,
                &self.relative,
                item.metadata.id,
                item.next_file,
                &encoded,
                content.as_deref(),
            )?;
            item.next_file = next;
            item.used += added;
            item.files.insert(given.clone(), file.clone());
            *used += added;
        }
        Ok(())
    }
}

fn validate_limits(max_checkpoint_bytes: usize, max_session_bytes: usize) -> Result<(), String> {
    if max_checkpoint_bytes == 0
        || max_session_bytes == 0
        || max_checkpoint_bytes > max_session_bytes
    {
        return Err("invalid checkpoint limits".to_string());
    }
    Ok(())
}

fn read_state(
    path: &Path,
    relative: String,
    limit: usize,
) -> Result<(FileState, Option<Vec<u8>>), String> {
    let before = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => metadata,
        Ok(_) => return Err(format!("{}: expected a regular file", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((
                FileState {
                    version: VERSION,
                    path: relative,
                    identity: "missing".to_string(),
                    content_bytes: None,
                    mode: None,
                },
                None,
            ));
        }
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    if before.len() > limit as u64 {
        return Err(format!(
            "{} has {} bytes; checkpoint limit is {limit}",
            path.display(),
            before.len()
        ));
    }
    let mut content = Vec::with_capacity(before.len() as usize);
    std::fs::File::open(path)
        .and_then(|file| {
            file.take(limit.saturating_add(1) as u64)
                .read_to_end(&mut content)
        })
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let after = std::fs::symlink_metadata(path).map_err(|error| {
        format!(
            "{} changed while making a checkpoint: {error}",
            path.display()
        )
    })?;
    if content.len() > limit
        || !after.file_type().is_file()
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || file_mode(&before) != file_mode(&after)
        || !same_file(&before, &after)
    {
        return Err(format!(
            "{} changed while making a checkpoint",
            path.display()
        ));
    }
    let mut digest = Sha256::new();
    digest.update(&content);
    Ok((
        FileState {
            version: VERSION,
            path: relative,
            identity: format!("sha256:{}", crate::tools::hex(&digest.finalize())),
            content_bytes: Some(content.len() as u64),
            mode: file_mode(&before),
        },
        Some(content),
    ))
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
fn same_file(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.dev() == after.dev() && before.ino() == after.ino()
}

#[cfg(not(target_os = "linux"))]
fn same_file(_before: &std::fs::Metadata, _after: &std::fs::Metadata) -> bool {
    true
}

fn publish_file(
    state: &StateDir,
    relative: &Path,
    checkpoint: u64,
    id: u64,
    metadata: &[u8],
    content: Option<&[u8]>,
) -> Result<(), String> {
    let parent = state.directory(&relative.join(checkpoint.to_string()).join("files"))?;
    let staging = parent.join(format!(".new-{id}"));
    std::fs::create_dir(&staging).map_err(|error| format!("{}: {error}", staging.display()))?;
    if let Some(content) = content {
        write_new(&staging.join("content"), content)?;
    }
    write_new(&staging.join("metadata.json"), metadata)?;
    let destination = parent.join(id.to_string());
    match std::fs::symlink_metadata(&destination) {
        Ok(_) => {
            return Err(format!(
                "{}: file record already exists",
                destination.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("{}: {error}", destination.display())),
    }
    std::fs::rename(&staging, &destination)
        .map_err(|error| format!("{}: {error}", destination.display()))
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty() || name.chars().any(char::is_control) {
        return Err(
            "checkpoint name must contain visible text without control characters".to_string(),
        );
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn scan(
    state: &StateDir,
    relative: &Path,
    max_checkpoint_bytes: usize,
    max_session_bytes: usize,
) -> Result<Catalog, String> {
    let Some(directory) = state.existing_directory(relative)? else {
        return Ok(Catalog {
            next: 1,
            used: 0,
            entries: BTreeMap::new(),
        });
    };
    let mut entries = BTreeMap::new();
    let mut names = std::collections::BTreeSet::new();
    let mut used = 0usize;
    let mut highest = 0u64;
    for entry in std::fs::read_dir(&directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| format!("{}: {error}", directory.display()))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "checkpoint entry name is not UTF-8".to_string())?;
        if name.starts_with(".new-") {
            return Err(format!("{}: incomplete checkpoint", entry.path().display()));
        }
        let id = canonical_id(&name).ok_or_else(|| {
            format!(
                "{}: unexpected checkpoint entry {name:?}",
                directory.display()
            )
        })?;
        let item = relative.join(&name);
        state
            .existing_directory(&item)?
            .ok_or_else(|| format!("checkpoint {id}: directory disappeared"))?;
        let path = state
            .existing_file(&item.join("metadata.json"))?
            .ok_or_else(|| format!("checkpoint {id}: metadata is missing"))?;
        let bytes = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        if bytes.len() > max_checkpoint_bytes {
            return Err(format!(
                "checkpoint {id} has {} metadata bytes; limit is {max_checkpoint_bytes}",
                bytes.len()
            ));
        }
        let metadata: Metadata = serde_json::from_slice(&bytes)
            .map_err(|error| format!("checkpoint {id}: bad metadata: {error}"))?;
        validate_name(&metadata.name)?;
        if metadata.version != VERSION || metadata.id != id || !names.insert(metadata.name.clone())
        {
            return Err(format!("checkpoint {id}: metadata is inconsistent"));
        }
        let (files, file_bytes, next_file) = scan_files(state, &item, id, max_checkpoint_bytes)?;
        let item_used = bytes
            .len()
            .checked_add(file_bytes)
            .ok_or("checkpoint quota overflow")?;
        if item_used > max_checkpoint_bytes {
            return Err(format!(
                "checkpoint {id} uses {item_used} bytes; limit is {max_checkpoint_bytes}"
            ));
        }
        used = used
            .checked_add(item_used)
            .ok_or("checkpoint quota overflow")?;
        if used > max_session_bytes {
            return Err(format!(
                "existing session checkpoints use {used} bytes; limit is {max_session_bytes}"
            ));
        }
        highest = highest.max(id);
        entries.insert(
            id,
            Item {
                metadata,
                files,
                used: item_used,
                next_file,
            },
        );
    }
    Ok(Catalog {
        next: highest
            .checked_add(1)
            .ok_or("checkpoint id space is exhausted")?,
        used,
        entries,
    })
}

fn scan_files(
    state: &StateDir,
    item: &Path,
    checkpoint: u64,
    max_checkpoint_bytes: usize,
) -> Result<(BTreeMap<String, FileState>, usize, u64), String> {
    let directory = state
        .existing_directory(item)?
        .ok_or_else(|| format!("checkpoint {checkpoint}: directory disappeared"))?;
    let mut files_directory = None;
    for entry in std::fs::read_dir(&directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| format!("{}: {error}", directory.display()))?;
        let kind = entry
            .file_type()
            .map_err(|error| format!("{}: {error}", entry.path().display()))?;
        if entry.file_name() == "metadata.json" && kind.is_file() {
            continue;
        }
        if entry.file_name() == "files" && kind.is_dir() {
            files_directory = Some(entry.path());
            continue;
        }
        return Err(format!(
            "checkpoint {checkpoint}: unexpected or unsafe entry {}",
            entry.path().display()
        ));
    }
    let Some(directory) = files_directory else {
        return Ok((BTreeMap::new(), 0, 1));
    };
    let mut files = BTreeMap::new();
    let mut used = 0usize;
    let mut highest = 0u64;
    for entry in std::fs::read_dir(&directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| format!("{}: {error}", directory.display()))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("checkpoint {checkpoint}: file entry name is not UTF-8"))?;
        if name.starts_with(".new-") {
            return Err(format!(
                "{}: incomplete checkpoint file",
                entry.path().display()
            ));
        }
        let id = canonical_id(&name)
            .ok_or_else(|| format!("checkpoint {checkpoint}: unexpected file entry {name:?}"))?;
        let relative = item.join("files").join(&name);
        let (metadata_path, content_path) = file_entries(state, &relative, checkpoint, id)?;
        let metadata_size = std::fs::metadata(&metadata_path)
            .map_err(|error| format!("{}: {error}", metadata_path.display()))?
            .len();
        if metadata_size > max_checkpoint_bytes as u64 {
            return Err(format!(
                "checkpoint {checkpoint} file {id}: metadata exceeds the {max_checkpoint_bytes}-byte checkpoint limit"
            ));
        }
        let metadata_bytes = std::fs::read(&metadata_path)
            .map_err(|error| format!("{}: {error}", metadata_path.display()))?;
        let file: FileState = serde_json::from_slice(&metadata_bytes)
            .map_err(|error| format!("checkpoint {checkpoint} file {id}: bad metadata: {error}"))?;
        let content_bytes = content_path
            .as_ref()
            .map(|path| std::fs::metadata(path).map(|metadata| metadata.len()))
            .transpose()
            .map_err(|error| format!("checkpoint {checkpoint} file {id}: {error}"))?
            .unwrap_or(0);
        let added = metadata_bytes
            .len()
            .checked_add(
                usize::try_from(content_bytes)
                    .map_err(|_| format!("checkpoint {checkpoint} file {id} is too large"))?,
            )
            .ok_or("checkpoint quota overflow")?;
        used = used.checked_add(added).ok_or("checkpoint quota overflow")?;
        if used > max_checkpoint_bytes {
            return Err(format!(
                "checkpoint {checkpoint} files use {used} bytes; limit is {max_checkpoint_bytes}"
            ));
        }
        validate_file_state(checkpoint, id, &file, content_path.as_deref())?;
        if files.insert(file.path.clone(), file).is_some() {
            return Err(format!("checkpoint {checkpoint}: duplicate captured path"));
        }
        highest = highest.max(id);
    }
    Ok((
        files,
        used,
        highest
            .checked_add(1)
            .ok_or("checkpoint file id space is exhausted")?,
    ))
}

fn file_entries(
    state: &StateDir,
    relative: &Path,
    checkpoint: u64,
    id: u64,
) -> Result<(PathBuf, Option<PathBuf>), String> {
    let directory = state
        .existing_directory(relative)?
        .ok_or_else(|| format!("checkpoint {checkpoint} file {id}: directory disappeared"))?;
    let mut metadata = None;
    let mut content = None;
    for entry in std::fs::read_dir(&directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| format!("{}: {error}", directory.display()))?;
        let kind = entry
            .file_type()
            .map_err(|error| format!("{}: {error}", entry.path().display()))?;
        match entry.file_name().to_str() {
            Some("metadata.json") if kind.is_file() => metadata = Some(entry.path()),
            Some("content") if kind.is_file() => content = Some(entry.path()),
            _ => {
                return Err(format!(
                    "checkpoint {checkpoint} file {id}: unexpected or unsafe entry {}",
                    entry.path().display()
                ));
            }
        }
    }
    let metadata = metadata
        .ok_or_else(|| format!("checkpoint {checkpoint} file {id}: metadata is missing"))?;
    Ok((metadata, content))
}

fn validate_file_state(
    checkpoint: u64,
    id: u64,
    state: &FileState,
    content: Option<&Path>,
) -> Result<(), String> {
    if state.version != VERSION
        || !safe_relative(&state.path)
        || state.mode.is_some_and(|mode| mode > 0o7777)
    {
        return Err(format!(
            "checkpoint {checkpoint} file {id}: invalid metadata"
        ));
    }
    match (state.content_bytes, content) {
        (None, None) if state.identity == "missing" && state.mode.is_none() => Ok(()),
        (Some(expected), Some(path))
            if state.identity.len() == 71
                && state.identity.starts_with("sha256:")
                && state.identity[7..]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
        {
            let bytes =
                std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
            let mut digest = Sha256::new();
            digest.update(&bytes);
            if bytes.len() as u64 != expected
                || state.identity != format!("sha256:{}", crate::tools::hex(&digest.finalize()))
            {
                return Err(format!(
                    "checkpoint {checkpoint} file {id}: content does not match metadata"
                ));
            }
            Ok(())
        }
        _ => Err(format!(
            "checkpoint {checkpoint} file {id}: content does not match metadata"
        )),
    }
}

fn safe_relative(given: &str) -> bool {
    let path = Path::new(given);
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn canonical_id(name: &str) -> Option<u64> {
    let id = name.parse::<u64>().ok()?;
    (id > 0 && name == id.to_string()).then_some(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn workspace(name: &str) -> PathBuf {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "gears-checkpoint-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn named_checkpoint_metadata_survives_reopen_and_is_session_scoped() {
        let root = workspace("catalog");
        let store = Store::open(&root, "18-1", 1024, 4096).unwrap();
        let first = store.create("before refactor", 3, 7).unwrap();
        let second = store.create("tests pass", 3, 9).unwrap();
        assert_eq!((first.id, second.id), (1, 2));
        assert_eq!(store.metadata(1).unwrap(), first);
        assert!(store.create("tests pass", 4, 10).is_err());
        drop(store);

        let reopened = Store::open(&root, "18-1", 1024, 4096).unwrap();
        assert_eq!(reopened.list(), [first, second]);
        assert!(
            Store::open(&root, "18-2", 1024, 4096)
                .unwrap()
                .list()
                .is_empty()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn names_and_storage_are_bounded_before_publication() {
        let root = workspace("limits");
        let store = Store::open(&root, "18-1", 128, 128).unwrap();
        for name in ["", "  ", "bad\nname"] {
            assert!(store.create(name, 0, 0).is_err());
        }
        let error = store.create(&"x".repeat(256), 0, 0).unwrap_err();
        assert!(error.contains("limit is 128"), "{error}");
        assert!(store.list().is_empty());
        assert!(!root.join(".gears/checkpoints/v1/18-1/1").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn captured_file_records_are_validated_and_reopened() {
        let root = workspace("files");
        let store = Store::open(&root, "18-1", 4096, 16384).unwrap();
        store.create("before edit", 1, 2).unwrap();
        drop(store);

        let directory = root.join(".gears/checkpoints/v1/18-1/1/files/1");
        std::fs::create_dir_all(&directory).unwrap();
        let content = b"one\n";
        let mut digest = Sha256::new();
        digest.update(content);
        let state = FileState {
            version: VERSION,
            path: "src/lib.rs".to_string(),
            identity: format!("sha256:{}", crate::tools::hex(&digest.finalize())),
            content_bytes: Some(content.len() as u64),
            mode: None,
        };
        std::fs::write(
            directory.join("metadata.json"),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        std::fs::write(directory.join("content"), content).unwrap();

        let store = Store::open(&root, "18-1", 4096, 16384).unwrap();
        assert_eq!(store.files(1).unwrap(), [state]);
        drop(store);
        std::fs::write(directory.join("content"), "changed\n").unwrap();
        let error = Store::open(&root, "18-1", 4096, 16384).err().unwrap();
        assert!(error.contains("content does not match metadata"), "{error}");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn checkpoints_capture_each_paths_first_state_lazily() {
        let root = workspace("capture");
        let source = root.join("src/lib.rs");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::write(&source, "one\n").unwrap();
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let store = Store::open(&root, "18-1", 4096, 16384).unwrap();
        let first = store.create("first", 1, 1).unwrap();
        store.note(&source).unwrap();
        std::fs::write(&source, "two\n").unwrap();
        store.note(&source).unwrap();
        let second = store.create("second", 1, 2).unwrap();
        store.note(&source).unwrap();
        let missing = root.join("src/new.rs");
        store.note(&missing).unwrap();

        let first_files = store.files(first.id).unwrap();
        let first_source = first_files
            .iter()
            .find(|file| file.path == "src/lib.rs")
            .unwrap();
        let second_files = store.files(second.id).unwrap();
        let second_source = second_files
            .iter()
            .find(|file| file.path == "src/lib.rs")
            .unwrap();
        assert_ne!(first_source.identity, second_source.identity);
        assert_eq!(first_source.content_bytes, Some(4));
        assert_eq!(second_source.content_bytes, Some(4));
        assert_eq!(
            first_files
                .iter()
                .find(|file| file.path == "src/new.rs")
                .unwrap()
                .identity,
            "missing"
        );
        #[cfg(target_os = "linux")]
        assert_eq!(first_source.mode, Some(0o755));
        assert_eq!(
            std::fs::read(root.join(format!(
                ".gears/checkpoints/v1/18-1/{}/files/1/content",
                first.id
            )))
            .unwrap(),
            b"one\n"
        );
        assert_eq!(
            std::fs::read(root.join(format!(
                ".gears/checkpoints/v1/18-1/{}/files/1/content",
                second.id
            )))
            .unwrap(),
            b"two\n"
        );

        let expected = (first_files, second_files);
        drop(store);
        let reopened = Store::open(&root, "18-1", 4096, 16384).unwrap();
        assert_eq!(
            (
                reopened.files(first.id).unwrap(),
                reopened.files(second.id).unwrap()
            ),
            expected
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn oversized_capture_is_refused_before_publication() {
        let root = workspace("capture-limit");
        let source = root.join("large.rs");
        std::fs::write(&source, vec![b'x'; 1024]).unwrap();
        let store = Store::open(&root, "18-1", 512, 2048).unwrap();
        store.create("before", 0, 0).unwrap();

        let error = store.note(&source).unwrap_err();
        assert!(error.contains("checkpoint limit is 512"), "{error}");
        assert!(store.files(1).unwrap().is_empty());
        assert!(!root.join(".gears/checkpoints/v1/18-1/1/files").exists());
        assert_eq!(std::fs::read(&source).unwrap(), vec![b'x'; 1024]);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn session_quota_is_checked_before_any_checkpoint_is_changed() {
        let root = workspace("session-limit");
        let source = root.join("large.rs");
        std::fs::write(&source, vec![b'x'; 400]).unwrap();
        let store = Store::open(&root, "18-1", 700, 900).unwrap();
        store.create("first", 0, 0).unwrap();
        store.create("second", 0, 0).unwrap();

        let error = store.note(&source).unwrap_err();
        assert!(error.contains("session checkpoints would use"), "{error}");
        assert!(store.files(1).unwrap().is_empty());
        assert!(store.files(2).unwrap().is_empty());
        assert!(!root.join(".gears/checkpoints/v1/18-1/1/files").exists());
        assert!(!root.join(".gears/checkpoints/v1/18-1/2/files").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn catalog_refuses_unexpected_checkpoint_state() {
        use std::os::unix::fs::symlink;

        let root = workspace("unsafe");
        let store = Store::open(&root, "18-1", 1024, 4096).unwrap();
        store.create("safe", 0, 0).unwrap();
        drop(store);
        symlink(&root, root.join(".gears/checkpoints/v1/18-1/1/redirect")).unwrap();

        let error = Store::open(&root, "18-1", 1024, 4096).err().unwrap();
        assert!(error.contains("unexpected or unsafe entry"), "{error}");
        std::fs::remove_dir_all(root).unwrap();
    }
}
