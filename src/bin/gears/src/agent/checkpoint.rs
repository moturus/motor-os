//! Durable, session-owned named workspace checkpoints.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

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

struct Catalog {
    next: u64,
    used: usize,
    entries: BTreeMap<u64, Metadata>,
}

pub struct Store {
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
        if max_checkpoint_bytes == 0
            || max_session_bytes == 0
            || max_checkpoint_bytes > max_session_bytes
        {
            return Err("invalid checkpoint limits".to_string());
        }
        let state = StateDir::new(workspace)?;
        let relative = Path::new(ROOT).join(session);
        let catalog = scan(&state, &relative, max_checkpoint_bytes, max_session_bytes)?;
        Ok(Store {
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
            .cloned()
            .collect()
    }

    pub fn metadata(&self, id: u64) -> Result<Metadata, String> {
        self.catalog
            .lock()
            .unwrap()
            .entries
            .get(&id)
            .cloned()
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
        if catalog.entries.values().any(|entry| entry.name == name) {
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
        catalog.entries.insert(id, metadata.clone());
        Ok(metadata)
    }
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
        validate_entries(state, &item, id)?;
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
        used = used
            .checked_add(bytes.len())
            .ok_or("checkpoint quota overflow")?;
        if used > max_session_bytes {
            return Err(format!(
                "existing session checkpoints use {used} bytes; limit is {max_session_bytes}"
            ));
        }
        let metadata: Metadata = serde_json::from_slice(&bytes)
            .map_err(|error| format!("checkpoint {id}: bad metadata: {error}"))?;
        validate_name(&metadata.name)?;
        if metadata.version != VERSION || metadata.id != id || !names.insert(metadata.name.clone())
        {
            return Err(format!("checkpoint {id}: metadata is inconsistent"));
        }
        highest = highest.max(id);
        entries.insert(id, metadata);
    }
    Ok(Catalog {
        next: highest
            .checked_add(1)
            .ok_or("checkpoint id space is exhausted")?,
        used,
        entries,
    })
}

fn validate_entries(state: &StateDir, item: &Path, id: u64) -> Result<(), String> {
    let directory = state
        .existing_directory(item)?
        .ok_or_else(|| format!("checkpoint {id}: directory disappeared"))?;
    for entry in std::fs::read_dir(&directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| format!("{}: {error}", directory.display()))?;
        let kind = entry
            .file_type()
            .map_err(|error| format!("{}: {error}", entry.path().display()))?;
        if entry.file_name() != "metadata.json" || !kind.is_file() {
            return Err(format!(
                "checkpoint {id}: unexpected or unsafe entry {}",
                entry.path().display()
            ));
        }
    }
    Ok(())
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
