//! Durable, session-owned large results.
//!
//! An artifact becomes visible by renaming one complete directory into place.
//! A failed write leaves its `.new-ID` directory for an operator to inspect;
//! opening the store reports it rather than deleting evidence silently.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::state::StateDir;

const VERSION: u32 = 1;
const ARTIFACTS: &str = "artifacts/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Origin {
    pub producer: String,
    pub reference: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    pub version: u32,
    pub id: u64,
    #[serde(rename = "type")]
    pub artifact_type: String,
    /// Content bytes, excluding the metadata sidecar.
    pub size: u64,
    pub origin: Origin,
    pub created_unix_seconds: u64,
}

struct Catalog {
    used: usize,
    entries: BTreeMap<u64, Metadata>,
}

pub struct Store {
    state: StateDir,
    relative: PathBuf,
    catalog: Mutex<Catalog>,
}

impl Store {
    pub fn open(
        workspace: &Path,
        session: &str,
        max_artifact_bytes: usize,
        max_session_bytes: usize,
    ) -> Result<Store, String> {
        super::session::validate_id(session)?;
        if max_artifact_bytes == 0
            || max_session_bytes == 0
            || max_artifact_bytes > max_session_bytes
        {
            return Err("invalid artifact limits".to_string());
        }
        let state = StateDir::new(workspace)?;
        let relative = Path::new(ARTIFACTS).join(session);
        let catalog = scan(&state, &relative, max_artifact_bytes, max_session_bytes)?;
        Ok(Store {
            state,
            relative,
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

    pub fn used_bytes(&self) -> usize {
        self.catalog.lock().unwrap().used
    }

    pub fn read(&self, id: u64) -> Result<Vec<u8>, String> {
        let catalog = self.catalog.lock().unwrap();
        let metadata = catalog
            .entries
            .get(&id)
            .ok_or_else(|| format!("there is no artifact {id}"))?;
        let relative = self.relative.join(id.to_string()).join("content");
        let path = self
            .state
            .existing_file(&relative)?
            .ok_or_else(|| format!("artifact {id}: content is missing"))?;
        let content =
            std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        if content.len() as u64 != metadata.size {
            return Err(format!("artifact {id}: content size changed on disk"));
        }
        Ok(content)
    }
}

fn scan(
    state: &StateDir,
    relative: &Path,
    max_artifact_bytes: usize,
    max_session_bytes: usize,
) -> Result<Catalog, String> {
    let Some(dir) = state.existing_directory(relative)? else {
        return Ok(Catalog {
            used: 0,
            entries: BTreeMap::new(),
        });
    };
    let mut entries = BTreeMap::new();
    let mut used = 0usize;
    for entry in std::fs::read_dir(&dir).map_err(|error| format!("{}: {error}", dir.display()))? {
        let entry = entry.map_err(|error| format!("{}: {error}", dir.display()))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("{}: artifact entry name is not UTF-8", dir.display()))?;
        if let Some(id) = name.strip_prefix(".new-").and_then(canonical_id) {
            if !entry
                .file_type()
                .map_err(|error| format!("{}: {error}", entry.path().display()))?
                .is_dir()
            {
                return Err(format!(
                    "{}: incomplete artifact must be a real directory",
                    entry.path().display()
                ));
            }
            let bytes = directory_stats(&entry.path())?.0;
            return Err(format!(
                "incomplete artifact {id} has {bytes} bytes that count toward the session quota"
            ));
        }
        let id = canonical_id(&name)
            .ok_or_else(|| format!("{}: unexpected artifact entry {name:?}", dir.display()))?;
        let item = relative.join(&name);
        let item_dir = state
            .existing_directory(&item)?
            .ok_or_else(|| format!("artifact {id}: directory disappeared"))?;
        let (bytes, files) = directory_stats(&item_dir)?;
        used = used.checked_add(bytes).ok_or("artifact quota overflow")?;
        if used > max_session_bytes {
            return Err(format!(
                "existing session artifacts use {used} bytes; limit is {max_session_bytes}"
            ));
        }
        let metadata_path = state
            .existing_file(&item.join("metadata.json"))?
            .ok_or_else(|| format!("artifact {id}: metadata is missing"))?;
        let content_path = state
            .existing_file(&item.join("content"))?
            .ok_or_else(|| format!("artifact {id}: content is missing"))?;
        let metadata: Metadata = serde_json::from_slice(
            &std::fs::read(&metadata_path)
                .map_err(|error| format!("{}: {error}", metadata_path.display()))?,
        )
        .map_err(|error| format!("artifact {id}: bad metadata: {error}"))?;
        let size = std::fs::metadata(&content_path)
            .map_err(|error| format!("{}: {error}", content_path.display()))?
            .len();
        if size > max_artifact_bytes as u64 {
            return Err(format!(
                "artifact {id} has {size} content bytes; limit is {max_artifact_bytes}"
            ));
        }
        if metadata.version != VERSION
            || metadata.id != id
            || metadata.size != size
            || metadata.artifact_type.is_empty()
            || metadata.origin.producer.is_empty()
            || metadata.origin.reference.is_empty()
        {
            return Err(format!(
                "artifact {id}: metadata does not match its content"
            ));
        }
        if files != 2 {
            return Err(format!(
                "artifact {id}: unexpected entries beside its content"
            ));
        }
        entries.insert(id, metadata);
    }
    Ok(Catalog { used, entries })
}

fn canonical_id(name: &str) -> Option<u64> {
    let id = name.parse::<u64>().ok()?;
    (id > 0 && name == id.to_string()).then_some(id)
}

fn directory_stats(path: &Path) -> Result<(usize, usize), String> {
    let mut bytes = 0usize;
    let mut files = 0usize;
    for entry in std::fs::read_dir(path).map_err(|error| format!("{}: {error}", path.display()))? {
        let entry = entry.map_err(|error| format!("{}: {error}", path.display()))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("{}: {error}", entry.path().display()))?;
        if !file_type.is_file() {
            return Err(format!(
                "{}: artifact entries must be regular files",
                entry.path().display()
            ));
        }
        let metadata = entry
            .metadata()
            .map_err(|error| format!("{}: {error}", entry.path().display()))?;
        bytes = bytes
            .checked_add(usize::try_from(metadata.len()).map_err(|_| "artifact is too large")?)
            .ok_or("artifact quota overflow")?;
        files += 1;
    }
    Ok((bytes, files))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn workspace(name: &str) -> PathBuf {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "gears-artifact-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn origin(reference: &str) -> Origin {
        Origin {
            producer: "test".to_string(),
            reference: reference.to_string(),
        }
    }

    fn seed(root: &Path, session: &str, id: u64, content: &[u8]) -> Metadata {
        let metadata = Metadata {
            version: VERSION,
            id,
            artifact_type: "tool_output".to_string(),
            size: content.len() as u64,
            origin: origin("call-1"),
            created_unix_seconds: 123,
        };
        let path = root
            .join(".gears/artifacts/v1")
            .join(session)
            .join(id.to_string());
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("content"), content).unwrap();
        std::fs::write(
            path.join("metadata.json"),
            serde_json::to_vec(&metadata).unwrap(),
        )
        .unwrap();
        metadata
    }

    #[test]
    fn artifacts_are_cataloged_and_read() {
        let root = workspace("resume");
        let first = seed(&root, "17-3", 1, b"answer");

        let error = Store::open(&root, "17-3", 5, 4096).err().unwrap();
        assert!(error.contains("6 content bytes"), "{error}");
        let store = Store::open(&root, "17-3", 1024, 4096).unwrap();
        assert_eq!(store.list(), [first]);
        assert_eq!(store.read(1).unwrap(), b"answer");
        let error = Store::open(&root, "17-3", 6, store.used_bytes() - 1)
            .err()
            .unwrap();
        assert!(error.contains("existing session artifacts"), "{error}");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn incomplete_artifacts_are_reported_and_counted() {
        let root = workspace("incomplete");
        let state = StateDir::new(&root).unwrap();
        let staging = state
            .directory(Path::new("artifacts/v1/17-5/.new-1"))
            .unwrap();
        std::fs::write(staging.join("content"), b"partial").unwrap();
        let error = Store::open(&root, "17-5", 1024, 4096).err().unwrap();
        assert!(error.contains("incomplete artifact 1"), "{error}");
        assert!(error.contains("7 bytes"), "{error}");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn artifact_state_refuses_a_redirected_directory() {
        use std::os::unix::fs::symlink;

        let root = workspace("link");
        let outside = workspace("outside");
        std::fs::create_dir(root.join(".gears")).unwrap();
        symlink(&outside, root.join(".gears/artifacts")).unwrap();
        let error = Store::open(&root, "17-6", 1024, 4096).err().unwrap();
        assert!(error.contains("symlink"), "{error}");
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none());

        std::fs::remove_file(root.join(".gears/artifacts")).unwrap();
        let session = root.join(".gears/artifacts/v1/17-6");
        std::fs::create_dir_all(&session).unwrap();
        symlink(&outside, session.join(".new-1")).unwrap();
        let error = Store::open(&root, "17-6", 1024, 4096).err().unwrap();
        assert!(error.contains("real directory"), "{error}");
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }
}
