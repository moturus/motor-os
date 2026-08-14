//! Durable, session-owned large results.
//!
//! An artifact becomes visible by renaming one complete directory into place.
//! A failed write leaves its `.new-ID` directory for an operator to inspect;
//! opening the store reports it rather than deleting evidence silently.

use std::collections::BTreeMap;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

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

pub struct ContentSlice {
    pub bytes: Vec<u8>,
    pub total_size: u64,
}

struct Catalog {
    next: u64,
    used: usize,
    entries: BTreeMap<u64, Metadata>,
}

pub struct Store {
    state: StateDir,
    relative: PathBuf,
    max_artifact_bytes: usize,
    max_session_bytes: usize,
    catalog: Mutex<Catalog>,
}

/// A session store that performs no state I/O until an artifact is used.
pub struct LazyStore {
    workspace: PathBuf,
    session: String,
    max_artifact_bytes: usize,
    max_session_bytes: usize,
    store: OnceLock<Result<Store, String>>,
}

impl LazyStore {
    pub fn new(
        workspace: PathBuf,
        session: String,
        max_artifact_bytes: usize,
        max_session_bytes: usize,
    ) -> Result<LazyStore, String> {
        super::session::validate_id(&session)?;
        validate_limits(max_artifact_bytes, max_session_bytes)?;
        Ok(LazyStore {
            workspace,
            session,
            max_artifact_bytes,
            max_session_bytes,
            store: OnceLock::new(),
        })
    }

    pub fn get(&self) -> Result<&Store, String> {
        match self.store.get_or_init(|| {
            Store::open(
                &self.workspace,
                &self.session,
                self.max_artifact_bytes,
                self.max_session_bytes,
            )
        }) {
            Ok(store) => Ok(store),
            Err(error) => Err(error.clone()),
        }
    }
}

impl Store {
    pub fn open(
        workspace: &Path,
        session: &str,
        max_artifact_bytes: usize,
        max_session_bytes: usize,
    ) -> Result<Store, String> {
        super::session::validate_id(session)?;
        validate_limits(max_artifact_bytes, max_session_bytes)?;
        let state = StateDir::new(workspace)?;
        let relative = Path::new(ARTIFACTS).join(session);
        let catalog = scan(&state, &relative, max_artifact_bytes, max_session_bytes)?;
        Ok(Store {
            state,
            relative,
            max_artifact_bytes,
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

    pub fn list_after(&self, after: u64, limit: usize) -> (Vec<Metadata>, bool) {
        use std::ops::Bound::{Excluded, Unbounded};

        let catalog = self.catalog.lock().unwrap();
        let mut entries: Vec<Metadata> = catalog
            .entries
            .range((Excluded(after), Unbounded))
            .take(limit.saturating_add(1))
            .map(|(_, metadata)| metadata.clone())
            .collect();
        let more = entries.len() > limit;
        entries.truncate(limit);
        (entries, more)
    }

    pub fn used_bytes(&self) -> usize {
        self.catalog.lock().unwrap().used
    }

    pub fn read(&self, id: u64) -> Result<Vec<u8>, String> {
        let size = self.metadata(id)?.size;
        let length = usize::try_from(size).map_err(|_| format!("artifact {id} is too large"))?;
        Ok(self.read_bytes(id, 0, length)?.bytes)
    }

    pub fn metadata(&self, id: u64) -> Result<Metadata, String> {
        self.catalog
            .lock()
            .unwrap()
            .entries
            .get(&id)
            .cloned()
            .ok_or_else(|| format!("there is no artifact {id}"))
    }

    pub fn read_bytes(&self, id: u64, start: u64, length: usize) -> Result<ContentSlice, String> {
        let (mut file, metadata) = self.open_content(id)?;
        if start > metadata.size {
            return Err(format!(
                "artifact {id}: byte {start} is past its {}-byte end",
                metadata.size
            ));
        }
        let available = usize::try_from(metadata.size - start)
            .map_err(|_| format!("artifact {id} is too large"))?;
        let wanted = length.min(available);
        file.seek(std::io::SeekFrom::Start(start))
            .map_err(|error| format!("artifact {id}: {error}"))?;
        let mut bytes = Vec::with_capacity(wanted);
        file.take(wanted as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("artifact {id}: {error}"))?;
        if bytes.len() != wanted {
            return Err(format!("artifact {id}: content size changed on disk"));
        }
        Ok(ContentSlice {
            bytes,
            total_size: metadata.size,
        })
    }

    pub fn read_lines(
        &self,
        id: u64,
        start: u64,
        count: u64,
        max_bytes: usize,
    ) -> Result<ContentSlice, String> {
        if start == 0 || count == 0 || max_bytes == 0 {
            return Err("line start, count, and byte limit must be positive".to_string());
        }
        let end = start.checked_add(count).ok_or("line range overflow")?;
        let (mut file, metadata) = self.open_content(id)?;
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 8192];
        let mut line = 1u64;
        let mut saw_byte = false;
        let mut ended_with_newline = false;
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|error| format!("artifact {id}: {error}"))?;
            if read == 0 {
                let lines = u64::from(saw_byte) + line - 1 - u64::from(ended_with_newline);
                if start > lines && !(lines == 0 && start == 1) {
                    return Err(format!(
                        "artifact {id}: line {start} is past its {lines}-line end"
                    ));
                }
                break;
            }
            for &byte in &buffer[..read] {
                saw_byte = true;
                ended_with_newline = byte == b'\n';
                if line >= start && line < end {
                    if bytes.len() == max_bytes {
                        return Err(format!(
                            "artifact {id}: requested lines exceed the {max_bytes}-byte read limit; use a byte range"
                        ));
                    }
                    bytes.push(byte);
                }
                if byte == b'\n' {
                    line += 1;
                    if line >= end {
                        return Ok(ContentSlice {
                            bytes,
                            total_size: metadata.size,
                        });
                    }
                }
            }
        }
        Ok(ContentSlice {
            bytes,
            total_size: metadata.size,
        })
    }

    fn open_content(&self, id: u64) -> Result<(std::fs::File, Metadata), String> {
        let metadata = self.metadata(id)?;
        let relative = self.relative.join(id.to_string()).join("content");
        let path = self
            .state
            .existing_file(&relative)?
            .ok_or_else(|| format!("artifact {id}: content is missing"))?;
        let file =
            std::fs::File::open(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        let size = file
            .metadata()
            .map_err(|error| format!("{}: {error}", path.display()))?
            .len();
        if size != metadata.size {
            return Err(format!("artifact {id}: content size changed on disk"));
        }
        Ok((file, metadata))
    }

    pub fn put(
        &self,
        artifact_type: &str,
        origin: Origin,
        content: &[u8],
    ) -> Result<Metadata, String> {
        if artifact_type.is_empty() || origin.producer.is_empty() || origin.reference.is_empty() {
            return Err("artifact type and origin must not be empty".to_string());
        }
        if content.len() > self.max_artifact_bytes {
            return Err(format!(
                "artifact has {} bytes; limit is {}",
                content.len(),
                self.max_artifact_bytes
            ));
        }
        let mut catalog = self.catalog.lock().unwrap();
        let id = catalog.next;
        let next = id.checked_add(1).ok_or("artifact id space is exhausted")?;
        let metadata = Metadata {
            version: VERSION,
            id,
            artifact_type: artifact_type.to_string(),
            size: content.len() as u64,
            origin,
            created_unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or_default(),
        };
        let encoded = serde_json::to_vec(&metadata).map_err(|error| error.to_string())?;
        let added = content
            .len()
            .checked_add(encoded.len())
            .ok_or("artifact size overflow")?;
        let used = catalog
            .used
            .checked_add(added)
            .ok_or("artifact quota overflow")?;
        if used > self.max_session_bytes {
            return Err(format!(
                "session artifacts would use {used} bytes; limit is {}",
                self.max_session_bytes
            ));
        }

        let parent = self.state.directory(&self.relative)?;
        let staging = parent.join(format!(".new-{id}"));
        std::fs::create_dir(&staging).map_err(|error| format!("{}: {error}", staging.display()))?;
        write_new(&staging.join("content"), content)?;
        write_new(&staging.join("metadata.json"), &encoded)?;
        let destination = parent.join(id.to_string());
        match std::fs::symlink_metadata(&destination) {
            Ok(_) => {
                return Err(format!(
                    "{}: artifact already exists",
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

fn validate_limits(max_artifact_bytes: usize, max_session_bytes: usize) -> Result<(), String> {
    if max_artifact_bytes == 0 || max_session_bytes == 0 || max_artifact_bytes > max_session_bytes {
        return Err("invalid artifact limits".to_string());
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
        .and_then(|()| file.flush())
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn scan(
    state: &StateDir,
    relative: &Path,
    max_artifact_bytes: usize,
    max_session_bytes: usize,
) -> Result<Catalog, String> {
    let Some(dir) = state.existing_directory(relative)? else {
        return Ok(Catalog {
            next: 1,
            used: 0,
            entries: BTreeMap::new(),
        });
    };
    let mut entries = BTreeMap::new();
    let mut used = 0usize;
    let mut highest = 0u64;
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
        highest = highest.max(id);
        entries.insert(id, metadata);
    }
    Ok(Catalog {
        next: highest
            .checked_add(1)
            .ok_or("artifact id space is exhausted")?,
        used,
        entries,
    })
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
        assert_eq!(store.list().as_slice(), std::slice::from_ref(&first));
        assert_eq!(store.read(1).unwrap(), b"answer");
        let error = Store::open(&root, "17-3", 6, store.used_bytes() - 1)
            .err()
            .unwrap();
        assert!(error.contains("existing session artifacts"), "{error}");

        let second = store.put("patch", origin("change-1"), b"diff").unwrap();
        assert_eq!(second.id, 2);
        drop(store);
        let store = Store::open(&root, "17-3", 1024, 4096).unwrap();
        assert_eq!(store.list(), [first, second]);
        assert_eq!(store.read(2).unwrap(), b"diff");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn quota_refusal_does_not_publish_a_partial_artifact() {
        let root = workspace("quota");
        let store = Store::open(&root, "17-4", 4, 4096).unwrap();
        assert!(store.put("text", origin("large"), b"12345").is_err());
        assert!(!root.join(".gears").exists());

        store.put("text", origin("first"), b"1234").unwrap();
        let used = store.used_bytes();
        drop(store);
        let store = Store::open(&root, "17-4", 4, used).unwrap();
        let error = store.put("text", origin("second"), b"").unwrap_err();
        assert!(error.contains("session artifacts"), "{error}");
        assert_eq!(store.list().len(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn byte_and_line_reads_are_precise_and_bounded() {
        let root = workspace("ranges");
        let content = b"one\n\xfftwo\nthree";
        seed(&root, "17-8", 1, content);
        let store = Store::open(&root, "17-8", 1024, 4096).unwrap();

        let bytes = store.read_bytes(1, 4, 5).unwrap();
        assert_eq!(bytes.bytes, b"\xfftwo\n");
        assert_eq!(bytes.total_size, content.len() as u64);
        assert!(store.read_bytes(1, content.len() as u64 + 1, 1).is_err());
        assert_eq!(store.read_lines(1, 2, 1, 5).unwrap().bytes, b"\xfftwo\n");
        let error = store.read_lines(1, 2, 1, 4).err().unwrap();
        assert!(error.contains("use a byte range"), "{error}");
        assert!(store.read_lines(1, 4, 1, 10).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn lazy_store_defers_catalog_io() {
        let root = workspace("lazy");
        let store = LazyStore::new(root.clone(), "17-9".to_string(), 1024, 4096).unwrap();
        assert!(!root.join(".gears").exists());
        let dir = root.join(".gears/artifacts/v1/17-9");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("unexpected"), b"broken").unwrap();
        let error = store.get().err().unwrap();
        assert!(error.contains("unexpected artifact entry"), "{error}");
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

        let write_root = workspace("write-link");
        let store = Store::open(&write_root, "17-7", 1024, 4096).unwrap();
        let staging = write_root.join(".gears/artifacts/v1/17-7");
        std::fs::create_dir_all(&staging).unwrap();
        symlink(&outside, staging.join(".new-1")).unwrap();
        assert!(store.put("text", origin("call-1"), b"secret").is_err());
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none());
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(write_root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }
}
