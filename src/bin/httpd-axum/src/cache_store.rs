use axum::body::Bytes;
use http::HeaderMap;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Instant;

pub const MAX_FILE_SIZE: usize = 256 * 1024;
const MAX_ENTRIES: usize = 1024;

pub struct CachedFile {
    pub headers: HeaderMap,
    pub body: Bytes,
    pub loaded: Instant,
    pub expires: Instant,
}

impl CachedFile {
    fn charge(&self, path: &str) -> usize {
        // Include both copies of the key, header data, and a per-entry allowance.
        // In-flight responses may retain shared bytes after eviction.
        self.body.len()
            + 2 * path.len()
            + 512
            + self
                .headers
                .iter()
                .map(|(k, v)| k.as_str().len() + v.len())
                .sum::<usize>()
    }
}

struct Entry {
    file: Arc<CachedFile>,
    charge: usize,
    sequence: u64,
}

pub struct CacheStore {
    files: HashMap<String, Entry>,
    order: BTreeMap<u64, String>,
    sequence: u64,
    used: usize,
    budget: usize,
}

impl CacheStore {
    pub fn new(budget: usize) -> Self {
        Self {
            files: HashMap::new(),
            order: BTreeMap::new(),
            sequence: 0,
            used: 0,
            budget,
        }
    }

    pub fn get(&mut self, path: &str, now: Instant) -> Option<Arc<CachedFile>> {
        let entry = self.files.get(path)?;
        if now < entry.file.expires {
            return Some(entry.file.clone());
        }
        self.remove(path);
        None
    }

    pub fn insert(&mut self, path: String, file: CachedFile, now: Instant) {
        let charge = file.charge(&path);
        if file.body.len() > MAX_FILE_SIZE || charge > self.budget || now >= file.expires {
            return;
        }
        // A slow earlier fill must not overwrite a newer representation or
        // extend its freshness. Deadlines are measured from before filesystem I/O.
        if self
            .files
            .get(&path)
            .is_some_and(|old| old.file.expires >= file.expires)
        {
            return;
        }
        let Some(sequence) = self.sequence.checked_add(1) else {
            return;
        };
        self.remove(&path);
        while self.used > self.budget - charge || self.files.len() >= MAX_ENTRIES {
            let (_, oldest) = self.order.pop_first().unwrap();
            self.used -= self.files.remove(&oldest).unwrap().charge;
        }
        self.used += charge;
        self.sequence = sequence;
        self.order.insert(sequence, path.clone());
        self.files.insert(
            path,
            Entry {
                file: Arc::new(file),
                charge,
                sequence,
            },
        );
    }

    fn remove(&mut self, path: &str) {
        if let Some(entry) = self.files.remove(path) {
            self.used -= entry.charge;
            // Keep exactly one index node per entry; no queue scan or retained
            // tombstones on replacement, expiry, or cascaded eviction.
            self.order.remove(&entry.sequence);
        }
    }
}
