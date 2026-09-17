use axum::body::Bytes;
use http::HeaderMap;
use std::collections::{HashMap, VecDeque};
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

pub struct CacheStore {
    files: HashMap<String, Arc<CachedFile>>,
    order: VecDeque<String>,
    used: usize,
    budget: usize,
}

impl CacheStore {
    pub fn new(budget: usize) -> Self {
        Self {
            files: HashMap::new(),
            order: VecDeque::new(),
            used: 0,
            budget,
        }
    }

    pub fn get(&mut self, path: &str, now: Instant) -> Option<Arc<CachedFile>> {
        let file = self.files.get(path)?;
        if now < file.expires {
            return Some(file.clone());
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
            .is_some_and(|old| old.expires >= file.expires)
        {
            return;
        }
        self.remove(&path);
        while self.used > self.budget - charge || self.files.len() >= MAX_ENTRIES {
            let oldest = self.order.front().unwrap().clone();
            self.remove(&oldest);
        }
        self.used += charge;
        self.order.push_back(path.clone());
        self.files.insert(path, Arc::new(file));
    }

    fn remove(&mut self, path: &str) {
        if let Some(file) = self.files.remove(path) {
            self.used -= file.charge(path);
            self.order.retain(|key| key != path);
        }
    }
}
