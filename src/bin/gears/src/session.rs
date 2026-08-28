//! Versioned append-only session trees.

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::provider::{Message, Role, Usage, UsageMeter};
use crate::state::StateRoot;

const VERSION: u32 = 1;
static NEXT_FILE: AtomicU32 = AtomicU32::new(0);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Header {
    #[serde(rename = "type")]
    kind: String,
    pub version: u32,
    pub id: String,
    pub created_ms: u64,
    pub workspace: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_session: Option<PathBuf>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Entry {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    pub parent_id: Option<String>,
    pub timestamp_ms: u64,
    #[serde(default)]
    pub data: Value,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Compaction {
    pub summary: String,
    pub retained_tail: Vec<Message>,
    pub tokens_before: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RuntimeIdentity {
    pub prompt_hash: String,
    pub manifest_hash: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HookState {
    pub hook: String,
    pub state: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Message>,
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub id: String,
    pub path: PathBuf,
    pub name: Option<String>,
    pub created_ms: u64,
    pub modified_ms: u64,
    pub messages: usize,
}

#[derive(Debug, Clone)]
pub struct TreeItem {
    pub id: String,
    pub parent_id: Option<String>,
    pub kind: String,
    pub summary: String,
    pub active: bool,
    pub user_message: bool,
}

#[derive(Debug, Clone)]
pub struct Store {
    state: StateRoot,
    workspace: PathBuf,
    group: PathBuf,
}

impl Store {
    pub fn new(workspace: &Path) -> Result<Self, String> {
        Self::with_root(workspace, default_root()?)
    }

    pub fn with_root(workspace: &Path, root: PathBuf) -> Result<Self, String> {
        let workspace = workspace
            .canonicalize()
            .map_err(|error| format!("workspace {}: {error}", workspace.display()))?;
        if !workspace.is_dir() {
            return Err(format!(
                "workspace {} is not a directory",
                workspace.display()
            ));
        }
        let group = PathBuf::from(workspace_key(&workspace));
        Ok(Self {
            state: StateRoot::new(root)?,
            workspace,
            group,
        })
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub fn create(&self, ephemeral: bool, name: Option<&str>) -> Result<Session, String> {
        self.create_from(ephemeral, name, None, &[])
    }

    pub fn continue_recent(&self) -> Result<Session, String> {
        let info = self
            .list()?
            .into_iter()
            .max_by_key(|item| item.modified_ms)
            .ok_or("no saved session for this workspace")?;
        self.open_path(&info.path)
    }

    pub fn open(&self, selector: &str) -> Result<Session, String> {
        let candidate = PathBuf::from(selector);
        if candidate.exists() || candidate.components().count() > 1 {
            return self.open_path(&candidate);
        }
        let matches = self
            .list()?
            .into_iter()
            .filter(|item| item.id == selector || item.id.starts_with(selector))
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [] => Err(format!("no session matches {selector:?}")),
            [info] => self.open_path(&info.path),
            _ => Err(format!("session id {selector:?} is ambiguous")),
        }
    }

    pub fn open_path(&self, path: &Path) -> Result<Session, String> {
        let path = path
            .canonicalize()
            .map_err(|error| format!("session {}: {error}", path.display()))?;
        let parsed = read_session(&path)?;
        if parsed.header.workspace != self.workspace {
            return Err(format!(
                "session {} belongs to workspace {}",
                path.display(),
                parsed.header.workspace.display()
            ));
        }
        Session::saved(path, parsed)
    }

    pub fn list(&self) -> Result<Vec<SessionInfo>, String> {
        let relative = self.group.clone();
        let Some(directory) = self.state.existing_directory(&relative)? else {
            return Ok(Vec::new());
        };
        let mut result = Vec::new();
        for entry in std::fs::read_dir(&directory)
            .map_err(|error| format!("{}: {error}", directory.display()))?
        {
            let entry = entry.map_err(|error| format!("{}: {error}", directory.display()))?;
            let path = entry.path();
            if path.extension().and_then(|part| part.to_str()) != Some("jsonl") {
                continue;
            }
            let metadata = entry
                .metadata()
                .map_err(|error| format!("{}: {error}", path.display()))?;
            if !metadata.is_file() {
                continue;
            }
            let parsed = read_session(&path)?;
            let name = parsed
                .entries
                .iter()
                .rev()
                .find(|entry| entry.kind == "session_name")
                .and_then(|entry| entry.data.get("name"))
                .and_then(Value::as_str)
                .map(str::to_string);
            let modified_ms = metadata
                .modified()
                .ok()
                .map(system_ms)
                .unwrap_or(parsed.header.created_ms);
            result.push(SessionInfo {
                id: parsed.header.id,
                path,
                name,
                created_ms: parsed.header.created_ms,
                modified_ms,
                messages: parsed
                    .entries
                    .iter()
                    .filter(|entry| entry.kind == "message")
                    .count(),
            });
        }
        result.sort_by_key(|item| std::cmp::Reverse(item.modified_ms));
        Ok(result)
    }

    pub fn clone_active(&self, source: &Session) -> Result<Session, String> {
        let records = source.active_entries()?;
        self.create_from(false, source.name().as_deref(), source.path(), &records)
    }

    pub fn fork_at_user(
        &self,
        source: &Session,
        entry_id: &str,
    ) -> Result<(Session, String), String> {
        let entry = source
            .entry(entry_id)
            .ok_or_else(|| format!("no entry {entry_id:?}"))?;
        if entry.kind != "message" {
            return Err("fork must select a user message".to_string());
        }
        let message: Message = serde_json::from_value(entry.data.clone())
            .map_err(|error| format!("bad message entry: {error}"))?;
        if message.role != Role::User {
            return Err("fork must select a user message".to_string());
        }
        let draft = message.text_content();
        let records = source.path_to(entry.parent_id.as_deref())?;
        let session = self.create_from(false, source.name().as_deref(), source.path(), &records)?;
        Ok((session, draft))
    }

    fn create_from(
        &self,
        ephemeral: bool,
        name: Option<&str>,
        parent: Option<&Path>,
        records: &[Entry],
    ) -> Result<Session, String> {
        let created_ms = now_ms();
        let id = new_session_id(created_ms);
        let header = Header {
            kind: "session".to_string(),
            version: VERSION,
            id: id.clone(),
            created_ms,
            workspace: self.workspace.clone(),
            parent_session: parent.map(Path::to_path_buf),
        };
        let mut session = if ephemeral {
            Session::ephemeral(header, records.to_vec())?
        } else {
            let directory = self.state.directory(&self.group)?;
            let (path, file) = create_session_file(&directory, &id)?;
            Session::new_saved(path, file, header, records.to_vec())?
        };
        if let Some(name) = name.filter(|name| !name.trim().is_empty()) {
            session.set_name(name)?;
        }
        Ok(session)
    }
}

pub struct Session {
    header: Header,
    entries: Vec<Entry>,
    active_leaf: Option<String>,
    next_entry: u64,
    path: Option<PathBuf>,
    writer: Option<File>,
    lock: Option<PathBuf>,
}

impl Session {
    fn new_saved(
        path: PathBuf,
        mut file: File,
        header: Header,
        entries: Vec<Entry>,
    ) -> Result<Self, String> {
        write_line(&mut file, &header)?;
        for entry in &entries {
            write_line(&mut file, entry)?;
        }
        file.sync_data()
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let lock = acquire_lock(&path)?;
        Self::from_parts(header, entries, Some(path), Some(file), Some(lock))
    }

    fn saved(path: PathBuf, parsed: Parsed) -> Result<Self, String> {
        let lock = acquire_lock(&path)?;
        let writer = OpenOptions::new()
            .append(true)
            .open(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        Self::from_parts(
            parsed.header,
            parsed.entries,
            Some(path),
            Some(writer),
            Some(lock),
        )
    }

    fn ephemeral(header: Header, entries: Vec<Entry>) -> Result<Self, String> {
        Self::from_parts(header, entries, None, None, None)
    }

    fn from_parts(
        header: Header,
        entries: Vec<Entry>,
        path: Option<PathBuf>,
        writer: Option<File>,
        lock: Option<PathBuf>,
    ) -> Result<Self, String> {
        validate_entries(&entries)?;
        let active_leaf = entries.last().map(|entry| entry.id.clone());
        let next_entry = entries
            .iter()
            .filter_map(|entry| entry.id.strip_prefix('e'))
            .filter_map(|id| u64::from_str_radix(id, 16).ok())
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        Ok(Self {
            header,
            entries,
            active_leaf,
            next_entry,
            path,
            writer,
            lock,
        })
    }

    pub fn id(&self) -> &str {
        &self.header.id
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn workspace(&self) -> &Path {
        &self.header.workspace
    }

    pub fn is_ephemeral(&self) -> bool {
        self.path.is_none()
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn entry(&self, id: &str) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.id == id)
    }

    pub fn active_leaf(&self) -> Option<&str> {
        self.active_leaf.as_deref()
    }

    pub fn append<T: Serialize>(&mut self, kind: &str, data: &T) -> Result<String, String> {
        let data = serde_json::to_value(data)
            .map_err(|error| format!("cannot serialize session entry: {error}"))?;
        let id = format!("e{:016x}", self.next_entry);
        self.next_entry = self.next_entry.saturating_add(1);
        let entry = Entry {
            kind: kind.to_string(),
            id: id.clone(),
            parent_id: self.active_leaf.clone(),
            timestamp_ms: now_ms(),
            data,
        };
        if let Some(writer) = &mut self.writer {
            write_line(writer, &entry)?;
            writer
                .sync_data()
                .map_err(|error| format!("session flush: {error}"))?;
        }
        self.active_leaf = Some(id.clone());
        self.entries.push(entry);
        Ok(id)
    }

    pub fn append_message(&mut self, message: &Message) -> Result<String, String> {
        self.append("message", message)
    }

    pub fn append_error(&mut self, detail: &str, cancelled: bool) -> Result<String, String> {
        self.append(
            "turn_error",
            &serde_json::json!({"detail": detail, "cancelled": cancelled}),
        )
    }

    pub fn append_usage(&mut self, usage: &Usage) -> Result<String, String> {
        self.append("usage", usage)
    }

    pub fn usage(&self) -> UsageMeter {
        let mut meter = UsageMeter::new();
        if let Ok(entries) = self.active_entries() {
            for entry in entries.into_iter().filter(|entry| entry.kind == "usage") {
                if let Ok(usage) = serde_json::from_value(entry.data) {
                    meter.add(&usage);
                }
            }
        }
        meter
    }

    pub fn set_model(&mut self, model: &str) -> Result<String, String> {
        self.append("model_change", &serde_json::json!({"model": model}))
    }

    pub fn model(&self) -> Option<String> {
        self.active_entries()
            .ok()?
            .iter()
            .rev()
            .find(|entry| entry.kind == "model_change")
            .and_then(|entry| entry.data.get("model"))
            .and_then(Value::as_str)
            .map(str::to_string)
    }

    pub fn set_name(&mut self, name: &str) -> Result<String, String> {
        let name = name.trim();
        if name.is_empty() {
            return Err("session name must not be empty".to_string());
        }
        self.append("session_name", &serde_json::json!({"name": name}))
    }

    pub fn name(&self) -> Option<String> {
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.kind == "session_name")
            .and_then(|entry| entry.data.get("name"))
            .and_then(Value::as_str)
            .map(str::to_string)
    }

    pub fn append_compaction(&mut self, compaction: &Compaction) -> Result<String, String> {
        self.append("compaction", compaction)
    }

    pub fn append_hook_state(&mut self, state: &HookState) -> Result<String, String> {
        self.append("hook_state", state)
    }

    pub fn append_runtime_identity(
        &mut self,
        identity: &RuntimeIdentity,
    ) -> Result<String, String> {
        self.append("runtime_identity", identity)
    }

    pub fn latest_runtime_identity(&self) -> Option<RuntimeIdentity> {
        self.active_entries()
            .ok()?
            .iter()
            .rev()
            .find(|entry| entry.kind == "runtime_identity")
            .and_then(|entry| serde_json::from_value(entry.data.clone()).ok())
    }

    pub fn hook_state(&self, hook: &str) -> Option<Value> {
        self.active_entries()
            .ok()?
            .iter()
            .rev()
            .filter(|entry| entry.kind == "hook_state")
            .filter_map(|entry| serde_json::from_value::<HookState>(entry.data.clone()).ok())
            .find(|state| state.hook == hook)
            .map(|state| state.state)
    }

    pub fn context_messages(&self) -> Result<Vec<Message>, String> {
        let mut messages = Vec::new();
        for entry in self.active_entries()? {
            match entry.kind.as_str() {
                "message" => {
                    let message = serde_json::from_value(entry.data)
                        .map_err(|error| format!("entry {}: bad message: {error}", entry.id))?;
                    messages.push(message);
                }
                "compaction" => {
                    let compact: Compaction = serde_json::from_value(entry.data)
                        .map_err(|error| format!("entry {}: bad compaction: {error}", entry.id))?;
                    messages.clear();
                    messages.push(Message::user(format!(
                        "[Conversation summary]\n{}",
                        compact.summary
                    )));
                    messages.extend(compact.retained_tail);
                }
                "hook_state" => {
                    let state: HookState = serde_json::from_value(entry.data)
                        .map_err(|error| format!("entry {}: bad hook state: {error}", entry.id))?;
                    if let Some(context) = state.context {
                        messages.push(context);
                    }
                }
                _ => {}
            }
        }
        Ok(messages)
    }

    pub fn active_entries(&self) -> Result<Vec<Entry>, String> {
        self.path_to(self.active_leaf())
    }

    fn path_to(&self, leaf: Option<&str>) -> Result<Vec<Entry>, String> {
        let by_id = self
            .entries
            .iter()
            .map(|entry| (entry.id.as_str(), entry))
            .collect::<HashMap<_, _>>();
        let mut path = Vec::new();
        let mut cursor = leaf;
        while let Some(id) = cursor {
            let entry = by_id
                .get(id)
                .ok_or_else(|| format!("entry {id:?} does not exist"))?;
            path.push((*entry).clone());
            cursor = entry.parent_id.as_deref();
        }
        path.reverse();
        Ok(path)
    }

    pub fn select(&mut self, id: &str) -> Result<Option<String>, String> {
        let entry = self
            .entry(id)
            .ok_or_else(|| format!("no entry {id:?}"))?
            .clone();
        if entry.kind == "message" {
            let message: Message = serde_json::from_value(entry.data)
                .map_err(|error| format!("entry {id}: bad message: {error}"))?;
            if message.role == Role::User {
                self.active_leaf = entry.parent_id;
                return Ok(Some(message.text_content()));
            }
        }
        self.active_leaf = Some(entry.id);
        Ok(None)
    }

    pub fn tree(&self) -> Vec<TreeItem> {
        let mut labels = HashMap::new();
        for entry in self.entries.iter().filter(|entry| entry.kind == "label") {
            let Some(target) = entry.data.get("target").and_then(Value::as_str) else {
                continue;
            };
            match entry.data.get("label").and_then(Value::as_str) {
                Some(label) => {
                    labels.insert(target, label);
                }
                None => {
                    labels.remove(target);
                }
            }
        }
        self.entries
            .iter()
            .map(|entry| {
                let mut summary = entry_summary(entry);
                if let Some(label) = labels.get(entry.id.as_str()) {
                    summary = format!("[{label}] {summary}");
                }
                TreeItem {
                    id: entry.id.clone(),
                    parent_id: entry.parent_id.clone(),
                    kind: entry.kind.clone(),
                    summary,
                    active: self.active_leaf.as_deref() == Some(entry.id.as_str()),
                    user_message: entry.kind == "message"
                        && serde_json::from_value::<Message>(entry.data.clone())
                            .is_ok_and(|message| message.role == Role::User),
                }
            })
            .collect()
    }

    pub fn set_label(&mut self, target: &str, label: Option<&str>) -> Result<String, String> {
        if self.entry(target).is_none() {
            return Err(format!("no entry {target:?}"));
        }
        self.append(
            "label",
            &serde_json::json!({
                "target": target,
                "label": label.map(str::trim).filter(|label| !label.is_empty())
            }),
        )
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.writer.take();
        if let Some(lock) = self.lock.take() {
            let _ = std::fs::remove_file(lock);
        }
    }
}

struct Parsed {
    header: Header,
    entries: Vec<Entry>,
}

fn read_session(path: &Path) -> Result<Parsed, String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!("session {} is not a regular file", path.display()));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let mut lines = bytes.split(|byte| *byte == b'\n').collect::<Vec<_>>();
    // A trailing newline contributes an empty slice; without one, the last
    // slice is the only record that may have been interrupted by a crash.
    lines.pop();
    let Some(first) = lines.first() else {
        return Err(format!("session {} has no complete header", path.display()));
    };
    let header: Header = serde_json::from_slice(first)
        .map_err(|error| format!("{}: bad header: {error}", path.display()))?;
    if header.kind != "session" || header.version != VERSION {
        return Err(format!(
            "{}: unsupported session header or version",
            path.display()
        ));
    }
    let mut entries = Vec::new();
    for (index, line) in lines.into_iter().enumerate().skip(1) {
        if line.is_empty() {
            return Err(format!(
                "{}:{}: empty JSONL record",
                path.display(),
                index + 1
            ));
        }
        let entry = serde_json::from_slice(line)
            .map_err(|error| format!("{}:{}: {error}", path.display(), index + 1))?;
        entries.push(entry);
    }
    validate_entries(&entries)?;
    Ok(Parsed { header, entries })
}

fn validate_entries(entries: &[Entry]) -> Result<(), String> {
    let mut ids = HashSet::new();
    for entry in entries {
        if entry.id.is_empty() || !ids.insert(entry.id.clone()) {
            return Err(format!(
                "duplicate or empty session entry id {:?}",
                entry.id
            ));
        }
        if let Some(parent) = &entry.parent_id
            && !ids.contains(parent)
        {
            return Err(format!(
                "session entry {} names missing or later parent {}",
                entry.id, parent
            ));
        }
    }
    Ok(())
}

fn create_session_file(directory: &Path, id: &str) -> Result<(PathBuf, File), String> {
    for suffix in 0..1000_u32 {
        let name = if suffix == 0 {
            format!("{id}.jsonl")
        } else {
            format!("{id}-{suffix}.jsonl")
        };
        let path = directory.join(name);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("{}: {error}", path.display())),
        }
    }
    Err("could not allocate a unique session filename".to_string())
}

fn acquire_lock(path: &Path) -> Result<PathBuf, String> {
    let lock = path.with_extension("jsonl.lock");
    for attempt in 0..2 {
        match OpenOptions::new().write(true).create_new(true).open(&lock) {
            Ok(mut file) => {
                writeln!(file, "{}", std::process::id())
                    .map_err(|error| format!("{}: {error}", lock.display()))?;
                file.sync_data()
                    .map_err(|error| format!("{}: {error}", lock.display()))?;
                return Ok(lock);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && attempt == 0 => {
                let metadata = std::fs::symlink_metadata(&lock)
                    .map_err(|error| format!("{}: {error}", lock.display()))?;
                if !metadata.file_type().is_file() {
                    return Err(format!("unsafe session lock {}", lock.display()));
                }
                let owner = std::fs::read_to_string(&lock)
                    .ok()
                    .and_then(|text| text.trim().parse::<u32>().ok());
                if owner.is_some_and(crate::platform::process_alive) {
                    return Err(format!(
                        "session is already open by process {}",
                        owner.unwrap()
                    ));
                }
                std::fs::remove_file(&lock).map_err(|error| {
                    format!("cannot remove stale lock {}: {error}", lock.display())
                })?;
            }
            Err(error) => return Err(format!("cannot lock {}: {error}", path.display())),
        }
    }
    Err(format!("cannot lock {}", path.display()))
}

fn write_line(writer: &mut File, value: &impl Serialize) -> Result<(), String> {
    serde_json::to_writer(&mut *writer, value)
        .map_err(|error| format!("cannot serialize session record: {error}"))?;
    writer
        .write_all(b"\n")
        .map_err(|error| format!("cannot write session record: {error}"))?;
    writer
        .flush()
        .map_err(|error| format!("cannot flush session record: {error}"))
}

fn entry_summary(entry: &Entry) -> String {
    match entry.kind.as_str() {
        "message" => serde_json::from_value::<Message>(entry.data.clone())
            .map(|message| clipped(&message.text_content(), 80))
            .unwrap_or_else(|_| "invalid message".to_string()),
        "session_name" => entry
            .data
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        other => other.replace('_', " "),
    }
}

fn clipped(text: &str, limit: usize) -> String {
    match text.char_indices().nth(limit) {
        None => text.to_string(),
        Some((at, _)) => format!("{}…", &text[..at]),
    }
}

fn default_root() -> Result<PathBuf, String> {
    #[cfg(target_os = "motor")]
    {
        Ok(PathBuf::from("/user/cfg/gears/sessions"))
    }
    #[cfg(all(unix, not(target_os = "motor")))]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join(".gears/sessions"))
            .ok_or("HOME is not set; cannot locate Gears sessions".to_string())
    }
    #[cfg(not(any(target_os = "motor", unix)))]
    {
        Err("this platform has no Gears session root".to_string())
    }
}

fn workspace_key(workspace: &Path) -> String {
    let name = workspace
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("workspace")
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '-'
            }
        })
        .take(40)
        .collect::<String>();
    let digest = Sha256::digest(workspace.as_os_str().as_encoded_bytes());
    format!("{name}-{}", hex(&digest[..12]))
}

fn new_session_id(created_ms: u64) -> String {
    let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
    format!(
        "{created_ms:016x}-{:08x}-{sequence:08x}",
        std::process::id()
    )
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn now_ms() -> u64 {
    system_ms(SystemTime::now())
}

fn system_ms(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> (PathBuf, PathBuf, Store) {
        let base =
            std::env::temp_dir().join(format!("gears-session-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let workspace = base.join("workspace");
        let state = base.join("state");
        std::fs::create_dir_all(&workspace).unwrap();
        let store = Store::with_root(&workspace, state.clone()).unwrap();
        (base, state, store)
    }

    #[test]
    fn branching_preserves_both_paths() {
        let (base, _, store) = fixture("branch");
        let mut session = store.create(false, None).unwrap();
        let first = session.append_message(&Message::user("one")).unwrap();
        let answer = session
            .append_message(&Message::assistant("answer"))
            .unwrap();
        let draft = session.select(&first).unwrap().unwrap();
        let new_user = session.append_message(&Message::user(draft)).unwrap();
        let branch = session
            .append_message(&Message::assistant("other"))
            .unwrap();
        assert_eq!(
            session.entry(&answer).unwrap().parent_id.as_deref(),
            Some(first.as_str())
        );
        assert_eq!(session.entry(&new_user).unwrap().parent_id, None);
        assert_eq!(
            session.entry(&branch).unwrap().parent_id.as_deref(),
            Some(new_user.as_str())
        );
        assert_eq!(
            session.context_messages().unwrap()[1].text_content(),
            "other"
        );
        drop(session);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn a_partial_tail_is_ignored_but_earlier_damage_is_not() {
        let (base, _, store) = fixture("tail");
        let mut session = store.create(false, None).unwrap();
        session.append_message(&Message::user("complete")).unwrap();
        let path = session.path().unwrap().to_path_buf();
        drop(session);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{partial")
            .unwrap();
        let reopened = store.open_path(&path).unwrap();
        assert_eq!(reopened.context_messages().unwrap().len(), 1);
        drop(reopened);
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines = text.lines().map(str::to_string).collect::<Vec<_>>();
        lines[1] = "{broken}".to_string();
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        assert!(store.open_path(&path).is_err());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn clone_keeps_only_the_active_branch() {
        let (base, _, store) = fixture("clone");
        let mut source = store.create(false, Some("named")).unwrap();
        let user = source.append_message(&Message::user("question")).unwrap();
        source.append_message(&Message::assistant("first")).unwrap();
        let draft = source.select(&user).unwrap().unwrap();
        source.append_message(&Message::user(draft)).unwrap();
        source
            .append_message(&Message::assistant("second"))
            .unwrap();
        let cloned = store.clone_active(&source).unwrap();
        assert_eq!(cloned.context_messages().unwrap().len(), 2);
        assert_eq!(cloned.name().as_deref(), Some("named"));
        drop(cloned);
        drop(source);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn fork_uses_the_parent_path_and_returns_the_selected_prompt() {
        let (base, _, store) = fixture("fork");
        let mut source = store.create(false, None).unwrap();
        source.append_message(&Message::user("first")).unwrap();
        source
            .append_message(&Message::assistant("answer"))
            .unwrap();
        let selected = source.append_message(&Message::user("edit me")).unwrap();
        source
            .append_message(&Message::assistant("discarded"))
            .unwrap();
        let (forked, draft) = store.fork_at_user(&source, &selected).unwrap();
        assert_eq!(draft, "edit me");
        assert_eq!(forked.context_messages().unwrap().len(), 2);
        assert_eq!(forked.header.parent_session.as_deref(), source.path());
        drop(forked);
        drop(source);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn resume_restores_messages_model_usage_and_labels() {
        let (base, _, store) = fixture("resume");
        let mut session = store.create(false, None).unwrap();
        let message = session.append_message(&Message::user("saved")).unwrap();
        session.set_model("test/model").unwrap();
        session
            .append_usage(&Usage {
                prompt_tokens: 12,
                completion_tokens: 3,
                ..Usage::default()
            })
            .unwrap();
        session.set_label(&message, Some("important")).unwrap();
        let id = session.id().to_string();
        drop(session);

        let reopened = store.open(&id).unwrap();
        assert_eq!(
            reopened.context_messages().unwrap()[0].text_content(),
            "saved"
        );
        assert_eq!(reopened.model().as_deref(), Some("test/model"));
        assert_eq!(reopened.usage().total_tokens(), 15);
        assert!(
            reopened
                .tree()
                .iter()
                .find(|item| item.id == message)
                .unwrap()
                .summary
                .starts_with("[important]")
        );
        drop(reopened);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn a_second_writer_is_rejected() {
        let (base, _, store) = fixture("lock");
        let session = store.create(false, None).unwrap();
        let path = session.path().unwrap().to_path_buf();
        assert!(store.open_path(&path).is_err());
        drop(session);
        assert!(store.open_path(&path).is_ok());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn workspaces_have_separate_groups() {
        let base =
            std::env::temp_dir().join(format!("gears-session-groups-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let one = base.join("one");
        let two = base.join("two");
        std::fs::create_dir_all(&one).unwrap();
        std::fs::create_dir_all(&two).unwrap();
        let root = base.join("state");
        let first = Store::with_root(&one, root.clone()).unwrap();
        let second = Store::with_root(&two, root).unwrap();
        let session = first.create(false, None).unwrap();
        assert_eq!(first.list().unwrap().len(), 1);
        assert!(second.list().unwrap().is_empty());
        drop(session);
        std::fs::remove_dir_all(base).unwrap();
    }
}
