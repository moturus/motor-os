//! Versioned append-only session trees.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::provider::{ContentBlock, Message, Role, Usage, UsageMeter};
use crate::state::StateRoot;

const VERSION: u32 = 1;
/// Ephemeral sessions keep shell state here, inside the session store.
const EPHEMERAL_SHELL_STATE: &str = "ephemeral";
/// Every entry kind Gears writes; a session holding any other is refused.
const ENTRY_KINDS: [&str; 12] = [
    "message",
    "turn_error",
    "usage",
    "model_change",
    "provider_change",
    "session_name",
    "compaction",
    "hook_state",
    "tool_state",
    "permission_grant",
    "runtime_identity",
    "label",
];
static NEXT_FILE: AtomicU32 = AtomicU32::new(0);

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolState {
    Enabled,
    Disabled,
    Inherit,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ToolStateEntry {
    pub name: String,
    pub state: ToolState,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct PermissionGrant {
    pub name: String,
    pub identity: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub created_ms: u64,
    /// None revokes an earlier answer for this identity.
    pub allow: Option<bool>,
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
        self.open_path(&self.resolve_selector(selector)?)
    }

    /// Read a live session without taking its writer lock or repairing its file.
    pub fn read(&self, selector: &str) -> Result<Snapshot, String> {
        let snapshot = read_snapshot(&self.resolve_selector(selector)?)?;
        if snapshot.workspace() != self.workspace {
            return Err(format!(
                "session {} belongs to workspace {}",
                snapshot.path().unwrap().display(),
                snapshot.workspace().display()
            ));
        }
        Ok(snapshot)
    }

    fn resolve_selector(&self, selector: &str) -> Result<PathBuf, String> {
        let candidate = PathBuf::from(selector);
        if candidate.exists() || candidate.components().count() > 1 {
            return Ok(candidate);
        }
        let matches = self
            .list()?
            .into_iter()
            .filter(|item| item.id == selector || item.id.starts_with(selector))
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [] => Err(format!("no session matches {selector:?}")),
            [info] => Ok(info.path.clone()),
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
        self.clone_active_with_options(source, false)
    }

    pub fn clone_active_with_options(
        &self,
        source: &Session,
        ephemeral: bool,
    ) -> Result<Session, String> {
        let records = source.active_entries()?;
        self.create_from(ephemeral, source.name().as_deref(), source.path(), &records)
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
        // Grants belong to the source session, not to its conversation path.
        let mut retained = Vec::with_capacity(records.len());
        for record in records
            .iter()
            .filter(|entry| entry.kind != "permission_grant")
        {
            let mut record = record.clone();
            record.parent_id = retained.last().map(|previous: &Entry| previous.id.clone());
            retained.push(record);
        }
        let mut session = if ephemeral {
            Session::ephemeral(header, retained, self.state.clone())?
        } else {
            let directory = self.state.directory(&self.group)?;
            let (path, file) = create_session_file(&directory, &id)?;
            Session::new_saved(path, file, header, retained)?
        };
        if let Some(name) = name.filter(|name| !name.trim().is_empty()) {
            session.set_name(name)?;
        }
        Ok(session)
    }
}

/// An immutable view of the complete, usable prefix of a session file.
/// Later appends do not change this snapshot. It never owns a writer or lock.
pub struct Snapshot(Session);

impl Snapshot {
    /// Read the branch ending at an exact saved entry, without changing its source.
    pub fn at(&self, entry_id: &str) -> Result<Self, String> {
        let entries = self.0.path_to(Some(entry_id))?;
        if incomplete_round_start(&entries)?.is_some() {
            return Err("snapshot entry ends in an unfinished tool round".into());
        }
        Session::from_parts(
            self.0.header.clone(),
            entries,
            self.0.path.clone(),
            None,
            None,
            0,
        )
        .map(Self)
    }
}

impl std::ops::Deref for Snapshot {
    type Target = Session;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Read while another process appends. Partial records and unfinished tool
/// rounds are omitted in memory; the source file is never changed.
/// Every session file under a Gears directory, in each workspace's group
/// directory. Entries that cannot be read safely are reported, not followed.
pub fn discover(
    directory: &Path,
    files: &mut Vec<PathBuf>,
    unavailable: &mut Vec<(PathBuf, String)>,
) -> Result<(), String> {
    let root = directory;
    let sessions = root.join("sessions");
    let mut pending = vec![directory.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            if directory == root && entry.file_name() == "sessions" {
                let kind = entry.file_type().map_err(|error| error.to_string())?;
                if kind.is_symlink() || !kind.is_dir() {
                    unavailable.push((
                        entry.path(),
                        "session directory is not a plain directory".into(),
                    ));
                } else {
                    pending.push(entry.path());
                }
                continue;
            }
            if directory == root || directory == sessions {
                let name = entry.file_name();
                let group = name
                    .to_str()
                    .and_then(|name| name.rsplit_once('-'))
                    .is_some_and(|(_, hash)| {
                        hash.len() == 24 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                    });
                if !group {
                    continue;
                }
            }
            let kind = entry.file_type().map_err(|error| error.to_string())?;
            if kind.is_symlink() {
                unavailable.push((entry.path(), "symbolic link refused".into()));
            } else if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file()
                && entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "jsonl")
            {
                files.push(entry.path());
            }
        }
    }
    Ok(())
}

pub fn read_snapshot(path: &Path) -> Result<Snapshot, String> {
    let path = path
        .canonicalize()
        .map_err(|error| format!("session {}: {error}", path.display()))?;
    let parsed = read_session(&path)?;
    Session::from_parts(
        parsed.header,
        parsed.entries,
        Some(path),
        None,
        None,
        parsed.discarded_entries,
    )
    .map(Snapshot)
}

pub struct Session {
    header: Header,
    entries: Vec<Entry>,
    active_leaf: Option<String>,
    next_entry: u64,
    path: Option<PathBuf>,
    writer: Option<File>,
    lock: Option<PathBuf>,
    recovered_entries: usize,
    /// The session store that holds an ephemeral session's shell state.
    ephemeral_root: Option<StateRoot>,
    ephemeral_shell_state: Option<PathBuf>,
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
        Self::from_parts(header, entries, Some(path), Some(file), Some(lock), 0)
    }

    fn saved(path: PathBuf, parsed: Parsed) -> Result<Self, String> {
        let lock = acquire_lock(&path)?;
        let opened = (|| {
            let writer = OpenOptions::new()
                .append(true)
                .open(&path)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            let size = writer
                .metadata()
                .map_err(|error| format!("{}: {error}", path.display()))?
                .len();
            if size < parsed.valid_len {
                return Err(format!("session {} changed while opening", path.display()));
            }
            if size > parsed.valid_len {
                writer
                    .set_len(parsed.valid_len)
                    .and_then(|()| writer.sync_data())
                    .map_err(|error| {
                        format!("{}: cannot discard partial tail: {error}", path.display())
                    })?;
            }
            Ok(writer)
        })();
        let writer = match opened {
            Ok(writer) => writer,
            Err(error) => {
                let _ = std::fs::remove_file(&lock);
                return Err(error);
            }
        };
        Self::from_parts(
            parsed.header,
            parsed.entries,
            Some(path),
            Some(writer),
            Some(lock),
            parsed.discarded_entries,
        )
    }

    fn ephemeral(header: Header, entries: Vec<Entry>, root: StateRoot) -> Result<Self, String> {
        let mut session = Self::from_parts(header, entries, None, None, None, 0)?;
        session.ephemeral_root = Some(root);
        Ok(session)
    }

    fn from_parts(
        header: Header,
        entries: Vec<Entry>,
        path: Option<PathBuf>,
        writer: Option<File>,
        lock: Option<PathBuf>,
        recovered_entries: usize,
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
            recovered_entries,
            ephemeral_root: None,
            ephemeral_shell_state: None,
        })
    }

    pub fn id(&self) -> &str {
        &self.header.id
    }

    pub fn format_version(&self) -> u32 {
        self.header.version
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

    /// Allocate shell state only when the session first runs `sh`.
    /// The saved shell directory, without creating it during permission checks.
    pub fn shell_state_path(&self) -> Option<PathBuf> {
        self.ephemeral_shell_state.clone().or_else(|| {
            self.path
                .as_ref()
                .map(|path| path.with_extension("sh-state"))
        })
    }

    pub fn shell_state_directory(&mut self) -> Result<PathBuf, String> {
        if let Some(path) = &self.ephemeral_shell_state {
            return Ok(path.clone());
        }
        if let Some(path) = &self.path {
            let directory = path.with_extension("sh-state");
            private_directory(&directory)?;
            return Ok(directory);
        }
        let parent = self
            .ephemeral_root
            .as_ref()
            .ok_or("this session has no shell state location")?
            .directory(Path::new(EPHEMERAL_SHELL_STATE))?;
        for suffix in 0..1000_u32 {
            let directory = parent.join(format!("sh-{}-{suffix}", self.id()));
            match create_private_directory(&directory) {
                Ok(()) => {
                    self.ephemeral_shell_state = Some(directory.clone());
                    return Ok(directory);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(format!("{}: {error}", directory.display())),
            }
        }
        Err("could not allocate an ephemeral shell state directory".to_string())
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn recovered_entries(&self) -> usize {
        self.recovered_entries
    }

    pub fn entry(&self, id: &str) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.id == id)
    }

    pub fn active_leaf(&self) -> Option<&str> {
        self.active_leaf.as_deref()
    }

    fn append<T: Serialize>(&mut self, kind: &str, data: &T) -> Result<String, String> {
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

    pub fn set_provider(&mut self, provider: &str) -> Result<String, String> {
        self.append(
            "provider_change",
            &serde_json::json!({"provider": provider}),
        )
    }

    pub fn provider(&self) -> Option<String> {
        self.active_entries()
            .ok()?
            .iter()
            .rev()
            .find(|entry| entry.kind == "provider_change")
            .and_then(|entry| entry.data.get("provider"))
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

    pub fn set_tool_state(&mut self, name: &str, state: ToolState) -> Result<String, String> {
        self.append(
            "tool_state",
            &ToolStateEntry {
                name: name.to_string(),
                state,
            },
        )
    }

    pub fn append_permission_grant(&mut self, grant: &PermissionGrant) -> Result<String, String> {
        self.append("permission_grant", grant)
    }

    /// Grants are session-wide, even when the selected conversation branch moves.
    pub fn permission_grants(&self) -> Result<BTreeMap<String, PermissionGrant>, String> {
        let mut grants = BTreeMap::new();
        for entry in self
            .entries
            .iter()
            .filter(|entry| entry.kind == "permission_grant")
        {
            let grant: PermissionGrant = serde_json::from_value(entry.data.clone())
                .map_err(|error| format!("entry {}: bad permission grant: {error}", entry.id))?;
            if grant.name.is_empty() || !crate::permissions::valid_identity(&grant.identity) {
                return Err(format!("entry {}: invalid permission grant", entry.id));
            }
            if grant.allow.is_some() {
                grants.insert(grant.identity.clone(), grant);
            } else {
                grants.remove(&grant.identity);
            }
        }
        Ok(grants)
    }

    /// Only the selected conversation branch contributes enablement overrides.
    pub fn tool_states(&self) -> Result<BTreeMap<String, ToolState>, String> {
        let mut states = BTreeMap::new();
        for entry in self.active_entries()? {
            if entry.kind != "tool_state" {
                continue;
            }
            let change: ToolStateEntry = serde_json::from_value(entry.data)
                .map_err(|error| format!("entry {}: bad tool state: {error}", entry.id))?;
            if change.name.is_empty() {
                return Err(format!("entry {}: empty tool name", entry.id));
            }
            if change.state == ToolState::Inherit {
                states.remove(&change.name);
            } else {
                states.insert(change.name, change.state);
            }
        }
        Ok(states)
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
                "turn_error" => {
                    let ended_at_tool = messages.last().is_some_and(|message| {
                        message.role == Role::Tool || message.tool_calls().next().is_some()
                    });
                    if ended_at_tool {
                        // Keep the next user message out of the interrupted
                        // tool round without adding another session record.
                        messages.push(Message::assistant(
                            "The previous tool round ended early. The next user message starts a new turn.",
                        ));
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
        if let Some(directory) = self.ephemeral_shell_state.take() {
            let _ = std::fs::remove_dir_all(directory);
        }
        if let Some(lock) = self.lock.take() {
            let _ = std::fs::remove_file(lock);
        }
    }
}

fn private_directory(path: &Path) -> Result<(), String> {
    match create_private_directory(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(path)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            if !metadata.file_type().is_dir() {
                return Err(format!(
                    "{}: shell state is not a directory",
                    path.display()
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
                    return Err(format!("{}: shell state is not private", path.display()));
                }
            }
            Ok(())
        }
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

fn create_private_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::DirBuilder::new().create(path)
    }
}

struct Parsed {
    header: Header,
    entries: Vec<Entry>,
    valid_len: u64,
    discarded_entries: usize,
}

fn read_session(path: &Path) -> Result<Parsed, String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!("session {} is not a regular file", path.display()));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| {
            let length = file.metadata()?.len();
            file.take(length).read_to_end(&mut bytes)
        })
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let mut valid_len = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1) as u64;
    let partial_tail = bytes.len() as u64 > valid_len;
    let mut lines = bytes.split(|byte| *byte == b'\n').collect::<Vec<_>>();
    // A trailing newline contributes an empty slice; without one, the last
    // slice is the only record that may have been interrupted by a crash.
    lines.pop();
    let mut starts = Vec::with_capacity(lines.len());
    let mut offset = 0;
    for line in &lines {
        starts.push(offset);
        offset += line.len() + 1;
    }
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
    let discarded_entries = match incomplete_round_start(&entries)? {
        Some(index) => {
            let count = entries.len() - index;
            valid_len = starts[index + 1] as u64;
            entries.truncate(index);
            count
        }
        None => 0,
    } + usize::from(partial_tail);
    validate_entries(&entries)?;
    Ok(Parsed {
        header,
        entries,
        valid_len,
        discarded_entries,
    })
}

fn incomplete_round_start(entries: &[Entry]) -> Result<Option<usize>, String> {
    let mut results = HashMap::<String, usize>::new();
    for (index, entry) in entries.iter().enumerate().rev() {
        if entry.kind != "message" {
            continue;
        }
        let message: Message = serde_json::from_value(entry.data.clone())
            .map_err(|error| format!("entry {}: bad message: {error}", entry.id))?;
        match message.role {
            Role::Tool => {
                for block in message.content {
                    if let ContentBlock::ToolResult { call_id, .. } = block {
                        *results.entry(call_id).or_default() += 1;
                    }
                }
            }
            Role::Assistant => {
                let calls = message.tool_calls().collect::<Vec<_>>();
                if calls.is_empty() {
                    return Ok(None);
                }
                let paired = calls.iter().all(|call| results.get(&call.id) == Some(&1))
                    && calls.len() == results.len();
                return Ok((!paired).then_some(index));
            }
            Role::User => return Ok(None),
        }
    }
    Ok(None)
}

fn validate_entries(entries: &[Entry]) -> Result<(), String> {
    let mut ids = HashSet::new();
    for entry in entries {
        if !ENTRY_KINDS.contains(&entry.kind.as_str()) {
            return Err(format!(
                "session entry {} has unknown kind {:?}",
                entry.id, entry.kind
            ));
        }
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
    crate::run_lock::create_pid_file(&lock, crate::platform::process_alive, |pid| {
        format!("session is already open by process {pid}")
    })?;
    Ok(lock)
}

/// A file that a failed record can be cut back from.
trait RecordFile: Write + Seek {
    fn cut(&mut self, len: u64) -> std::io::Result<()>;
}

impl RecordFile for File {
    fn cut(&mut self, len: u64) -> std::io::Result<()> {
        self.set_len(len)
    }
}

/// Write one record with one call. A failed write is cut off, so the next
/// record cannot continue a partial line in the middle of the file.
fn write_line(writer: &mut impl RecordFile, value: &impl Serialize) -> Result<(), String> {
    let mut line = serde_json::to_vec(value)
        .map_err(|error| format!("cannot serialize session record: {error}"))?;
    line.push(b'\n');
    let start = writer
        .seek(SeekFrom::End(0))
        .map_err(|error| format!("cannot write session record: {error}"))?;
    let Err(error) = writer.write_all(&line) else {
        return Ok(());
    };
    match writer
        .cut(start)
        .and_then(|()| writer.seek(SeekFrom::Start(start)))
    {
        Ok(_) => Err(format!("cannot write session record: {error}")),
        Err(cut) => Err(format!(
            "cannot write session record: {error}; its partial bytes remain: {cut}"
        )),
    }
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
    Ok(crate::directory::default_root()?.join("sessions"))
}

/// Removes shell state that ephemeral sessions of a killed Gears left behind.
/// Call only while holding the Gears directory lock, before any session starts.
pub fn remove_abandoned_shell_state(directory: &StateRoot) -> Result<usize, String> {
    let relative = Path::new("sessions").join(EPHEMERAL_SHELL_STATE);
    let Some(parent) = directory.existing_directory(&relative)? else {
        return Ok(0);
    };
    let mut removed = 0;
    for entry in
        std::fs::read_dir(&parent).map_err(|error| format!("{}: {error}", parent.display()))?
    {
        let path = entry
            .map_err(|error| format!("{}: {error}", parent.display()))?
            .path();
        let kind = std::fs::symlink_metadata(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?
            .file_type();
        if kind.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        }
        .map_err(|error| format!("{}: {error}", path.display()))?;
        removed += 1;
    }
    Ok(removed)
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

pub(crate) fn now_ms() -> u64 {
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

    #[test]
    fn snapshots_read_a_locked_writer_without_changing_its_file() {
        let (base, _, store) = fixture("live-snapshot");
        let mut writer = store.create(false, Some("live")).unwrap();
        writer.append_message(&Message::user("first")).unwrap();
        let path = writer.path().unwrap().to_path_buf();
        let lock = writer.lock.clone().unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(store.open(writer.id()).is_err());
        let snapshot = store.read(writer.id()).unwrap();
        assert_eq!(snapshot.id(), writer.id());
        assert_eq!(snapshot.path(), Some(path.as_path()));
        assert_eq!(snapshot.name().as_deref(), Some("live"));
        assert_eq!(snapshot.context_messages().unwrap().len(), 1);
        writer
            .append_message(&Message::assistant("second"))
            .unwrap();
        assert_eq!(snapshot.context_messages().unwrap().len(), 1);
        let updated = read_snapshot(&path).unwrap();
        assert_eq!(updated.context_messages().unwrap().len(), 2);
        drop(snapshot);
        drop(updated);
        assert!(std::fs::read(&path).unwrap().starts_with(&before));
        assert!(lock.exists());
        writer.append_message(&Message::user("third")).unwrap();
        drop(writer);
        assert!(!lock.exists());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn anchored_snapshots_keep_old_context_and_refuse_unfinished_tool_rounds() {
        let (base, _, store) = fixture("anchored-snapshot");
        let mut writer = store.create(false, None).unwrap();
        writer.append_message(&Message::user("work")).unwrap();
        let call = crate::provider::ToolCall::new("call", "sh", "{}");
        let start = writer
            .append_message(&Message::assistant_response("running".into(), vec![call]))
            .unwrap();
        let result = writer
            .append_message(&Message::tool_result("call", "sh", "done", false))
            .unwrap();
        writer
            .append_hook_state(&HookState {
                hook: "batteries".into(),
                state: serde_json::json!({"prompt_snapshot": "original"}),
                context: None,
            })
            .unwrap();
        let anchor = writer
            .append_message(&Message::assistant("original result"))
            .unwrap();
        let original = writer.context_messages().unwrap();
        writer
            .append_compaction(&Compaction {
                summary: "later summary".into(),
                retained_tail: Vec::new(),
                tokens_before: 100,
            })
            .unwrap();
        writer.append_message(&Message::user("next task")).unwrap();
        writer
            .append_hook_state(&HookState {
                hook: "batteries".into(),
                state: serde_json::json!({"prompt_snapshot": "refreshed"}),
                context: None,
            })
            .unwrap();
        let source = writer.path().unwrap();
        let before = std::fs::read(source).unwrap();
        let snapshot = store.read(writer.id()).unwrap();
        assert_ne!(snapshot.context_messages().unwrap(), original);
        let selected = snapshot.at(&anchor).unwrap();
        assert_eq!(selected.context_messages().unwrap(), original);
        assert_eq!(selected.active_leaf(), Some(anchor.as_str()));
        assert_eq!(selected.path(), Some(source));
        assert_eq!(
            selected.hook_state("batteries").unwrap()["prompt_snapshot"],
            "original"
        );
        assert!(selected.entry(snapshot.active_leaf().unwrap()).is_none());
        assert!(snapshot.at(&start).err().unwrap().contains("unfinished"));
        assert!(snapshot.at("missing").is_err());
        assert_eq!(
            snapshot
                .at(&result)
                .unwrap()
                .context_messages()
                .unwrap()
                .len(),
            3
        );
        let mut child = store.clone_active_with_options(&selected, true).unwrap();
        assert_eq!(child.context_messages().unwrap(), original);
        child.append_message(&Message::user("review")).unwrap();
        assert_eq!(std::fs::read(source).unwrap(), before);
        assert_ne!(snapshot.active_leaf(), selected.active_leaf());
        drop(child);
        drop(selected);
        drop(snapshot);
        writer
            .append_message(&Message::assistant("parent still live"))
            .unwrap();
        drop(writer);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn entries_of_an_unknown_kind_are_refused() {
        let (base, _, store) = fixture("unknown-kind");
        let mut writer = store.create(false, None).unwrap();
        writer.append_message(&Message::user("work")).unwrap();
        let path = writer.path().unwrap().to_path_buf();
        drop(writer);
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        let entry = Entry {
            kind: "request_prefix".into(),
            id: "e00000000000000ff".into(),
            parent_id: None,
            timestamp_ms: 0,
            data: serde_json::json!({}),
        };
        writeln!(file, "{}", serde_json::to_string(&entry).unwrap()).unwrap();
        let error = store.open_path(&path).err().unwrap();
        assert!(error.contains("unknown kind \"request_prefix\""), "{error}");
        assert!(read_snapshot(&path).is_err());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn snapshots_omit_partial_records_and_unfinished_rounds_without_repairing() {
        let (base, _, store) = fixture("live-snapshot-prefix");
        let mut writer = store.create(false, None).unwrap();
        writer.append_message(&Message::user("work")).unwrap();
        let message = Message::assistant_response(
            "running".into(),
            vec![crate::provider::ToolCall::new("live-call", "sh", "{}")],
        );
        writer.append_message(&message).unwrap();
        let path = writer.path().unwrap();
        let mut file = OpenOptions::new().append(true).open(path).unwrap();
        file.write_all(b"{partial").unwrap();
        let before = std::fs::read(path).unwrap();
        let snapshot = read_snapshot(path).unwrap();
        assert_eq!(
            snapshot.context_messages().unwrap(),
            [Message::user("work")]
        );
        assert_eq!(snapshot.recovered_entries(), 2);
        assert_eq!(std::fs::read(path).unwrap(), before);
        drop(snapshot);
        drop(writer);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn a_live_snapshot_can_be_forked_ephemerally_without_saved_grants() {
        let (base, _, store) = fixture("live-ephemeral-fork");
        let mut writer = store.create(false, Some("parent")).unwrap();
        writer.append_message(&Message::user("work")).unwrap();
        writer
            .append_permission_grant(&PermissionGrant {
                name: "sh".into(),
                identity: "a".repeat(64),
                allow: Some(true),
                ..PermissionGrant::default()
            })
            .unwrap();
        let snapshot = store.read(writer.id()).unwrap();
        let mut fork = store.clone_active_with_options(&snapshot, true).unwrap();
        assert!(fork.is_ephemeral());
        assert!(fork.path().is_none());
        assert_eq!(fork.header.parent_session.as_deref(), writer.path());
        assert_eq!(fork.name().as_deref(), Some("parent"));
        assert!(fork.permission_grants().unwrap().is_empty());
        fork.append_message(&Message::assistant("child")).unwrap();
        assert_eq!(writer.context_messages().unwrap(), [Message::user("work")]);
        assert_eq!(store.list().unwrap().len(), 1);
        let other = Store::with_root(&base, base.join("other-state")).unwrap();
        assert!(
            other
                .read(writer.path().unwrap().to_str().unwrap())
                .is_err()
        );
        drop(fork);
        drop(snapshot);
        drop(writer);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn saved_shell_state_stays_beside_the_session() {
        let (base, _, store) = fixture("saved-shell-state");
        let mut session = store.create(false, None).unwrap();
        let path = session.path().unwrap().to_path_buf();
        let state = session.shell_state_directory().unwrap();
        assert_eq!(state, path.with_extension("sh-state"));
        assert_eq!(session.shell_state_directory().unwrap(), state);
        drop(session);
        let mut reopened = store.open_path(&path).unwrap();
        assert_eq!(reopened.shell_state_directory().unwrap(), state);
        drop(reopened);
        assert!(state.is_dir());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn ephemeral_shell_state_is_removed_with_the_session() {
        let (base, root, store) = fixture("ephemeral-shell-state");
        let mut session = store.create(true, None).unwrap();
        let state = session.shell_state_directory().unwrap();
        assert!(state.starts_with(root.join(EPHEMERAL_SHELL_STATE)));
        assert_eq!(session.shell_state_directory().unwrap(), state);
        drop(session);
        assert!(!state.exists());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn saved_shell_state_rejects_a_symlink() {
        let (base, _, store) = fixture("shell-state-symlink");
        let mut session = store.create(false, None).unwrap();
        let state = session.path().unwrap().with_extension("sh-state");
        std::os::unix::fs::symlink(&base, &state).unwrap();
        assert!(session.shell_state_directory().is_err());
        drop(session);
        std::fs::remove_dir_all(base).unwrap();
    }

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
    fn tool_state_follows_branch_and_survives_clone_and_resume() {
        let (base, _, store) = fixture("tool-state");
        let mut session = store.create(false, None).unwrap();
        let branch_point = session.append_message(&Message::user("first")).unwrap();
        session.set_tool_state("sh", ToolState::Disabled).unwrap();
        let disabled_leaf = session.active_leaf().unwrap().to_string();
        session.set_tool_state("sh", ToolState::Inherit).unwrap();
        assert!(session.tool_states().unwrap().is_empty());
        session.select(&disabled_leaf).unwrap();
        assert_eq!(session.tool_states().unwrap()["sh"], ToolState::Disabled);
        let cloned = store.clone_active(&session).unwrap();
        assert_eq!(cloned.tool_states().unwrap()["sh"], ToolState::Disabled);
        drop(cloned);
        session.select(&branch_point).unwrap();
        assert!(session.tool_states().unwrap().is_empty());
        session.set_tool_state("ls", ToolState::Enabled).unwrap();
        let path = session.path().unwrap().to_path_buf();
        drop(session);
        let resumed = store.open_path(&path).unwrap();
        assert_eq!(resumed.tool_states().unwrap()["ls"], ToolState::Enabled);
        assert!(!resumed.tool_states().unwrap().contains_key("sh"));
        drop(resumed);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn permission_grants_ignore_branches_but_not_session_boundaries() {
        let (base, _, store) = fixture("permission-grants");
        let mut session = store.create(false, None).unwrap();
        let user = session.append_message(&Message::user("first")).unwrap();
        let grant = PermissionGrant {
            name: "sh".into(),
            identity: "a".repeat(64),
            allow: Some(false),
            ..PermissionGrant::default()
        };
        session.append_permission_grant(&grant).unwrap();
        session
            .append_message(&Message::assistant("answer"))
            .unwrap();
        let cloned = store.clone_active(&session).unwrap();
        assert!(cloned.permission_grants().unwrap().is_empty());
        assert_eq!(cloned.context_messages().unwrap().len(), 2);
        drop(cloned);
        session.select(&user).unwrap();
        assert_eq!(session.permission_grants().unwrap()[&grant.identity], grant);
        let (forked, _) = store.fork_at_user(&session, &user).unwrap();
        assert!(forked.permission_grants().unwrap().is_empty());
        drop(forked);
        let path = session.path().unwrap().to_path_buf();
        drop(session);
        let mut resumed = store.open_path(&path).unwrap();
        assert_eq!(resumed.permission_grants().unwrap()[&grant.identity], grant);
        resumed
            .append_permission_grant(&PermissionGrant {
                allow: None,
                ..grant
            })
            .unwrap();
        assert!(resumed.permission_grants().unwrap().is_empty());
        drop(resumed);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn malformed_permission_identities_are_reported() {
        let (base, _, store) = fixture("bad-permission-identity");
        for identity in ["short".to_string(), "é".repeat(32), "z".repeat(64)] {
            let mut session = store.create(true, None).unwrap();
            session
                .append_permission_grant(&PermissionGrant {
                    name: "sh".into(),
                    identity,
                    allow: Some(true),
                    ..PermissionGrant::default()
                })
                .unwrap();
            assert!(session.permission_grants().is_err());
        }
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn failed_grant_write_does_not_change_the_session_answer() {
        let (base, _, store) = fixture("grant-write-failure");
        let mut session = store.create(false, None).unwrap();
        let grant = PermissionGrant {
            name: "sh".into(),
            identity: "a".repeat(64),
            allow: Some(false),
            ..PermissionGrant::default()
        };
        session.append_permission_grant(&grant).unwrap();
        session.writer = Some(std::fs::File::open(session.path().unwrap()).unwrap());
        assert!(
            session
                .append_permission_grant(&PermissionGrant {
                    allow: Some(true),
                    ..grant.clone()
                })
                .is_err()
        );
        assert_eq!(session.permission_grants().unwrap()[&grant.identity], grant);
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
    fn a_partial_tail_is_removed_before_appending_new_records() {
        let (base, _, store) = fixture("tail-append");
        let mut session = store.create(false, None).unwrap();
        session.append_message(&Message::user("before")).unwrap();
        let path = session.path().unwrap().to_path_buf();
        drop(session);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{partial")
            .unwrap();

        let mut reopened = store.open_path(&path).unwrap();
        assert_eq!(reopened.recovered_entries(), 1);
        reopened
            .append_message(&Message::assistant("after"))
            .unwrap();
        drop(reopened);
        let again = store.open_path(&path).unwrap();
        let context = again.context_messages().unwrap();
        assert_eq!(context.len(), 2);
        assert_eq!(context[1].text_content(), "after");
        drop(again);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn an_incomplete_tool_round_is_discarded_before_resume() {
        let (base, _, store) = fixture("crashed-round");
        let mut session = store.create(false, None).unwrap();
        session.append_message(&Message::user("first")).unwrap();
        session
            .append_message(&Message::assistant_response(
                String::new(),
                vec![
                    crate::provider::ToolCall::new("call_1", "sh", "{}"),
                    crate::provider::ToolCall::new("call_2", "sh", "{}"),
                ],
            ))
            .unwrap();
        session
            .append_message(&Message::tool_result("call_1", "sh", "done", false))
            .unwrap();
        let path = session.path().unwrap().to_path_buf();
        drop(session);

        let mut resumed = store.open_path(&path).unwrap();
        assert_eq!(resumed.recovered_entries(), 2);
        assert_eq!(
            resumed.context_messages().unwrap(),
            [Message::user("first")]
        );
        resumed.append_message(&Message::user("next")).unwrap();
        resumed
            .append_message(&Message::assistant("new answer"))
            .unwrap();
        drop(resumed);
        let again = store.open_path(&path).unwrap();
        let context = again.context_messages().unwrap();
        assert_eq!(context.len(), 3);
        assert_eq!(context[2].text_content(), "new answer");
        drop(again);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn an_interrupted_tool_round_has_a_transient_assistant_closer() {
        let (base, _, store) = fixture("interrupted-closer");
        let mut session = store.create(false, None).unwrap();
        session.append_message(&Message::user("first")).unwrap();
        session
            .append_message(&Message::assistant_response(
                String::new(),
                vec![crate::provider::ToolCall::new("call_1", "sh", "{}")],
            ))
            .unwrap();
        session
            .append_message(&Message::tool_result("call_1", "sh", "done", false))
            .unwrap();
        session.append_error("turn cancelled", true).unwrap();
        session.append_message(&Message::user("next")).unwrap();

        let context = session.context_messages().unwrap();
        assert_eq!(context.len(), 5);
        assert_eq!(context[3].role, Role::Assistant);
        assert!(context[3].text_content().contains("ended early"));
        assert_eq!(context[4].text_content(), "next");
        assert_eq!(
            session
                .entries()
                .iter()
                .filter(|entry| entry.kind == "message")
                .count(),
            4
        );
        drop(session);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn an_error_before_tools_needs_no_closer() {
        let (base, _, store) = fixture("no-closer");
        let mut session = store.create(false, None).unwrap();
        session.append_message(&Message::user("first")).unwrap();
        session.append_error("provider failed", false).unwrap();
        session.append_message(&Message::user("next")).unwrap();
        assert_eq!(session.context_messages().unwrap().len(), 2);
        drop(session);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn an_unpaired_tool_call_also_gets_a_closer() {
        let (base, _, store) = fixture("unpaired-closer");
        let mut session = store.create(false, None).unwrap();
        session.append_message(&Message::user("first")).unwrap();
        session
            .append_message(&Message::assistant_response(
                String::new(),
                vec![crate::provider::ToolCall::new("call_1", "sh", "{}")],
            ))
            .unwrap();
        session.append_error("turn cancelled", true).unwrap();
        let context = session.context_messages().unwrap();
        assert_eq!(context.len(), 3);
        assert!(context[2].text_content().contains("ended early"));
        drop(session);
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

    /// Accepts `room` more bytes, then fails like a full disk.
    struct Full {
        inner: std::io::Cursor<Vec<u8>>,
        room: usize,
    }

    impl Write for Full {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.room == 0 {
                return Err(std::io::Error::other("disk full"));
            }
            let count = buf.len().min(self.room);
            self.room -= count;
            self.inner.write(&buf[..count])
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Seek for Full {
        fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(to)
        }
    }

    impl RecordFile for Full {
        fn cut(&mut self, len: u64) -> std::io::Result<()> {
            self.inner.get_mut().truncate(len as usize);
            Ok(())
        }
    }

    #[test]
    fn a_failed_record_write_leaves_only_whole_lines() {
        let mut file = Full {
            inner: std::io::Cursor::new(Vec::new()),
            room: 20,
        };
        write_line(&mut file, &serde_json::json!({"a": 1})).unwrap();
        let long = serde_json::json!({"long": "x".repeat(40)});
        assert!(write_line(&mut file, &long).is_err());
        file.room = 100;
        write_line(&mut file, &serde_json::json!({"b": 2})).unwrap();
        assert_eq!(file.inner.into_inner(), b"{\"a\":1}\n{\"b\":2}\n");
    }

    #[test]
    fn a_session_lock_still_being_written_is_not_taken_over() {
        let (base, _, store) = fixture("fresh-lock");
        let session = store.create(false, Some("fresh")).unwrap();
        let (id, path) = (
            session.id().to_string(),
            session.path().unwrap().to_path_buf(),
        );
        drop(session);
        let lock = path.with_extension("jsonl.lock");
        std::fs::write(&lock, "").unwrap();
        let error = store.open(&id).err().unwrap();
        assert!(error.contains("being initialized"), "{error}");
        assert!(lock.exists());
        std::fs::remove_file(&lock).unwrap();
        store.open(&id).unwrap();
        std::fs::remove_dir_all(base).unwrap();
    }
}
