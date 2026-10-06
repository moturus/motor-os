//! Read all recorded branches without repairing files or acquiring writer locks.

use crate::{memory_format::Source, paths::ToolContext, skill_loads::Load};
use gears::provider::{ContentBlock, Message, ToolOutcome};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Seek, SeekFrom},
    path::Path,
};

#[derive(Default)]
pub struct Usage {
    pub last_load: BTreeMap<String, Load>,
    pub last_snapshot: BTreeMap<String, u64>,
    pub entries: BTreeMap<String, BTreeSet<String>>,
    pub unavailable: Vec<Value>,
    pub sessions_read: usize,
}

impl Usage {
    fn observe(&mut self, load: Load) -> Result<(), String> {
        if load.version != 1
            || !crate::skill_format::valid_name(&load.name)
            || load.content_hash.len() != 64
            || !load
                .content_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !load.source.valid_review()
            || !crate::memory_format::identifier(&load.source.session)
            || load.source.entries.is_empty()
            || load.source.entries.len() > 32
            || load
                .source
                .entries
                .iter()
                .any(|id| !crate::memory_format::identifier(id))
        {
            return Err("invalid skill load observation".into());
        }
        if self
            .last_load
            .get(&load.name)
            .is_none_or(|old| old.date_ms < load.date_ms)
        {
            self.last_load.insert(load.name.clone(), load);
        }
        Ok(())
    }

    pub fn source_available(&self, source: &Source) -> bool {
        self.entries
            .get(&source.session)
            .is_some_and(|entries| source.entries.iter().all(|id| entries.contains(id)))
    }
}

// Unlike general history reads, cleanup must not infer disuse from a lost tail.
pub fn complete_file(path: &Path) -> Result<(), String> {
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let size = file.metadata().map_err(|e| e.to_string())?.len();
    if size > 32 * 1024 * 1024 {
        return Err("history exceeds 32 MiB".into());
    }
    if size != 0 {
        file.seek(SeekFrom::End(-1)).map_err(|e| e.to_string())?;
        let mut tail = [0];
        file.read_exact(&mut tail).map_err(|e| e.to_string())?;
        if tail[0] != b'\n' {
            return Err("history has an incomplete final record".into());
        }
    }
    Ok(())
}

pub fn scan(context: &ToolContext) -> Result<Usage, String> {
    let mut usage = Usage::default();
    let loads = (|| {
        if let Some(path) = context
            .state
            .existing_file(Path::new(crate::skill_loads::FILE))?
        {
            complete_file(&path)?;
        }
        crate::journal::visit(
            &context.state,
            Path::new(crate::skill_loads::FILE),
            |record| usage.observe(serde_json::from_value(record).map_err(|e| e.to_string())?),
        )
    })();
    if let Err(error) = loads {
        usage
            .unavailable
            .push(json!({"file": crate::skill_loads::FILE, "error": error}));
    }
    let Some(root) = context.state.existing_directory(Path::new(""))? else {
        return Ok(usage);
    };
    let mut files = Vec::new();
    let mut unavailable = Vec::new();
    crate::session_search::discover(&root, &mut files, &mut unavailable)?;
    usage.unavailable.extend(unavailable.into_iter().map(
        |(path, error)| json!({"file": path.strip_prefix(&root).unwrap_or(&path), "error": error}),
    ));
    files.sort();
    if files.len() > 4096 {
        return Err("cleanup exceeds 4096 saved sessions".into());
    }
    let mut entries_read = 0;
    for file in files {
        let read = (|| {
            complete_file(&file)?;
            let session = gears::session::read_snapshot(&file)?;
            if session.recovered_entries() != 0 {
                return Err("session has an unfinished tool round".into());
            }
            entries_read += session.entries().len();
            if entries_read > 100_000 {
                return Err("cleanup exceeds 100000 saved entries".into());
            }
            if usage.entries.contains_key(session.id()) {
                return Err("duplicate saved session identity".into());
            }
            let mut entries = BTreeSet::new();
            for entry in session.entries() {
                entries.insert(entry.id.clone());
                if entry.kind == "hook_state" {
                    for key in ["skill_snapshot", "skill_view_snapshot"] {
                        if let Some(hash) = entry.data["state"][key].as_str() {
                            for loaded in crate::skill_snapshot::load(context, hash)?.loaded {
                                usage
                                    .last_snapshot
                                    .entry(loaded.name)
                                    .and_modify(|date| *date = (*date).max(entry.timestamp_ms))
                                    .or_insert(entry.timestamp_ms);
                            }
                        }
                    }
                }
                if entry.kind != "message" {
                    continue;
                }
                let message: Message =
                    serde_json::from_value(entry.data.clone()).map_err(|e| e.to_string())?;
                for block in message.content {
                    let ContentBlock::ToolResult {
                        tool_name,
                        content,
                        is_error: false,
                        outcome: ToolOutcome::Completed,
                        ..
                    } = block
                    else {
                        continue;
                    };
                    if tool_name != "skill_view" {
                        continue;
                    }
                    let result: Value = serde_json::from_str(&content)
                        .map_err(|e| format!("invalid skill_view result: {e}"))?;
                    if result.get("name").is_none() {
                        continue;
                    }
                    let content: crate::skill_format::Content =
                        serde_json::from_value(result["content"].clone())
                            .map_err(|e| e.to_string())?;
                    if result["version"] != 1 || result["hash"] != content.hash() {
                        return Err("skill_view result has inconsistent content".into());
                    }
                    usage.observe(Load {
                        version: 1,
                        name: result["name"]
                            .as_str()
                            .ok_or("skill_view result has no name")?
                            .into(),
                        content_hash: content.hash(),
                        source: Source {
                            review: None,
                            session: session.id().into(),
                            entries: vec![entry.id.clone()],
                        },
                        date_ms: entry.timestamp_ms,
                    })?;
                }
            }
            usage.entries.insert(session.id().into(), entries);
            usage.sessions_read += 1;
            Ok::<_, String>(())
        })();
        if entries_read > 100_000 {
            return Err("cleanup exceeds 100000 saved entries".into());
        }
        if let Err(error) = read {
            usage
                .unavailable
                .push(json!({"file": file.strip_prefix(&root).unwrap_or(&file), "error": error}));
        }
    }
    Ok(usage)
}
