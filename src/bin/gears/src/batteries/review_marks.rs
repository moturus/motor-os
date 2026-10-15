//! Durable, session-local review marks; interrupted runs leave their mark due.

use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::batteries::{paths::ToolContext, review_config::Model};

const MAX_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    Command,
    Compaction,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Due,
    Completed,
    Dropped,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Mark {
    version: u32,
    pub session: String,
    pub entry: String,
    pub reason: Reason,
    pub focus: String,
    pub executor: Model,
    pub disposition: Disposition,
}

impl Mark {
    pub fn id(&self) -> String {
        crate::batteries::snapshot::digest(
            serde_json::to_string(&(
                &self.session,
                &self.entry,
                self.reason,
                &self.focus,
                &self.executor,
            ))
            .expect("review mark fields serialize")
            .as_bytes(),
        )
    }

    fn validate(&self, context: &ToolContext) -> Result<(), String> {
        if self.version != 1 || self.session != context.session {
            return Err("unsupported or foreign review mark".into());
        }
        if self.entry.is_empty()
            || self.entry.len() > 128
            || self.entry.chars().any(char::is_control)
            || self.focus.len() > 4096
            || self.focus.contains('\0')
            || (self.reason == Reason::Compaction && !self.focus.is_empty())
        {
            return Err("invalid review entry or focus (maximum 4096 bytes)".into());
        }
        for name in [&self.executor.provider, &self.executor.model] {
            if name.trim().is_empty() || name.chars().any(char::is_control) {
                return Err("invalid review executor".into());
            }
        }
        Ok(())
    }
}

fn name(id: &str) -> Result<String, String> {
    if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid review mark id".into());
    }
    Ok(format!("reviews/{id}.json"))
}

pub fn load(context: &ToolContext, id: &str) -> Result<Option<Mark>, String> {
    let relative = format!("batteries/sessions/{}/{}", context.session, name(id)?);
    let Some(path) = context.state.existing_file(Path::new(&relative))? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|error| error.to_string())?
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > MAX_BYTES {
        return Err("review mark exceeds 16 KiB".into());
    }
    let mark: Mark =
        serde_json::from_slice(&bytes).map_err(|error| format!("invalid review mark: {error}"))?;
    mark.validate(context)?;
    if mark.id() != id {
        return Err("review mark identity changed".into());
    }
    Ok(Some(mark))
}

fn save(context: &ToolContext, mark: &Mark) -> Result<(), String> {
    mark.validate(context)?;
    let bytes = serde_json::to_vec(mark).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_BYTES {
        return Err("review mark exceeds 16 KiB".into());
    }
    context.replace_data(&name(&mark.id())?, &bytes)
}

pub fn create(
    context: &ToolContext,
    entry: &str,
    reason: Reason,
    focus: &str,
    executor: &Model,
) -> Result<String, String> {
    let mark = Mark {
        version: 1,
        session: context.session.clone(),
        entry: entry.into(),
        reason,
        focus: focus.into(),
        executor: executor.clone(),
        disposition: Disposition::Due,
    };
    mark.validate(context)?;
    let id = mark.id();
    // Repeated triggers must not resurrect a completed or dismissed mark.
    if load(context, &id)?.is_none() {
        save(context, &mark)?;
    }
    Ok(id)
}

pub fn finish(context: &ToolContext, id: &str, disposition: Disposition) -> Result<(), String> {
    if disposition == Disposition::Due {
        return Err("a review cannot be reset to due".into());
    }
    let mut mark = load(context, id)?.ok_or("review mark is missing")?;
    if mark.disposition != Disposition::Due && mark.disposition != disposition {
        return Err("review mark is already handled".into());
    }
    if mark.disposition != disposition {
        mark.disposition = disposition;
        save(context, &mark)?;
    }
    Ok(())
}

pub fn due(context: &ToolContext) -> Result<Vec<Mark>, String> {
    let relative = format!("batteries/sessions/{}/reviews", context.session);
    let Some(path) = context.state.existing_directory(Path::new(&relative))? else {
        return Ok(Vec::new());
    };
    let mut marks = Vec::new();
    for item in std::fs::read_dir(path).map_err(|error| error.to_string())? {
        let item = item.map_err(|error| error.to_string())?;
        let filename = item.file_name();
        let Some(id) = filename
            .to_str()
            .and_then(|name| name.strip_suffix(".json"))
        else {
            continue;
        };
        let mark = load(context, id)?.ok_or("review mark disappeared")?;
        if mark.disposition == Disposition::Due {
            marks.push(mark);
        }
    }
    marks.sort_by_cached_key(Mark::id);
    Ok(marks)
}
