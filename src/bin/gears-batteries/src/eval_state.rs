//! Freeze selected memory versions without copying conversation or review history.

use crate::{
    memory_format::{Document, Entry, Kind, Target},
    paths::ToolContext,
};
use std::{collections::BTreeMap, path::Path};

pub struct Frozen {
    settings: String,
    memories: Vec<(Target, Vec<(Entry, bool)>)>,
    skills: Vec<crate::skill_cleanup::Version>,
}

pub fn capture(context: &ToolContext) -> Result<Frozen, String> {
    crate::workspace_memory::require_approved(context)?;
    if let Some(path) = context
        .state
        .existing_file(Path::new("batteries/changes.jsonl"))?
    {
        crate::skill_usage::complete_file(&path)?;
    }
    let limits = crate::memory_config::load(&context.state)?;
    crate::skill_config::load(&context.state)?;
    crate::review_config::load(&context.state)?;
    let text = crate::memory_config::read(&context.state)?.unwrap_or("version=1".into());
    let mut settings: toml::Value = toml::from_str(&text).map_err(|e| e.to_string())?;
    let table = settings
        .as_table_mut()
        .ok_or("batteries settings must be a table")?;
    let reviews = table
        .entry("reviews")
        .or_insert_with(|| toml::Value::Table(Default::default()));
    reviews
        .as_table_mut()
        .ok_or("reviews settings must be a table")?
        .insert("enabled".into(), toml::Value::Boolean(false));
    let mut origins: BTreeMap<(String, String), Entry> = BTreeMap::new();
    crate::journal::visit(
        &context.state,
        Path::new("batteries/changes.jsonl"),
        |record| {
            if record["decision"] == "approve" && record["kind"] == "workspace_memory" {
                origins.retain(|(target, _), _| {
                    target != Target::Workspace.relative().to_str().unwrap()
                });
            } else if record["decision"] == "approve" && record["kind"].is_null() {
                let record: crate::pending::Record =
                    serde_json::from_value(record.clone()).map_err(|e| e.to_string())?;
                record.proposal.validate()?;
                let target = record
                    .proposal
                    .target
                    .relative()
                    .to_str()
                    .unwrap()
                    .to_string();
                if let Some(before) = record.proposal.before {
                    origins.remove(&(target.clone(), before.metadata.id));
                }
                if let Some(after) = record.proposal.after {
                    origins.insert((target, after.metadata.id.clone()), after);
                }
            }
            Ok(())
        },
    )?;
    let mut memories = Vec::new();
    for target in [Target::User, Target::Global, Target::Workspace] {
        let document = crate::memory::load(context, target)?;
        document.encode(target, limits.for_target(target))?;
        let target_key = target.relative().to_str().unwrap().to_string();
        let entries = document
            .entries
            .into_iter()
            .map(|entry| {
                let learned = entry.metadata.kind != Kind::User
                    && origins.get(&(target_key.clone(), entry.metadata.id.clone()))
                        == Some(&entry);
                (entry, learned)
            })
            .collect();
        memories.push((target, entries));
    }
    Ok(Frozen {
        settings: toml::to_string(&settings).map_err(|e| e.to_string())?,
        memories,
        skills: crate::skill_cleanup::versions(context)?,
    })
}

impl Frozen {
    pub fn memory(&self, target: Target, learning: bool) -> Document {
        let (_, entries) = self
            .memories
            .iter()
            .find(|(stored, _)| *stored == target)
            .unwrap();
        Document {
            entries: entries
                .iter()
                .filter(|(_, learned)| learning || !learned)
                .map(|(entry, _)| entry.clone())
                .collect(),
        }
    }

    pub fn skills(&self, learning: bool) -> Vec<(&str, &crate::skill_format::Content, bool)> {
        self.skills
            .iter()
            .filter(|s| learning || s.origin.is_none())
            .map(|s| (s.name.as_str(), &s.content, s.origin.is_some()))
            .collect()
    }

    pub fn settings(&self) -> &str {
        &self.settings
    }
}
