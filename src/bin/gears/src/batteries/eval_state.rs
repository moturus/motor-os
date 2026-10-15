//! Freeze selected memory versions without copying conversation or review history.

use crate::batteries::{
    memory_format::{Document, Entry, Kind, Target},
    paths::ToolContext,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub struct Frozen {
    source_workspace: PathBuf,
    settings: String,
    memories: Vec<(Target, Vec<(Entry, bool)>)>,
    skills: Vec<crate::batteries::skill_cleanup::Version>,
}

pub fn capture(context: &ToolContext) -> Result<Frozen, String> {
    crate::batteries::workspace_memory::require_approved(context)?;
    if let Some(path) = context
        .state
        .existing_file(Path::new("batteries/changes.jsonl"))?
    {
        crate::batteries::skill_usage::complete_file(&path)?;
    }
    let limits = crate::batteries::memory_config::load(&context.state)?;
    crate::batteries::skill_config::load(&context.state)?;
    crate::batteries::review_config::load(&context.state)?;
    let text = crate::batteries::memory_config::read(&context.state)?.unwrap_or("version=1".into());
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
    crate::batteries::journal::visit(
        &context.state,
        Path::new("batteries/changes.jsonl"),
        |record| {
            if record["decision"] == "approve" && record["kind"] == "workspace_memory" {
                origins.retain(|(target, _), _| {
                    target != Target::Workspace.relative().to_str().unwrap()
                });
            } else if record["decision"] == "approve" && record["kind"].is_null() {
                let record: crate::batteries::pending::Record =
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
        let document = crate::batteries::memory::load(context, target)?;
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
        source_workspace: context.workspace.clone(),
        settings: toml::to_string(&settings).map_err(|e| e.to_string())?,
        memories,
        skills: crate::batteries::skill_cleanup::versions(context)?,
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

    pub fn skills(
        &self,
        learning: bool,
    ) -> Vec<(&str, &crate::batteries::skill_format::Content, bool)> {
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
impl Frozen {
    pub fn install(&self, workspace: &Path, root: &Path, learning: bool) -> Result<Value, String> {
        let context = ToolContext::new(workspace.into(), root.into(), "eval-state".into(), None)?;
        if context.workspace.starts_with(&self.source_workspace)
            || self.source_workspace.starts_with(&context.workspace)
        {
            return Err("evaluation state must be installed in a separate workspace copy".into());
        }
        match std::fs::symlink_metadata(context.state.path()) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err("evaluation state destination must not exist".into()),
        }
        if context.workspace.starts_with(context.state.path())
            || context.state.path().starts_with(&context.workspace)
        {
            return Err("evaluation workspace and state must be separate".into());
        }
        context
            .state
            .replace_file(Path::new("batteries.toml"), self.settings.as_bytes())?;
        let limits = crate::batteries::memory_config::load(&context.state)?;
        let mut versions = Vec::new();
        for (target, entries) in &self.memories {
            let selected: Vec<_> = entries
                .iter()
                .filter(|(_, learned)| learning || !learned)
                .collect();
            let document = Document {
                entries: selected.iter().map(|(entry, _)| entry.clone()).collect(),
            };
            let text = document.encode(*target, limits.for_target(*target))?;
            crate::batteries::memory::root(&context, *target)?
                .replace_file(target.relative(), text.as_bytes())?;
            versions.push(json!({"target": target, "hash": crate::batteries::snapshot::digest(text.as_bytes()),
                "entries": selected.iter().map(|(e, learned)| json!({"id":e.metadata.id,
                "kind":e.metadata.kind,"learned":learned,"hash":crate::batteries::snapshot::digest(&serde_json::to_vec(e).unwrap())})).collect::<Vec<_>>() }));
            if *target == Target::Workspace {
                admission(
                    &context,
                    json!({"kind":"workspace_memory", "workspace_memory_hash":crate::batteries::snapshot::digest(text.as_bytes())}),
                )?;
            }
        }
        let mut skills = Vec::new();
        for skill in &self.skills {
            if !learning && skill.origin.is_some() {
                continue;
            }
            crate::batteries::skill_store::write(&context, &skill.name, Some(&skill.content))?;
            admission(
                &context,
                json!({"kind":"skill", "name":skill.name,
                "content_hash":skill.content.hash(), "content":skill.content}),
            )?;
            skills.push(json!({"name":skill.name, "hash":skill.content.hash(), "learned":skill.origin.is_some()}));
        }
        Ok(
            json!({"version":1, "learning":learning, "memory":versions, "skills":skills,
            "settings_hash":crate::batteries::snapshot::digest(self.settings.as_bytes()),
            "history":"only minimal admission records; no source sessions, pending proposals or review artifacts"}),
        )
    }
}

fn admission(context: &ToolContext, mut record: Value) -> Result<(), String> {
    record["version"] = json!(1);
    record["decision"] = json!("approve");
    record["date_ms"] = json!(0);
    record["source"] = json!({"path":"evaluation snapshot"});
    let path = context.state.file(Path::new("batteries/changes.jsonl"))?;
    crate::batteries::journal::append_at(&context.state, &path, &record)
}
