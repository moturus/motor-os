//! Immutable skill catalogs and loaded versions follow session branches.

use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::batteries::memory_format::Source;
use crate::batteries::paths::ToolContext;
use crate::batteries::skill_catalog::Descriptor;
use crate::batteries::skill_format::Content;

const MAX_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Loaded {
    pub name: String,
    pub content: Content,
    pub source: Source,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub version: u32,
    pub catalog: Vec<Descriptor>,
    pub loaded: Vec<Loaded>,
}

impl Snapshot {
    fn validate(&self) -> Result<(), String> {
        if self.version != 1 || self.catalog.len() > 128 || self.loaded.len() > 3 {
            return Err("unsupported or oversized skill snapshot".into());
        }
        let mut names = std::collections::HashSet::new();
        for skill in &self.catalog {
            if !crate::batteries::skill_format::valid_name(&skill.name)
                || !names.insert(&skill.name)
                || skill.description.trim().is_empty()
                || skill.description.chars().count() > 1024
                || skill.hash.len() != 64
                || !skill
                    .hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err("invalid skill catalog snapshot".into());
            }
        }
        names.clear();
        for skill in &self.loaded {
            skill.content.parse(&skill.name, 65536, 65536)?;
            if !names.insert(&skill.name)
                || !crate::batteries::memory_format::identifier(&skill.source.session)
                || skill.source.entries.is_empty()
                || skill.source.entries.len() > 32
                || skill
                    .source
                    .entries
                    .iter()
                    .any(|id| !crate::batteries::memory_format::identifier(id))
            {
                return Err("invalid loaded skill snapshot".into());
            }
        }
        Ok(())
    }
}

fn path(hash: &str) -> Result<std::path::PathBuf, String> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("invalid skill snapshot hash".into());
    }
    Ok(Path::new("batteries/snapshots").join(format!("skill-{hash}.json")))
}

pub fn save(context: &ToolContext, snapshot: &Snapshot) -> Result<String, String> {
    snapshot.validate()?;
    let bytes = serde_json::to_vec(snapshot).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_BYTES {
        return Err("skill snapshot exceeds 2 MiB".into());
    }
    let hash = crate::batteries::snapshot::digest(&bytes);
    context.state.replace_file(&path(&hash)?, &bytes)?;
    Ok(hash)
}

pub fn load(context: &ToolContext, hash: &str) -> Result<Snapshot, String> {
    let path = context
        .state
        .existing_file(&path(hash)?)?
        .ok_or("skill snapshot is unavailable")?;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|error| error.to_string())?
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > MAX_BYTES || crate::batteries::snapshot::digest(&bytes) != hash {
        return Err("skill snapshot hash changed or exceeds its limit".into());
    }
    let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    snapshot.validate()?;
    Ok(snapshot)
}

pub fn reconcile(
    context: &ToolContext,
    frozen: &Snapshot,
    live: &[Descriptor],
) -> Result<Snapshot, String> {
    let catalog = crate::batteries::skill_catalog::reconcile(&frozen.catalog, live);
    let mut loaded = Vec::new();
    for old in &frozen.loaded {
        let Some(descriptor) = catalog.iter().find(|skill| skill.name == old.name) else {
            continue;
        };
        let Some(content) = crate::batteries::skill_store::current(context, &old.name)? else {
            continue;
        };
        if content.hash() != descriptor.hash {
            return Err("skill changed while building its snapshot".into());
        }
        loaded.push(Loaded {
            name: old.name.clone(),
            content,
            source: old.source.clone(),
        });
    }
    Ok(Snapshot {
        version: 1,
        catalog,
        loaded,
    })
}

pub fn changes(previous: &Snapshot, desired: &Snapshot) -> Result<Option<String>, String> {
    let mut lines = Vec::new();
    for before in &previous.catalog {
        let after = desired
            .catalog
            .iter()
            .find(|skill| skill.name == before.name);
        match after {
            None => lines.push(format!("Withdraw skill {} from available skills. Do not use its earlier instructions or notes.", before.name)),
            Some(after) if after != before => lines.push(format!("Correct skill {} metadata: {}", before.name, serde_json::to_string(after).map_err(|error| error.to_string())?)),
            _ => {},
        }
    }
    for before in &previous.loaded {
        match desired.loaded.iter().find(|skill| skill.name == before.name) {
            None => lines.push(format!("Withdraw loaded skill {}. Do not use its earlier instructions or notes; load it again only if available and needed.", before.name)),
            Some(after) if after.content != before.content => lines.push(format!("Correct loaded skill {}. Its earlier version is superseded by: {}", before.name,
                serde_json::to_string(&after.content).map_err(|error| error.to_string())?)),
            _ => {},
        }
    }
    for after in &desired.loaded {
        if !previous.loaded.iter().any(|skill| skill.name == after.name) {
            lines.push(format!(
                "Restore loaded skill {}: {}",
                after.name,
                serde_json::to_string(&after.content).map_err(|error| error.to_string())?
            ));
        }
    }
    Ok((!lines.is_empty()).then(|| format!("Skill updates: current instructions take precedence. Approval admits use, not usefulness.\n{}", lines.join("\n"))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_reject_corruption_and_include_notes_in_correction_and_withdrawal_notices() {
        let path =
            std::env::temp_dir().join(format!("batteries-skill-snapshot-{}", std::process::id()));
        std::fs::create_dir_all(path.join("workspace")).unwrap();
        let context = ToolContext::new(
            path.join("workspace"),
            path.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        let content = Content {
            skill_md: "---\nname: checks\ndescription: Run checks.\n---\nSteps.\n".into(),
            notes_md: Some("Old quirk.".into()),
        };
        let old = Snapshot {
            version: 1,
            catalog: vec![Descriptor {
                name: "checks".into(),
                description: "Run checks.".into(),
                platforms: None,
                hash: content.hash(),
            }],
            loaded: vec![Loaded {
                name: "checks".into(),
                content,
                source: Source {
                    review: None,
                    session: "s1".into(),
                    entries: vec!["e1".into()],
                },
            }],
        };
        let hash = save(&context, &old).unwrap();
        assert_eq!(load(&context, &hash).unwrap(), old);
        let mut corrected = old.clone();
        corrected.loaded[0].content.notes_md = Some("Corrected quirk.".into());
        assert!(
            changes(&old, &corrected)
                .unwrap()
                .unwrap()
                .contains("Corrected quirk.")
        );
        assert!(changes(&corrected, &corrected).unwrap().is_none());
        let empty = Snapshot {
            version: 1,
            catalog: Vec::new(),
            loaded: Vec::new(),
        };
        let notice = changes(&old, &empty).unwrap().unwrap();
        assert!(notice.contains("Withdraw loaded skill checks"));
        assert!(!notice.contains("Old quirk."));
        context
            .state
            .replace_file(&super::path(&hash).unwrap(), b"{}")
            .unwrap();
        assert!(load(&context, &hash).unwrap_err().contains("hash changed"));
        assert!(load(&context, "../escape").is_err());
        std::fs::remove_dir_all(path).unwrap();
    }
}
