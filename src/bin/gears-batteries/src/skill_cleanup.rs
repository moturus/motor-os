//! Conservative cleanup candidates retain the provenance of the current version.

use crate::{paths::ToolContext, skill_format::Content, skill_pending::Proposal};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub struct Version {
    pub name: String,
    pub content: Content,
    pub origin: Option<(Proposal, u64)>,
    pub archive_denied: bool,
}

pub fn versions(context: &ToolContext) -> Result<Vec<Version>, String> {
    let mut origins = BTreeMap::new();
    let mut denied = BTreeSet::new();
    crate::journal::visit(
        &context.state,
        Path::new("batteries/changes.jsonl"),
        |record| {
            if record["version"] != 1
                || !matches!(record["decision"].as_str(), Some("approve" | "deny"))
            {
                return Err("unsupported or malformed decision record".into());
            }
            if record["kind"] == "skill"
                && record["decision"] == "deny"
                && record.get("proposal").is_some()
            {
                let proposal: Proposal = serde_json::from_value(record["proposal"].clone())
                    .map_err(|e| e.to_string())?;
                proposal.validate()?;
                if proposal.after.is_none() {
                    denied.insert((proposal.name, proposal.before.unwrap().hash()));
                }
            }
            if record["kind"] == "skill" && record["decision"] == "approve" {
                let name = record["name"]
                    .as_str()
                    .ok_or("skill decision has no name")?;
                let date = record["date_ms"]
                    .as_u64()
                    .ok_or("skill decision has no date")?;
                // A user admission replaces agent provenance, even for identical bytes.
                origins.remove(name);
                if let Some(value) = record.get("proposal") {
                    let proposal: Proposal =
                        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
                    proposal.validate()?;
                    if proposal.name != name
                        || record["content_hash"]
                            != json!(proposal.after.as_ref().map(Content::hash))
                    {
                        return Err("skill decision disagrees with its proposal".into());
                    }
                    if let Some(content) = &proposal.after {
                        origins.insert(name.to_string(), (content.hash(), proposal, date));
                    }
                }
            }
            Ok(())
        },
    )?;
    let mut versions = Vec::new();
    for name in crate::skill_store::names(context)? {
        let Some(content) = crate::skill_store::current(context, &name)? else {
            continue;
        };
        crate::skill_store::parse(context, &name, &content)?;
        let hash = content.hash();
        let origin = origins
            .remove(&name)
            .filter(|(expected, _, _)| *expected == hash)
            .map(|(_, proposal, date)| (proposal, date));
        let archive_denied = denied.contains(&(name.clone(), hash));
        versions.push(Version {
            name,
            content,
            origin,
            archive_denied,
        });
    }
    let mut approved: Vec<_> = versions
        .iter()
        .map(|v| (v.name.clone(), v.content.hash(), false))
        .collect();
    crate::skill_store::approvals(context, &mut approved)?;
    versions.retain(|v| {
        approved
            .iter()
            .any(|(name, _, admitted)| *admitted && *name == v.name)
    });
    Ok(versions)
}

fn when(content: &Content) -> Option<String> {
    let (_, body) = content
        .skill_md
        .strip_prefix("---\n")?
        .split_once("\n---\n")?;
    let (_, section) = body.split_once("## When it applies\n")?;
    let section = section.split("\n## ").next()?;
    let normalized = section
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    (!normalized.is_empty()).then_some(normalized)
}

pub fn overlaps(versions: &[Version]) -> Vec<Value> {
    let mut sections: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for v in versions {
        if let Some(section) = when(&v.content) {
            sections.entry(section).or_default().push(&v.name);
        }
    }
    sections.into_iter().filter(|(_, names)| names.len() > 1)
        .map(|(section, names)| json!({"names": names, "when": section,
            "basis": "identical When it applies sections after case and whitespace normalization; inspect before merging"})).collect()
}

/// Midnight UTC; no implicit retention duration or host timezone.
pub fn cutoff(value: &str) -> Result<u64, String> {
    let invalid = || "cleanup --since needs a valid YYYY-MM-DD date from 1970 onward".to_string();
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(i, b)| !matches!(i, 4 | 7) && !b.is_ascii_digit())
    {
        return Err(invalid());
    }
    let year: u32 = value[..4].parse().map_err(|_| invalid())?;
    let month: usize = value[5..7].parse().map_err(|_| invalid())?;
    let day: u64 = value[8..].parse().map_err(|_| invalid())?;
    let leap = |y: u32| y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    let months = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if year < 1970 || !(1..=12).contains(&month) || day == 0 || day > months[month - 1] {
        return Err(invalid());
    }
    let days: u64 = (1970..year)
        .map(|y| if leap(y) { 366 } else { 365 })
        .sum::<u64>()
        + months[..month - 1].iter().sum::<u64>()
        + day
        - 1;
    Ok(days * 86_400_000)
}

pub const LIMITATIONS: &str = "Only recorded history is inspected. Deleted sessions and prior ephemeral runs cannot be reconstructed. Loads and loaded snapshots do not establish usefulness.";

pub fn propose(context: &ToolContext, since_ms: u64) -> Result<Value, String> {
    let now = crate::pending::now_ms()?;
    if since_ms > now {
        return Err("cleanup cutoff must not be in the future".into());
    }
    if let Some(path) = context
        .state
        .existing_file(Path::new("batteries/changes.jsonl"))?
    {
        crate::skill_usage::complete_file(&path)?;
    }
    let versions = versions(context)?;
    let usage = crate::skill_usage::scan(context)?;
    let mut proposals = Vec::new();
    let mut retained = Vec::new();
    for version in &versions {
        let last_load = usage.last_load.get(&version.name).map(|load| load.date_ms);
        let last_snapshot = usage.last_snapshot.get(&version.name).copied();
        let reason = match &version.origin {
            None => Some("current version is user-managed"),
            Some((_, date)) if *date >= since_ms => {
                Some("current version was approved since cutoff")
            }
            _ if last_load.is_some_and(|date| date >= since_ms)
                || last_snapshot.is_some_and(|date| date >= since_ms) =>
            {
                Some("recorded skill activity since cutoff")
            }
            _ if version.archive_denied => Some("archiving this version was denied"),
            _ if !usage.unavailable.is_empty() => Some("recorded history is unavailable"),
            Some((origin, _)) if !usage.source_available(&origin.source) => {
                Some("origin evidence is unavailable")
            }
            _ => None,
        };
        if let Some(reason) = reason {
            retained.push(json!({"name": version.name, "reason": reason, "last_load_ms": last_load, "last_snapshot_ms": last_snapshot}));
            continue;
        }
        let proposal = Proposal {
            version: 1,
            kind: "skill".into(),
            name: version.name.clone(),
            before: Some(version.content.clone()),
            after: None,
            source: version.origin.as_ref().unwrap().0.source.clone(),
            date_ms: now,
            cleanup: Some(crate::skill_pending::Cleanup {
                since_ms,
                checked_ms: now,
                last_load_ms: last_load,
                last_snapshot_ms: last_snapshot,
                recorded_sessions: usage.sessions_read,
                limitations: LIMITATIONS.into(),
            }),
        };
        let id = crate::skill_pending::propose(context, &proposal)?
            .ok_or("archive proposal unexpectedly empty")?;
        proposals.push(json!({"id": id, "change": crate::skill_pending::load(context, &id)?,
            "archive_on_approval": crate::skill_archive::relative(&version.name, &version.content)}));
    }
    Ok(
        json!({"version": 1, "since_ms": since_ms, "checked_ms": now,
        "requires_approval": true, "proposals": proposals, "retained": retained, "overlaps": overlaps(&versions),
        "coverage": {"sessions_read": usage.sessions_read, "unavailable": usage.unavailable,
            "limitations": LIMITATIONS}}),
    )
}
