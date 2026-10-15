//! Approved skill versions bind both SKILL.md and optional NOTES.md bytes.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::json;

use crate::batteries::paths::ToolContext;
use crate::batteries::pending::Decision;
use crate::batteries::skill_format::{Content, MAX_BYTES, Metadata};

pub fn relative(name: &str, file: &str) -> Result<PathBuf, String> {
    if !crate::batteries::skill_format::valid_name(name) || !matches!(file, "SKILL.md" | "NOTES.md")
    {
        return Err("invalid skill path".into());
    }
    Ok(Path::new("batteries/skills").join(name).join(file))
}

fn read(context: &ToolContext, relative: &Path) -> Result<Option<String>, String> {
    let Some(path) = context.state.existing_file(relative)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|error| error.to_string())?
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > MAX_BYTES {
        return Err("skill file exceeds 256 KiB".into());
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| "skill file is not UTF-8".into())
}

pub fn current(context: &ToolContext, name: &str) -> Result<Option<Content>, String> {
    let skill = read(context, &relative(name, "SKILL.md")?)?;
    let notes = read(context, &relative(name, "NOTES.md")?)?;
    match skill {
        Some(skill_md) => Ok(Some(Content {
            skill_md,
            notes_md: notes,
        })),
        None if notes.is_some() => Err("NOTES.md has no SKILL.md".into()),
        None => Ok(None),
    }
}

pub fn parse(context: &ToolContext, name: &str, content: &Content) -> Result<Metadata, String> {
    let limits = crate::batteries::skill_config::load(&context.state)?;
    content.parse(name, limits.skill_chars, limits.notes_chars)
}

pub fn approved(context: &ToolContext, name: &str, hash: &str) -> Result<bool, String> {
    let mut versions = vec![(name.to_string(), hash.to_string(), false)];
    approvals(context, &mut versions)?;
    Ok(versions[0].2)
}

pub fn approvals(
    context: &ToolContext,
    versions: &mut [(String, String, bool)],
) -> Result<(), String> {
    crate::batteries::journal::visit(
        &context.state,
        Path::new("batteries/changes.jsonl"),
        |record| {
            if record["version"] != 1
                || !matches!(record["decision"].as_str(), Some("approve" | "deny"))
            {
                return Err("unsupported or malformed decision record".into());
            }
            if record["kind"] == "skill" && record["decision"] == "approve" {
                for (name, hash, approved) in &mut *versions {
                    *approved |= record["name"] == *name && record["content_hash"] == *hash;
                }
            }
            Ok(())
        },
    )
}

pub fn admit(
    context: &ToolContext,
    name: &str,
    hash: &str,
    decision: Decision,
) -> Result<(), String> {
    if decision == Decision::Postpone {
        return Ok(());
    }
    let content = current(context, name)?.ok_or("skill is unavailable")?;
    if content.hash() != hash {
        return Err("skill changed since it was shown".into());
    }
    parse(context, name, &content)?;
    let path = context.state.file(Path::new("batteries/changes.jsonl"))?;
    crate::batteries::journal::append_at(
        &context.state,
        &path,
        &json!({"version": 1, "kind": "skill", "name": name,
        "content_hash": hash, "content": content, "decision": decision, "date_ms": crate::batteries::pending::now_ms()?,
        "source": {"path": format!("batteries/skills/{name}")}}),
    )
}

pub fn names(context: &ToolContext) -> Result<Vec<String>, String> {
    let Some(path) = context
        .state
        .existing_directory(Path::new("batteries/skills"))?
    else {
        return Ok(Vec::new());
    };
    let mut names = Vec::new();
    for entry in std::fs::read_dir(path).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "skill directory name is not ASCII")?;
        if name.starts_with(".gears-tmp-") {
            continue;
        }
        if !crate::batteries::skill_format::valid_name(&name) {
            return Err(format!("invalid skill directory name: {name}"));
        }
        names.push(name);
        if names.len() > 128 {
            return Err("more than 128 skill directories".into());
        }
    }
    names.sort();
    Ok(names)
}

pub fn write(context: &ToolContext, name: &str, content: Option<&Content>) -> Result<(), String> {
    for (file, text) in [
        ("SKILL.md", content.map(|content| content.skill_md.as_str())),
        (
            "NOTES.md",
            content.and_then(|content| content.notes_md.as_deref()),
        ),
    ] {
        let path = relative(name, file)?;
        if let Some(text) = text {
            context.state.replace_file(&path, text.as_bytes())?;
        } else if let Some(path) = context.state.existing_file(&path)? {
            std::fs::remove_file(path).map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_notes_edit_hides_the_version_and_a_stale_file_admission_cannot_bless_it() {
        let path =
            std::env::temp_dir().join(format!("batteries-skill-store-{}", std::process::id()));
        std::fs::create_dir_all(path.join("workspace")).unwrap();
        let context = ToolContext::new(
            path.join("workspace"),
            path.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        let mut content = Content { skill_md: "---\nname: checks\ndescription: Run checks.\nmetadata:\n  platforms: motor\n---\nInstructions.\n".into(), notes_md: Some("Original note.\n".into()) };
        write(&context, "checks", Some(&content)).unwrap();
        let hash = content.hash();
        assert!(!approved(&context, "checks", &hash).unwrap());
        admit(&context, "checks", &hash, Decision::Postpone).unwrap();
        assert!(!approved(&context, "checks", &hash).unwrap());
        admit(&context, "checks", &hash, Decision::Approve).unwrap();
        assert!(approved(&context, "checks", &hash).unwrap());
        content.notes_md = Some("Changed note.\n".into());
        write(&context, "checks", Some(&content)).unwrap();
        assert!(!approved(&context, "checks", &content.hash()).unwrap());
        assert!(
            admit(&context, "checks", &hash, Decision::Approve)
                .unwrap_err()
                .contains("changed since")
        );
        assert_eq!(
            crate::batteries::memory_history::history(&context, 0, 20).unwrap()["total"],
            1
        );
        assert_eq!(names(&context).unwrap(), ["checks"]);
        assert!(relative("../escape", "SKILL.md").is_err());
        #[cfg(unix)]
        {
            let notes = context
                .state
                .path()
                .join(relative("checks", "NOTES.md").unwrap());
            std::fs::remove_file(&notes).unwrap();
            std::os::unix::fs::symlink(path.join("outside"), &notes).unwrap();
            assert!(
                current(&context, "checks")
                    .unwrap_err()
                    .contains("expected regular file, found symlink")
            );
            assert!(write(&context, "checks", Some(&content)).is_err());
        }
        std::fs::remove_dir_all(path).unwrap();
    }
}
