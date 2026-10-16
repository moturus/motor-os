//! The user's skill directories: SKILL.md with an optional NOTES.md beside it.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::batteries::paths::ToolContext;
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
    fn skills_are_read_back_as_written_and_bad_paths_are_refused() {
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
        assert_eq!(current(&context, "checks").unwrap().unwrap(), content);
        content.notes_md = Some("Changed note.\n".into());
        write(&context, "checks", Some(&content)).unwrap();
        assert_eq!(current(&context, "checks").unwrap().unwrap(), content);
        assert!(current(&context, "absent").unwrap().is_none());
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
