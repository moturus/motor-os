//! `gears reset` and `/reset` remove everything the user and Gears added.

use std::path::Path;

/// What an installation provides in the Gears directory; reset keeps it, and
/// the lock file, which a running Gears holds.
const KEPT: [&str; 4] = ["gears.toml", "gears-batteries.toml", "tools", "gears.lock"];

pub const DESCRIPTION: &str = "Reset Gears: remove keys, saved settings, memory, skills and \
    sessions from the Gears directory (keeping gears.toml, gears-batteries.toml and tools/) \
    and remove .gears/ from this directory.";

/// Returns how many entries were removed. The caller holds the directory lock.
pub fn reset(directory: &Path, workspace: &Path) -> Result<usize, String> {
    let directory = canonical(directory)?;
    if directory.parent().is_none()
        || std::env::var_os("HOME")
            .is_some_and(|home| canonical(Path::new(&home)).ok() == Some(directory.clone()))
    {
        return Err(format!(
            "refusing to reset {}: it is not a Gears directory",
            directory.display()
        ));
    }
    let mut removed = 0;
    for entry in std::fs::read_dir(&directory).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if KEPT.iter().any(|name| entry.file_name() == *name) {
            continue;
        }
        remove(&entry.path())?;
        removed += 1;
    }
    let local = workspace.join(".gears");
    // `~/.gears` is the Linux Gears directory itself when run from the home directory.
    if std::fs::symlink_metadata(&local).is_ok() && !directory.starts_with(canonical(&local)?) {
        remove(&local)?;
        removed += 1;
    }
    Ok(removed)
}

fn canonical(path: &Path) -> Result<std::path::PathBuf, String> {
    path.canonicalize()
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn remove(path: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
    .map_err(|error| format!("{}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_keeps_the_installation_and_removes_everything_else() {
        let root = std::env::temp_dir().join(format!("gears-reset-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let directory = root.join("gears");
        let workspace = root.join("workspace");
        for path in [
            "gears/tools/sh",
            "gears/sessions/group",
            "gears/batteries/skills/s",
            "workspace/.gears",
        ] {
            std::fs::create_dir_all(root.join(path)).unwrap();
        }
        for file in [
            "gears/gears.toml",
            "gears/gears-batteries.toml",
            "gears/gears.lock",
            "gears/tools/sh/tool.toml",
            "gears/openrouter.key",
            "gears/provider.toml",
            "gears/permissions.toml",
            "gears/tools.toml",
            "gears/batteries.toml",
            "gears/batteries/MEMORY.md",
            "gears/sessions/group/s.jsonl",
            "workspace/.gears/MEMORY.md",
            "workspace/AGENTS.md",
        ] {
            std::fs::write(root.join(file), "x").unwrap();
        }
        assert_eq!(reset(&directory, &workspace).unwrap(), 8);
        let mut left = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        left.sort();
        assert_eq!(
            left,
            ["gears-batteries.toml", "gears.lock", "gears.toml", "tools"]
        );
        assert!(root.join("gears/tools/sh/tool.toml").is_file());
        assert!(!workspace.join(".gears").exists());
        assert!(workspace.join("AGENTS.md").is_file());
        assert_eq!(reset(&directory, &workspace).unwrap(), 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_workspace_whose_gears_directory_is_the_gears_directory_keeps_the_installation() {
        let root = std::env::temp_dir().join(format!("gears-reset-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(".gears/tools")).unwrap();
        std::fs::write(root.join(".gears/gears.toml"), "x").unwrap();
        std::fs::write(root.join(".gears/local.key"), "x").unwrap();
        assert_eq!(reset(&root.join(".gears"), &root).unwrap(), 1);
        assert!(root.join(".gears/gears.toml").is_file());
        assert!(root.join(".gears/tools").is_dir());
        assert!(reset(Path::new("/"), &root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
