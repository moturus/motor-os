//! Paths for gears-owned state inside a workspace.
//!
//! Repository contents are untrusted. In particular, ordinary
//! `create_dir_all(".gears/...")` follows a checked-out `.gears` symlink.
//! This module walks each state-directory component without following links
//! and refuses a state file that is already anything but a regular file.

use std::path::{Component, Path, PathBuf};

pub const STATE_DIR: &str = ".gears";

#[derive(Debug, Clone)]
pub struct StateDir {
    root: PathBuf,
}

impl StateDir {
    /// Bind state to a real workspace directory. This is lazy: it validates
    /// an existing `.gears`, but does not create one until a path is asked for.
    pub fn new(workspace: &Path) -> Result<StateDir, String> {
        let workspace = workspace
            .canonicalize()
            .map_err(|error| format!("workspace {}: {error}", workspace.display()))?;
        if !workspace.is_dir() {
            return Err(format!(
                "workspace {} is not a directory",
                workspace.display()
            ));
        }
        let state = StateDir {
            root: workspace.join(STATE_DIR),
        };
        if state.root.exists() {
            checked_directory(&state.root)?;
        } else if let Ok(metadata) = std::fs::symlink_metadata(&state.root) {
            return Err(not_directory(&state.root, &metadata));
        }
        Ok(state)
    }

    /// Ensure a state-owned directory and all of its parents are real
    /// directories, never symlinks.
    pub fn directory(&self, relative: &Path) -> Result<PathBuf, String> {
        let components = components(relative, true)?;
        ensure_directory(&self.root)?;
        let mut path = self.root.clone();
        for component in components {
            path.push(component);
            ensure_directory(&path)?;
        }
        Ok(path)
    }

    /// Return a state-owned file path after safely creating its parents and
    /// refusing a pre-existing symlink, directory, or special file.
    pub fn file(&self, relative: &Path) -> Result<PathBuf, String> {
        let mut components = components(relative, false)?;
        let name = components.pop().unwrap();
        let mut parent = PathBuf::new();
        for component in components {
            parent.push(component);
        }
        let path = self.directory(&parent)?.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => Ok(path),
            Ok(metadata) => Err(not_file(&path, &metadata)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(path),
            Err(error) => Err(format!("{}: {error}", path.display())),
        }
    }
}

fn components(relative: &Path, empty: bool) -> Result<Vec<PathBuf>, String> {
    if relative.is_absolute() {
        return Err(format!(
            "{}: gears state paths must be relative",
            relative.display()
        ));
    }
    let mut result = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(name) => result.push(PathBuf::from(name)),
            _ => {
                return Err(format!(
                    "{}: gears state paths must not contain '.' or '..'",
                    relative.display()
                ));
            }
        }
    }
    if !empty && result.is_empty() {
        return Err("a gears state file needs a name".to_string());
    }
    Ok(result)
}

fn ensure_directory(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => checked_directory_with(path, &metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::create_dir(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    checked_directory(path)
                }
                Err(error) => Err(format!("{}: {error}", path.display())),
            }
        }
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

fn checked_directory(path: &Path) -> Result<(), String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    checked_directory_with(path, &metadata)
}

fn checked_directory_with(path: &Path, metadata: &std::fs::Metadata) -> Result<(), String> {
    match metadata.file_type().is_dir() {
        true => Ok(()),
        false => Err(not_directory(path, metadata)),
    }
}

fn not_directory(path: &Path, metadata: &std::fs::Metadata) -> String {
    format!(
        "{}: unsafe gears state component (expected a directory, found {})",
        path.display(),
        kind(metadata)
    )
}

fn not_file(path: &Path, metadata: &std::fs::Metadata) -> String {
    format!(
        "{}: unsafe gears state entry (expected a regular file, found {})",
        path.display(),
        kind(metadata)
    )
}

fn kind(metadata: &std::fs::Metadata) -> &'static str {
    let kind = metadata.file_type();
    if kind.is_symlink() {
        "a symlink"
    } else if kind.is_dir() {
        "a directory"
    } else if kind.is_file() {
        "a regular file"
    } else {
        "a special file"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn workspace(name: &str) -> PathBuf {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "gears-state-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn state_is_lazy_and_creates_only_real_components() {
        let root = workspace("basic");
        let state = StateDir::new(&root).unwrap();
        assert!(!root.join(STATE_DIR).exists());
        let file = state.file(Path::new("sessions/1-2.jsonl")).unwrap();
        assert!(file.parent().unwrap().is_dir());
        std::fs::write(&file, "session\n").unwrap();
        assert_eq!(state.file(Path::new("sessions/1-2.jsonl")).unwrap(), file);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn state_paths_are_relative_and_normal() {
        let root = workspace("paths");
        let state = StateDir::new(&root).unwrap();
        for path in ["../outside", "sessions/../outside", ".", ""] {
            assert!(state.file(Path::new(path)).is_err(), "accepted {path:?}");
        }
        assert!(state.file(Path::new("/tmp/outside")).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn state_refuses_root_nested_and_file_symlinks() {
        use std::os::unix::fs::symlink;

        let root = workspace("links");
        let outside = workspace("outside");
        symlink(&outside, root.join(STATE_DIR)).unwrap();
        let error = StateDir::new(&root).unwrap_err();
        assert!(error.contains("symlink"), "{error}");
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none());
        std::fs::remove_file(root.join(STATE_DIR)).unwrap();

        let state = StateDir::new(&root).unwrap();
        let sessions = state.directory(Path::new("sessions")).unwrap();
        symlink(&outside, sessions.join("redirect")).unwrap();
        assert!(
            state
                .directory(Path::new("sessions/redirect/deeper"))
                .is_err()
        );
        symlink(outside.join("file"), sessions.join("linked.jsonl")).unwrap();
        assert!(state.file(Path::new("sessions/linked.jsonl")).is_err());
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none());
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }
}
