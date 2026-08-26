//! Symlink-safe access to Gears-owned user state.

use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone)]
pub struct StateRoot {
    root: PathBuf,
}

impl StateRoot {
    pub fn new(root: PathBuf) -> Result<Self, String> {
        if root.exists() {
            checked_directory(&root)?;
        } else if let Ok(metadata) = std::fs::symlink_metadata(&root) {
            return Err(not_directory(&root, &metadata));
        }
        Ok(Self { root })
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    pub fn directory(&self, relative: &Path) -> Result<PathBuf, String> {
        let components = components(relative, true)?;
        ensure_ancestors(&self.root)?;
        ensure_directory(&self.root)?;
        let mut path = self.root.clone();
        for component in components {
            path.push(component);
            ensure_directory(&path)?;
        }
        Ok(path)
    }

    pub fn existing_directory(&self, relative: &Path) -> Result<Option<PathBuf>, String> {
        let components = components(relative, true)?;
        let mut path = self.root.clone();
        for component in std::iter::once(None).chain(components.into_iter().map(Some)) {
            if let Some(component) = component {
                path.push(component);
            }
            match std::fs::symlink_metadata(&path) {
                Ok(metadata) => checked_directory_with(&path, &metadata)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(format!("{}: {error}", path.display())),
            }
        }
        Ok(Some(path))
    }

    pub fn file(&self, relative: &Path) -> Result<PathBuf, String> {
        let mut parts = components(relative, false)?;
        let name = parts.pop().expect("a file name was checked");
        let parent = parts.into_iter().collect::<PathBuf>();
        let path = self.directory(&parent)?.join(name);
        check_file_or_missing(&path)?;
        Ok(path)
    }

    pub fn existing_file(&self, relative: &Path) -> Result<Option<PathBuf>, String> {
        let mut parts = components(relative, false)?;
        let name = parts.pop().expect("a file name was checked");
        let parent = parts.into_iter().collect::<PathBuf>();
        let Some(parent) = self.existing_directory(&parent)? else {
            return Ok(None);
        };
        let path = parent.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => Ok(Some(path)),
            Ok(metadata) => Err(not_file(&path, &metadata)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("{}: {error}", path.display())),
        }
    }
}

fn ensure_ancestors(path: &Path) -> Result<(), String> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.exists() {
        checked_directory(parent)?;
        return Ok(());
    }
    ensure_ancestors(parent)?;
    match std::fs::create_dir(parent) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            checked_directory(parent)
        }
        Err(error) => Err(format!("{}: {error}", parent.display())),
    }
}

fn components(relative: &Path, allow_empty: bool) -> Result<Vec<PathBuf>, String> {
    if relative.is_absolute() {
        return Err(format!(
            "state path {} must be relative",
            relative.display()
        ));
    }
    let mut result = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(name) => result.push(PathBuf::from(name)),
            _ => {
                return Err(format!(
                    "state path {} contains a non-normal component",
                    relative.display()
                ));
            }
        }
    }
    if !allow_empty && result.is_empty() {
        return Err("a state file needs a name".to_string());
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

fn check_file_or_missing(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(metadata) => Err(not_file(path, &metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

fn checked_directory(path: &Path) -> Result<(), String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    checked_directory_with(path, &metadata)
}

fn checked_directory_with(path: &Path, metadata: &std::fs::Metadata) -> Result<(), String> {
    if metadata.file_type().is_dir() {
        Ok(())
    } else {
        Err(not_directory(path, metadata))
    }
}

fn not_directory(path: &Path, metadata: &std::fs::Metadata) -> String {
    format!(
        "{}: unsafe state component (expected directory, found {})",
        path.display(),
        kind(metadata)
    )
}

fn not_file(path: &Path, metadata: &std::fs::Metadata) -> String {
    format!(
        "{}: unsafe state entry (expected regular file, found {})",
        path.display(),
        kind(metadata)
    )
}

fn kind(metadata: &std::fs::Metadata) -> &'static str {
    let kind = metadata.file_type();
    if kind.is_symlink() {
        "symlink"
    } else if kind.is_dir() {
        "directory"
    } else if kind.is_file() {
        "regular file"
    } else {
        "special file"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("gears-state-{name}-{}", std::process::id()))
    }

    #[test]
    fn creates_a_checked_tree() {
        let root = temp("tree");
        let _ = std::fs::remove_dir_all(&root);
        let state = StateRoot::new(root.clone()).unwrap();
        let file = state
            .file(Path::new("sessions/work/session.jsonl"))
            .unwrap();
        std::fs::write(&file, "ok").unwrap();
        assert_eq!(
            state
                .existing_file(Path::new("sessions/work/session.jsonl"))
                .unwrap(),
            Some(file)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_components() {
        use std::os::unix::fs::symlink;

        let root = temp("link");
        let outside = temp("outside");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        symlink(&outside, root.join("sessions")).unwrap();
        let state = StateRoot::new(root.clone()).unwrap();
        assert!(state.file(Path::new("sessions/x")).is_err());
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }
}
