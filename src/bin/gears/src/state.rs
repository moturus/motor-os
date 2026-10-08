//! Symlink-safe access to Gears-owned user state.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

const TEMP_PREFIX: &str = ".gears-tmp-";
static NEXT_TEMP: AtomicU32 = AtomicU32::new(0);

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

    /// Replace one Gears-owned file without exposing a partially written value.
    pub fn replace_file(&self, relative: &Path, bytes: &[u8]) -> Result<(), String> {
        self.replace(relative, bytes, false)
    }

    /// Replace a workspace file, preserving Unix permission bits or the
    /// caller's Motor OS access. Other native roles retain creation defaults.
    pub fn replace_file_preserving_access(
        &self,
        relative: &Path,
        bytes: &[u8],
    ) -> Result<(), String> {
        self.replace(relative, bytes, true)
    }

    fn replace(&self, relative: &Path, bytes: &[u8], preserve_access: bool) -> Result<(), String> {
        let destination = self.file(relative)?;
        let parent = destination.parent().expect("state files have a parent");
        let temp = parent.join(format!(
            "{TEMP_PREFIX}{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                // A new workspace file gets the usual umask-based permissions.
                options.mode(if preserve_access { 0o666 } else { 0o600 });
            }
            let mut file = options
                .open(&temp)
                .map_err(|error| format!("{}: {error}", temp.display()))?;
            file.write_all(bytes)
                .and_then(|()| file.sync_data())
                .map_err(|error| format!("{}: {error}", temp.display()))?;
            if preserve_access {
                preserve_permissions(&destination, &temp)?;
                file.sync_all()
                    .map_err(|error| format!("{}: {error}", temp.display()))?;
            }
            std::fs::rename(&temp, &destination)
                .map_err(|error| format!("{}: {error}", destination.display()))
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        result
    }

    /// Read a TOML file whose `version` must match; a missing file is the default.
    pub fn load_toml<T: serde::de::DeserializeOwned + Default>(
        &self,
        name: &str,
        version: u32,
    ) -> Result<T, String> {
        let Some(path) = self.existing_file(Path::new(name))? else {
            return Ok(T::default());
        };
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let mut table: toml::Table =
            toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        match table.remove("version") {
            Some(toml::Value::Integer(found)) if found == i64::from(version) => {}
            found => {
                return Err(format!(
                    "{}: unsupported version {} (expected {version})",
                    path.display(),
                    found.map_or("none".to_string(), |found| found.to_string())
                ));
            }
        }
        T::deserialize(toml::Value::Table(table))
            .map_err(|error| format!("{}: {error}", path.display()))
    }

    /// Replace a TOML file, recording its format version.
    pub fn save_toml<T: serde::Serialize>(
        &self,
        name: &str,
        version: u32,
        data: &T,
    ) -> Result<(), String> {
        let mut table = toml::Table::try_from(data)
            .map_err(|error| format!("cannot serialize {name}: {error}"))?;
        table.insert("version".into(), toml::Value::Integer(version.into()));
        let text =
            toml::to_string(&table).map_err(|error| format!("cannot serialize {name}: {error}"))?;
        self.replace_file(Path::new(name), text.as_bytes())
    }

    /// Remove only temporary files made by `replace_file` after a crash.
    pub fn cleanup_temporary_files(&self) -> Result<usize, String> {
        let Some(root) = self.existing_directory(Path::new(""))? else {
            return Ok(0);
        };
        cleanup_temporary_files(&root)
    }
}

fn preserve_permissions(source: &Path, temporary: &Path) -> Result<(), String> {
    let metadata = match std::fs::metadata(source) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("{}: {error}", source.display())),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Replacing contents does not preserve setuid, setgid or sticky bits.
        let mode = metadata.permissions().mode() & 0o777;
        std::fs::set_permissions(temporary, std::fs::Permissions::from_mode(mode))
            .map_err(|error| format!("{}: {error}", temporary.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        use moto_rt::fs::{PERM_EXEC, PERM_READ};
        let source = source.to_str().ok_or("file path is not UTF-8")?;
        let temporary = temporary.to_str().ok_or("temporary path is not UTF-8")?;
        let mode = moto_rt::fs::stat(source)
            .map_err(|error| format!("{source}: {error:?}"))?
            .perm;
        // Native editable executables finalize rw- -> r-x -> rwx. Set access
        // only after the bytes are durable, before publishing the replacement.
        if mode & PERM_EXEC != 0 {
            moto_rt::fs::set_perm(temporary, PERM_READ | PERM_EXEC)
                .map_err(|error| format!("{temporary}: {error:?}"))?;
        }
        moto_rt::fs::set_perm(temporary, mode).map_err(|error| format!("{temporary}: {error:?}"))
    }
}

fn cleanup_temporary_files(directory: &Path) -> Result<usize, String> {
    let mut removed = 0;
    for entry in
        std::fs::read_dir(directory).map_err(|error| format!("{}: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| format!("{}: {error}", directory.display()))?;
        let path = entry.path();
        let kind = entry
            .file_type()
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if kind.is_dir() {
            removed += cleanup_temporary_files(&path)?;
        } else if kind.is_file() && entry.file_name().to_string_lossy().starts_with(TEMP_PREFIX) {
            std::fs::remove_file(&path).map_err(|error| format!("{}: {error}", path.display()))?;
            removed += 1;
        }
    }
    Ok(removed)
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

    #[test]
    fn replacement_is_complete_and_crash_temporaries_are_cleaned() {
        let root = temp("replacement");
        let _ = std::fs::remove_dir_all(&root);
        let state = StateRoot::new(root.clone()).unwrap();
        let relative = Path::new("settings/provider.toml");
        state.replace_file(relative, b"first").unwrap();
        state.replace_file(relative, b"second").unwrap();
        assert_eq!(
            std::fs::read(state.file(relative).unwrap()).unwrap(),
            b"second"
        );

        let settings = root.join("settings");
        std::fs::write(settings.join(".gears-tmp-crashed"), "partial").unwrap();
        std::fs::write(settings.join("keep.txt"), "keep").unwrap();
        assert_eq!(state.cleanup_temporary_files().unwrap(), 1);
        assert!(!settings.join(".gears-tmp-crashed").exists());
        assert_eq!(
            std::fs::read_to_string(settings.join("keep.txt")).unwrap(),
            "keep"
        );
        assert_eq!(
            std::fs::read(state.file(relative).unwrap()).unwrap(),
            b"second"
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

    #[cfg(unix)]
    #[test]
    fn new_workspace_files_get_ordinary_permissions_and_state_stays_private() {
        use std::os::unix::fs::PermissionsExt;
        let root = temp("modes");
        let _ = std::fs::remove_dir_all(&root);
        let state = StateRoot::new(root.clone()).unwrap();
        state.directory(Path::new("")).unwrap();
        std::fs::write(root.join("ordinary"), "x").unwrap();
        state
            .replace_file_preserving_access(Path::new("created"), b"x")
            .unwrap();
        state.replace_file(Path::new("private"), b"x").unwrap();
        let mode = |name: &str| {
            std::fs::metadata(root.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode("created"), mode("ordinary"));
        assert_eq!(mode("private"), 0o600);
        std::fs::remove_dir_all(root).unwrap();
    }
}
