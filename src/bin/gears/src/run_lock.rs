//! One Gears owner per user-state directory.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::platform;
use crate::state::StateRoot;

const OWNER_ENV: &str = "GEARS_LOCK_OWNER";
const INCOMPLETE_GRACE: Duration = Duration::from_secs(2);

pub struct DirectoryLock {
    state: StateRoot,
    path: Option<PathBuf>,
    owner: u32,
}

impl DirectoryLock {
    /// # Safety
    /// Call only while process startup is single-threaded.
    pub unsafe fn select_directory(directory: &Path) -> Result<(), String> {
        let previous = crate::directory::default_root()
            .ok()
            .and_then(|root| root.canonicalize().ok());
        let directory = if directory.is_absolute() {
            directory.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|e| e.to_string())?
                .join(directory)
        };
        let selected = StateRoot::new(directory)?
            .directory(Path::new(""))?
            .canonicalize()
            .map_err(|e| e.to_string())?;
        // A different directory needs its own owner; the ancestor still owns its root.
        if previous.as_ref() != Some(&selected) {
            unsafe { std::env::remove_var(OWNER_ENV) };
        }
        unsafe { std::env::set_var(crate::directory::ENV, selected) };
        Ok(())
    }

    pub fn acquire_default() -> Result<Self, String> {
        Self::acquire_at(&crate::directory::default_root()?)
    }

    pub fn acquire_at(root: &Path) -> Result<Self, String> {
        let state = StateRoot::new(root.to_path_buf())?;
        let path = state.file(Path::new("gears.lock"))?;
        if let Ok(owner) = std::env::var(OWNER_ENV) {
            let owner = owner
                .parse::<u32>()
                .map_err(|_| "invalid inherited Gears lock owner".to_string())?;
            if owner == 0
                || !platform::process_is_descendant_of(owner)
                || !platform::process_is_gears(owner)
                || lock_pid(&path) != Some(owner)
            {
                return Err("inherited Gears lock owner is not a live ancestor".to_string());
            }
            return Ok(Self {
                state,
                path: None,
                owner,
            });
        }
        for attempt in 0..2 {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    let owner = std::process::id();
                    if let Err(error) = writeln!(file, "{owner}").and_then(|()| file.sync_data()) {
                        let _ = std::fs::remove_file(&path);
                        return Err(format!("{}: {error}", path.display()));
                    }
                    return Ok(Self {
                        state,
                        path: Some(path),
                        owner,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && attempt == 0 => {
                    let metadata = std::fs::symlink_metadata(&path)
                        .map_err(|error| format!("{}: {error}", path.display()))?;
                    if !metadata.file_type().is_file() {
                        return Err(format!("unsafe Gears lock {}", path.display()));
                    }
                    match lock_pid(&path) {
                        Some(pid)
                            if pid != std::process::id()
                                && platform::process_alive(pid)
                                && platform::process_is_gears(pid) =>
                        {
                            return Err(format!("Gears directory is locked by process {pid}"));
                        }
                        None if metadata
                            .modified()
                            .ok()
                            .and_then(|time| time.elapsed().ok())
                            .is_none_or(|age| age < INCOMPLETE_GRACE) =>
                        {
                            return Err("Gears lock is being initialized".to_string());
                        }
                        _ => {}
                    }
                    // The publication race is tracked in docs/plans/future-work.md.
                    std::fs::remove_file(&path)
                        .map_err(|error| format!("cannot remove stale lock: {error}"))?;
                }
                Err(error) => return Err(format!("cannot lock {}: {error}", path.display())),
            }
        }
        Err(format!("cannot lock {}", path.display()))
    }

    pub fn cleanup_temporaries(&self) -> Result<usize, String> {
        if self.path.is_none() {
            return Ok(0);
        }
        self.state.cleanup_temporary_files()
    }

    pub fn owner(&self) -> u32 {
        self.owner
    }

    /// # Safety
    /// Call only while process startup is single-threaded.
    pub unsafe fn export_owner(&self) {
        if self.path.is_some() {
            unsafe { std::env::set_var(OWNER_ENV, self.owner.to_string()) };
        }
    }
}

impl Drop for DirectoryLock {
    fn drop(&mut self) {
        if let Some(path) = &self.path
            && lock_pid(path) == Some(self.owner)
        {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn lock_pid(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_a_stale_pid_and_removes_its_own_lock() {
        let root = std::env::temp_dir().join(format!("gears-run-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("gears.lock"), "0\n").unwrap();
        let lock = DirectoryLock::acquire_at(&root).unwrap();
        assert_eq!(lock_pid(&root.join("gears.lock")), Some(std::process::id()));
        drop(lock);
        assert!(!root.join("gears.lock").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_fresh_incomplete_lock_is_not_removed() {
        let root = std::env::temp_dir().join(format!("gears-empty-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("gears.lock"), "").unwrap();
        let error = DirectoryLock::acquire_at(&root).err().unwrap();
        assert!(error.contains("initialized"), "{error}");
        assert!(root.join("gears.lock").exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}
