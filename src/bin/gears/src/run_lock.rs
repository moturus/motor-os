//! One Gears owner per user-state directory.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use crate::platform;
use crate::state::StateRoot;

const OWNER_ENV: &str = "GEARS_LOCK_OWNER";
const INCOMPLETE_GRACE: Duration = Duration::from_secs(2);

/// The owner holds an exclusive lock on `gears.lock` for the whole run. The
/// system drops the lock when the owner exits or is killed, so no file is ever
/// judged stale or removed; the PID inside only names the owner.
pub struct DirectoryLock {
    state: StateRoot,
    /// The locked file; `None` in a nested Gears that shares its ancestor's lock.
    file: Option<File>,
    owner: u32,
}

impl DirectoryLock {
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
                file: None,
                owner,
            });
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|error| format!("cannot lock {}: {error}", path.display()))?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(match lock_pid(&path) {
                    Some(pid) => format!("Another gears session {pid} is running. Exiting."),
                    None => "Another gears session is running. Exiting.".into(),
                });
            }
            Err(TryLockError::Error(error)) => {
                return Err(format!("cannot lock {}: {error}", path.display()));
            }
        }
        let owner = std::process::id();
        file.set_len(0)
            .and_then(|()| writeln!(file, "{owner}"))
            .and_then(|()| file.sync_data())
            .map_err(|error| format!("{}: {error}", path.display()))?;
        Ok(Self {
            state,
            file: Some(file),
            owner,
        })
    }

    /// Only the lock's owner cleans up; a nested Gears shares a live directory.
    pub fn cleanup_temporaries(&self) -> Result<usize, String> {
        if self.file.is_none() {
            return Ok(0);
        }
        Ok(self.state.cleanup_temporary_files()?
            + crate::session::remove_abandoned_shell_state(&self.state)?)
    }

    pub fn owner(&self) -> u32 {
        self.owner
    }

    /// False in a nested Gears, which shares its ancestor's lock.
    pub fn owns_directory(&self) -> bool {
        self.file.is_some()
    }

    /// # Safety
    /// Call only while process startup is single-threaded.
    pub unsafe fn export_owner(&self) {
        if self.file.is_some() {
            unsafe { std::env::set_var(OWNER_ENV, self.owner.to_string()) };
        }
    }
}

fn lock_pid(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Create a lock file holding this process id. A file whose owner is gone is
/// replaced; one still being written gets a short grace period.
pub(crate) fn create_pid_file(
    path: &Path,
    live_owner: fn(u32) -> bool,
    held: impl Fn(u32) -> String,
) -> Result<(), String> {
    for attempt in 0..2 {
        match OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(mut file) => {
                let owner = std::process::id();
                if let Err(error) = writeln!(file, "{owner}").and_then(|()| file.sync_data()) {
                    let _ = std::fs::remove_file(path);
                    return Err(format!("{}: {error}", path.display()));
                }
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && attempt == 0 => {
                let metadata = std::fs::symlink_metadata(path)
                    .map_err(|error| format!("{}: {error}", path.display()))?;
                if !metadata.file_type().is_file() {
                    return Err(format!("unsafe lock {}", path.display()));
                }
                match lock_pid(path) {
                    Some(pid) if live_owner(pid) => return Err(held(pid)),
                    None if metadata
                        .modified()
                        .ok()
                        .and_then(|time| time.elapsed().ok())
                        .is_none_or(|age| age < INCOMPLETE_GRACE) =>
                    {
                        return Err(format!("lock {} is being initialized", path.display()));
                    }
                    _ => {}
                }
                // The publication race is tracked in docs/plans/future-work.md.
                std::fs::remove_file(path).map_err(|error| {
                    format!("cannot remove stale lock {}: {error}", path.display())
                })?;
            }
            Err(error) => return Err(format!("cannot lock {}: {error}", path.display())),
        }
    }
    Err(format!("cannot lock {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_held_lock_refuses_another_owner_and_its_file_stays() {
        let root = std::env::temp_dir().join(format!("gears-run-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("gears.lock");
        // A PID left by an earlier owner does not matter; only the lock does.
        std::fs::write(&path, "4242\n").unwrap();
        let lock = DirectoryLock::acquire_at(&root).unwrap();
        assert_eq!(lock_pid(&path), Some(std::process::id()));
        assert_eq!(
            DirectoryLock::acquire_at(&root).err().unwrap(),
            format!(
                "Another gears session {} is running. Exiting.",
                std::process::id()
            )
        );
        drop(lock);
        // Release is checked across processes (tool-smoke directory_lock): here a
        // test spawning in parallel can hold a forked copy of the file until exec.
        assert!(path.is_file());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exactly_one_of_concurrent_starts_gets_the_lock() {
        let root = std::env::temp_dir().join(format!("gears-lock-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let barrier = std::sync::Barrier::new(8);
        let winners = std::thread::scope(|scope| {
            let attempts = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        let lock = DirectoryLock::acquire_at(&root);
                        // Hold any lock until every thread has tried.
                        barrier.wait();
                        lock.is_ok()
                    })
                })
                .collect::<Vec<_>>();
            attempts
                .into_iter()
                .map(|attempt| attempt.join().unwrap())
                .filter(|won| *won)
                .count()
        });
        assert_eq!(winners, 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_owner_removes_shell_state_that_a_killed_gears_left_behind() {
        let root =
            std::env::temp_dir().join(format!("gears-shell-leftovers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let abandoned = root.join("sessions/ephemeral/sh-old-0");
        std::fs::create_dir_all(&abandoned).unwrap();
        std::fs::write(abandoned.join("cwd"), "/\n").unwrap();
        let saved = root.join("sessions/group/session.sh-state");
        std::fs::create_dir_all(&saved).unwrap();
        let lock = DirectoryLock::acquire_at(&root).unwrap();
        assert_eq!(lock.cleanup_temporaries().unwrap(), 1);
        assert!(!abandoned.exists());
        assert!(root.join("sessions/ephemeral").is_dir());
        assert!(saved.is_dir());
        drop(lock);
        std::fs::remove_dir_all(root).unwrap();
    }
}
