//! The undo log: a copy of each file taken before gears first changes it.
//!
//! This is the automatic safety net (plan decision D3). gears does not commit
//! on its own — it works on checkouts the user owns, and making commits in one
//! uninvited is invasive — so instead every file is copied once, the first
//! time a session is about to change it, and `/undo` puts them all back.
//!
//! It is pure `std::fs`, which is the other half of the point: the same code
//! is the Motor OS v1 snapshot story, with no version control involved.
//!
//! What it does *not* cover is anything `run` does (plan step 5): a command
//! that writes files goes around this, and is gated instead.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

use serde_json::{Value, json};

/// Where a session's undo state lives, relative to the workspace root.
pub fn dir_in(workspace: &Path, session: &str) -> PathBuf {
    workspace.join(".gears/undo").join(session)
}

pub struct UndoLog {
    root: PathBuf,
    state: crate::state::StateDir,
    relative: PathBuf,
    /// Workspace-relative paths already copied, so that only the *first*
    /// change to a file is recorded — undo means "back to how this session
    /// found it", not "back one step".
    seen: Mutex<BTreeSet<PathBuf>>,
}

impl UndoLog {
    /// Open (or reopen, after a resume) the log for one session.
    pub fn new(workspace: &Path, session: &str) -> Result<UndoLog, String> {
        let root = workspace
            .canonicalize()
            .map_err(|error| format!("workspace {}: {error}", workspace.display()))?;
        let state = crate::state::StateDir::new(&root)?;
        let relative = Path::new("undo").join(session);
        state.existing_directory(&relative)?;
        let log = UndoLog {
            root,
            state,
            relative,
            seen: Mutex::new(BTreeSet::new()),
        };
        let already: BTreeSet<PathBuf> = log.entries()?.into_iter().map(|(path, _)| path).collect();
        *log.seen.lock().unwrap() = already;
        Ok(log)
    }

    pub fn is_empty(&self) -> bool {
        self.seen.lock().unwrap().is_empty()
    }

    pub fn files(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|path| path.display().to_string())
            .collect()
    }

    /// Record what `path` looks like now, because it is about to change. A
    /// failure here stops the change: a write that goes ahead without its
    /// snapshot is exactly the thing this exists to prevent.
    pub fn note(&self, path: &Path) -> Result<(), String> {
        let relative = self.confined(path)?;
        let path = self.root.join(&relative);
        // Held across the copy rather than only across the check: two agents
        // about to write the same file must not both take one, or the second
        // copy would be of what the first had already written and `/undo`
        // would put that back instead of what the session found.
        let mut seen = self.seen.lock().unwrap();
        if seen.contains(&relative) {
            return Ok(());
        }
        let existed = path.exists();
        if existed {
            let copy = self
                .state
                .file(&self.relative.join("files").join(&relative))?;
            std::fs::copy(&path, &copy).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        self.append(&relative, existed)?;
        seen.insert(relative);
        Ok(())
    }

    /// Put every file this session changed back the way it found it. Files
    /// that did not exist before are removed.
    pub fn restore(&self) -> Result<Vec<String>, String> {
        let workspace = crate::tools::Workspace::new(&self.root)?;
        let mut restored = Vec::new();
        for (relative, existed) in self.entries()? {
            let given = relative
                .to_str()
                .ok_or_else(|| format!("{}: path is not UTF-8", relative.display()))?;
            let target = workspace.resolve(given)?;
            match existed {
                true => {
                    let copy_relative = self.relative.join("files").join(&relative);
                    let copy = self.state.existing_file(&copy_relative)?.ok_or_else(|| {
                        format!(
                            "{}: missing undo copy",
                            self.root.join(".gears").join(copy_relative).display()
                        )
                    })?;
                    if let Some(parent) = target.parent() {
                        std::fs::create_dir_all(parent)
                            .map_err(|e| format!("{}: {e}", parent.display()))?;
                    }
                    std::fs::copy(&copy, &target)
                        .map_err(|e| format!("{}: {e}", target.display()))?;
                }
                false => match std::fs::remove_file(&target) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(format!("{}: {e}", target.display())),
                },
            }
            restored.push(relative.display().to_string());
        }
        Ok(restored)
    }

    fn confined(&self, path: &Path) -> Result<PathBuf, String> {
        let relative = path
            .strip_prefix(&self.root)
            .map_err(|_| format!("{} is not in the workspace", path.display()))?;
        let given = relative
            .to_str()
            .ok_or_else(|| format!("{}: path is not UTF-8", relative.display()))?;
        let workspace = crate::tools::Workspace::new(&self.root)?;
        let resolved = workspace.resolve(given)?;
        resolved
            .strip_prefix(&self.root)
            .map(Path::to_path_buf)
            .map_err(|_| format!("{} is not in the workspace", path.display()))
    }

    fn manifest(&self) -> PathBuf {
        self.relative.join("manifest.jsonl")
    }

    fn append(&self, relative: &Path, existed: bool) -> Result<(), String> {
        let path = self.state.file(&self.manifest())?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let line = json!({"path": relative.display().to_string(), "existed": existed});
        writeln!(file, "{line}").map_err(|e| format!("{}: {e}", path.display()))?;
        file.flush().map_err(|e| format!("{}: {e}", path.display()))
    }

    /// The manifest, in the order it was written. A line that cannot be read
    /// is skipped: a half-written last line must not make the rest unusable.
    fn entries(&self) -> Result<Vec<(PathBuf, bool)>, String> {
        let Some(path) = self.state.existing_file(&self.manifest())? else {
            return Ok(Vec::new());
        };
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let mut entries = Vec::new();
        for (line_number, line) in text.lines().enumerate() {
            let Ok(value) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let (Some(given), Some(existed)) = (value["path"].as_str(), value["existed"].as_bool())
            else {
                continue;
            };
            let relative = safe_relative(given)
                .map_err(|error| format!("{}:{}: {error}", path.display(), line_number + 1))?;
            entries.push((relative, existed));
        }
        Ok(entries)
    }
}

fn safe_relative(given: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(given);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "unsafe undo path {given:?}: expected a normal relative path"
        ));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn workspace(name: &str) -> PathBuf {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "gears-undo-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Two agents changing the same file is one snapshot, of what was there
    /// before either of them: whoever gets there first copies, and the other
    /// waits rather than copying what the first has just written.
    #[test]
    fn one_snapshot_however_many_agents_want_it() {
        let root = workspace("shared");
        let path = root.join("notes.txt");
        std::fs::write(&path, "original\n").unwrap();

        let log = UndoLog::new(&root, "s1").unwrap();
        std::thread::scope(|scope| {
            for text in ["one\n", "two\n", "three\n"] {
                let (log, path) = (&log, &path);
                scope.spawn(move || {
                    log.note(path).unwrap();
                    std::fs::write(path, text).unwrap();
                });
            }
        });
        assert_eq!(log.files(), ["notes.txt"]);
        assert_eq!(log.entries().unwrap().len(), 1);

        log.restore().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "original\n");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_changed_file_goes_back_and_a_new_one_disappears() {
        let root = workspace("basic");
        let existing = root.join("src/lib.rs");
        std::fs::create_dir_all(existing.parent().unwrap()).unwrap();
        std::fs::write(&existing, "original\n").unwrap();
        let created = root.join("notes.txt");

        let log = UndoLog::new(&root, "s1").unwrap();
        assert!(log.is_empty());
        log.note(&existing).unwrap();
        std::fs::write(&existing, "changed\n").unwrap();
        log.note(&created).unwrap();
        std::fs::write(&created, "new\n").unwrap();
        assert_eq!(log.files(), ["notes.txt", "src/lib.rs"]);

        let restored = log.restore().unwrap();
        assert_eq!(restored, ["src/lib.rs", "notes.txt"]);
        assert_eq!(std::fs::read_to_string(&existing).unwrap(), "original\n");
        assert!(!created.exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Undo means "back to how this session found it", so only the first copy
    /// of a file counts — otherwise a file edited three times would come back
    /// as it was after the second edit.
    #[test]
    fn only_the_first_change_to_a_file_is_recorded() {
        let root = workspace("first");
        let path = root.join("a.txt");
        std::fs::write(&path, "one\n").unwrap();

        let log = UndoLog::new(&root, "s1").unwrap();
        log.note(&path).unwrap();
        std::fs::write(&path, "two\n").unwrap();
        log.note(&path).unwrap();
        std::fs::write(&path, "three\n").unwrap();

        log.restore().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one\n");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A session that survives a restart (plan step 9) must not snapshot a
    /// file a second time when it comes back.
    #[test]
    fn a_reopened_log_remembers_what_it_already_holds() {
        let root = workspace("reopen");
        let path = root.join("a.txt");
        std::fs::write(&path, "before\n").unwrap();

        let log = UndoLog::new(&root, "s1").unwrap();
        log.note(&path).unwrap();
        std::fs::write(&path, "after\n").unwrap();
        drop(log);

        let log = UndoLog::new(&root, "s1").unwrap();
        assert_eq!(log.files(), ["a.txt"]);
        log.note(&path).unwrap();
        assert_eq!(log.restore().unwrap(), ["a.txt"]);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "before\n");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_path_outside_the_workspace_is_refused() {
        let root = workspace("outside");
        let log = UndoLog::new(&root, "s1").unwrap();
        assert!(log.note(Path::new("/etc/passwd")).is_err());
        assert!(log.is_empty());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn undoing_nothing_is_not_an_error() {
        let root = workspace("empty");
        let log = UndoLog::new(&root, "s1").unwrap();
        assert!(log.restore().unwrap().is_empty());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_manifest_path_can_never_escape_the_workspace() {
        let root = workspace("manifest-path");
        let outside = root.with_extension("outside");
        let _ = std::fs::remove_file(&outside);
        std::fs::write(&outside, "leave this alone\n").unwrap();
        let log = UndoLog::new(&root, "s1").unwrap();
        let dir = dir_in(&root, "s1");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("manifest.jsonl"),
            format!(
                "{{\"path\":\"../{}\",\"existed\":false}}\n",
                outside.file_name().unwrap().to_string_lossy()
            ),
        )
        .unwrap();
        drop(log);

        let error = UndoLog::new(&root, "s1").err().unwrap();
        assert!(error.contains("unsafe undo path"), "{error}");
        assert_eq!(
            std::fs::read_to_string(&outside).unwrap(),
            "leave this alone\n"
        );
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_file(outside).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn restore_refuses_a_destination_redirected_after_snapshot() {
        use std::os::unix::fs::symlink;

        let root = workspace("restore-link");
        let outside = workspace("restore-link-outside");
        let log = UndoLog::new(&root, "s1").unwrap();
        log.note(&root.join("nested/new.txt")).unwrap();
        symlink(&outside, root.join("nested")).unwrap();

        let error = log.restore().unwrap_err();
        assert!(error.contains("outside the workspace"), "{error}");
        assert!(!outside.join("new.txt").exists());
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }
}
