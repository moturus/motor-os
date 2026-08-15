//! The permission gate: what the user says a tool may do.
//!
//! It sits on the UI side of the bus (a proposal decision) and the agent never
//! sees it — an agent asks, this answers, and what it remembers between runs
//! lives in `<workspace>/.gears/permissions.toml`.
//!
//! An answer is remembered under a *key*, not a call: `write_file` covers
//! every write, while `run` narrows to the command word (plan step 5), because
//! "always allow cargo" and "always allow anything" are not the same sentence.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::agent::bus::{Decision, PermissionRequest};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Every mutating call is put to the user.
    #[default]
    Ask,
    /// Nothing is. **This exists for gears' own test suite**, which has no
    /// user to answer, and it is documented as such: with it set, a model can
    /// change any file in the workspace and run any command without a word.
    AutoApprove,
}

impl Mode {
    pub const NAMES: &str = "ask, auto-approve";

    pub fn parse(name: &str) -> Option<Mode> {
        match name {
            "ask" => Some(Mode::Ask),
            "auto-approve" => Some(Mode::AutoApprove),
            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct StoredV1 {
    version: u32,
    #[serde(default)]
    allow: Vec<String>,
}

#[derive(Debug)]
pub struct Gate {
    mode: Mode,
    allowed: BTreeSet<String>,
    /// Where answers are remembered, or `None` for a gate that forgets.
    state: Option<crate::state::StateDir>,
    /// A failure to persist, waiting to be shown. Not being able to *remember*
    /// an answer does not change the answer, so it is reported rather than
    /// raised.
    complaint: Option<String>,
}

impl Gate {
    pub fn new(mode: Mode) -> Gate {
        Gate {
            mode,
            allowed: BTreeSet::new(),
            state: None,
            complaint: None,
        }
    }

    pub fn path_in(workspace: &Path) -> PathBuf {
        workspace.join(".gears/permissions.toml")
    }

    /// Load what this workspace already allows. A file that is there but
    /// unreadable is an error: quietly starting with an empty set would ask
    /// again for everything, which reads as gears having forgotten.
    pub fn load(workspace: &Path, mode: Mode) -> Result<Gate, String> {
        let state = crate::state::StateDir::new(workspace)?;
        let allowed = match state.existing_file(Path::new("permissions.toml"))? {
            Some(path) => {
                let text = std::fs::read_to_string(&path)
                    .map_err(|error| format!("{}: {error}", path.display()))?;
                parse(&text).map_err(|error| format!("{}: {error}", path.display()))?
            }
            None => BTreeSet::new(),
        };
        Ok(Gate {
            mode,
            allowed,
            state: Some(state),
            complaint: None,
        })
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn allows(&self, key: &str) -> bool {
        self.allowed.contains(key)
    }

    /// The answer without asking anybody, when there is one. `None` means the
    /// user has to be put to the trouble.
    pub fn known(&self, request: &PermissionRequest) -> Option<Decision> {
        match self.mode == Mode::AutoApprove || self.allowed.contains(&request.key) {
            true => Some(Decision::Allow),
            false => None,
        }
    }

    /// Remember an "always" answer, and write it down.
    pub fn remember(&mut self, key: &str) {
        self.allowed.insert(key.to_string());
        self.complaint = self.save().err();
    }

    /// A persistence failure worth telling the user about, taken once.
    pub fn complaint(&mut self) -> Option<String> {
        self.complaint.take()
    }

    fn save(&self) -> Result<(), String> {
        let Some(state) = &self.state else {
            return Ok(());
        };
        let path = state.file(Path::new("permissions.toml"))?;
        let stored = StoredV1 {
            version: 1,
            allow: self.allowed.iter().cloned().collect(),
        };
        let text = toml::to_string(&stored).map_err(|e| e.to_string())?;
        std::fs::write(&path, format!("{HEADER}{text}"))
            .map_err(|e| format!("{}: {e}", path.display()))
    }
}

const HEADER: &str = "# Written by gears: the calls this workspace always allows.\n\
                      # Delete a line to be asked about it again.\n";

fn parse(text: &str) -> Result<BTreeSet<String>, String> {
    let stored: StoredV1 = toml::from_str(text).map_err(|e| e.to_string())?;
    if stored.version != 1 {
        return Err(format!(
            "unsupported permissions version {} (expected 1)",
            stored.version
        ));
    }
    Ok(stored.allow.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn workspace(name: &str) -> PathBuf {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "gears-gate-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn request(key: &str) -> PermissionRequest {
        PermissionRequest::new(key, format!("{key} something"))
    }

    #[test]
    fn an_unknown_call_has_to_be_asked_about() {
        let gate = Gate::new(Mode::Ask);
        assert_eq!(gate.known(&request("write_file")), None);
        assert!(!gate.allows("write_file"));
    }

    #[test]
    fn always_is_remembered_across_runs() {
        let dir = workspace("always");
        let mut gate = Gate::load(&dir, Mode::Ask).unwrap();
        assert_eq!(gate.known(&request("run:cargo")), None);
        gate.remember("run:cargo");
        assert_eq!(gate.complaint(), None);

        // Not asked again, in this run or the next one.
        assert_eq!(gate.known(&request("run:cargo")), Some(Decision::Allow));
        let later = Gate::load(&dir, Mode::Ask).unwrap();
        assert!(later.allows("run:cargo"));
        assert_eq!(later.known(&request("run:cargo")), Some(Decision::Allow));
        // And an answer about one key says nothing about another.
        assert!(!later.allows("run:rm"));
        assert_eq!(later.known(&request("run:rm")), None);

        let text = std::fs::read_to_string(Gate::path_in(&dir)).unwrap();
        assert!(text.contains("run:cargo"), "{text}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn auto_approve_never_asks() {
        let dir = workspace("auto");
        let gate = Gate::load(&dir, Mode::AutoApprove).unwrap();
        assert_eq!(gate.known(&request("write_file")), Some(Decision::Allow));
        // Nothing is remembered either: the mode is the whole answer, so the
        // file does not quietly fill up with permissions nobody granted.
        assert!(!Gate::path_in(&dir).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_broken_permissions_file_is_reported_not_ignored() {
        let dir = workspace("broken");
        std::fs::create_dir_all(dir.join(".gears")).unwrap();
        std::fs::write(Gate::path_in(&dir), "version = 1\nallow = 7\n").unwrap();
        assert!(Gate::load(&dir, Mode::Ask).is_err());

        std::fs::write(Gate::path_in(&dir), "version = 9\nallow = []\n").unwrap();
        let error = Gate::load(&dir, Mode::Ask).unwrap_err();
        assert!(error.contains("version 9"), "{error}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_gate_with_nowhere_to_write_still_works() {
        let mut gate = Gate::new(Mode::Ask);
        gate.remember("edit_file");
        assert_eq!(gate.complaint(), None);
        assert!(gate.allows("edit_file"));
    }

    #[cfg(unix)]
    #[test]
    fn permissions_refuse_a_symlink_even_when_it_appears_after_load() {
        use std::os::unix::fs::symlink;

        let dir = workspace("state-link");
        let outside = dir.join("outside.toml");
        std::fs::write(&outside, "leave this alone\n").unwrap();
        let mut gate = Gate::load(&dir, Mode::Ask).unwrap();
        std::fs::create_dir(dir.join(crate::state::STATE_DIR)).unwrap();
        symlink(&outside, Gate::path_in(&dir)).unwrap();

        gate.remember("run:cargo");
        let error = gate.complaint().unwrap();
        assert!(error.contains("symlink"), "{error}");
        assert_eq!(
            std::fs::read_to_string(&outside).unwrap(),
            "leave this alone\n"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn modes_parse() {
        assert_eq!(Mode::parse("ask"), Some(Mode::Ask));
        assert_eq!(Mode::parse("auto-approve"), Some(Mode::AutoApprove));
        assert_eq!(Mode::parse("yolo"), None);
    }

    #[test]
    fn arbitrary_permission_keys_match_exactly_and_round_trip() {
        let dir = workspace("property");
        let mut persisted = Gate::load(&dir, Mode::Ask).unwrap();
        for (case, bytes) in
            crate::property::byte_cases(0x7065_726d_6973_7369, 256, 512).enumerate()
        {
            let key = String::from_utf8_lossy(&bytes);
            let mut gate = Gate::new(Mode::Ask);
            assert_eq!(gate.known(&request(&key)), None);
            gate.remember(&key);
            assert_eq!(gate.known(&request(&key)), Some(Decision::Allow));
            assert_eq!(gate.known(&request(&format!("{key}\0"))), None);
            assert_eq!(gate.known(&request(&format!(" {key}"))), None);
            if case < 32 {
                persisted.remember(&key);
            }
        }
        let loaded = Gate::load(&dir, Mode::Ask).unwrap();
        for bytes in crate::property::byte_cases(0x7065_726d_6973_7369, 32, 512) {
            let key = String::from_utf8_lossy(&bytes);
            assert_eq!(loaded.known(&request(&key)), Some(Decision::Allow));
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn arbitrary_permission_documents_are_safely_bounded() {
        for bytes in crate::property::byte_cases(0x7065_726d_2d64_6f63, 512, 4096) {
            let text = String::from_utf8_lossy(&bytes);
            if let Ok(allowed) = parse(&text) {
                assert!(allowed.len() <= bytes.len().saturating_add(1));
            }
        }
    }
}
