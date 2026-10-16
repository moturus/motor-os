//! One memory change at a time, written only after the user says yes.

use std::path::Path;

use crate::state::StateRoot;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::batteries::memory_format::{Document, Entry, Target};
use crate::batteries::paths::ToolContext;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Add,
    Replace,
    Remove,
}

/// A proposed change, kept in hook state while the user is asked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub version: u32,
    pub target: Target,
    pub action: Action,
    pub before: Option<Entry>,
    pub after: Option<Entry>,
}

impl Change {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 2 {
            return Err("unsupported memory change version".into());
        }
        let shape = match self.action {
            Action::Add => self.before.is_none() && self.after.is_some(),
            Action::Replace => {
                self.before.is_some()
                    && self.after.is_some()
                    && self.before.as_ref().map(|entry| &entry.id)
                        == self.after.as_ref().map(|entry| &entry.id)
            }
            Action::Remove => self.before.is_some() && self.after.is_none(),
        };
        if !shape {
            return Err("memory change does not match its action".into());
        }
        for entry in self.before.iter().chain(&self.after) {
            entry.validate()?;
        }
        Ok(())
    }

    /// The entry the user is asked about.
    pub fn subject(&self) -> &Entry {
        self.after.as_ref().or(self.before.as_ref()).unwrap()
    }

    /// Applies the change to the current file's entries; the entry it replaces
    /// or removes must still read as it did when the change was proposed.
    fn apply_to(&self, document: &mut Document) -> Result<(), String> {
        match self.action {
            Action::Add => {
                let after = self.after.as_ref().unwrap();
                if document.entries.iter().any(|entry| entry.id == after.id) {
                    return Err("memory entry id already exists".into());
                }
                document.entries.push(after.clone());
            }
            Action::Replace | Action::Remove => {
                let before = self.before.as_ref().unwrap();
                let index = document
                    .entries
                    .iter()
                    .position(|entry| entry.id == before.id)
                    .ok_or("memory entry was removed since the change was proposed")?;
                if document.entries[index].text != before.text {
                    return Err("memory entry changed since the change was proposed".into());
                }
                match &self.after {
                    Some(after) => document.entries[index] = after.clone(),
                    None => {
                        document.entries.remove(index);
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn root(context: &ToolContext, target: Target) -> Result<StateRoot, String> {
    if target == Target::Workspace {
        StateRoot::new(context.workspace.clone())
    } else {
        Ok(context.state.clone())
    }
}

fn limit(context: &ToolContext, target: Target) -> Result<usize, String> {
    Ok(crate::batteries::memory_config::load(&context.state)?.for_target(target))
}

pub fn load(context: &ToolContext, target: Target) -> Result<Document, String> {
    crate::batteries::memory_format::load(&root(context, target)?, target, limit(context, target)?)
}

/// Checks a change against the current file without writing anything.
/// `Ok(false)` means the entry to add is already there.
pub fn propose(context: &ToolContext, change: &Change) -> Result<bool, String> {
    change.validate()?;
    let mut document = load(context, change.target)?;
    if change.action == Action::Add
        && document
            .entries
            .iter()
            .any(|entry| entry.text == change.after.as_ref().unwrap().text)
    {
        return Ok(false);
    }
    change.apply_to(&mut document)?;
    document.encode(limit(context, change.target)?)?;
    Ok(true)
}

pub fn apply(context: &ToolContext, change: &Change) -> Result<(), String> {
    change.validate()?;
    let mut document = load(context, change.target)?;
    change.apply_to(&mut document)?;
    let text = document.encode(limit(context, change.target)?)?;
    root(context, change.target)?.replace_file(change.target.relative(), text.as_bytes())
}

/// Appends the user's answer to `changes.jsonl`.
pub fn log(context: &ToolContext, change: &Change, yes: bool) -> Result<(), String> {
    let (date, time_ms) = crate::batteries::memory_format::today()?;
    let subject = change.subject();
    let before = change
        .before
        .as_ref()
        .filter(|_| change.action == Action::Replace)
        .map(|entry| entry.text.clone());
    let record = json!({"version": 2, "date": date, "time_ms": time_ms,
        "decision": if yes { "yes" } else { "no" }, "target": change.target, "action": change.action,
        "id": subject.id, "text": subject.text, "before": before, "session": subject.session});
    let path = context.state.file(Path::new("batteries/changes.jsonl"))?;
    crate::batteries::journal::append_at(&context.state, &path, &record)
}

/// A short id that no current entry uses.
pub fn new_id(document: &Document, seed: &str) -> String {
    let digest = crate::batteries::snapshot::digest(seed.as_bytes());
    let mut length = 4;
    loop {
        let id = &digest[..length];
        if !document.entries.iter().any(|entry| entry.id == id) || length == digest.len() {
            return id.to_string();
        }
        length += 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(label: &str) -> (std::path::PathBuf, ToolContext) {
        let path =
            std::env::temp_dir().join(format!("batteries-memory-{label}-{}", std::process::id()));
        std::fs::create_dir_all(path.join("workspace")).unwrap();
        let context = ToolContext::new(
            path.join("workspace"),
            path.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        (path, context)
    }

    fn entry(id: &str, text: &str) -> Entry {
        Entry {
            id: id.into(),
            date: "2026-10-15".into(),
            session: "s1".into(),
            text: text.into(),
        }
    }

    fn change(
        target: Target,
        action: Action,
        before: Option<Entry>,
        after: Option<Entry>,
    ) -> Change {
        Change {
            version: 2,
            target,
            action,
            before,
            after,
        }
    }

    #[test]
    fn changes_apply_once_detect_duplicates_and_refuse_stale_entries() {
        let (path, context) = fixture("apply");
        let add = change(
            Target::Global,
            Action::Add,
            None,
            Some(entry("a1", "Prefer Rust.")),
        );
        assert!(propose(&context, &add).unwrap());
        assert!(load(&context, Target::Global).unwrap().entries.is_empty());
        apply(&context, &add).unwrap();
        assert_eq!(
            load(&context, Target::Global).unwrap().entries,
            [entry("a1", "Prefer Rust.")]
        );
        assert!(
            !propose(
                &context,
                &change(
                    Target::Global,
                    Action::Add,
                    None,
                    Some(entry("a2", "Prefer Rust."))
                )
            )
            .unwrap()
        );
        assert!(
            apply(&context, &add)
                .unwrap_err()
                .contains("already exists")
        );
        let replace = change(
            Target::Global,
            Action::Replace,
            Some(entry("a1", "Prefer Rust.")),
            Some(entry("a1", "Prefer native APIs.")),
        );
        assert!(propose(&context, &replace).unwrap());
        context
            .state
            .replace_file(
                Target::Global.relative(),
                b"# Gears memory v2\n\xc2\xa7 a1 2026-10-15 s1\nA hand correction.\n",
            )
            .unwrap();
        assert!(
            apply(&context, &replace)
                .unwrap_err()
                .contains("changed since")
        );
        let remove = change(
            Target::Global,
            Action::Remove,
            Some(entry("a1", "A hand correction.")),
            None,
        );
        apply(&context, &remove).unwrap();
        assert!(load(&context, Target::Global).unwrap().entries.is_empty());
        assert!(
            apply(&context, &remove)
                .unwrap_err()
                .contains("removed since")
        );
        for bad in [
            change(
                Target::Global,
                Action::Add,
                Some(entry("a1", "x")),
                Some(entry("a1", "y")),
            ),
            change(Target::Global, Action::Remove, None, None),
            change(
                Target::Global,
                Action::Replace,
                Some(entry("a1", "x")),
                Some(entry("a2", "y")),
            ),
            Change {
                version: 1,
                ..add.clone()
            },
        ] {
            assert!(propose(&context, &bad).is_err());
        }
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn decisions_are_logged_and_workspace_memory_lives_in_the_workspace() {
        let (path, context) = fixture("log");
        let add = change(
            Target::Workspace,
            Action::Add,
            None,
            Some(entry("w1", "Paths are relative.")),
        );
        apply(&context, &add).unwrap();
        assert!(context.workspace.join(".gears/MEMORY.md").is_file());
        log(&context, &add, true).unwrap();
        let remove = change(
            Target::Workspace,
            Action::Remove,
            Some(entry("w1", "Paths are relative.")),
            None,
        );
        log(&context, &remove, false).unwrap();
        let history = crate::batteries::memory_history::history(&context, 0, 10).unwrap();
        assert_eq!(history["total"], 2);
        assert_eq!(history["records"][0]["decision"], "yes");
        assert_eq!(history["records"][1]["action"], "remove");
        assert_eq!(history["records"][1]["text"], "Paths are relative.");
        let document = load(&context, Target::Workspace).unwrap();
        let id = new_id(&document, "seed");
        assert_eq!(id.len(), 4);
        assert_ne!(
            new_id(
                &Document {
                    entries: vec![entry(&id, "taken")]
                },
                "seed"
            )
            .len(),
            4
        );
        std::fs::remove_dir_all(path).unwrap();
    }
}
