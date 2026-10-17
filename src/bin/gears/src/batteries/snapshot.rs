//! Content-addressed prompt fragments, frozen for the life of a session.

use std::io::Read;
use std::path::Path;

use crate::state::StateRoot;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::batteries::Event;
use crate::batteries::memory_format::Target;
use crate::batteries::paths::ToolContext;

const MAX_BYTES: usize = 1024 * 1024;
const VERSION: u32 = 3;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    pub version: u32,
    pub fragments: Vec<String>,
}

pub(crate) fn load(root: &StateRoot, hash: &str) -> Result<Snapshot, String> {
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid prompt snapshot hash".into());
    }
    let relative = format!("batteries/snapshots/{hash}.json");
    let path = root
        .existing_file(Path::new(&relative))?
        .ok_or("saved prompt snapshot is unavailable")?;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|error| error.to_string())?
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > MAX_BYTES || digest(&bytes) != hash {
        return Err("saved prompt snapshot is oversized or its hash changed".into());
    }
    let snapshot: Snapshot = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid prompt snapshot: {error}"))?;
    if snapshot.version != VERSION {
        return Err("unsupported prompt snapshot version".into());
    }
    Ok(snapshot)
}

pub(crate) fn save(root: &StateRoot, snapshot: &Snapshot) -> Result<String, String> {
    let bytes = serde_json::to_vec(snapshot).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_BYTES {
        return Err("prompt snapshot exceeds 1 MiB".into());
    }
    let hash = digest(&bytes);
    root.replace_file(
        Path::new(&format!("batteries/snapshots/{hash}.json")),
        &bytes,
    )?;
    Ok(hash)
}

/// Project instructions, the memory files, the skill list and, when offers
/// are on, the offer instruction with recently declined entries.
fn fragments(context: &ToolContext, notices: &mut Vec<String>) -> Vec<String> {
    let mut fragments = Vec::new();
    match crate::batteries::instructions::load(&context.workspace) {
        Ok(fragment) => fragments.extend(fragment),
        Err(error) => notices.push(format!("project instructions unavailable: {error}")),
    }
    for target in [Target::User, Target::Global, Target::Workspace] {
        match crate::batteries::memory::load(context, target) {
            Ok(document) if document.entries.is_empty() => {}
            Ok(document) => fragments.push(document.prompt(target)),
            Err(error) => notices.push(format!(
                "{} unavailable: {error}",
                target.title().to_lowercase()
            )),
        }
    }
    let (catalog, skill_notices) =
        crate::batteries::skill_catalog::load(context, crate::batteries::skill_catalog::platform());
    notices.extend(skill_notices);
    if !catalog.is_empty() {
        match crate::batteries::skill_catalog::prompt(&catalog) {
            Ok(prompt) => fragments.push(prompt),
            Err(error) => notices.push(format!("skill list unavailable: {error}")),
        }
    }
    match crate::batteries::memory_config::load(&context.state) {
        Ok(limits) if limits.offer_lessons => fragments.push(offer(context, notices)),
        Ok(_) => {}
        Err(error) => notices.push(format!("batteries.toml unavailable: {error}")),
    }
    fragments
}

fn offer(context: &ToolContext, notices: &mut Vec<String>) -> String {
    let mut text = "After finishing a task whose check passed, you may offer at most one thing worth remembering next time: a mistake and its fix, or a procedure that ran and worked. Propose it with the memory tool; the user decides. Otherwise offer nothing.".to_string();
    match crate::batteries::memory_history::declines(context, 5) {
        Ok(declined) if !declined.is_empty() => {
            text.push_str("\nThe user declined these; do not offer them again:");
            for entry in declined {
                text.push_str("\n- ");
                text.push_str(&entry);
            }
        }
        Ok(_) => {}
        Err(error) => notices.push(format!("declined changes unavailable: {error}")),
    }
    text
}

pub fn initialize(event: &Event, root: &StateRoot) -> Result<Value, String> {
    let mut state = crate::batteries::hook_state(event)?;
    let saved = match state.get("prompt_snapshot") {
        None => None,
        Some(hash) => Some(load(
            root,
            hash.as_str().ok_or("invalid prompt snapshot hash")?,
        )?),
    };
    let compacted = event.payload["reason"] == "compaction";
    let mut notices = Vec::new();
    let snapshot = match saved {
        Some(saved) if !compacted => saved,
        _ => {
            let context = ToolContext::new(
                event.workspace.clone(),
                root.path().to_path_buf(),
                event.session.id.clone(),
                event.session.path.as_deref(),
            )?;
            let snapshot = Snapshot {
                version: VERSION,
                fragments: fragments(&context, &mut notices),
            };
            state["prompt_snapshot"] = json!(save(root, &snapshot)?);
            snapshot
        }
    };
    let mut response = json!({"prompt_fragments": snapshot.fragments});
    if event.session.state.as_ref() != Some(&state) {
        response["state"] = state;
    }
    if !notices.is_empty() {
        response["notice"] = json!(notices.join("\n"));
    }
    Ok(response)
}

pub fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> (std::path::PathBuf, Event, StateRoot) {
        let root =
            std::env::temp_dir().join(format!("batteries-snapshot-{name}-{}", std::process::id()));
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        let event = crate::batteries::read_event(
            json!({"protocol_version": 1, "event": "initialize",
            "workspace": root.join("workspace"), "session": {"id": "fixture"},
            "payload": {"reason": "startup"}})
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        let state = StateRoot::new(root.join("state")).unwrap();
        (root, event, state)
    }

    #[test]
    fn keeps_the_snapshot_until_compaction_or_a_new_session() {
        let (root, mut event, state) = fixture("lifecycle");
        std::fs::write(event.workspace.join("AGENTS.md"), "first instructions").unwrap();
        state
            .replace_file(
                Target::Global.relative(),
                "# Gears memory v2\n§ g1 2026-10-15 s0\nFirst fact.\n".as_bytes(),
            )
            .unwrap();
        let first = initialize(&event, &state).unwrap();
        assert_eq!(first["prompt_fragments"].as_array().unwrap().len(), 2);
        assert_eq!(
            first["prompt_fragments"][1],
            "Global memory:\n[g1] First fact."
        );
        event.session.state = Some(first["state"].clone());
        std::fs::write(event.workspace.join("AGENTS.md"), "new instructions").unwrap();
        state
            .replace_file(Target::Global.relative(), b"# Gears memory v2\n")
            .unwrap();
        for reason in [
            "startup",
            "resume",
            "fork",
            "clone",
            "provider_change",
            "model_change",
        ] {
            event.payload["reason"] = json!(reason);
            let response = initialize(&event, &state).unwrap();
            assert_eq!(response["prompt_fragments"], first["prompt_fragments"]);
            assert!(response.get("state").is_none());
        }
        event.payload["reason"] = json!("compaction");
        let compacted = initialize(&event, &state).unwrap();
        assert_eq!(compacted["prompt_fragments"].as_array().unwrap().len(), 1);
        assert!(
            compacted["prompt_fragments"][0]
                .as_str()
                .unwrap()
                .ends_with("new instructions")
        );
        assert_ne!(
            compacted["state"]["prompt_snapshot"],
            first["state"]["prompt_snapshot"]
        );
        event.session.state = None;
        event.payload["reason"] = json!("new");
        assert_eq!(
            initialize(&event, &state).unwrap()["prompt_fragments"],
            compacted["prompt_fragments"]
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn offers_are_listed_only_when_turned_on_and_name_declined_entries() {
        let (root, event, state) = fixture("offers");
        assert!(initialize(&event, &state).unwrap()["prompt_fragments"] == json!([]));
        state
            .replace_file(
                Path::new("batteries.toml"),
                b"version = 1\n[memory]\noffer_lessons = true",
            )
            .unwrap();
        let context = ToolContext::new(
            event.workspace.clone(),
            state.path().to_path_buf(),
            "fixture".into(),
            None,
        )
        .unwrap();
        let change = crate::batteries::memory::Change {
            version: 2,
            target: Target::Global,
            action: crate::batteries::memory::Action::Add,
            before: None,
            after: Some(crate::batteries::memory_format::Entry {
                id: "d1".into(),
                date: "2026-10-15".into(),
                session: "fixture".into(),
                text: "Declined lesson.".into(),
            }),
        };
        crate::batteries::memory::log(&context, &change, false).unwrap();
        let fragments = initialize(&event, &state).unwrap()["prompt_fragments"].to_string();
        assert!(fragments.contains("you may offer at most one thing"));
        assert!(fragments.contains("do not offer them again:\\n- Declined lesson."));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_corrupt_and_traversing_snapshot_references() {
        let (root, mut event, state) = fixture("corruption");
        let response = initialize(&event, &state).unwrap();
        let hash = response["state"]["prompt_snapshot"].as_str().unwrap();
        std::fs::write(
            state
                .path()
                .join(format!("batteries/snapshots/{hash}.json")),
            "corrupt",
        )
        .unwrap();
        event.session.state = Some(response["state"].clone());
        assert!(
            initialize(&event, &state)
                .unwrap_err()
                .contains("hash changed")
        );
        event.session.state.as_mut().unwrap()["prompt_snapshot"] = json!("../../outside");
        assert!(
            initialize(&event, &state)
                .unwrap_err()
                .contains("invalid prompt snapshot hash")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn snapshots_in_another_format_are_refused() {
        let (root, mut event, state) = fixture("legacy");
        for (bytes, error) in [
            (
                br#"{"version":2,"fragments":["old"],"memory":[]}"#.as_slice(),
                "unknown field",
            ),
            (
                br#"{"version":2,"fragments":["old"]}"#,
                "unsupported prompt snapshot version",
            ),
        ] {
            let hash = digest(bytes);
            state
                .replace_file(
                    Path::new(&format!("batteries/snapshots/{hash}.json")),
                    bytes,
                )
                .unwrap();
            event.session.state = Some(json!({"prompt_snapshot": hash}));
            let refused = initialize(&event, &state).unwrap_err();
            assert!(refused.contains(error), "{refused}");
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
