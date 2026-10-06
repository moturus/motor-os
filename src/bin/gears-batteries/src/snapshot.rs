//! Content-addressed prompt fragments that follow session branches.

use std::io::Read;
use std::path::Path;

use gears::state::StateRoot;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::Event;
use crate::memory_snapshot::Stored;
use crate::paths::ToolContext;

const MAX_BYTES: usize = 1024 * 1024;

#[derive(Serialize, Deserialize)]
pub(crate) struct Snapshot {
    pub version: u32,
    pub fragments: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory: Vec<Stored>,
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
    if !matches!(snapshot.version, 1 | 2) || (snapshot.version == 1 && !snapshot.memory.is_empty())
    {
        return Err("unsupported prompt snapshot version".into());
    }
    crate::memory_snapshot::changes(&snapshot.memory, &snapshot.memory)?;
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

pub fn initialize(event: &Event, root: &StateRoot) -> Result<Value, String> {
    let mut state = crate::hook_state(event)?;
    let saved = state
        .get("prompt_snapshot")
        .map(|hash| load(root, hash.as_str().ok_or("invalid prompt snapshot hash")?))
        .transpose()?;
    let context = ToolContext::new(
        event.workspace.clone(),
        root.path().to_path_buf(),
        event.session.id.clone(),
        event.session.path.as_deref(),
    )?;
    let (live, mut notices) = crate::memory_snapshot::load(&context);
    let preserve = event.payload["preserve_prefix"] == true;
    let compacted = event.payload["reason"] == "compaction";
    let refresh = (!preserve && compacted) || saved.is_none();
    let mut rewrite = refresh;
    let snapshot = if refresh {
        let fragments = match crate::instructions::load(&event.workspace) {
            Ok(fragment) => fragment.into_iter().collect(),
            Err(error) => {
                notices.push(format!("project instructions unavailable: {error}"));
                saved
                    .as_ref()
                    .map(|snapshot| snapshot.fragments.clone())
                    .unwrap_or_default()
            }
        };
        Snapshot {
            version: 2,
            fragments,
            memory: live,
        }
    } else if preserve {
        saved.unwrap()
    } else {
        let mut saved = saved.unwrap();
        let memory = crate::memory_snapshot::reconcile(&saved.memory, &live)?;
        rewrite = saved.memory != memory;
        saved.memory = memory;
        saved
    };
    let hash = if rewrite {
        save(root, &snapshot)?
    } else {
        state["prompt_snapshot"].as_str().unwrap().to_string()
    };
    if state["prompt_snapshot"] != hash || refresh || (preserve && compacted) {
        state
            .as_object_mut()
            .unwrap()
            .remove("memory_view_snapshot");
    }
    state["prompt_snapshot"] = json!(hash);
    let correction = if preserve {
        match crate::instructions::load(&event.workspace) {
            Ok(current) => {
                let current: Vec<_> = current.into_iter().collect();
                (current != snapshot.fragments).then(|| {
                    gears::provider::Message::user(format!(
                        "Current project instructions supersede the historical prefix.\n{}",
                        if current.is_empty() {
                            "The previous project instructions were removed.".into()
                        } else {
                            current.join("\n\n")
                        }
                    ))
                })
            }
            Err(error) => {
                notices.push(format!("current project instructions unavailable: {error}"));
                None
            }
        }
    } else {
        None
    };
    let mut fragments = snapshot.fragments;
    fragments.extend(snapshot.memory.iter().map(Stored::prompt));
    let mut response = json!({"prompt_fragments": fragments});
    if let Some(correction) = correction {
        response["context"] = json!(correction);
    }
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
        let event = crate::read_event(
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
        let first = initialize(&event, &state).unwrap();
        event.session.state = Some(first["state"].clone());
        std::fs::write(event.workspace.join("AGENTS.md"), "new instructions").unwrap();
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
    fn legacy_project_only_snapshots_keep_their_hash_and_prompt() {
        let (root, mut event, state) = fixture("legacy");
        let bytes = br#"{"version":1,"fragments":["legacy project text"]}"#;
        let hash = digest(bytes);
        state
            .replace_file(
                Path::new(&format!("batteries/snapshots/{hash}.json")),
                bytes,
            )
            .unwrap();
        event.session.state = Some(json!({"prompt_snapshot": hash}));
        let response = initialize(&event, &state).unwrap();
        assert_eq!(response["prompt_fragments"], json!(["legacy project text"]));
        assert!(response.get("state").is_none());
        assert_eq!(
            std::fs::read(
                state
                    .path()
                    .join(format!("batteries/snapshots/{hash}.json"))
            )
            .unwrap(),
            bytes
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
