//! Content-addressed prompt fragments that follow session branches.

use std::io::Read;
use std::path::Path;

use gears::state::StateRoot;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::Event;

const MAX_BYTES: usize = 128 * 1024;

#[derive(Serialize, Deserialize)]
struct Snapshot {
    version: u32,
    fragments: Vec<String>,
}

pub fn initialize(event: &Event, root: &StateRoot) -> Result<Value, String> {
    let mut state = event.session.state.clone().unwrap_or_else(|| json!({}));
    if !state.is_object() {
        return Err("batteries hook state is not an object".into());
    }
    let refresh = event.payload["reason"] == "compaction";
    let (hash, snapshot) = match state.get("prompt_snapshot") {
        Some(hash) if !refresh => {
            let hash = hash
                .as_str()
                .filter(|hash| {
                    hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
                .ok_or("invalid prompt snapshot hash")?;
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
            if snapshot.version != 1 {
                return Err("unsupported prompt snapshot version".into());
            }
            (hash.to_string(), snapshot)
        }
        _ => {
            let fragments = crate::instructions::load(&event.workspace)?
                .into_iter()
                .collect();
            let snapshot = Snapshot {
                version: 1,
                fragments,
            };
            let bytes = serde_json::to_vec(&snapshot).map_err(|error| error.to_string())?;
            let hash = digest(&bytes);
            root.replace_file(
                Path::new(&format!("batteries/snapshots/{hash}.json")),
                &bytes,
            )?;
            (hash, snapshot)
        }
    };
    state["prompt_snapshot"] = json!(hash);
    let mut response = json!({"prompt_fragments": snapshot.fragments});
    if event.session.state.as_ref() != Some(&state) {
        response["state"] = state;
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
}
