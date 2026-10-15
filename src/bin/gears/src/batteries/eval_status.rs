//! The last-result index is metadata only; damaged optional state does not hide pending work.

use crate::state::StateRoot;
use serde_json::{Value, json};
use std::{io::Read, path::Path};
const FILE: &str = "batteries/last-eval.json";

pub fn record(root: &StateRoot, path: &Path, report: &Value) -> Result<(), String> {
    crate::process::ensure_cleanup()?;
    let value = json!({"version":1,"date_ms":crate::batteries::pending::now_ms()?,"report":path,
        "status":report["status"],"verdict":report["verdict"],"arms":report["arms"],
        "provider":report["settings"]["provider"],"model":report["settings"]["model"]});
    validate(&value)?;
    let bytes = serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?;
    if bytes.len() > 16 * 1024 {
        return Err("last eval exceeds 16 KiB".into());
    }
    root.replace_file(Path::new(FILE), &bytes)
}

pub fn latest(root: &StateRoot) -> Result<Option<Value>, String> {
    let Some(path) = root.existing_file(Path::new(FILE))? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 16 * 1024 {
        return Err("last eval exceeds 16 KiB".into());
    }
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid last eval: {e}"))?;
    validate(&value)?;
    Ok(Some(value))
}
fn validate(value: &Value) -> Result<(), String> {
    if value["version"] != 1
        || value["date_ms"].as_u64().is_none()
        || !value["report"]
            .as_str()
            .is_some_and(|s| Path::new(s).is_absolute())
        || !matches!(
            value["status"].as_str(),
            Some("complete" | "failed" | "cancelled")
        )
        || !matches!(value["verdict"].as_str(), Some("insufficient_evidence"))
        || ["provider", "model"].iter().any(|key| {
            !value[key]
                .as_str()
                .is_some_and(|s| !s.trim().is_empty() && !s.chars().any(char::is_control))
        })
        || !value["arms"].as_array().is_some_and(|arms| arms.len() == 2)
    {
        return Err("unsupported or malformed last eval".into());
    }
    Ok(())
}
