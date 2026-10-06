//! Optional latest-result display; damaged records do not hide pending changes.

use std::io::Read;
use std::path::Path;

use gears::state::StateRoot;
use serde_json::Value;

pub fn latest(root: &StateRoot) -> Result<Option<Value>, String> {
    let Some(path) = root.existing_file(Path::new("batteries/last-review.json"))? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|error| error.to_string())?
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 16 * 1024 {
        return Err("last review exceeds 16 KiB".into());
    }
    let record: Value =
        serde_json::from_slice(&bytes).map_err(|error| format!("invalid last review: {error}"))?;
    if record["version"] != 1
        || record["date_ms"].as_u64().is_none()
        || !record["answer"].is_string()
        || !record["workspace"].is_string()
        || !record["session"]
            .as_str()
            .is_some_and(crate::memory_format::identifier)
        || !record["mark"]
            .as_str()
            .is_some_and(|id| id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err("unsupported or malformed last review".into());
    }
    serde_json::from_value::<crate::review_config::Model>(record["executor"].clone())
        .map_err(|error| format!("invalid last review executor: {error}"))?;
    serde_json::from_value::<Option<crate::review_config::Model>>(record["reviewer"].clone())
        .map_err(|error| format!("invalid last review reviewer: {error}"))?;
    serde_json::from_value::<crate::review_runner::Usage>(record["usage"].clone())
        .map_err(|error| format!("invalid last review usage: {error}"))?;
    Ok(Some(record))
}
