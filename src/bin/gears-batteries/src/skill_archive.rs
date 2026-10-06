//! Keep exact approved removals before withdrawing their live files.

use crate::{paths::ToolContext, skill_format::Content};
use serde_json::json;
use std::path::{Path, PathBuf};

pub fn relative(name: &str, content: &Content) -> PathBuf {
    Path::new("batteries/archived-skills").join(format!("{name}-{}.json", content.hash()))
}

pub fn save(context: &ToolContext, name: &str, content: &Content) -> Result<(), String> {
    if !crate::skill_format::valid_name(name) {
        return Err("invalid archived skill name".into());
    }
    let bytes = serde_json::to_vec_pretty(&json!({"version": 1, "name": name,
        "content_hash": content.hash(), "content": content}))
    .map_err(|error| error.to_string())?;
    context.state.replace_file(&relative(name, content), &bytes)
}
