//! Successful loads are observations, including ephemeral workers and reviews.

use crate::{memory_format::Source, paths::ToolContext};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const FILE: &str = "batteries/skill-loads.jsonl";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Load {
    pub version: u32,
    pub name: String,
    pub content_hash: String,
    pub source: Source,
    pub date_ms: u64,
}

pub fn record(context: &ToolContext, name: &str, hash: &str, source: Source) -> Result<(), String> {
    crate::journal::append_at(
        &context.state,
        &context.state.file(Path::new(FILE))?,
        &Load {
            version: 1,
            name: name.into(),
            content_hash: hash.into(),
            source,
            date_ms: crate::pending::now_ms()?,
        },
    )
}
