use std::io;
use std::path::Path;

use crate::semantic::uri_path;
use serde_json::Value;

pub(super) fn require_generated_definition(definition: &Value, root: &Path) -> io::Result<()> {
    let location = definition
        .as_array()
        .and_then(|locations| locations.first())
        .unwrap_or(definition);
    let uri = location["uri"]
        .as_str()
        .or_else(|| location["targetUri"].as_str())
        .ok_or_else(|| io::Error::other(format!("missing generated definition: {definition}")))?;
    let path = uri_path(uri)?;
    if !path.starts_with(root.join("target/rust-analyzer"))
        || path.file_name().is_none_or(|name| name != "generated.rs")
    {
        return Err(io::Error::other(format!(
            "wrong generated definition: {definition}"
        )));
    }
    Ok(())
}

pub(super) fn require_completion(completion: &Value, label: &str) -> io::Result<()> {
    let items = completion
        .as_array()
        .or_else(|| completion["items"].as_array());
    if !items.is_some_and(|items| items.iter().any(|item| item["label"] == label)) {
        return Err(io::Error::other(format!(
            "missing {label} completion: {completion}"
        )));
    }
    Ok(())
}
