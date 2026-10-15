//! External-tool entry points, with one bounded JSON argument object.

use std::io::Read;

use serde::Deserialize;
use serde_json::Value;

use crate::batteries::paths::ToolContext;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadFile {
    path: String,
    #[serde(default)]
    offset: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Patch {
    path: String,
    old_text: String,
    new_text: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteFile {
    path: String,
    content: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionSearch {
    query: String,
    #[serde(default)]
    offset: usize,
    #[serde(default = "search_limit")]
    limit: usize,
}

fn search_limit() -> usize {
    10
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchFiles {
    pattern: String,
    #[serde(default = "search_root")]
    path: String,
}

fn search_root() -> String {
    ".".into()
}

pub fn run(name: &str, reader: impl Read, context: &ToolContext) -> Result<Value, String> {
    let mut bytes = Vec::new();
    reader
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 1024 * 1024 {
        return Err("tool arguments exceed 1 MiB".into());
    }
    match name {
        "session_search" => {
            let arguments: SessionSearch = serde_json::from_slice(&bytes)
                .map_err(|error| format!("invalid session_search arguments: {error}"))?;
            crate::batteries::session_search::search(
                context,
                &arguments.query,
                arguments.offset,
                arguments.limit,
            )
        }
        "check" => {
            let _: Empty = serde_json::from_slice(&bytes)
                .map_err(|error| format!("invalid check arguments: {error}"))?;
            crate::batteries::check::execute(context)
        }
        "patch" => {
            let arguments: Patch = serde_json::from_slice(&bytes)
                .map_err(|error| format!("invalid patch arguments: {error}"))?;
            crate::batteries::file_patch::patch(
                context,
                &arguments.path,
                &arguments.old_text,
                &arguments.new_text,
            )
        }
        "write_file" => {
            let arguments: WriteFile = serde_json::from_slice(&bytes)
                .map_err(|error| format!("invalid write_file arguments: {error}"))?;
            crate::batteries::file_write::write(context, &arguments.path, &arguments.content)
        }
        "search_files" => {
            let arguments: SearchFiles = serde_json::from_slice(&bytes)
                .map_err(|error| format!("invalid search_files arguments: {error}"))?;
            crate::batteries::search::files(context, &arguments.pattern, &arguments.path)
        }
        "read_file" => {
            let arguments: ReadFile = serde_json::from_slice(&bytes)
                .map_err(|error| format!("invalid read_file arguments: {error}"))?;
            let page =
                crate::batteries::file_read::read(context, &arguments.path, arguments.offset)?;
            serde_json::to_value(page).map_err(|error| error.to_string())
        }
        _ => Err(format!("unknown tool {name:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_arguments_never_create_read_coverage() {
        let root = std::env::temp_dir().join(format!("batteries-tool-{}", std::process::id()));
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        let context = ToolContext::new(
            root.join("workspace"),
            root.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        for invalid in [
            "{}",
            "[]",
            "{\"path\":\"f\",\"offset\":-1}",
            "{\"path\":\"f\",\"unknown\":true}",
            "{\"path\":\"f\",\"path\":\"g\"}",
        ] {
            assert!(run("read_file", invalid.as_bytes(), &context).is_err());
        }
        assert!(!context.state.path().exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}
