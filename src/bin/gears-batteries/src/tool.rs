//! External-tool entry points, with one bounded JSON argument object.

use std::io::Read;

use serde::Deserialize;
use serde_json::Value;

use crate::paths::ToolContext;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadFile {
    path: String,
    #[serde(default)]
    offset: u64,
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
        "read_file" => {
            let arguments: ReadFile = serde_json::from_slice(&bytes)
                .map_err(|error| format!("invalid read_file arguments: {error}"))?;
            let page = crate::file_read::read(context, &arguments.path, arguments.offset)?;
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
