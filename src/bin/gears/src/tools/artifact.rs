//! Model access to the current session's durable artifacts.

use std::sync::Arc;

use serde_json::{Value, json};

use super::{DEFAULT_CAP, Tool, schema, string_arg};
use crate::agent::artifact::{ContentSlice, LazyStore};
use crate::provider::ToolSpec;

const DEFAULT_LIST_RESULTS: usize = 20;
const MAX_LIST_RESULTS: usize = 100;

pub struct ArtifactTool {
    store: Arc<LazyStore>,
    max_range_bytes: usize,
}

pub fn tool(store: Arc<LazyStore>, max_range_bytes: usize) -> Box<dyn Tool> {
    Box::new(ArtifactTool {
        store,
        max_range_bytes,
    })
}

impl Tool for ArtifactTool {
    fn name(&self) -> &'static str {
        "artifacts"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            self.name(),
            "List this session's durable artifacts, or read one exact byte or line range. \
             Byte offsets are zero-based; line numbers are one-based. Binary or control-byte \
             content is returned as exact lowercase hex.",
            schema(
                json!({
                    "action": {"type": "string", "enum": ["list", "read"]},
                    "id": {"type": "integer", "minimum": 1, "description":
                        "Artifact ID; required for read."},
                    "after_id": {"type": "integer", "minimum": 0, "description":
                        "For list, return IDs greater than this value (default 0)."},
                    "limit": {"type": "integer", "minimum": 1,
                        "maximum": MAX_LIST_RESULTS, "description":
                        "For list, maximum metadata records (default 20)."},
                    "byte_start": {"type": "integer", "minimum": 0},
                    "byte_length": {"type": "integer", "minimum": 1,
                        "maximum": self.max_range_bytes},
                    "line_start": {"type": "integer", "minimum": 1},
                    "line_count": {"type": "integer", "minimum": 1, "description":
                        "The selected lines must fit the configured byte-range limit."},
                }),
                &["action"],
            ),
        )
    }

    fn mutates(&self) -> bool {
        false
    }

    fn call(&self, args: &Value) -> Result<String, String> {
        match string_arg(args, "action")?.as_str() {
            "list" => self.list(args),
            "read" => self.read(args),
            other => Err(format!(
                "unknown action '{other}' (expected 'list' or 'read')"
            )),
        }
    }

    fn cap(&self) -> usize {
        DEFAULT_CAP.max(self.max_range_bytes.saturating_mul(2).saturating_add(1024))
    }
}

impl ArtifactTool {
    fn list(&self, args: &Value) -> Result<String, String> {
        reject(
            args,
            &[
                "id",
                "byte_start",
                "byte_length",
                "line_start",
                "line_count",
            ],
            "list",
        )?;
        let after = number(args, "after_id")?.unwrap_or(0);
        let limit = number(args, "limit")?.unwrap_or(DEFAULT_LIST_RESULTS as u64);
        let limit = usize::try_from(limit)
            .map_err(|_| "argument 'limit' is too large for this system".to_string())?;
        if limit == 0 || limit > MAX_LIST_RESULTS {
            return Err(format!(
                "argument 'limit' must be between 1 and {MAX_LIST_RESULTS}"
            ));
        }
        let (artifacts, more) = self.store.get()?.list_after(after, limit);
        let next_after_id = more.then(|| artifacts.last().unwrap().id);
        let output = serde_json::to_string_pretty(&json!({
            "artifacts": artifacts,
            "next_after_id": next_after_id,
        }))
        .map_err(|error| error.to_string())?;
        if output.len() > DEFAULT_CAP {
            return Err(format!(
                "artifact listing is {} bytes; reduce 'limit' to fit the {DEFAULT_CAP}-byte result limit",
                output.len()
            ));
        }
        Ok(output)
    }

    fn read(&self, args: &Value) -> Result<String, String> {
        reject(args, &["after_id", "limit"], "read")?;
        let id = positive(args, "id")?;
        let byte_start = number(args, "byte_start")?;
        let byte_length = number(args, "byte_length")?;
        let line_start = number(args, "line_start")?;
        let line_count = number(args, "line_count")?;
        let store = self.store.get()?;
        let (label, slice) = match (byte_start, byte_length, line_start, line_count) {
            (Some(start), Some(length), None, None) => {
                let length =
                    usize::try_from(length).map_err(|_| range_limit(self.max_range_bytes))?;
                if length == 0 || length > self.max_range_bytes {
                    return Err(range_limit(self.max_range_bytes));
                }
                let slice = store.read_bytes(id, start, length)?;
                let end = start + slice.bytes.len() as u64;
                (format!("bytes {start}..{end}"), slice)
            }
            (None, None, Some(start), Some(count)) if start > 0 && count > 0 => {
                let end = start.checked_add(count).ok_or("line range overflow")?;
                let slice = store.read_lines(id, start, count, self.max_range_bytes)?;
                (format!("lines {start}..{end}"), slice)
            }
            _ => {
                return Err(
                    "read requires exactly one complete range: byte_start with byte_length, or line_start with line_count"
                        .to_string(),
                );
            }
        };
        Ok(render(id, &label, slice))
    }
}

fn number(args: &Value, name: &str) -> Result<Option<u64>, String> {
    match &args[name] {
        Value::Null => Ok(None),
        Value::Number(number) => number
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("argument '{name}' must be a non-negative whole number")),
        _ => Err(format!("argument '{name}' must be a number")),
    }
}

fn positive(args: &Value, name: &str) -> Result<u64, String> {
    match number(args, name)? {
        Some(value) if value > 0 => Ok(value),
        _ => Err(format!("argument '{name}' must be a positive whole number")),
    }
}

fn reject(args: &Value, names: &[&str], action: &str) -> Result<(), String> {
    match names.iter().find(|name| !args[**name].is_null()) {
        Some(name) => Err(format!(
            "argument '{name}' does not apply to action '{action}'"
        )),
        None => Ok(()),
    }
}

fn range_limit(max: usize) -> String {
    format!("argument 'byte_length' must be between 1 and {max}")
}

fn render(id: u64, label: &str, slice: ContentSlice) -> String {
    let (encoding, content) = match std::str::from_utf8(&slice.bytes) {
        Ok(text)
            if text
                .chars()
                .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t')) =>
        {
            ("utf-8", text.to_string())
        }
        _ => ("hex", super::hex(&slice.bytes)),
    };
    format!(
        "artifact {id}: {label}; {} bytes returned of {}; encoding {encoding}\n{content}",
        slice.bytes.len(),
        slice.total_size
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::artifact::Origin;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn fixture() -> (PathBuf, Box<dyn Tool>) {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "gears-artifact-tool-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let store = Arc::new(LazyStore::new(root.clone(), "18-1".to_string(), 1024, 4096).unwrap());
        for (reference, content) in [
            ("first", b"one\n\xfftwo\nthree".as_slice()),
            ("second", b"last"),
        ] {
            store
                .get()
                .unwrap()
                .put(
                    "tool_output",
                    Origin {
                        producer: "test".to_string(),
                        reference: reference.to_string(),
                    },
                    content,
                )
                .unwrap();
        }
        (root, tool(store, 5))
    }

    #[test]
    fn metadata_pages_and_ranges_are_exact_and_bounded() {
        let (root, tool) = fixture();
        assert!(!tool.mutates());
        assert_eq!(
            tool.spec().function.parameters["properties"]["byte_length"]["maximum"],
            5
        );

        let first: Value =
            serde_json::from_str(&tool.call(&json!({"action": "list", "limit": 1})).unwrap())
                .unwrap();
        assert_eq!(first["artifacts"][0]["id"], 1);
        assert_eq!(first["next_after_id"], 1);
        let second = tool
            .call(&json!({"action": "list", "after_id": 1}))
            .unwrap();
        assert!(second.contains("\"id\": 2"), "{second}");

        let text = tool
            .call(&json!({"action": "read", "id": 1, "line_start": 1, "line_count": 1}))
            .unwrap();
        assert!(text.ends_with("encoding utf-8\none\n"), "{text:?}");
        let binary = tool
            .call(&json!({"action": "read", "id": 1, "byte_start": 4, "byte_length": 5}))
            .unwrap();
        assert!(binary.ends_with("encoding hex\nff74776f0a"), "{binary}");
        assert!(
            tool.call(&json!({"action": "read", "id": 1, "byte_start": 0, "byte_length": 6}))
                .unwrap_err()
                .contains("between 1 and 5")
        );
        assert!(tool.call(&json!({"action": "read", "id": 1, "byte_start": 0, "line_start": 1, "line_count": 1})).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
