//! Read coverage bound to a path and content hash.

use crate::batteries::paths::ToolContext;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;

pub struct FileVersion {
    pub hash: String,
    pub size: u64,
    pub bom: bool,
    pub windows_lines: bool,
}

impl FileVersion {
    /// The version of text already in memory, as `file_read` reports it for a file.
    pub fn of(bytes: &[u8]) -> Self {
        let mut lines = bytes
            .split_inclusive(|byte| *byte == b'\n')
            .filter(|line| line.ends_with(b"\n"));
        let first = lines.next();
        Self {
            hash: crate::batteries::snapshot::digest(bytes),
            size: bytes.len() as u64,
            bom: bytes.starts_with(&[0xef, 0xbb, 0xbf]),
            windows_lines: first.is_some_and(|line| line.ends_with(b"\r\n"))
                && lines.all(|line| line.ends_with(b"\r\n")),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ReadRecord {
    version: u32,
    path: std::path::PathBuf,
    hash: String,
    size: u64,
    ranges: Vec<(u64, u64)>,
}

fn record_name(context: &ToolContext, path: &Path) -> Result<String, String> {
    let relative = context.relative(path);
    let text = relative.to_str().ok_or("file path is not UTF-8")?;
    Ok(format!(
        "reads/{}.json",
        crate::batteries::snapshot::digest(text.as_bytes())
    ))
}

fn load(context: &ToolContext, path: &Path) -> Result<Option<ReadRecord>, String> {
    let path = context.data_file(&record_name(context, path)?)?;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let mut bytes = Vec::new();
    file.take(65537)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 65536 {
        return Err("file read record exceeds 64 KiB".into());
    }
    let record: ReadRecord = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if record.version != 1 {
        return Err("unsupported file read record version".into());
    }
    Ok(Some(record))
}

pub fn fully_read(
    context: &ToolContext,
    path: &Path,
    version: &FileVersion,
) -> Result<bool, String> {
    Ok(load(context, path)?.is_some_and(|record| {
        record.hash == version.hash
            && record.size == version.size
            && record.path == context.relative(path)
            && record.ranges == [(0, version.size)]
    }))
}

pub fn record(
    context: &ToolContext,
    path: &Path,
    version: &FileVersion,
    start: u64,
    end: u64,
) -> Result<bool, String> {
    let mut record = load(context, path)?
        .filter(|record| record.hash == version.hash)
        .unwrap_or_else(|| ReadRecord {
            version: 1,
            path: context.relative(path),
            hash: version.hash.clone(),
            size: version.size,
            ranges: Vec::new(),
        });
    record.ranges.push((start, end));
    record.ranges.sort_unstable();
    let mut ranges = Vec::<(u64, u64)>::new();
    for range in record.ranges {
        if let Some(last) = ranges.last_mut()
            && range.0 <= last.1
        {
            last.1 = last.1.max(range.1);
        } else {
            ranges.push(range);
        }
    }
    if ranges.len() > 1024 {
        return Err("file read coverage is too fragmented".into());
    }
    let complete = ranges == [(0, version.size)];
    record.ranges = ranges;
    context.replace_data(
        &record_name(context, path)?,
        &serde_json::to_vec(&record).map_err(|error| error.to_string())?,
    )?;
    Ok(complete)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gaps_and_changed_content_cannot_authorize_an_overwrite() {
        let root =
            std::env::temp_dir().join(format!("batteries-read-record-{}", std::process::id()));
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        let context = ToolContext::new(
            root.join("workspace"),
            root.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        let path = context.workspace.join("source");
        let mut version = FileVersion {
            hash: "first".into(),
            size: 100,
            bom: false,
            windows_lines: false,
        };
        assert!(!fully_read(&context, &path, &version).unwrap());
        assert!(!record(&context, &path, &version, 0, 40).unwrap());
        assert!(!record(&context, &path, &version, 60, 100).unwrap());
        assert!(record(&context, &path, &version, 30, 70).unwrap());
        assert!(fully_read(&context, &path, &version).unwrap());
        version.hash = "changed".into();
        assert!(!fully_read(&context, &path, &version).unwrap());
        assert!(!record(&context, &path, &version, 0, 40).unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }
}
