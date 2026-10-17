//! Durable derived JSON lines; only an unfinished final line is discarded.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::state::StateRoot;

use serde::Serialize;

const MAX_LINE: usize = 1024 * 1024;

/// Append to a checked state path, such as the decision history.
pub fn append_at(root: &StateRoot, path: &Path, value: &impl Serialize) -> Result<(), String> {
    let relative = path
        .strip_prefix(root.path())
        .map_err(|_| "journal is outside its state root")?;
    let path = root.file(relative)?;
    let mut bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_LINE {
        return Err("journal record exceeds 1 MiB".into());
    }
    bytes.push(b'\n');
    let mut options = OpenOptions::new();
    options.read(true).append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| error.to_string())?;
    repair_tail(&mut file).map_err(|error| error.to_string())?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_data())
        .map_err(|error| error.to_string())
}

/// Visit completed records without loading the entire history into memory.
/// An incomplete final line is ignored; completed malformed records are errors.
pub fn visit(
    root: &StateRoot,
    relative: &Path,
    mut record: impl FnMut(serde_json::Value) -> Result<(), String>,
) -> Result<(), String> {
    visit_lenient(root, relative, |value| record(value?))
}

/// Like `visit`, but a malformed record is passed on as an error for the
/// caller to count or skip, and the visit continues.
pub fn visit_lenient(
    root: &StateRoot,
    relative: &Path,
    mut record: impl FnMut(Result<serde_json::Value, String>) -> Result<(), String>,
) -> Result<(), String> {
    let Some(path) = root.existing_file(relative)? else {
        return Ok(());
    };
    let file = std::fs::File::open(&path).map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut number = 0;
    loop {
        line.clear();
        let count = reader
            .by_ref()
            .take(MAX_LINE as u64 + 2)
            .read_until(b'\n', &mut line)
            .map_err(|error| error.to_string())?;
        if count == 0 {
            return Ok(());
        }
        number += 1;
        if count > MAX_LINE + 1 {
            return Err(format!(
                "{}:{number}: journal record exceeds 1 MiB",
                path.display()
            ));
        }
        if line.last() != Some(&b'\n') {
            return Ok(());
        }
        let value = serde_json::from_slice(&line).map_err(|error| {
            format!(
                "{}:{number}: invalid journal record: {error}",
                path.display()
            )
        });
        record(value)?;
    }
}

fn repair_tail(file: &mut std::fs::File) -> std::io::Result<()> {
    let end = file.seek(SeekFrom::End(0))?;
    let mut position = end;
    let mut buffer = [0; 4096];
    while position != 0 {
        let count = position.min(buffer.len() as u64) as usize;
        position -= count as u64;
        file.seek(SeekFrom::Start(position))?;
        file.read_exact(&mut buffer[..count])?;
        if let Some(newline) = buffer[..count].iter().rposition(|byte| *byte == b'\n') {
            let complete = position + newline as u64 + 1;
            if complete != end {
                file.set_len(complete)?;
            }
            return Ok(());
        }
        if end - position > MAX_LINE as u64 + 1 {
            return Err(std::io::Error::other(
                "unfinished journal tail exceeds 1 MiB",
            ));
        }
    }
    if end != 0 {
        file.set_len(0)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn crash_tail_recovery_keeps_complete_records_and_utf8() {
        let root = std::env::temp_dir().join(format!("batteries-journal-{}", std::process::id()));
        let state = StateRoot::new(root.clone()).unwrap();
        let path = state.file(Path::new("batteries/records.jsonl")).unwrap();
        append_at(&state, &path, &json!({"version": 1, "turn": 1})).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"partial\":")
            .unwrap();
        append_at(&state, &path, &json!({"version": 1, "text": "🦀"})).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            lines,
            [
                json!({"version": 1, "turn": 1}),
                json!({"version": 1, "text": "🦀"})
            ]
        );
        assert!(text.ends_with('\n'));
        std::fs::write(&path, "unfinished first line").unwrap();
        append_at(&state, &path, &json!({"version": 1})).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"version\":1}\n");
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn reading_history_ignores_only_the_unfinished_tail_and_never_mutates_it() {
        let path =
            std::env::temp_dir().join(format!("batteries-journal-read-{}", std::process::id()));
        let root = StateRoot::new(path.clone()).unwrap();
        let relative = Path::new("batteries/changes.jsonl");
        let file = root.file(relative).unwrap();
        let original = b"{\"version\":1,\"decision\":\"deny\"}\n{\"partial\":";
        std::fs::write(&file, original).unwrap();
        let mut records = Vec::new();
        visit(&root, relative, |value| {
            records.push(value);
            Ok(())
        })
        .unwrap();
        assert_eq!(records, [json!({"version": 1, "decision": "deny"})]);
        assert_eq!(std::fs::read(&file).unwrap(), original);
        append_at(&root, &file, &json!({"version": 1, "decision": "approve"})).unwrap();
        records.clear();
        visit(&root, relative, |value| {
            records.push(value);
            Ok(())
        })
        .unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1]["decision"], "approve");
        std::fs::write(&file, b"{broken}\n{\"tail\":").unwrap();
        assert!(
            visit(&root, relative, |_| Ok(()))
                .unwrap_err()
                .contains("invalid journal record")
        );
        std::fs::write(&file, vec![b'x'; MAX_LINE + 2]).unwrap();
        assert!(
            visit(&root, relative, |_| Ok(()))
                .unwrap_err()
                .contains("exceeds")
        );
        assert!(visit(&root, Path::new("../escape"), |_| Ok(())).is_err());
        #[cfg(unix)]
        {
            std::fs::remove_file(&file).unwrap();
            std::os::unix::fs::symlink(path.join("outside"), &file).unwrap();
            assert!(visit(&root, relative, |_| Ok(())).is_err());
            assert!(append_at(&root, &file, &json!({})).is_err());
        }
        std::fs::remove_dir_all(path).unwrap();
    }
}
