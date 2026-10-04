//! Durable derived JSON lines; only an unfinished final line is discarded.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};

use serde::Serialize;

use crate::paths::ToolContext;

const MAX_LINE: usize = 1024 * 1024;

pub fn append(context: &ToolContext, name: &str, value: &impl Serialize) -> Result<(), String> {
    let mut bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_LINE {
        return Err("journal record exceeds 1 MiB".into());
    }
    bytes.push(b'\n');
    let path = context.data_file(name)?;
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
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        let context = ToolContext::new(
            root.join("workspace"),
            root.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        append(&context, "turns.jsonl", &json!({"version": 1, "turn": 1})).unwrap();
        let path = context.data_file("turns.jsonl").unwrap();
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
        append(
            &context,
            "turns.jsonl",
            &json!({"version": 1, "text": "🦀"}),
        )
        .unwrap();
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
        append(&context, "turns.jsonl", &json!({"version": 1})).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"version\":1}\n");
        std::fs::remove_dir_all(root).unwrap();
    }
}
