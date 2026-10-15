//! Bounded text pages and read coverage for the current file version.

use std::io::Read;
use std::path::Path;

use crate::batteries::file_record::{FileVersion, record};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::batteries::paths::ToolContext;

const PAGE_BYTES: usize = 30_000;
/// The file tools read, patch and overwrite text files up to this size.
pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct Page {
    pub path: std::path::PathBuf,
    pub offset: u64,
    pub next_offset: Option<u64>,
    pub total_bytes: u64,
    pub hash: String,
    pub all_pages_read: bool,
    pub content: String,
}

pub fn read(context: &ToolContext, input: &str, offset: u64) -> Result<Page, String> {
    let path = context.resolve(input, false)?;
    let (version, bytes, line, continued) = scan(&path, offset)?;
    let (content, consumed) = numbered(&bytes, line, continued, offset == 0)?;
    let end = offset + consumed as u64;
    let all_pages_read = record(context, &path, &version, offset, end)?;
    Ok(Page {
        path: context.relative(&path),
        offset,
        next_offset: (end < version.size).then_some(end),
        total_bytes: version.size,
        hash: version.hash,
        all_pages_read,
        content,
    })
}

pub fn version(path: &Path) -> Result<FileVersion, String> {
    scan(path, 0).map(|(version, _, _, _)| version)
}

fn scan(path: &Path, offset: u64) -> Result<(FileVersion, Vec<u8>, u64, bool), String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Err("read_file requires a regular file".into());
    }
    if metadata.len() > MAX_FILE_BYTES {
        return Err("file tools support files up to 4 MiB; use sh for larger ones".into());
    }
    if offset > metadata.len() {
        return Err("offset is beyond the end of the file".into());
    }
    let mut file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 32 * 1024];
    let mut pending = Vec::new();
    let mut page = Vec::new();
    let (mut position, mut line) = (0_u64, 1_u64);
    let (mut previous, mut before_offset) = (None, None);
    let (mut bom, mut saw_newline, mut windows_lines) = (false, false, true);
    loop {
        let count = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        let bytes = &buffer[..count];
        if position == 0 {
            bom = bytes.starts_with(&[0xef, 0xbb, 0xbf]);
        }
        if bytes.contains(&0) {
            return Err("binary files are not supported".into());
        }
        hash.update(bytes);
        pending.extend_from_slice(bytes);
        match std::str::from_utf8(&pending) {
            Ok(_) => pending.clear(),
            Err(error) if error.error_len().is_none() => {
                pending.drain(..error.valid_up_to());
            }
            Err(_) => return Err("file is not UTF-8".into()),
        }
        for (index, byte) in bytes.iter().enumerate() {
            let at = position + index as u64;
            if at < offset {
                before_offset = Some(*byte);
                line += u64::from(*byte == b'\n');
            }
            if *byte == b'\n' {
                saw_newline = true;
                windows_lines &= previous == Some(b'\r');
            }
            previous = Some(*byte);
        }
        let start = offset.saturating_sub(position).min(count as u64) as usize;
        let end = (offset
            .saturating_add(PAGE_BYTES as u64)
            .saturating_sub(position))
        .min(count as u64) as usize;
        if end > start {
            page.extend_from_slice(&bytes[start..end]);
        }
        position += count as u64;
    }
    if !pending.is_empty() {
        return Err("file ends inside a UTF-8 character".into());
    }
    let hash = hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok((
        FileVersion {
            hash,
            size: position,
            bom,
            windows_lines: saw_newline && windows_lines,
        },
        page,
        line,
        offset != 0 && before_offset != Some(b'\n'),
    ))
}

fn numbered(
    bytes: &[u8],
    mut line: u64,
    continued: bool,
    beginning: bool,
) -> Result<(String, usize), String> {
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) if error.error_len().is_none() => {
            std::str::from_utf8(&bytes[..error.valid_up_to()]).unwrap()
        }
        Err(_) => return Err("offset splits a UTF-8 character".into()),
    };
    let mut output = String::new();
    let (mut need_number, mut consumed) = (true, 0);
    for (index, ch) in text.char_indices() {
        if beginning && index == 0 && ch == '\u{feff}' {
            consumed = ch.len_utf8();
            continue;
        }
        let prefix = if need_number {
            format!(
                "{line}{}: ",
                if index == 0 && continued {
                    " (continued)"
                } else {
                    ""
                }
            )
        } else {
            String::new()
        };
        if output.len() + prefix.len() + ch.len_utf8() > PAGE_BYTES {
            break;
        }
        output.push_str(&prefix);
        output.push(ch);
        consumed = index + ch.len_utf8();
        need_number = ch == '\n';
        line += u64::from(need_number);
    }
    Ok((output, consumed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batteries::file_record::fully_read;

    #[test]
    fn pages_long_unicode_lines_and_requires_every_page_of_the_current_version() {
        let root = std::env::temp_dir().join(format!("batteries-read-{}", std::process::id()));
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        let context = ToolContext::new(
            root.join("workspace"),
            root.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        let path = context.workspace.join("text");
        let text = format!("\u{feff}first\r\n{}\r\nlast", "🦀".repeat(20_000));
        std::fs::write(&path, &text).unwrap();
        let first = read(&context, "text", 0).unwrap();
        assert!(first.content.starts_with("1: first\r\n2: "));
        assert!(!first.all_pages_read);
        let mut offset = first.next_offset;
        while let Some(next) = offset {
            let page = read(&context, "./text", next).unwrap();
            assert!(page.content.len() <= PAGE_BYTES);
            offset = page.next_offset;
        }
        let current = version(&path).unwrap();
        assert!(current.bom && current.windows_lines);
        let memory = FileVersion::of(text.as_bytes());
        assert_eq!(
            (memory.hash, memory.size, memory.bom, memory.windows_lines),
            (current.hash.clone(), current.size, true, true)
        );
        assert!(fully_read(&context, &path, &current).unwrap());
        std::fs::write(&path, text.replace("first", "other")).unwrap();
        assert!(!fully_read(&context, &path, &version(&path).unwrap()).unwrap());
        assert!(read(&context, "text", 12).is_err());
        std::fs::write(&path, [0, 1, 2]).unwrap();
        assert!(read(&context, "text", 0).unwrap_err().contains("binary"));
        std::fs::write(&path, [0xff]).unwrap();
        assert!(read(&context, "text", 0).is_err());
        std::fs::File::create(&path)
            .unwrap()
            .set_len(MAX_FILE_BYTES + 1)
            .unwrap();
        assert!(read(&context, "text", 0).unwrap_err().contains("4 MiB"));
        std::fs::remove_dir_all(root).unwrap();
    }
}
