//! File patches share atomic-write and current-read requirements.

use std::io::Read;

use serde_json::{Value, json};

use crate::batteries::file_read::MAX_FILE_BYTES;
use crate::batteries::paths::ToolContext;

const MAX_DIFF_BYTES: usize = 30_000;

pub fn patch(context: &ToolContext, input: &str, old: &str, new: &str) -> Result<Value, String> {
    let path = context.resolve(input, true)?;
    if !std::fs::symlink_metadata(&path)
        .map_err(|error| error.to_string())?
        .is_file()
    {
        return Err("patch requires a regular file".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&path)
        .map_err(|error| error.to_string())?
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err("file tools support files up to 4 MiB; use sh for larger ones".into());
    }
    let version = crate::batteries::file_record::FileVersion::of(&bytes);
    let source = String::from_utf8(bytes).map_err(|_| "patch requires UTF-8 text")?;
    let source = source.strip_prefix('\u{feff}').unwrap_or(&source);
    let matched = crate::batteries::patch_match::locate(source, old, new)?;
    let replacement = if version.windows_lines {
        matched
            .replacement
            .replace("\r\n", "\n")
            .replace('\n', "\r\n")
    } else {
        matched.replacement.clone()
    };
    let mut changed = source.to_string();
    changed.replace_range(matched.range.clone(), &replacement);
    let diff = diff(source, &changed, matched.range, replacement.len());
    let mut receipt =
        crate::batteries::file_write::write_over(context, &path, Some(version), &changed)?;
    receipt["match_rule"] = json!(matched.rule);
    receipt["diff"] = json!(diff.0);
    receipt["diff_truncated"] = json!(diff.1);
    Ok(receipt)
}

fn diff(before: &str, after: &str, range: std::ops::Range<usize>, added: usize) -> (String, bool) {
    // Show whole affected lines, including prefix/suffix for an inline edit.
    let start = before[..range.start].rfind('\n').map_or(0, |at| at + 1);
    let end = before[range.end..]
        .find('\n')
        .map_or(before.len(), |at| range.end + at + 1);
    let after_end = end - (range.end - range.start) + added;
    let old = &before[start..end];
    let new = &after[start..after_end];
    let line = before[..start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let mut output = format!(
        "@@ -{line},{} +{line},{} @@\n",
        old.lines().count(),
        new.lines().count()
    );
    for (prefix, text) in [('-', old), ('+', new)] {
        for line in text.split_inclusive('\n') {
            output.push(prefix);
            output.push_str(line);
            if !line.ends_with('\n') {
                output.push_str("\n\\ No newline at end of file\n");
            }
        }
    }
    let truncated = output.len() > MAX_DIFF_BYTES;
    if truncated {
        let mut end = MAX_DIFF_BYTES;
        while !output.is_char_boundary(end) {
            end -= 1;
        }
        output.truncate(end);
    }
    (output, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_requires_current_reads_preserves_format_and_reports_the_actual_diff() {
        let root = std::env::temp_dir().join(format!("batteries-patch-{}", std::process::id()));
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        let context = ToolContext::new(
            root.join("workspace"),
            root.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        let path = context.workspace.join("source");
        std::fs::write(&path, "\u{feff}    first\r\n      second\r\nlast\r\n").unwrap();
        assert!(patch(&context, "source", "first\nsecond\n", "new\n  next\n").is_err());
        crate::batteries::file_read::read(&context, "source", 0).unwrap();
        let result = patch(&context, "source", "first\nsecond\n", "new\n  next\n").unwrap();
        assert_eq!(result["match_rule"], "indentation");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "\u{feff}    new\r\n      next\r\nlast\r\n"
        );
        assert!(result["diff"].as_str().unwrap().contains("+    new\r\n"));
        patch(&context, "source", "last", "done").unwrap();
        std::fs::write(&path, "same same").unwrap();
        crate::batteries::file_read::read(&context, "source", 0).unwrap();
        assert!(
            patch(&context, "source", "same", "changed")
                .unwrap_err()
                .contains("ambiguous")
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "same same");
        assert!(patch(&context, "source", "", "changed").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inline_diff_and_unicode_truncation_have_valid_boundaries() {
        assert_eq!(
            diff("before old after", "before new after", 7..10, 3).0,
            "@@ -1,1 +1,1 @@\n-before old after\n\\ No newline at end of file\n+before new after\n\\ No newline at end of file\n"
        );
        let text = "🦀".repeat(10_000);
        let shown = diff("old", &text, 0..3, text.len());
        assert!(shown.1);
        assert!(shown.0.len() <= MAX_DIFF_BYTES);
    }
}
