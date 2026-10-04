//! Atomic UTF-8 replacements authorized by complete reads of this version.

use std::path::Path;

use gears::state::StateRoot;
use serde_json::{Value, json};

use crate::file_record::{FileVersion, fully_read, record};
use crate::paths::ToolContext;

pub fn write(context: &ToolContext, input: &str, content: &str) -> Result<Value, String> {
    let path = context.resolve(input, true)?;
    let previous = match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            let version = crate::file_read::version(&path)?;
            if !fully_read(context, &path, &version)? {
                return Err("read every page of the current file before overwriting it".into());
            }
            Some(version)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.to_string()),
    };
    if content.contains('\0') {
        return Err("binary files are not supported".into());
    }
    let mut content = match &previous {
        Some(version) => {
            let text = content.strip_prefix('\u{feff}').unwrap_or(content);
            if version.bom {
                format!("\u{feff}{text}")
            } else {
                text.into()
            }
        }
        None => content.to_string(),
    };
    if previous
        .as_ref()
        .is_some_and(|version| version.windows_lines)
    {
        content = content.replace("\r\n", "\n").replace('\n', "\r\n");
    }
    StateRoot::new(Path::new("/").to_path_buf())?
        .replace_file_preserving_access(path.strip_prefix("/").unwrap(), content.as_bytes())?;
    let version = FileVersion {
        hash: crate::snapshot::digest(content.as_bytes()),
        size: content.len() as u64,
        bom: content.starts_with('\u{feff}'),
        windows_lines: content.contains('\n')
            && content
                .split_inclusive('\n')
                .filter(|line| line.ends_with('\n'))
                .all(|line| line.ends_with("\r\n")),
    };
    let receipt = json!({"path": context.relative(&path), "hash": version.hash,
        "total_bytes": version.size, "written": true});
    // A bookkeeping failure must not misreport a workspace write as refused.
    let bookkeeping = record(context, &path, &version, 0, version.size).and_then(|_| {
        let name = format!(
            "writes/{}.json",
            crate::snapshot::digest(
                context
                    .relative(&path)
                    .to_str()
                    .ok_or("file path is not UTF-8")?
                    .as_bytes()
            )
        );
        context.replace_data(
            &name,
            &serde_json::to_vec(&receipt).map_err(|error| error.to_string())?,
        )
    });
    let mut receipt = receipt;
    if let Err(error) = bookkeeping {
        receipt["warning"] = json!(format!("file was written, but its record failed: {error}"));
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> (std::path::PathBuf, ToolContext) {
        let root =
            std::env::temp_dir().join(format!("batteries-write-{name}-{}", std::process::id()));
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        let context = ToolContext::new(
            root.join("workspace"),
            root.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        (root, context)
    }

    #[test]
    fn incomplete_and_changed_reads_refuse_overwrites_but_own_writes_remain_editable() {
        let (root, context) = fixture("coverage");
        let path = context.workspace.join("text");
        std::fs::write(&path, "a".repeat(40_000)).unwrap();
        assert!(write(&context, "text", "replacement").is_err());
        let first = crate::file_read::read(&context, "text", 0).unwrap();
        assert!(write(&context, "text", "replacement").is_err());
        crate::file_read::read(&context, "text", first.next_offset.unwrap()).unwrap();
        std::fs::write(&path, "b".repeat(40_000)).unwrap();
        assert!(write(&context, "text", "replacement").is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "b".repeat(40_000));
        write(&context, "new/dir/file", "first").unwrap();
        assert_eq!(
            write(&context, "new/dir/file", "second").unwrap()["written"],
            true
        );
        assert_eq!(
            std::fs::read_to_string(context.workspace.join("new/dir/file")).unwrap(),
            "second"
        );
        assert!(write(&context, "new/binary", "\0").is_err());
        assert!(!context.workspace.join("new/binary").exists());
        assert!(
            write(
                &context,
                context.state.path().join("key").to_str().unwrap(),
                "bad"
            )
            .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn keeps_bom_windows_lines_and_executable_permissions() {
        let (root, context) = fixture("format");
        let path = context.workspace.join("script");
        std::fs::write(&path, "\u{feff}first\r\nsecond\r\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o751)).unwrap();
        }
        crate::file_read::read(&context, "script", 0).unwrap();
        write(&context, "script", "changed\nline\r\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "\u{feff}changed\r\nline\r\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o751
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reports_a_write_even_if_later_bookkeeping_fails() {
        let (root, context) = fixture("receipt");
        std::fs::create_dir_all(root.join("state/batteries/sessions/s1")).unwrap();
        std::fs::write(
            root.join("state/batteries/sessions/s1/reads"),
            "obstruction",
        )
        .unwrap();
        let result = write(&context, "created", "actual contents").unwrap();
        assert_eq!(result["written"], true);
        assert!(
            result["warning"]
                .as_str()
                .unwrap()
                .contains("file was written")
        );
        assert_eq!(
            std::fs::read_to_string(context.workspace.join("created")).unwrap(),
            "actual contents"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
