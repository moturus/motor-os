//! Project instructions from the selected workspace root only.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::state::StateRoot;

const MAX_CHARS: usize = 20_000;
const HEAD_CHARS: usize = MAX_CHARS * 7 / 10;
const TAIL_CHARS: usize = MAX_CHARS * 2 / 10;

pub fn load(workspace: &Path) -> Result<Option<String>, String> {
    let root = StateRoot::new(workspace.to_path_buf())?;
    for name in ["AGENTS.md", ".gears.md"] {
        if let Some(path) = root.existing_file(Path::new(name))? {
            return bounded(&path, name).map(Some);
        }
    }
    Ok(None)
}

fn bounded(path: &Path, name: &str) -> Result<String, String> {
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let length = file.metadata().map_err(|error| error.to_string())?.len();
    let mut bytes = Vec::new();
    (&mut file)
        .take((MAX_CHARS * 4 + 4) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let complete = bytes.len() as u64 == length;
    let head = match std::str::from_utf8(&bytes) {
        Ok(text) => text,
        Err(error) if !complete && error.error_len().is_none() => {
            std::str::from_utf8(&bytes[..error.valid_up_to()]).unwrap()
        }
        Err(_) => return Err(format!("{name} is not UTF-8")),
    };
    let title = format!("Project instructions from {name}:\n\n");
    if complete && head.chars().count() + title.chars().count() <= MAX_CHARS {
        return Ok(format!("{title}{head}"));
    }
    let head: String = head.chars().take(HEAD_CHARS).collect();
    let tail_bytes = length.min((TAIL_CHARS * 4 + 4) as u64);
    file.seek(SeekFrom::End(-(tail_bytes as i64)))
        .map_err(|error| error.to_string())?;
    bytes.clear();
    (&mut file)
        .take(tail_bytes)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let start = bytes
        .iter()
        .position(|byte| byte & 0xc0 != 0x80)
        .unwrap_or(bytes.len());
    let tail = std::str::from_utf8(&bytes[start..]).map_err(|_| format!("{name} is not UTF-8"))?;
    let tail: String = tail
        .chars()
        .rev()
        .take(TAIL_CHARS)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    Ok(format!(
        "{title}{head}\n\n[Project instructions truncated]\n\n{tail}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "batteries-instructions-{name}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn selects_only_root_instructions_with_agents_taking_precedence() {
        let root = root("selection");
        let workspace = root.join("project");
        std::fs::create_dir_all(workspace.join("nested")).unwrap();
        std::fs::write(root.join("AGENTS.md"), "parent must not load").unwrap();
        std::fs::write(workspace.join("nested/AGENTS.md"), "nested must not load").unwrap();
        assert_eq!(load(&workspace).unwrap(), None);
        std::fs::write(workspace.join(".gears.md"), "fallback").unwrap();
        assert!(load(&workspace).unwrap().unwrap().ends_with("fallback"));
        std::fs::write(workspace.join("AGENTS.md"), "primary").unwrap();
        assert!(load(&workspace).unwrap().unwrap().ends_with("primary"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bounds_large_unicode_instructions_and_keeps_both_ends() {
        let root = root("bounded");
        for text in [
            format!("BEGIN{}END", "x".repeat(30_000)),
            format!("BEGIN{}END", "🦀".repeat(30_000)),
        ] {
            std::fs::write(root.join("AGENTS.md"), text).unwrap();
            let fragment = load(&root).unwrap().unwrap();
            assert!(fragment.chars().count() <= MAX_CHARS);
            assert!(fragment.contains("BEGIN"));
            assert!(fragment.ends_with("END"));
            assert!(fragment.contains("truncated"));
        }
        std::fs::write(root.join("AGENTS.md"), [0xff]).unwrap();
        assert!(load(&root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_instructions_instead_of_loading_the_fallback() {
        let root = root("symlink");
        std::fs::write(root.join("outside"), "outside").unwrap();
        std::fs::write(root.join(".gears.md"), "fallback").unwrap();
        std::os::unix::fs::symlink(root.join("outside"), root.join("AGENTS.md")).unwrap();
        assert!(load(&root).unwrap_err().contains("expected regular file"));
        std::fs::remove_dir_all(root).unwrap();
    }
}
