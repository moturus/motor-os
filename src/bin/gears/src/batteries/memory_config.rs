//! User-wide memory resource limits, independent of workspace check declarations.

use std::io::Read;
use std::path::Path;

use crate::state::StateRoot;
use serde::Deserialize;

use crate::batteries::memory_format::Target;

#[derive(Debug, Deserialize)]
struct Configuration {
    version: u32,
    #[serde(default)]
    memory: Limits,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub user_chars: usize,
    pub memory_chars: usize,
    /// Whether the model may offer one lesson after a task; off by default.
    pub offer_lessons: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            user_chars: 1375,
            memory_chars: 2200,
            offer_lessons: false,
        }
    }
}

impl Limits {
    pub fn for_target(&self, target: Target) -> usize {
        if target == Target::User {
            self.user_chars
        } else {
            self.memory_chars
        }
    }
}

pub fn load(root: &StateRoot) -> Result<Limits, String> {
    let Some(text) = read(root)? else {
        return Ok(Limits::default());
    };
    let config: Configuration =
        toml::from_str(&text).map_err(|error| format!("invalid user batteries.toml: {error}"))?;
    if config.version != 1 {
        return Err("unsupported user batteries.toml version".into());
    }
    if [config.memory.user_chars, config.memory.memory_chars]
        .iter()
        .any(|limit| !(1..=65536).contains(limit))
    {
        return Err("memory character limits must be between 1 and 65536".into());
    }
    Ok(config.memory)
}

pub(crate) fn read(root: &StateRoot) -> Result<Option<String>, String> {
    let Some(path) = root.existing_file(Path::new("batteries.toml"))? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|error| error.to_string())?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 65536 {
        return Err("user batteries.toml exceeds 64 KiB".into());
    }
    let text = String::from_utf8(bytes).map_err(|_| "user batteries.toml is not UTF-8")?;
    Ok(Some(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_user_wide_bounded_and_reject_typos() {
        let path =
            std::env::temp_dir().join(format!("batteries-memory-config-{}", std::process::id()));
        let root = StateRoot::new(path.clone()).unwrap();
        assert_eq!(load(&root).unwrap().for_target(Target::User), 1375);
        assert_eq!(load(&root).unwrap().for_target(Target::Workspace), 2200);
        let config = Path::new("batteries.toml");
        assert!(!load(&root).unwrap().offer_lessons);
        root.replace_file(
            config,
            b"version = 1\n[memory]\nuser_chars = 500\nmemory_chars = 1200\noffer_lessons = true",
        )
        .unwrap();
        assert_eq!(load(&root).unwrap().for_target(Target::User), 500);
        assert_eq!(load(&root).unwrap().for_target(Target::Global), 1200);
        assert!(load(&root).unwrap().offer_lessons);
        for invalid in [
            "version = 2",
            "[memory]\nuser_chars = 10",
            "version = 1\n[memory]\nuser_char = 100",
            "version = 1\n[memory]\nuser_chars = 0",
            "version = 1\n[memory]\nmemory_chars = 65537",
        ] {
            root.replace_file(config, invalid.as_bytes()).unwrap();
            assert!(load(&root).is_err(), "{invalid}");
        }
        std::fs::remove_dir_all(path).unwrap();
    }
}
