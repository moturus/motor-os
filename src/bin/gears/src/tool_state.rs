//! Versioned global tool enablement overrides.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::state::StateRoot;

const FILE: &str = "tools.toml";
const VERSION: u32 = 1;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overrides {
    pub tools: BTreeMap<String, bool>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileFormat {
    version: u32,
    #[serde(default)]
    tools: BTreeMap<String, bool>,
}

impl Overrides {
    pub fn default_directory() -> Result<PathBuf, String> {
        Config::default_path()
            .and_then(|path| path.parent().map(Path::to_path_buf))
            .ok_or("cannot locate Gears state directory".to_string())
    }

    pub fn load(directory: &Path) -> Result<Self, String> {
        let state = StateRoot::new(directory.to_path_buf())?;
        let Some(path) = state.existing_file(Path::new(FILE))? else {
            return Ok(Self::default());
        };
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let data: FileFormat =
            toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        if data.version != VERSION {
            return Err(format!(
                "{}: unsupported version {} (expected {VERSION})",
                path.display(),
                data.version
            ));
        }
        if data.tools.keys().any(String::is_empty) {
            return Err(format!("{}: empty tool name", path.display()));
        }
        Ok(Self { tools: data.tools })
    }

    pub fn save(&self, directory: &Path) -> Result<(), String> {
        let text = toml::to_string(&FileFormat {
            version: VERSION,
            tools: self.tools.clone(),
        })
        .map_err(|error| format!("cannot serialize tool overrides: {error}"))?;
        StateRoot::new(directory.to_path_buf())?.replace_file(Path::new(FILE), text.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("gears-tool-state-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        directory
    }

    #[test]
    fn round_trip_and_corrupt_file() {
        let directory = fixture("round-trip");
        assert_eq!(Overrides::load(&directory).unwrap(), Overrides::default());
        let mut overrides = Overrides::default();
        overrides.tools.insert("sh".into(), false);
        overrides.save(&directory).unwrap();
        assert_eq!(Overrides::load(&directory).unwrap(), overrides);
        std::fs::write(directory.join(FILE), "version = 2\n").unwrap();
        assert!(Overrides::load(&directory).unwrap_err().contains("version"));
        std::fs::write(directory.join(FILE), "version = 1\n[tools]\nsh = 'yes'\n").unwrap();
        assert!(Overrides::load(&directory).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_without_replacing_its_target() {
        let directory = fixture("symlink");
        std::fs::create_dir_all(&directory).unwrap();
        let target = directory.join("target");
        std::fs::write(&target, "untouched").unwrap();
        std::os::unix::fs::symlink(&target, directory.join(FILE)).unwrap();
        assert!(Overrides::load(&directory).is_err());
        assert!(Overrides::default().save(&directory).is_err());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "untouched");
        std::fs::remove_dir_all(directory).unwrap();
    }
}
