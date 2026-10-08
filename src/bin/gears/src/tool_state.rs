//! Versioned global tool enablement overrides.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::state::StateRoot;

const FILE: &str = "tools.toml";
const VERSION: u32 = 1;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overrides {
    pub tools: BTreeMap<String, bool>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileFormat {
    #[serde(default)]
    tools: BTreeMap<String, bool>,
}

impl Overrides {
    pub fn load(directory: &Path) -> Result<Self, String> {
        let data: FileFormat = StateRoot::new(directory.to_path_buf())?.load_toml(FILE, VERSION)?;
        if data.tools.keys().any(String::is_empty) {
            let path = directory.join(FILE);
            return Err(format!("{}: empty tool name", path.display()));
        }
        Ok(Self { tools: data.tools })
    }

    pub fn save(&self, directory: &Path) -> Result<(), String> {
        let data = FileFormat {
            tools: self.tools.clone(),
        };
        StateRoot::new(directory.to_path_buf())?.save_toml(FILE, VERSION, &data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
