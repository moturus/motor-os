//! Global permission grants, separate from tool enablement.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::state::StateRoot;

const FILE: &str = "permissions.toml";
const VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub name: String,
    pub allow: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Grants {
    pub by_identity: BTreeMap<String, Grant>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileFormat {
    version: u32,
    #[serde(default)]
    grants: BTreeMap<String, Grant>,
}

impl Grants {
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
        let file: FileFormat =
            toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        if file.version != VERSION {
            return Err(format!(
                "{}: unsupported version {}",
                path.display(),
                file.version
            ));
        }
        for (identity, grant) in &file.grants {
            if !valid_identity(identity) || grant.name.is_empty() {
                return Err(format!("{}: invalid permission grant", path.display()));
            }
        }
        Ok(Self {
            by_identity: file.grants,
        })
    }

    pub fn save(&self, directory: &Path) -> Result<(), String> {
        let text = toml::to_string(&FileFormat {
            version: VERSION,
            grants: self.by_identity.clone(),
        })
        .map_err(|error| format!("cannot serialize permission grants: {error}"))?;
        StateRoot::new(directory.to_path_buf())?.replace_file(Path::new(FILE), text.as_bytes())
    }
}

fn valid_identity(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_grants_round_trip_and_reject_corruption() {
        let directory =
            std::env::temp_dir().join(format!("gears-permissions-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        assert_eq!(Grants::load(&directory).unwrap(), Grants::default());
        let mut grants = Grants::default();
        grants.by_identity.insert(
            "a".repeat(64),
            Grant {
                name: "sh".into(),
                allow: false,
            },
        );
        grants.save(&directory).unwrap();
        assert_eq!(Grants::load(&directory).unwrap(), grants);
        std::fs::write(directory.join(FILE), "version = 2\n").unwrap();
        assert!(Grants::load(&directory).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
