//! Global permission grants, separate from tool enablement.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::state::StateRoot;

const FILE: &str = "permissions.toml";
const VERSION: u32 = 1;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub name: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub created_ms: u64,
    pub allow: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Grants {
    pub by_identity: BTreeMap<String, Grant>,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileFormat {
    #[serde(default)]
    grants: BTreeMap<String, Grant>,
}

impl Grants {
    pub fn load(directory: &Path) -> Result<Self, String> {
        let file: FileFormat = StateRoot::new(directory.to_path_buf())?.load_toml(FILE, VERSION)?;
        for (identity, grant) in &file.grants {
            if !valid_identity(identity) || grant.name.is_empty() {
                let path = directory.join(FILE);
                return Err(format!("{}: invalid permission grant", path.display()));
            }
        }
        Ok(Self {
            by_identity: file.grants,
        })
    }

    pub fn save(&self, directory: &Path) -> Result<(), String> {
        if self
            .by_identity
            .iter()
            .any(|(identity, grant)| !valid_identity(identity) || grant.name.is_empty())
        {
            return Err("invalid permission grant".to_string());
        }
        let data = FileFormat {
            grants: self.by_identity.clone(),
        };
        StateRoot::new(directory.to_path_buf())?.save_toml(FILE, VERSION, &data)
    }
}

pub(crate) fn valid_identity(value: &str) -> bool {
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
                ..Grant::default()
            },
        );
        grants.save(&directory).unwrap();
        assert_eq!(Grants::load(&directory).unwrap(), grants);
        grants.by_identity.insert(
            "short".into(),
            Grant {
                name: "sh".into(),
                ..Grant::default()
            },
        );
        assert!(grants.save(&directory).is_err());
        assert_eq!(Grants::load(&directory).unwrap().by_identity.len(), 1);
        std::fs::write(directory.join(FILE), "version = 2\n").unwrap();
        assert!(Grants::load(&directory).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
