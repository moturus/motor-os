//! Decisions Lorry records for one workspace in the user's own configuration:
//! `vendor --accept-all`, the review the user approved, and the build-time
//! code and repository Cargo configuration approved in an interactive review. A cloned repository cannot write
//! them, unlike its own files.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use semver::{Version, VersionReq};
use toml_edit::{Item, Table};

use crate::atomic::AtomicFile;
use crate::config::{Policy, PolicyAction, PolicyRule};
use crate::diagnostic::{Error, Result};
use crate::lockfile::write_toml_string;
use crate::redirect::TrustLock;
use crate::toml::Document;

const MAX_GRANTS: usize = 4096;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Decisions {
    pub accept_all: bool,
    pub approved_review: Option<String>,
    pub grants: BTreeSet<Grant>,
    /// Repository Cargo configuration files, by path and SHA-256.
    pub cargo_configs: BTreeSet<(PathBuf, String)>,
}

/// Build-time code the user approved in a review.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct Grant {
    pub name: String,
    pub source: GrantSource,
    pub build_script: bool,
    pub proc_macro: bool,
}

/// Outside packages are pinned exactly. A workspace member is named only,
/// like a hand-written member rule, because its sources are edited; another
/// path package keeps its source-tree pin.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum GrantSource {
    CratesIo {
        version: Version,
        checksum: String,
    },
    Git {
        version: Version,
        source_tree_sha256: String,
    },
    Path {
        source_tree_sha256: Option<String>,
    },
}

/// The decisions file of one workspace.
pub(crate) struct Store {
    path: PathBuf,
    workspace: PathBuf,
}

impl Store {
    /// The store for a canonical workspace root, or none on Linux without an
    /// absolute `HOME`.
    pub fn for_workspace(workspace: &Path, environment: &BTreeMap<String, String>) -> Option<Self> {
        let directory = if cfg!(target_os = "motor") {
            crate::role::Role::current()
                .config_directory()
                .join("lorry-workspaces")
        } else {
            let home = Path::new(environment.get("HOME")?);
            if !home.is_absolute() {
                return None;
            }
            home.join(".config/lorry/workspaces")
        };
        let mut digest = crate::hash::Sha256::new();
        digest.update(workspace.as_os_str().as_encoded_bytes());
        let name = digest.finish()[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Some(Self {
            path: directory.join(format!("{name}.toml")),
            workspace: workspace.to_path_buf(),
        })
    }

    /// The store as this process's user sees it.
    pub fn for_process(workspace: &Path) -> Option<Self> {
        let environment = std::env::var("HOME")
            .map(|home| BTreeMap::from([("HOME".to_owned(), home)]))
            .unwrap_or_default();
        Self::for_workspace(workspace, &environment)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Decisions> {
        match fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Decisions::default());
            }
            Err(error) => {
                return Err(Error::failure(format!(
                    "failed to inspect workspace decisions `{}`: {error}",
                    self.path.display()
                )));
            }
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(self.invalid("is not a real regular file"));
            }
            Ok(_) => {}
        }
        let document = Document::load(&self.path, "workspace decisions")?;
        let root = document.root();
        for (key, _) in root.iter() {
            if !matches!(
                key,
                "format-version"
                    | "workspace"
                    | "accept-all"
                    | "approved-review-sha256"
                    | "grant"
                    | "cargo-config"
            ) {
                return Err(self.invalid(&format!("has unknown key `{key}`")));
            }
        }
        if root.get("format-version").and_then(Item::as_integer) != Some(1) {
            return Err(self.invalid("requires `format-version = 1`"));
        }
        // A copied or renamed file must not apply to another workspace.
        if root.get("workspace").and_then(Item::as_str) != self.workspace.to_str() {
            return Err(self.invalid(&format!(
                "does not name this workspace, `{}`",
                self.workspace.display()
            )));
        }
        let accept_all = match root.get("accept-all") {
            None => false,
            Some(item) => item
                .as_bool()
                .ok_or_else(|| self.invalid("needs a boolean `accept-all`"))?,
        };
        let approved_review = match root.get("approved-review-sha256") {
            None => None,
            Some(item) => Some(
                item.as_str()
                    .filter(|value| is_digest(value))
                    .ok_or_else(|| self.invalid("needs a SHA-256 `approved-review-sha256`"))?
                    .to_owned(),
            ),
        };
        let mut grants = BTreeSet::new();
        if let Some(item) = root.get("grant") {
            let tables = item
                .as_array_of_tables()
                .ok_or_else(|| self.invalid("needs `[[grant]]` tables"))?;
            if tables.len() > MAX_GRANTS {
                return Err(self.invalid(&format!("exceeds {MAX_GRANTS} grants")));
            }
            for table in tables.iter() {
                grants.insert(self.grant(table)?);
            }
        }
        let mut cargo_configs = BTreeSet::new();
        if let Some(item) = root.get("cargo-config") {
            let tables = item
                .as_array_of_tables()
                .ok_or_else(|| self.invalid("needs `[[cargo-config]]` tables"))?;
            if tables.len() > MAX_GRANTS {
                return Err(self.invalid(&format!("exceeds {MAX_GRANTS} Cargo approvals")));
            }
            for table in tables.iter() {
                cargo_configs.insert(self.cargo_config(table)?);
            }
        }
        Ok(Decisions {
            accept_all,
            approved_review,
            grants,
            cargo_configs,
        })
    }

    /// Rewrites the file under its lock, starting from its latest contents.
    pub fn update(&self, change: impl FnOnce(&mut Decisions)) -> Result<()> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| Error::failure("workspace decisions have no parent directory"))?;
        if !parent.is_dir() {
            fs::create_dir_all(parent).map_err(|error| {
                Error::failure(format!("failed to create `{}`: {error}", parent.display()))
            })?;
        }
        let metadata = fs::symlink_metadata(parent).map_err(|error| {
            Error::failure(format!("failed to inspect `{}`: {error}", parent.display()))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(Error::failure(format!(
                "workspace decisions directory `{}` is not a real directory",
                parent.display()
            )));
        }
        let _lock = TrustLock::acquire(&parent.join(".lock"))?;
        let mut decisions = self.load()?;
        change(&mut decisions);
        if decisions.grants.len() > MAX_GRANTS || decisions.cargo_configs.len() > MAX_GRANTS {
            return Err(self.invalid(&format!("would exceed {MAX_GRANTS} grants")));
        }
        let mut staged = AtomicFile::new(&self.path)?;
        staged
            .write_all(self.render(&decisions).as_bytes())
            .map_err(|error| {
                Error::failure(format!(
                    "failed to write `{}`: {error}",
                    self.path.display()
                ))
            })?;
        staged.commit()
    }

    fn render(&self, decisions: &Decisions) -> String {
        let mut output = String::from(
            "# Generated by Lorry. Delete this file to forget these decisions.\n\
             format-version = 1\nworkspace = ",
        );
        write_toml_string(&mut output, &self.workspace.to_string_lossy());
        output.push('\n');
        if decisions.accept_all {
            output.push_str("accept-all = true\n");
        }
        if let Some(review) = &decisions.approved_review {
            output.push_str(&format!("approved-review-sha256 = \"{review}\"\n"));
        }
        for grant in &decisions.grants {
            output.push_str("\n[[grant]]\nname = ");
            write_toml_string(&mut output, &grant.name);
            match &grant.source {
                GrantSource::CratesIo { version, checksum } => output.push_str(&format!(
                    "\nsource = \"crates.io\"\nversion = \"{version}\"\nchecksum = \"{checksum}\""
                )),
                GrantSource::Git {
                    version,
                    source_tree_sha256,
                } => output.push_str(&format!(
                    "\nsource = \"git\"\nversion = \"{version}\"\n\
                     source-tree-sha256 = \"{source_tree_sha256}\""
                )),
                GrantSource::Path { source_tree_sha256 } => {
                    output.push_str("\nsource = \"path\"");
                    if let Some(digest) = source_tree_sha256 {
                        output.push_str(&format!("\nsource-tree-sha256 = \"{digest}\""));
                    }
                }
            }
            output.push_str(&format!(
                "\nbuild-script = {}\nproc-macro = {}\n",
                grant.build_script, grant.proc_macro
            ));
        }
        for (file, sha256) in &decisions.cargo_configs {
            output.push_str("\n[[cargo-config]]\nfile = ");
            write_toml_string(&mut output, &file.to_string_lossy());
            output.push_str(&format!("\nsha256 = \"{sha256}\"\n"));
        }
        output
    }

    fn cargo_config(&self, table: &Table) -> Result<(PathBuf, String)> {
        for (key, _) in table.iter() {
            if !matches!(key, "file" | "sha256") {
                return Err(self.invalid(&format!("has a Cargo approval with unknown key `{key}`")));
            }
        }
        let file = table
            .get("file")
            .and_then(Item::as_str)
            .filter(|file| Path::new(file).is_absolute())
            .ok_or_else(|| self.invalid("has a Cargo approval without an absolute `file`"))?;
        let sha256 = table
            .get("sha256")
            .and_then(Item::as_str)
            .filter(|value| is_digest(value))
            .ok_or_else(|| self.invalid("has a Cargo approval without a SHA-256 `sha256`"))?;
        Ok((PathBuf::from(file), sha256.to_owned()))
    }

    fn grant(&self, table: &Table) -> Result<Grant> {
        let string = |key: &str| {
            table
                .get(key)
                .and_then(Item::as_str)
                .ok_or_else(|| self.invalid(&format!("has a grant without a string `{key}`")))
        };
        let boolean = |key: &str| {
            table
                .get(key)
                .and_then(Item::as_bool)
                .ok_or_else(|| self.invalid(&format!("has a grant without a boolean `{key}`")))
        };
        let version = || {
            Version::parse(string("version")?)
                .map_err(|_| self.invalid("has a grant with an invalid version"))
        };
        let digest = |key: &str| {
            let value = string(key)?;
            if is_digest(value) {
                Ok(value.to_owned())
            } else {
                Err(self.invalid(&format!("has a grant with an invalid `{key}`")))
            }
        };
        let source = string("source")?;
        let (source, keys): (_, &[&str]) = match source {
            "crates.io" => (
                GrantSource::CratesIo {
                    version: version()?,
                    checksum: digest("checksum")?,
                },
                &["version", "checksum"],
            ),
            "git" => (
                GrantSource::Git {
                    version: version()?,
                    source_tree_sha256: digest("source-tree-sha256")?,
                },
                &["version", "source-tree-sha256"],
            ),
            "path" => (
                GrantSource::Path {
                    source_tree_sha256: match table.get("source-tree-sha256") {
                        None => None,
                        Some(_) => Some(digest("source-tree-sha256")?),
                    },
                },
                &["source-tree-sha256"],
            ),
            other => return Err(self.invalid(&format!("has a grant with source `{other}`"))),
        };
        for (key, _) in table.iter() {
            if !matches!(key, "name" | "source" | "build-script" | "proc-macro")
                && !keys.contains(&key)
            {
                return Err(self.invalid(&format!("has a grant with unknown key `{key}`")));
            }
        }
        Ok(Grant {
            name: string("name")?.to_owned(),
            source,
            build_script: boolean("build-script")?,
            proc_macro: boolean("proc-macro")?,
        })
    }

    fn invalid(&self, problem: &str) -> Error {
        Error::failure(format!(
            "workspace decisions `{}` {problem}",
            self.path.display()
        ))
        .with_help("delete the file and review the workspace again with `lorry vendor`")
    }
}

impl Decisions {
    /// Applies the decisions to the workspace's policy. Grants become exact
    /// allow rules whose build scripts receive the configured native tools.
    pub fn apply(self, policy: &mut Policy, provenance: &Path) -> Result<()> {
        policy.accept_all = self.accept_all;
        policy.approved_review = self.approved_review;
        policy.approved_cargo_configs = self.cargo_configs;
        for (index, grant) in self.grants.into_iter().enumerate() {
            let id = format!("lorry-grant-{index:05}");
            if policy.rules.contains_key(&id) {
                return Err(Error::failure(format!(
                    "configured policy rule `{id}` conflicts with recorded workspace decisions"
                )));
            }
            let (version, source, checksum, source_tree_sha256) = match grant.source {
                GrantSource::CratesIo { version, checksum } => {
                    (Some(version), "crates.io", Some(checksum), None)
                }
                GrantSource::Git {
                    version,
                    source_tree_sha256,
                } => (Some(version), "git", None, Some(source_tree_sha256)),
                GrantSource::Path { source_tree_sha256 } => {
                    (None, "path", None, source_tree_sha256)
                }
            };
            policy.rules.insert(
                id,
                PolicyRule {
                    action: PolicyAction::Allow,
                    name: Some(grant.name),
                    version: version
                        .map(|version| VersionReq::parse(&format!("={version}")))
                        .transpose()
                        .map_err(|error| {
                            Error::failure(format!("invalid recorded grant version: {error}"))
                        })?,
                    source: Some(source.to_owned()),
                    checksum,
                    source_tree_sha256,
                    license: None,
                    allow_build_script: grant.build_script,
                    allow_proc_macro: grant.proc_macro,
                    native_tools: BTreeSet::new(),
                    configured_native_tools: grant.build_script,
                    caller_env: BTreeSet::new(),
                    provenance: provenance.to_path_buf(),
                },
            );
        }
        Ok(())
    }
}

/// A workspace's admission record that the user has not approved, such as
/// one committed to a cloned repository.
pub(crate) fn unapproved_review() -> Error {
    Error::failure("you have not approved this workspace's dependency review").with_help(
        "run `lorry vendor` in the workspace root to review and approve it, \
             or `lorry vendor --accept-all` to trust this workspace",
    )
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "lorry-workspace-trust-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn store(temp: &TempDir, workspace: &str) -> Store {
        let environment =
            BTreeMap::from([("HOME".to_owned(), temp.0.to_string_lossy().into_owned())]);
        Store::for_workspace(Path::new(workspace), &environment).unwrap()
    }

    #[test]
    fn records_round_trip_and_stay_with_their_workspace() {
        let temp = TempDir::new();
        let helix = store(&temp, "/user/helix");
        assert_eq!(helix.load().unwrap(), Decisions::default());
        let checksum = "a".repeat(64);
        helix
            .update(|decisions| {
                decisions.accept_all = true;
                decisions.approved_review = Some("b".repeat(64));
                decisions.grants.insert(Grant {
                    name: "libc".into(),
                    source: GrantSource::CratesIo {
                        version: Version::new(0, 2, 189),
                        checksum: checksum.clone(),
                    },
                    build_script: true,
                    proc_macro: false,
                });
                decisions.cargo_configs.insert((
                    PathBuf::from("/user/helix/.cargo/config.toml"),
                    "c".repeat(64),
                ));
                decisions.grants.insert(Grant {
                    name: "helix-loader".into(),
                    source: GrantSource::Path {
                        source_tree_sha256: None,
                    },
                    build_script: true,
                    proc_macro: false,
                });
            })
            .unwrap();
        let loaded = helix.load().unwrap();
        assert!(loaded.accept_all);
        assert_eq!(loaded.grants.len(), 2);

        assert_eq!(loaded.cargo_configs.len(), 1);
        let mut policy = Policy::default();
        loaded.apply(&mut policy, helix.path()).unwrap();
        assert!(policy.accept_all);
        assert!(policy.approved_cargo_configs.contains(&(
            PathBuf::from("/user/helix/.cargo/config.toml"),
            "c".repeat(64)
        )));
        let libc = policy
            .rules
            .values()
            .find(|rule| rule.name.as_deref() == Some("libc"))
            .unwrap();
        assert_eq!(libc.checksum.as_deref(), Some(checksum.as_str()));
        assert_eq!(libc.version.as_ref().unwrap().to_string(), "=0.2.189");
        assert!(libc.allow_build_script && libc.configured_native_tools);

        // Another workspace has its own file, and a moved file is refused.
        let other = store(&temp, "/user/other");
        assert_ne!(other.path(), helix.path());
        assert_eq!(other.load().unwrap(), Decisions::default());
        fs::copy(helix.path(), other.path()).unwrap();
        assert!(
            other
                .load()
                .unwrap_err()
                .render()
                .contains("does not name this workspace")
        );
    }

    #[test]
    fn rejects_malformed_decisions() {
        let temp = TempDir::new();
        let helix = store(&temp, "/user/helix");
        fs::create_dir_all(helix.path().parent().unwrap()).unwrap();
        for body in [
            "format-version = 2\nworkspace = \"/user/helix\"\n",
            "format-version = 1\nworkspace = \"/user/helix\"\nextra = 1\n",
            "format-version = 1\nworkspace = \"/user/helix\"\napproved-review-sha256 = \"x\"\n",
            "format-version = 1\nworkspace = \"/user/helix\"\n[[grant]]\nname = \"a\"\n\
             source = \"crates.io\"\nversion = \"1.0.0\"\nbuild-script = true\nproc-macro = false\n",
            "format-version = 1\nworkspace = \"/user/helix\"\n[[grant]]\nname = \"a\"\n\
             source = \"path\"\nversion = \"1.0.0\"\nbuild-script = true\nproc-macro = false\n",
        ] {
            fs::write(helix.path(), body).unwrap();
            assert!(helix.load().is_err(), "{body}");
        }
    }
}
