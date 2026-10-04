use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use super::{
    DependencySource, MANIFEST_NAME, MAX_WORKSPACE_MEMBERS, Manifest, ManifestMode,
    canonical_manifest, dependency_workspace_package, require_table, resolve_target_defaults,
    string_array, workspace_member_root,
};
use crate::diagnostic::{Error, Result};
use crate::toml::Document;

pub(crate) struct SourceWorkspace {
    pub manifest_path: PathBuf,
    pub root: PathBuf,
    pub packages: Vec<Manifest>,
    pub default_members: Vec<PathBuf>,
}

impl SourceWorkspace {
    // Editor discovery describes source targets before dependency preparation.
    // It must neither inspect nor repair Cargo.lock or admission state.
    pub fn load(
        current: &Path,
        manifest_path: Option<&Path>,
        selected: Option<&str>,
    ) -> Result<Self> {
        let manifest_path =
            canonical_manifest(manifest_path.unwrap_or(&current.join(MANIFEST_NAME)))?;
        let directory = manifest_path.parent().unwrap().to_owned();
        let mut workspace = match nearest_workspace(&directory)? {
            Some(root) => {
                let packages = root.load_members()?;
                if directory == root.root || packages.contains_key(&directory) {
                    Self::from_root(manifest_path, root, packages)?
                } else {
                    // As in Lorry's build path, a package that its nearest
                    // workspace does not include is a standalone package.
                    Self::standalone(&manifest_path)?
                }
            }
            None => Self::standalone(&manifest_path)?,
        };
        if let Some(selected) = selected {
            let available = workspace
                .packages
                .iter()
                .map(|package| package.name.clone())
                .collect::<Vec<_>>();
            workspace
                .packages
                .retain(|package| package.name == selected);
            let Some(package) = workspace.packages.first() else {
                return Err(
                    Error::failure(format!("workspace has no package named `{selected}`"))
                        .with_help(format!(
                            "available workspace packages: {}",
                            available.join(", ")
                        )),
                );
            };
            workspace.default_members = vec![package.root.clone()];
        }
        if workspace.packages.is_empty() {
            return Err(Error::failure("workspace has no source packages"));
        }
        Ok(workspace)
    }

    fn from_root(
        manifest_path: PathBuf,
        root: WorkspaceRoot,
        packages: BTreeMap<PathBuf, Manifest>,
    ) -> Result<Self> {
        let directory = manifest_path.parent().unwrap();
        // Cargo applies default-members only to the root manifest. A member
        // selects itself, and a virtual root selects every member.
        let default_members = root.defaults(directory, packages.keys())?;
        Ok(Self {
            manifest_path,
            root: root.root,
            packages: packages.into_values().collect(),
            default_members,
        })
    }

    fn standalone(manifest_path: &Path) -> Result<Self> {
        let directory = manifest_path.parent().unwrap();
        Ok(Self {
            manifest_path: manifest_path.to_owned(),
            root: directory.to_owned(),
            packages: vec![load_package(directory, directory)?],
            default_members: vec![directory.to_owned()],
        })
    }
}

// Keep declarations separate from loading members: dependency inheritance
// must not require describing every package in an external workspace.
pub(super) struct WorkspaceRoot {
    pub root: PathBuf,
    package: bool,
    members: Vec<String>,
    exclude: Vec<PathBuf>,
    default_members: Option<Vec<String>>,
}

impl WorkspaceRoot {
    pub fn parse(root: &Path, path: &Path, document: &Document) -> Result<Self> {
        let item = document.root().get("workspace").unwrap();
        let table = require_table(path, document, item, "workspace")?;
        let paths = |key: &str| {
            table
                .get(key)
                .map(|item| string_array(path, document, item, &format!("workspace.{key}")))
                .transpose()
        };
        Ok(Self {
            root: root.to_owned(),
            package: document.root().contains_key("package"),
            members: paths("members")?.unwrap_or_default(),
            exclude: paths("exclude")?
                .unwrap_or_default()
                .iter()
                .map(|entry| root.join(entry))
                .collect(),
            default_members: paths("default-members")?,
        })
    }

    // An explicit member path takes precedence over `exclude`, as in Cargo.
    pub fn excludes(&self, directory: &Path) -> bool {
        self.exclude.iter().any(|path| directory.starts_with(path))
            && !self
                .members
                .iter()
                .any(|path| directory.starts_with(self.root.join(path)))
    }

    // Path dependencies below the root are implicit members in Cargo.
    pub fn load_members(&self) -> Result<BTreeMap<PathBuf, Manifest>> {
        let mut pending = self.member_roots(&self.members)?;
        if self.package {
            pending.push(self.root.clone());
        }
        let mut packages = BTreeMap::new();
        let mut names = BTreeSet::new();
        while let Some(directory) = pending.pop() {
            if packages.contains_key(&directory) {
                continue;
            }
            if packages.len() == MAX_WORKSPACE_MEMBERS {
                return Err(Error::failure(format!(
                    "workspace has more than {MAX_WORKSPACE_MEMBERS} members"
                )));
            }
            let package = load_package(&directory, &self.root)?;
            if !names.insert(package.name.clone()) {
                return Err(Error::failure(format!(
                    "workspace contains duplicate package name `{}`",
                    package.name
                )));
            }
            for dependency in &package.dependencies {
                if let DependencySource::Path(path) = &dependency.source
                    && let Ok(path) = fs::canonicalize(path)
                    && path.starts_with(&self.root)
                    && !self.excludes(&path)
                {
                    pending.push(path);
                }
            }
            packages.insert(directory, package);
        }
        Ok(packages)
    }

    pub fn defaults<'a>(
        &self,
        current: &Path,
        members: impl Iterator<Item = &'a PathBuf>,
    ) -> Result<Vec<PathBuf>> {
        let members = members.collect::<BTreeSet<_>>();
        if current == self.root
            && let Some(declared) = &self.default_members
        {
            let declared = self.member_roots(declared)?;
            if let Some(path) = declared.iter().find(|path| !members.contains(path)) {
                return Err(Error::failure(format!(
                    "package `{}` is listed in default-members but is not a member",
                    path.display()
                )));
            }
            return Ok(declared);
        }
        if current != self.root || self.package {
            Ok(vec![current.to_owned()])
        } else {
            Ok(members.into_iter().cloned().collect())
        }
    }

    fn member_roots(&self, declared: &[String]) -> Result<Vec<PathBuf>> {
        if declared.len() > MAX_WORKSPACE_MEMBERS {
            return Err(Error::failure(format!(
                "workspace lists more than {MAX_WORKSPACE_MEMBERS} member paths"
            )));
        }
        let path = self.root.join(MANIFEST_NAME);
        let document = Document::load(&path, "Cargo workspace manifest")?;
        declared
            .iter()
            .map(|member| match member.as_str() {
                "." => Ok(self.root.clone()),
                _ => workspace_member_root(&self.root, &path, &document, member),
            })
            .collect()
    }
}

// Cargo uses the nearest enclosing workspace that does not exclude the package.
pub(super) fn nearest_workspace(directory: &Path) -> Result<Option<WorkspaceRoot>> {
    for ancestor in directory.ancestors() {
        let path = ancestor.join(MANIFEST_NAME);
        if !path.is_file() {
            continue;
        }
        let document = Document::load(&path, "Cargo source manifest")?;
        if document.root().contains_key("workspace") {
            let workspace = WorkspaceRoot::parse(ancestor, &path, &document)?;
            if ancestor == directory || !workspace.excludes(directory) {
                return Ok(Some(workspace));
            }
        }
    }
    Ok(None)
}

fn load_package(directory: &Path, root: &Path) -> Result<Manifest> {
    let path = directory.join(MANIFEST_NAME);
    let document = Document::load(&path, "Cargo source manifest")?;
    let inherited = dependency_workspace_package(directory)?;
    let mut manifest = Manifest::parse_document_with_inheritance(
        directory,
        &path,
        &document,
        ManifestMode::Source,
        inherited.as_ref(),
    )?;
    resolve_target_defaults(&mut manifest)?;
    manifest.workspace_root = root.to_owned();
    Ok(manifest)
}
