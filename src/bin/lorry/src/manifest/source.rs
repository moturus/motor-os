use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use super::{
    DependencySource, MANIFEST_NAME, MAX_WORKSPACE_MEMBERS, Manifest, ManifestMode,
    dependency_workspace_package, discover_manifest, require_table, resolve_target_defaults,
    string_array, workspace_member_root,
};
use crate::diagnostic::{Error, Result};
use crate::toml::Document;

pub(crate) struct SourceWorkspace {
    pub manifest_path: PathBuf,
    pub root: PathBuf,
    pub packages: Vec<Manifest>,
    pub default_members: Vec<PathBuf>,
    pub metadata: serde_json::Value,
    pub virtual_root: bool,
}

impl SourceWorkspace {
    // Source-only discovery leaves the lock and execution settings untouched.
    // Dependency operations explicitly opt into the shared root context.
    pub(crate) fn load_locked_context(&mut self) -> Result<()> {
        self.load_context(true)
    }

    pub(crate) fn load_context(&mut self, require_lock: bool) -> Result<()> {
        let path = self.root.join(MANIFEST_NAME);
        let document = Document::load(&path, "Cargo workspace manifest")?;
        let patches = super::parse_patches(&path, &document, &self.root)?;
        let (dev, release, profile_errors) = super::parse_profiles(&path, &document)?;
        let lock_path = self.root.join(super::LOCK_NAME);
        let lock = match fs::symlink_metadata(&lock_path) {
            Err(error) if !require_lock && error.kind() == std::io::ErrorKind::NotFound => None,
            _ => Some(super::Lockfile::load(&lock_path)?),
        };
        let members = self
            .packages
            .iter()
            .map(|package| (package.name.clone(), package.root.clone()))
            .collect::<BTreeMap<_, _>>();
        for package in &mut self.packages {
            package.workspace_root.clone_from(&self.root);
            package.workspace_members.clone_from(&members);
            package.patches.clone_from(&patches);
            package.dev.clone_from(&dev);
            package.release.clone_from(&release);
            package.profile_errors.clone_from(&profile_errors);
            package.lock = lock.clone();
        }
        Ok(())
    }

    // Editor discovery describes source targets before dependency preparation.
    // It must neither inspect nor repair Cargo.lock or admission state.
    pub fn load(current: &Path, manifest_path: Option<&Path>) -> Result<Self> {
        let manifest_path = discover_manifest(current, manifest_path)?;
        let directory = manifest_path.parent().unwrap().to_owned();
        let workspace = match nearest_workspace(&directory)? {
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
            metadata: root.metadata,
            virtual_root: !root.package,
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
            metadata: serde_json::Value::Null,
            virtual_root: false,
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
    metadata: serde_json::Value,
}

impl WorkspaceRoot {
    pub fn parse(root: &Path, path: &Path, document: &Document) -> Result<Self> {
        let item = document.root().get("workspace").unwrap();
        let table = require_table(path, document, item, "workspace")?;
        super::inheritance::validate_dependencies(path, document, table)?;
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
            metadata: super::workspace_metadata(document),
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
        pending.retain(|directory| !self.excludes(directory));
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
        self.apply_settings(&mut packages)?;
        Ok(packages)
    }

    fn apply_settings(&self, packages: &mut BTreeMap<PathBuf, Manifest>) -> Result<()> {
        let path = self.root.join(MANIFEST_NAME);
        let document = Document::load(&path, "Cargo workspace manifest")?;
        let resolver = super::workspace_resolver(&self.root, &path, &document)?;
        let workspace = document
            .root()
            .get("workspace")
            .and_then(|item| item.as_table())
            .unwrap();
        let latest = packages
            .values()
            .map(|package| match package.edition {
                super::Edition::E2021 => 2021,
                super::Edition::E2024 => 2024,
                _ => 0,
            })
            .max()
            .unwrap_or(0);
        let default_warning = if !self.package && !workspace.contains_key("resolver") && latest != 0
        {
            Some(format!(
                "virtual workspace defaulting to `resolver = \"1\"` despite one or more workspace members \
                 being on edition {latest} which implies `resolver = \"{}\"`; specify workspace.resolver \
                 at `{}` to select the intended resolver",
                if latest == 2024 { 3 } else { 2 },
                path.display(),
            ))
        } else {
            None
        };
        for package in packages.values_mut() {
            if package.root != self.root {
                let member = Document::load(&package.path, "Cargo workspace member manifest")?;
                let mut ignored = Vec::new();
                if member.root().contains_key("profile") {
                    ignored.push("profiles");
                }
                for key in ["patch", "replace"] {
                    if member
                        .root()
                        .get(key)
                        .and_then(|item| item.as_table())
                        .is_some_and(|table| !table.is_empty())
                    {
                        ignored.push(key);
                    }
                }
                if member
                    .root()
                    .get("package")
                    .and_then(|item| item.as_table())
                    .is_some_and(|table| table.contains_key("resolver"))
                    && package.resolver != resolver
                {
                    ignored.push("resolver");
                }
                for setting in ignored {
                    package.warnings.push(format!(
                        "{setting} for the non root package will be ignored, specify {setting} at the workspace root:\n\
                         package:   {}\nworkspace: {}",
                        package.path.display(), path.display(),
                    ));
                }
            }
            if let Some(warning) = &default_warning {
                package.warnings.push(warning.clone());
            }
            package.resolver = resolver;
        }
        Ok(())
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
        let mut roots = BTreeSet::new();
        for member in declared {
            for directory in expand_members(&self.root, member)? {
                let relative = directory.strip_prefix(&self.root).unwrap();
                let canonical = if relative.as_os_str().is_empty() {
                    self.root.clone()
                } else {
                    workspace_member_root(
                        &self.root,
                        &path,
                        &document,
                        relative
                            .to_str()
                            .ok_or_else(|| Error::failure("workspace member path is not UTF-8"))?,
                    )?
                };
                roots.insert(canonical);
                if roots.len() > MAX_WORKSPACE_MEMBERS {
                    return Err(Error::failure(format!(
                        "workspace has more than {MAX_WORKSPACE_MEMBERS} members"
                    )));
                }
            }
        }
        Ok(roots.into_iter().collect())
    }
}

fn expand_members(root: &Path, member: &str) -> Result<Vec<PathBuf>> {
    if member.is_empty() || member.contains("**") {
        return Err(Error::failure(format!(
            "unsupported workspace member pattern `{member}`"
        )));
    }
    let mut components = Vec::new();
    for component in Path::new(member).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => components.push(value),
            _ => {
                return Err(Error::failure(format!(
                    "workspace member `{member}` must be below the root"
                )));
            }
        }
    }
    let mut paths = vec![root.to_owned()];
    for (index, component) in components.iter().enumerate() {
        let text = component
            .to_str()
            .ok_or_else(|| Error::failure("workspace pattern is not UTF-8"))?;
        let pattern = crate::glob::Pattern::parse(text).map_err(Error::failure)?;
        let magic = text.chars().any(|value| matches!(value, '*' | '?' | '['));
        let mut next = Vec::new();
        let mut matched = false;
        let mut include = |path: PathBuf| -> Result<()> {
            matched = true;
            // Cargo ignores matching files. Do not retain those matches or
            // apply a package count to them, even in a directory of files.
            if path.is_dir() {
                if next.len() == MAX_WORKSPACE_MEMBERS {
                    return Err(Error::failure(format!(
                        "workspace pattern `{member}` exceeds {MAX_WORKSPACE_MEMBERS} directories"
                    )));
                }
                next.push(path);
            }
            Ok(())
        };
        for directory in &paths {
            if magic {
                let entries = fs::read_dir(directory).map_err(|error| {
                    Error::failure(format!("failed to match `{member}`: {error}"))
                })?;
                for entry in entries {
                    let entry = entry.map_err(|error| {
                        Error::failure(format!("failed to match `{member}`: {error}"))
                    })?;
                    if entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| pattern.matches(name))
                    {
                        include(entry.path())?;
                    }
                }
            } else {
                let path = directory.join(component);
                match fs::metadata(&path) {
                    Ok(_) => include(path)?,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                        ) => {}
                    Err(error) => {
                        return Err(Error::failure(format!(
                            "failed to match `{member}`: {error}"
                        )));
                    }
                }
            }
        }
        if !matched || (next.is_empty() && index + 1 != components.len()) {
            return Err(Error::failure(format!(
                "workspace member pattern `{member}` matches no paths"
            )));
        }
        paths = next;
    }
    Ok(paths)
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

pub(super) fn load_package(directory: &Path, root: &Path) -> Result<Manifest> {
    let path = directory.join(MANIFEST_NAME);
    let document = Document::load(&path, "Cargo source manifest")?;
    if directory != root && document.root().contains_key("workspace") {
        return Err(Error::failure(format!(
            "workspace member `{}` defines another workspace root",
            path.display()
        )));
    }
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
