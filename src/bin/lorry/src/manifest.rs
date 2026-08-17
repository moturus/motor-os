use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use semver::{Version as SemVersion, VersionReq};
use toml_edit::{Array, InlineTable, Item, Table, Value};

use crate::diagnostic::{Error, Result};
use crate::sparse::DependencyKind;
use crate::toml::Document;
use crate::toolchain::TargetInfo;

const MANIFEST_NAME: &str = "Cargo.toml";
const LOCK_NAME: &str = "Cargo.lock";
const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
const MAX_BINARY_TARGETS: usize = 64;
const MAX_WORKSPACE_MEMBERS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Manifest {
    pub root: PathBuf,
    pub workspace_root: PathBuf,
    pub workspace_members: BTreeSet<String>,
    pub path: PathBuf,
    pub name: String,
    pub crate_name: String,
    pub version: Version,
    pub edition: Edition,
    pub metadata: PackageMetadata,
    pub default_run: Option<String>,
    pub dev: DevProfile,
    pub release: ReleaseProfile,
    #[allow(dead_code)]
    pub resolver: Resolver,
    pub links: Option<String>,
    #[allow(dead_code)]
    pub build_script: Option<PathBuf>,
    #[allow(dead_code)]
    pub library: Option<LibraryTarget>,
    #[allow(dead_code)]
    pub binaries: Vec<BinaryTarget>,
    pub integration_tests: Vec<IntegrationTestTarget>,
    #[allow(dead_code)]
    pub dependencies: Vec<Dependency>,
    #[allow(dead_code)]
    pub features: BTreeMap<String, Vec<String>>,
    #[allow(dead_code)]
    pub patches: Vec<PathPatch>,
    #[allow(dead_code)]
    pub rust_lints: BTreeMap<String, Lint>,
    #[allow(dead_code)]
    pub lock: Option<Lockfile>,
    unsupported_target_dev_dependencies: Vec<UnsupportedTargetDevDependency>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UnsupportedTargetDevDependency {
    selector: String,
    line: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Edition {
    E2015,
    E2018,
    E2021,
    E2024,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resolver {
    V1,
    V2,
    V3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Version {
    pub original: String,
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre: String,
    pub build: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PackageMetadata {
    pub authors: Vec<String>,
    pub description: String,
    pub homepage: String,
    pub documentation: String,
    pub repository: String,
    pub license: String,
    pub license_file: String,
    pub readme: String,
    pub rust_version: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lto {
    Default,
    True,
    Fat,
    Thin,
    Off,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Strip {
    None,
    Debuginfo,
    Symbols,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DevProfile {
    pub panic_abort: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseProfile {
    pub panic_abort: bool,
    pub lto: Lto,
    pub strip: Strip,
    pub codegen_units: Option<u32>,
}

impl Default for ReleaseProfile {
    fn default() -> Self {
        Self {
            panic_abort: false,
            lto: Lto::Default,
            strip: Strip::None,
            codegen_units: None,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LibraryTarget {
    pub name: String,
    pub path: PathBuf,
    pub proc_macro: bool,
    pub test: bool,
    pub doctest: bool,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryTarget {
    pub name: String,
    pub path: PathBuf,
    pub test: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrationTestTarget {
    pub name: String,
    pub path: PathBuf,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dependency {
    pub alias: String,
    pub package: String,
    pub requirement: VersionReq,
    pub source: DependencySource,
    pub optional: bool,
    pub default_features: bool,
    pub features: Vec<String>,
    pub target: Option<String>,
    pub kind: DependencyKind,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DependencySource {
    CratesIo,
    Path(PathBuf),
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathPatch {
    pub alias: String,
    pub package: String,
    pub path: PathBuf,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lint {
    pub level: String,
    pub priority: i64,
    pub check_cfg: Vec<String>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lockfile {
    pub packages: Vec<LockedPackage>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedPackage {
    pub name: String,
    pub version: Version,
    pub source: Option<String>,
    pub checksum: Option<String>,
    pub dependencies: Vec<String>,
}

impl Manifest {
    pub fn panic_abort(&self, release: bool) -> bool {
        if release {
            self.release.panic_abort
        } else {
            self.dev.panic_abort
        }
    }

    #[allow(dead_code)]
    pub fn load(root: &Path) -> Result<Self> {
        Self::load_selected(root, None)
    }

    #[allow(dead_code)]
    pub fn load_for_vendor(root: &Path) -> Result<Self> {
        Self::load_for_vendor_selected(root, None)
    }

    pub fn load_selected(root: &Path, package: Option<&str>) -> Result<Self> {
        Self::load_project(root, package, true)
    }

    pub fn load_for_vendor_selected(root: &Path, package: Option<&str>) -> Result<Self> {
        Self::load_project(root, package, false)
    }

    pub fn with_lock_source(mut self, source: String) -> Result<Self> {
        let path = self.root.join(LOCK_NAME);
        let document = Document::parse(&path, "Cargo lockfile", source)?;
        self.lock = Some(parse_lock_document(&self, &path, &document, true)?);
        Ok(self)
    }

    pub fn require_supported_target(&self, target: &TargetInfo) -> Result<()> {
        for dependency in &self.unsupported_target_dev_dependencies {
            let selected = if dependency.selector.starts_with("cfg(") {
                target.cfg.matches_selector(&dependency.selector)?
            } else {
                dependency.selector == target.triple
            };
            if selected {
                return Err(Error::at(
                    &self.path,
                    dependency.line,
                    format!(
                        "root `target.{}.dev-dependencies` is not supported in Stage 2",
                        dependency.selector
                    ),
                    "remove the selected target's root dev-dependencies",
                ));
            }
        }
        Ok(())
    }

    fn load_project(
        root: &Path,
        package: Option<&str>,
        require_current_lock: bool,
    ) -> Result<Self> {
        let root = fs::canonicalize(root).map_err(|error| {
            Error::failure(format!(
                "failed to canonicalize package directory `{}`: {error}",
                root.display()
            ))
        })?;
        let path = root.join(MANIFEST_NAME);
        if !path.is_file() {
            return Err(Error::failure(format!(
                "manifest `{}` does not exist; Lorry does not search parent directories",
                path.display()
            )));
        }
        let document = Document::load(&path, "Cargo manifest")?;
        let Some(workspace) = discover_workspace(&root, &path, &document)? else {
            let mut manifest =
                Self::finish_root(root.clone(), path, document, &root, require_current_lock)?;
            if let Some(requested) = package
                && requested != manifest.name
            {
                return Err(Error::failure(format!(
                    "package `{requested}` is not the current package `{}`",
                    manifest.name
                )));
            }
            manifest.workspace_root = root;
            return Ok(manifest);
        };
        let member = workspace.select(&root, package)?;
        let member_path = member.join(MANIFEST_NAME);
        let member_document = if member == root {
            document
        } else {
            Document::load(&member_path, "Cargo workspace member manifest")?
        };
        let mut manifest = Self::finish_root(
            member,
            member_path,
            member_document,
            &workspace.root,
            require_current_lock,
        )?;
        workspace.apply(&mut manifest)?;
        Ok(manifest)
    }

    fn finish_root(
        root: PathBuf,
        path: PathBuf,
        document: Document,
        lock_root: &Path,
        require_current_lock: bool,
    ) -> Result<Self> {
        let mut manifest = Self::parse_document(&root, &path, &document, ManifestMode::Root)?;
        manifest.root = root;
        manifest.workspace_root = lock_root.to_owned();
        manifest.path = manifest.root.join(MANIFEST_NAME);
        resolve_target_defaults(&mut manifest)?;
        manifest.integration_tests = discover_integration_tests(&manifest.root)?;

        let lock_path = lock_root.join(LOCK_NAME);
        if !lock_path.is_file() {
            if require_current_lock {
                return Err(Error::failure(format!(
                    "required lockfile `{}` is missing",
                    lock_path.display()
                ))
                .with_help(
                    "create a version-4 Cargo.lock; build commands never resolve or write it",
                ));
            }
            return Ok(manifest);
        }
        let lock_document = Document::load(&lock_path, "Cargo lockfile")?;
        manifest.lock = Some(parse_lock_document(
            &manifest,
            &lock_path,
            &lock_document,
            require_current_lock,
        )?);
        Ok(manifest)
    }

    pub fn load_path_dependency(root: &Path) -> Result<Self> {
        let root = fs::canonicalize(root).map_err(|error| {
            Error::failure(format!(
                "failed to canonicalize path dependency directory `{}`: {error}",
                root.display()
            ))
        })?;
        let path = root.join(MANIFEST_NAME);
        if !path.is_file() {
            return Err(Error::failure(format!(
                "path dependency manifest `{}` does not exist",
                path.display()
            )));
        }
        let document = Document::load(&path, "Cargo path dependency manifest")?;
        let mut manifest = Self::parse_document(&root, &path, &document, ManifestMode::Dependency)?;
        manifest.root = root;
        manifest.path = manifest.root.join(MANIFEST_NAME);
        resolve_target_defaults(&mut manifest)?;
        Ok(manifest)
    }

    #[cfg(test)]
    pub(crate) fn parse(root: &Path, path: &Path, source: &str) -> Result<Self> {
        let document = Document::parse(path, "Cargo manifest", source.to_owned())?;
        Self::parse_document(root, path, &document, ManifestMode::Root)
    }

    #[cfg(test)]
    pub(crate) fn parse_dependency(root: &Path, path: &Path, source: &str) -> Result<Self> {
        let document = Document::parse(path, "Cargo manifest", source.to_owned())?;
        Self::parse_document(root, path, &document, ManifestMode::Dependency)
    }

    fn parse_document(
        root: &Path,
        path: &Path,
        document: &Document,
        mode: ManifestMode,
    ) -> Result<Self> {
        validate_manifest_tables(path, document, mode)?;
        let package_item = document.root().get("package").ok_or_else(|| {
            Error::failure(format!(
                "manifest `{}` is missing required table `[package]`",
                path.display()
            ))
        })?;
        let package = require_table(path, document, package_item, "package")?;
        validate_package_keys(path, document, package, mode)?;

        let name = required_string(path, document, package, "package", "name")?;
        validate_package_name(path, document.line_of_item(package_item), &name)?;
        let version_text = required_string(path, document, package, "package", "version")?;
        let version = parse_version(path, item_line(document, package, "version"), &version_text)?;
        let edition = parse_edition(
            path,
            document,
            package.get("edition"),
            document.line_of_table(package),
        )?;
        let resolver = parse_resolver(
            path,
            document,
            package.get("resolver"),
            edition,
            document.line_of_table(package),
        )?;
        let mut metadata = parse_package_metadata(path, document, package)?;
        if metadata.readme.is_empty() {
            for candidate in ["README.md", "README.txt", "README"] {
                if root.join(candidate).is_file() {
                    metadata.readme = candidate.to_owned();
                    break;
                }
            }
        }

        let links = optional_string(path, document, package, "package", "links")?;
        let build_script = parse_build_script(path, document, package, root)?;
        let library = parse_library(path, document, root, &name, mode)?;
        let binaries = if mode == ManifestMode::Root {
            parse_binaries(path, document, root, package, &name)?
        } else {
            Vec::new()
        };
        let mut dependencies = Vec::new();
        if let Some(item) = document.root().get("dependencies") {
            let table = require_table(path, document, item, "dependencies")?;
            parse_dependency_table(
                path,
                document,
                root,
                table,
                None,
                DependencyKind::Normal,
                &mut dependencies,
            )?;
        }
        if mode == ManifestMode::Dependency
            && let Some(item) = document.root().get("build-dependencies")
        {
            let table = require_table(path, document, item, "build-dependencies")?;
            parse_dependency_table(
                path,
                document,
                root,
                table,
                None,
                DependencyKind::Build,
                &mut dependencies,
            )?;
        }
        validate_ignored_dev_dependencies(path, document)?;
        let mut unsupported_target_dev_dependencies = Vec::new();
        parse_target_dependencies(
            path,
            document,
            root,
            mode,
            &mut dependencies,
            &mut unsupported_target_dev_dependencies,
        )?;
        let features = parse_features(path, document)?;
        let patches = if mode == ManifestMode::Root {
            parse_patches(path, document, root)?
        } else {
            Vec::new()
        };
        let rust_lints = parse_rust_lints(path, document, mode)?;
        let (dev, release) = if mode == ManifestMode::Root {
            parse_profiles(path, document)?
        } else {
            (DevProfile::default(), ReleaseProfile::default())
        };

        Ok(Self {
            root: root.to_path_buf(),
            workspace_root: root.to_path_buf(),
            workspace_members: std::iter::once(name.clone()).collect(),
            path: path.to_path_buf(),
            crate_name: name.replace('-', "_"),
            name,
            version,
            edition,
            metadata,
            default_run: optional_string(path, document, package, "package", "default-run")?,
            dev,
            release,
            resolver,
            links,
            build_script,
            library,
            binaries,
            integration_tests: Vec::new(),
            dependencies,
            features,
            patches,
            rust_lints,
            lock: None,
            unsupported_target_dev_dependencies,
        })
    }
}

#[derive(Clone)]
struct Workspace {
    root: PathBuf,
    members: BTreeMap<String, PathBuf>,
    dev: DevProfile,
    release: ReleaseProfile,
    resolver: Resolver,
    patches: Vec<PathPatch>,
}

impl Workspace {
    fn parse(root: &Path, path: &Path, document: &Document) -> Result<Self> {
        let item = document.root().get("workspace").ok_or_else(|| {
            Error::failure(format!(
                "workspace manifest `{}` has no `[workspace]`",
                path.display()
            ))
        })?;
        let table = require_table(path, document, item, "workspace")?;
        for (key, item) in table.iter() {
            if !matches!(key, "members" | "resolver") {
                return Err(Error::at(
                    path,
                    document.line_of_item(item),
                    format!("workspace.{key} is outside selected-member workspace support"),
                    "use explicit members without workspace inheritance, exclusions, or defaults",
                ));
            }
        }
        let declared = table.get("members").ok_or_else(|| {
            Error::at(
                path,
                document.line_of_table(table),
                "workspace.members is required",
                "list each member with an explicit relative path",
            )
        })?;
        let declared = string_array(path, document, declared, "workspace.members")?;
        if declared.len() > MAX_WORKSPACE_MEMBERS {
            return Err(Error::failure(format!(
                "workspace declares more than {MAX_WORKSPACE_MEMBERS} members"
            )));
        }

        if !document.root().contains_key("package") {
            for (key, item) in document.root().iter() {
                if !matches!(key, "workspace" | "profile" | "patch") {
                    return Err(Error::at(
                        path,
                        document.line_of_item(item),
                        format!("unsupported virtual-workspace table or key `{key}`"),
                        "keep only workspace-wide profiles and crates.io patches",
                    ));
                }
            }
        }
        let resolver = if let Some(item) = table.get("resolver") {
            parse_resolver(path, document, Some(item), Edition::E2015, 1)?
        } else if let Some(package) = document.root().get("package") {
            let package = require_table(path, document, package, "package")?;
            let edition = parse_edition(path, document, package.get("edition"), 1)?;
            parse_resolver(path, document, package.get("resolver"), edition, 1)?
        } else {
            Resolver::V1
        };

        let mut roots = declared
            .into_iter()
            .map(|member| workspace_member_root(root, path, document, &member))
            .collect::<Result<Vec<_>>>()?;
        if document.root().contains_key("package") {
            roots.push(root.to_owned());
        }
        roots.sort();
        roots.dedup();
        let mut members = BTreeMap::new();
        for member in roots {
            let member_path = member.join(MANIFEST_NAME);
            let member_document = Document::load(&member_path, "Cargo workspace member manifest")?;
            let package = member_document.root().get("package").ok_or_else(|| {
                Error::failure(format!(
                    "workspace member `{}` has no `[package]`",
                    member.display()
                ))
            })?;
            let package = require_table(&member_path, &member_document, package, "package")?;
            let name = required_string(&member_path, &member_document, package, "package", "name")?;
            validate_package_name(&member_path, member_document.line_of_table(package), &name)?;
            if members.insert(name.clone(), member).is_some() {
                return Err(Error::failure(format!(
                    "workspace contains duplicate package name `{name}`"
                )));
            }
        }
        let (dev, release) = parse_profiles(path, document)?;
        Ok(Self {
            root: root.to_owned(),
            members,
            dev,
            release,
            resolver,
            patches: parse_patches(path, document, root)?,
        })
    }

    fn select(&self, current: &Path, requested: Option<&str>) -> Result<PathBuf> {
        if let Some(name) = requested {
            return self.members.get(name).cloned().ok_or_else(|| {
                Error::failure(format!("workspace has no package named `{name}`")).with_help(
                    format!(
                        "available workspace packages: {}",
                        self.members.keys().cloned().collect::<Vec<_>>().join(", ")
                    ),
                )
            });
        }
        if let Some((_, member)) = self.members.iter().find(|(_, root)| *root == current) {
            return Ok(member.clone());
        }
        Err(Error::failure("a virtual workspace has no current package")
            .with_help("select one exact workspace package with `-p NAME`"))
    }

    fn apply(&self, manifest: &mut Manifest) -> Result<()> {
        if manifest.root != self.root {
            let document = Document::load(&manifest.path, "Cargo workspace member manifest")?;
            for key in ["workspace", "profile", "patch"] {
                if let Some(item) = document.root().get(key) {
                    return Err(Error::at(
                        &manifest.path,
                        document.line_of_item(item),
                        format!("workspace member cannot define `{key}`"),
                        "move workspace-wide settings to the workspace root",
                    ));
                }
            }
            let package = require_table(
                &manifest.path,
                &document,
                document.root().get("package").unwrap(),
                "package",
            )?;
            if let Some(item) = package.get("resolver") {
                return Err(Error::at(
                    &manifest.path,
                    document.line_of_item(item),
                    "workspace member cannot define package.resolver",
                    "set workspace.resolver at the workspace root",
                ));
            }
        }
        manifest.workspace_root.clone_from(&self.root);
        manifest.workspace_members = self.members.keys().cloned().collect();
        manifest.dev.clone_from(&self.dev);
        manifest.release.clone_from(&self.release);
        manifest.resolver = self.resolver;
        manifest.patches.clone_from(&self.patches);
        Ok(())
    }
}

fn discover_workspace(
    current: &Path,
    path: &Path,
    document: &Document,
) -> Result<Option<Workspace>> {
    if document.root().contains_key("workspace") {
        return Workspace::parse(current, path, document).map(Some);
    }
    for parent in current.ancestors().skip(1) {
        let candidate = parent.join(MANIFEST_NAME);
        if !candidate.is_file() {
            continue;
        }
        let candidate_document = Document::load(&candidate, "possible Cargo workspace manifest")?;
        if !candidate_document.root().contains_key("workspace") {
            continue;
        }
        let workspace = Workspace::parse(parent, &candidate, &candidate_document)?;
        if workspace.members.values().any(|member| member == current) {
            return Ok(Some(workspace));
        }
    }
    Ok(None)
}

fn workspace_member_root(
    root: &Path,
    path: &Path,
    document: &Document,
    member: &str,
) -> Result<PathBuf> {
    let candidate = Path::new(member);
    if member.is_empty()
        || candidate
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || member
            .bytes()
            .any(|byte| matches!(byte, b'*' | b'?' | b'[' | b']'))
    {
        return Err(Error::at(
            path,
            document.line_of_item(document.root().get("workspace").unwrap()),
            format!("unsupported workspace member path `{member}`"),
            "use an explicit descendant path without globs or `..`",
        ));
    }
    let declared = root.join(candidate);
    let canonical = fs::canonicalize(&declared).map_err(|error| {
        Error::failure(format!(
            "failed to resolve workspace member `{}`: {error}",
            declared.display()
        ))
    })?;
    if !canonical.starts_with(root) || !canonical.join(MANIFEST_NAME).is_file() {
        return Err(Error::failure(format!(
            "workspace member `{}` is not a package directory below the workspace root",
            declared.display()
        )));
    }
    Ok(canonical)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ManifestMode {
    Root,
    Dependency,
}

fn validate_manifest_tables(path: &Path, document: &Document, mode: ManifestMode) -> Result<()> {
    for (key, item) in document.root().iter() {
        let supported = matches!(
            (mode, key),
            (
                ManifestMode::Root,
                "package"
                    | "dependencies"
                    | "target"
                    | "features"
                    | "patch"
                    | "profile"
                    | "lib"
                    | "bin"
                    | "lints"
                    | "workspace"
            ) | (
                ManifestMode::Dependency,
                "package"
                    | "dependencies"
                    | "build-dependencies"
                    | "dev-dependencies"
                    | "target"
                    | "features"
                    | "profile"
                    | "lib"
                    | "bin"
                    | "example"
                    | "test"
                    | "bench"
                    | "lints"
                    | "hints"
                    | "badges"
                    | "workspace"
            )
        );
        if !supported {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("unsupported Stage-2 manifest table or key `{key}`"),
                "remove it or use a later Lorry stage that supports its build semantics",
            ));
        }
    }
    Ok(())
}

fn validate_package_keys(
    path: &Path,
    document: &Document,
    package: &Table,
    mode: ManifestMode,
) -> Result<()> {
    const ROOT_ALLOWED: &[&str] = &[
        "name",
        "version",
        "edition",
        "resolver",
        "rust-version",
        "build",
        "authors",
        "description",
        "homepage",
        "documentation",
        "repository",
        "license",
        "license-file",
        "readme",
        "keywords",
        "categories",
        "publish",
        "include",
        "exclude",
        "default-run",
        "autobins",
        "metadata",
    ];
    const DEPENDENCY_ONLY: &[&str] = &[
        "links",
        "autolib",
        "autobins",
        "autoexamples",
        "autotests",
        "autobenches",
    ];
    for (key, item) in package.iter() {
        if !ROOT_ALLOWED.contains(&key)
            && !(mode == ManifestMode::Dependency && DEPENDENCY_ONLY.contains(&key))
        {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("unsupported Stage-2 manifest key `package.{key}`"),
                "remove the key or use a later Lorry stage that supports its build semantics",
            ));
        }
    }
    if let Some(item) = package.get("autobins")
        && item.as_bool().is_none()
    {
        return Err(type_error(
            path,
            document.line_of_item(item),
            "package.autobins",
            "a boolean",
        ));
    }
    if mode == ManifestMode::Dependency {
        for key in DEPENDENCY_ONLY
            .iter()
            .copied()
            .filter(|key| *key != "links")
        {
            if let Some(item) = package.get(key)
                && item.as_bool().is_none()
            {
                return Err(type_error(
                    path,
                    document.line_of_item(item),
                    &format!("package.{key}"),
                    "a boolean",
                ));
            }
        }
        if let Some(item) = package.get("links")
            && item.as_str().is_none()
        {
            return Err(type_error(
                path,
                document.line_of_item(item),
                "package.links",
                "a string",
            ));
        }
    }
    for key in ["authors", "keywords", "categories", "include", "exclude"] {
        if let Some(item) = package.get(key) {
            string_array(path, document, item, &format!("package.{key}"))?;
        }
    }
    if let Some(item) = package.get("publish") {
        if item.as_bool().is_none() && item.as_array().is_none() {
            return Err(type_error(
                path,
                document.line_of_item(item),
                "package.publish",
                "a boolean or string array",
            ));
        }
        if item.as_array().is_some() {
            string_array(path, document, item, "package.publish")?;
        }
    }
    Ok(())
}

fn parse_package_metadata(
    path: &Path,
    document: &Document,
    package: &Table,
) -> Result<PackageMetadata> {
    Ok(PackageMetadata {
        authors: optional_string_array(path, document, package, "package", "authors")?
            .unwrap_or_default(),
        description: optional_string(path, document, package, "package", "description")?
            .unwrap_or_default(),
        homepage: optional_string(path, document, package, "package", "homepage")?
            .unwrap_or_default(),
        documentation: optional_string(path, document, package, "package", "documentation")?
            .unwrap_or_default(),
        repository: optional_string(path, document, package, "package", "repository")?
            .unwrap_or_default(),
        license: optional_string(path, document, package, "package", "license")?
            .unwrap_or_default(),
        license_file: optional_string(path, document, package, "package", "license-file")?
            .unwrap_or_default(),
        readme: optional_string_or_false(path, document, package, "package", "readme")?
            .unwrap_or_default(),
        rust_version: optional_string(path, document, package, "package", "rust-version")?
            .unwrap_or_default(),
    })
}

fn parse_edition(
    path: &Path,
    document: &Document,
    item: Option<&Item>,
    default_line: usize,
) -> Result<Edition> {
    let Some(item) = item else {
        return Ok(Edition::E2015);
    };
    let line = document.line_of_item(item).max(default_line);
    match item.as_str() {
        Some("2015") => Ok(Edition::E2015),
        Some("2018") => Ok(Edition::E2018),
        Some("2021") => Ok(Edition::E2021),
        Some("2024") => Ok(Edition::E2024),
        Some(value) => Err(Error::at(
            path,
            line,
            format!("unsupported package edition `{value}`"),
            "choose edition 2015, 2018, 2021, or 2024",
        )),
        None => Err(type_error(path, line, "package.edition", "a string")),
    }
}

fn parse_resolver(
    path: &Path,
    document: &Document,
    item: Option<&Item>,
    edition: Edition,
    default_line: usize,
) -> Result<Resolver> {
    let Some(item) = item else {
        return Ok(match edition {
            Edition::E2015 | Edition::E2018 => Resolver::V1,
            Edition::E2021 => Resolver::V2,
            Edition::E2024 => Resolver::V3,
        });
    };
    let line = document.line_of_item(item).max(default_line);
    match item.as_str() {
        Some("1") => Ok(Resolver::V1),
        Some("2") => Ok(Resolver::V2),
        Some("3") => Ok(Resolver::V3),
        Some(value) => Err(Error::at(
            path,
            line,
            format!("unsupported Cargo feature resolver `{value}`"),
            "choose resolver `1`, `2`, or `3`",
        )),
        None => Err(type_error(path, line, "package.resolver", "a string")),
    }
}

fn parse_build_script(
    path: &Path,
    document: &Document,
    package: &Table,
    root: &Path,
) -> Result<Option<PathBuf>> {
    match package.get("build") {
        Some(item) if item.as_bool() == Some(false) => Ok(None),
        Some(item) if item.as_str().is_some() => {
            let value = item.as_str().unwrap();
            validate_relative_path(path, document.line_of_item(item), "package.build", value)?;
            Ok(Some(root.join(value)))
        }
        Some(item) => Err(type_error(
            path,
            document.line_of_item(item),
            "package.build",
            "a relative path string or false",
        )),
        None if root.join("build.rs").is_file() => Ok(Some(root.join("build.rs"))),
        None => Ok(None),
    }
}

fn parse_library(
    path: &Path,
    document: &Document,
    root: &Path,
    package_name: &str,
    mode: ManifestMode,
) -> Result<Option<LibraryTarget>> {
    let Some(item) = document.root().get("lib") else {
        return Ok(root.join("src/lib.rs").is_file().then(|| LibraryTarget {
            name: package_name.replace('-', "_"),
            path: root.join("src/lib.rs"),
            proc_macro: false,
            test: true,
            doctest: true,
        }));
    };
    let table = require_table(path, document, item, "lib")?;
    for (key, item) in table.iter() {
        if !matches!(
            key,
            "name" | "path" | "test" | "doctest" | "crate-type" | "bench" | "doc" | "proc-macro"
        ) {
            return Err(unsupported_key(path, document, item, &format!("lib.{key}")));
        }
        if matches!(key, "bench" | "doc") && item.as_bool().is_none() {
            return Err(type_error(
                path,
                document.line_of_item(item),
                &format!("lib.{key}"),
                "a boolean",
            ));
        }
        if key == "proc-macro" && item.as_bool().is_none() {
            return Err(type_error(
                path,
                document.line_of_item(item),
                "lib.proc-macro",
                "a boolean",
            ));
        }
    }
    if mode == ManifestMode::Root {
        for key in ["bench", "doc"] {
            if table
                .get(key)
                .is_some_and(|item| item.as_bool() != Some(false))
            {
                return Err(Error::at(
                    path,
                    item_line(document, table, key),
                    format!("`lib.{key}` must be false in Stage 2 root packages"),
                    "disable the unsupported library target mode",
                ));
            }
        }
    }
    if let Some(crate_types) = table.get("crate-type") {
        let values = string_array(path, document, crate_types, "lib.crate-type")?;
        if values
            .iter()
            .any(|value| !matches!(value.as_str(), "lib" | "rlib"))
        {
            return Err(Error::at(
                path,
                document.line_of_item(crate_types),
                "custom library crate types are not supported in Stage 2",
                "use `lib` or `rlib` only",
            ));
        }
    }
    let proc_macro = optional_bool(path, document, table, "lib", "proc-macro")?.unwrap_or(false);
    if mode == ManifestMode::Root && proc_macro {
        return Err(Error::at(
            path,
            document.line_of_item(table.get("proc-macro").unwrap()),
            "selecting a procedural-macro package as the root is not supported",
            "use procedural-macro crates as dependencies of an ordinary root package",
        ));
    }
    if proc_macro && table.contains_key("crate-type") {
        return Err(Error::at(
            path,
            document.line_of_item(table.get("crate-type").unwrap()),
            "lib.crate-type cannot be combined with lib.proc-macro = true",
            "remove lib.crate-type; proc-macro selects the compiler-host procedural-macro artifact type",
        ));
    }
    let name = optional_string(path, document, table, "lib", "name")?
        .unwrap_or_else(|| package_name.replace('-', "_"));
    validate_crate_name(path, document.line_of_table(table), &name)?;
    let relative = optional_string(path, document, table, "lib", "path")?
        .unwrap_or_else(|| "src/lib.rs".to_owned());
    validate_relative_path(path, document.line_of_table(table), "lib.path", &relative)?;
    Ok(Some(LibraryTarget {
        name,
        path: root.join(relative),
        proc_macro,
        test: optional_bool(path, document, table, "lib", "test")?.unwrap_or(true),
        doctest: optional_bool(path, document, table, "lib", "doctest")?.unwrap_or(true),
    }))
}

fn parse_binaries(
    path: &Path,
    document: &Document,
    root: &Path,
    package: &Table,
    package_name: &str,
) -> Result<Vec<BinaryTarget>> {
    let mut binaries = if package.get("autobins").and_then(Item::as_bool) == Some(false) {
        BTreeMap::new()
    } else {
        discover_binaries(root, package_name)?
    };
    if let Some(item) = document.root().get("bin") {
        let mut explicit_names = BTreeSet::new();
        let tables = item.as_array_of_tables().ok_or_else(|| {
            type_error(
                path,
                document.line_of_item(item),
                "bin",
                "an array of tables",
            )
        })?;
        if tables.len() > MAX_BINARY_TARGETS {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("package declares more than {MAX_BINARY_TARGETS} binary targets"),
                "reduce the number of program targets",
            ));
        }
        for table in tables.iter() {
            for (key, item) in table.iter() {
                if !matches!(key, "name" | "path" | "test" | "bench" | "doc") {
                    return Err(unsupported_key(path, document, item, &format!("bin.{key}")));
                }
                if matches!(key, "bench" | "doc") && item.as_bool() != Some(false) {
                    return Err(Error::at(
                        path,
                        document.line_of_item(item),
                        format!("`bin.{key}` must be false in Stage 2"),
                        "benches and binary documentation targets are deferred",
                    ));
                }
            }
            let name = optional_string(path, document, table, "bin", "name")?
                .unwrap_or_else(|| package_name.to_owned());
            validate_package_name(path, document.line_of_table(table), &name)?;
            let relative = optional_string(path, document, table, "bin", "path")?
                .unwrap_or_else(|| "src/main.rs".to_owned());
            validate_relative_path(path, document.line_of_table(table), "bin.path", &relative)?;
            let target = BinaryTarget {
                name,
                path: root.join(relative),
                test: optional_bool(path, document, table, "bin", "test")?.unwrap_or(true),
            };
            if !explicit_names.insert(target.name.clone()) {
                return Err(Error::at(
                    path,
                    document.line_of_table(table),
                    "duplicate binary target name",
                    "give every `[[bin]]` target a distinct name",
                ));
            }
            binaries.insert(target.name.clone(), target);
        }
    }
    if binaries.len() > MAX_BINARY_TARGETS {
        return Err(Error::failure(format!(
            "package discovers more than {MAX_BINARY_TARGETS} binary targets"
        )));
    }
    Ok(binaries.into_values().collect())
}

fn discover_binaries(root: &Path, package_name: &str) -> Result<BTreeMap<String, BinaryTarget>> {
    let mut binaries = BTreeMap::new();
    let main = root.join("src/main.rs");
    if main.is_file() {
        binaries.insert(
            package_name.to_owned(),
            BinaryTarget {
                name: package_name.to_owned(),
                path: main,
                test: true,
            },
        );
    }
    let directory = root.join("src/bin");
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(binaries),
        Err(error) => {
            return Err(Error::failure(format!(
                "failed to discover binary targets in `{}`: {error}",
                directory.display()
            )));
        }
    };
    let mut entries = entries
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|error| {
            Error::failure(format!(
                "failed to read a binary target in `{}`: {error}",
                directory.display()
            ))
        })?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let metadata = entry.file_type().map_err(|error| {
            Error::failure(format!(
                "failed to inspect binary target `{}`: {error}",
                entry.path().display()
            ))
        })?;
        let (name, source) = if metadata.is_file()
            && entry.path().extension().and_then(|value| value.to_str()) == Some("rs")
        {
            (
                entry.path().file_stem().map(|value| value.to_owned()),
                entry.path(),
            )
        } else if metadata.is_dir() && entry.path().join("main.rs").is_file() {
            (Some(entry.file_name()), entry.path().join("main.rs"))
        } else {
            continue;
        };
        let name = name
            .and_then(|value| value.into_string().ok())
            .ok_or_else(|| {
                Error::failure(format!(
                    "binary target name in `{}` is not valid UTF-8",
                    directory.display()
                ))
            })?;
        validate_package_name(&root.join(MANIFEST_NAME), 1, &name)?;
        if binaries
            .insert(
                name.clone(),
                BinaryTarget {
                    name: name.clone(),
                    path: source,
                    test: true,
                },
            )
            .is_some()
        {
            return Err(Error::failure(format!(
                "binary target name `{name}` is discovered more than once"
            )));
        }
    }
    Ok(binaries)
}

fn resolve_target_defaults(manifest: &mut Manifest) -> Result<()> {
    if let Some(library) = &manifest.library
        && !library.path.is_file()
    {
        return Err(Error::failure(format!(
            "library target `{}` does not exist",
            library.path.display()
        )));
    }
    for binary in &manifest.binaries {
        if !binary.path.is_file() {
            return Err(Error::failure(format!(
                "binary target `{}` does not exist",
                binary.path.display()
            )));
        }
    }
    if manifest.library.is_none() && manifest.binaries.is_empty() {
        return Err(Error::failure(format!(
            "package `{}` has no supported library or binary target",
            manifest.name
        ))
        .with_help("add `src/lib.rs`, `src/main.rs`, or one supported `[[bin]]`"));
    }
    if let Some(default) = &manifest.default_run
        && !manifest
            .binaries
            .iter()
            .any(|binary| &binary.name == default)
    {
        return Err(Error::failure(format!(
            "package.default-run names unknown binary target `{default}`"
        ))
        .with_help("choose one of the package's binary target names"));
    }
    Ok(())
}

fn discover_integration_tests(root: &Path) -> Result<Vec<IntegrationTestTarget>> {
    let directory = root.join("tests");
    let metadata = match fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(Error::failure(format!(
                "failed to inspect integration-test directory `{}`: {error}",
                directory.display()
            )));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::failure(format!(
            "integration-test path `{}` is not a real directory",
            directory.display()
        )));
    }

    let mut targets = Vec::new();
    let mut crate_names = BTreeSet::new();
    for entry in fs::read_dir(&directory).map_err(|error| {
        Error::failure(format!(
            "failed to read integration-test directory `{}`: {error}",
            directory.display()
        ))
    })? {
        let entry = entry.map_err(|error| {
            Error::failure(format!(
                "failed to read an integration-test entry in `{}`: {error}",
                directory.display()
            ))
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            Error::failure(format!(
                "failed to inspect integration-test entry `{}`: {error}",
                path.display()
            ))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(Error::failure(format!(
                "integration-test entry `{}` is a symbolic link",
                path.display()
            )));
        }
        if metadata.is_dir() || path.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }
        if !metadata.is_file() {
            return Err(Error::failure(format!(
                "integration-test entry `{}` is not a regular file",
                path.display()
            )));
        }
        let name = path
            .file_stem()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                Error::failure(format!(
                    "integration-test filename `{}` is not valid UTF-8",
                    path.display()
                ))
            })?
            .to_owned();
        validate_package_name(&root.join(MANIFEST_NAME), 1, &name)?;
        let crate_name = name.replace('-', "_");
        if !crate_names.insert(crate_name.clone()) {
            return Err(Error::failure(format!(
                "integration-test target `{name}` has duplicate crate name `{crate_name}`"
            )));
        }
        targets.push(IntegrationTestTarget { name, path });
    }
    targets.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(targets)
}

fn parse_dependency_table(
    path: &Path,
    document: &Document,
    root: &Path,
    table: &Table,
    target: Option<&str>,
    kind: DependencyKind,
    output: &mut Vec<Dependency>,
) -> Result<()> {
    for (alias, item) in table.iter() {
        validate_package_name(path, document.line_of_item(item), alias)?;
        output.push(parse_dependency(
            path, document, root, alias, item, target, kind,
        )?);
    }
    Ok(())
}

fn parse_dependency(
    path: &Path,
    document: &Document,
    root: &Path,
    alias: &str,
    item: &Item,
    target: Option<&str>,
    kind: DependencyKind,
) -> Result<Dependency> {
    if let Some(requirement) = item.as_str() {
        return Ok(Dependency {
            alias: alias.to_owned(),
            package: alias.to_owned(),
            requirement: parse_requirement(path, document.line_of_item(item), alias, requirement)?,
            source: DependencySource::CratesIo,
            optional: false,
            default_features: true,
            features: Vec::new(),
            target: target.map(str::to_owned),
            kind,
        });
    }
    let (lookup, line) = match item {
        Item::Value(Value::InlineTable(table)) => {
            (DependencyTable::Inline(table), document.line_of_item(item))
        }
        Item::Table(table) => (DependencyTable::Regular(table), document.line_of_item(item)),
        _ => {
            return Err(type_error(
                path,
                document.line_of_item(item),
                &format!("dependencies.{alias}"),
                "a version string or dependency table",
            ));
        }
    };
    const ALLOWED: &[&str] = &[
        "version",
        "path",
        "package",
        "optional",
        "default-features",
        "features",
    ];
    for (key, value) in lookup.entries() {
        if !ALLOWED.contains(&key) {
            let unsupported = if matches!(
                key,
                "git"
                    | "branch"
                    | "tag"
                    | "rev"
                    | "registry"
                    | "registry-index"
                    | "workspace"
                    | "artifact"
                    | "lib"
            ) {
                format!("dependency source or mode `{key}` is not supported in Stage 2")
            } else {
                format!("unknown dependency key `{key}`")
            };
            return Err(Error::at(
                path,
                value.line(document),
                unsupported,
                "use a crates.io version or a local path dependency",
            ));
        }
    }
    let package = match lookup.get("package") {
        Some(value) => value
            .as_str()
            .ok_or_else(|| {
                type_error(
                    path,
                    value.line(document),
                    &format!("dependencies.{alias}.package"),
                    "a string",
                )
            })?
            .to_owned(),
        None => alias.to_owned(),
    };
    validate_package_name(path, line, &package)?;
    let source = match lookup.get("path") {
        Some(value) => {
            let declared = value.as_str().ok_or_else(|| {
                type_error(
                    path,
                    value.line(document),
                    &format!("dependencies.{alias}.path"),
                    "a string",
                )
            })?;
            validate_dependency_path(
                path,
                value.line(document),
                &format!("dependencies.{alias}.path"),
                declared,
            )?;
            DependencySource::Path(resolve_declared_path(root, declared))
        }
        None => DependencySource::CratesIo,
    };
    let requirement = match lookup.get("version") {
        Some(item) => {
            let text = item.as_str().ok_or_else(|| {
                type_error(
                    path,
                    item.line(document),
                    &format!("dependencies.{alias}.version"),
                    "a string",
                )
            })?;
            parse_requirement(path, item.line(document), alias, text)?
        }
        None if matches!(source, DependencySource::Path(_)) => VersionReq::STAR,
        None => {
            return Err(Error::at(
                path,
                line,
                format!("crates.io dependency `{alias}` is missing a version requirement"),
                "add `version = \"...\"` or declare an explicit local `path`",
            ));
        }
    };
    Ok(Dependency {
        alias: alias.to_owned(),
        package,
        requirement,
        source,
        optional: lookup_bool(path, document, &lookup, alias, "optional")?.unwrap_or(false),
        default_features: lookup_bool(path, document, &lookup, alias, "default-features")?
            .unwrap_or(true),
        features: match lookup.get("features") {
            Some(value) => node_string_array(
                path,
                document,
                value,
                &format!("dependencies.{alias}.features"),
            )?,
            None => Vec::new(),
        },
        target: target.map(str::to_owned),
        kind,
    })
}

fn parse_target_dependencies(
    path: &Path,
    document: &Document,
    root: &Path,
    mode: ManifestMode,
    output: &mut Vec<Dependency>,
    unsupported_target_dev_dependencies: &mut Vec<UnsupportedTargetDevDependency>,
) -> Result<()> {
    let Some(item) = document.root().get("target") else {
        return Ok(());
    };
    let targets = require_table(path, document, item, "target")?;
    for (selector, item) in targets.iter() {
        validate_target_selector(path, document.line_of_item(item), selector)?;
        let target = require_table(path, document, item, &format!("target.{selector}"))?;
        for (key, item) in target.iter() {
            let kind = match (mode, key) {
                (_, "dependencies") => Some(DependencyKind::Normal),
                (ManifestMode::Dependency, "build-dependencies") => Some(DependencyKind::Build),
                (ManifestMode::Dependency, "dev-dependencies") => None,
                (ManifestMode::Root, "dev-dependencies") => {
                    require_table(
                        path,
                        document,
                        item,
                        &format!("target.{selector}.dev-dependencies"),
                    )?;
                    unsupported_target_dev_dependencies.push(UnsupportedTargetDevDependency {
                        selector: selector.to_owned(),
                        line: document.line_of_item(item),
                    });
                    continue;
                }
                _ => {
                    return Err(Error::at(
                        path,
                        document.line_of_item(item),
                        format!("root `target.{selector}.{key}` is not supported in Stage 2"),
                        "root build-dependencies and dev-dependencies are deferred",
                    ));
                }
            };
            let dependencies =
                require_table(path, document, item, &format!("target.{selector}.{key}"))?;
            if let Some(kind) = kind {
                parse_dependency_table(
                    path,
                    document,
                    root,
                    dependencies,
                    Some(selector),
                    kind,
                    output,
                )?;
            }
        }
    }
    Ok(())
}

fn validate_ignored_dev_dependencies(path: &Path, document: &Document) -> Result<()> {
    if let Some(item) = document.root().get("dev-dependencies") {
        require_table(path, document, item, "dev-dependencies")?;
    }
    Ok(())
}

fn parse_features(path: &Path, document: &Document) -> Result<BTreeMap<String, Vec<String>>> {
    let Some(item) = document.root().get("features") else {
        return Ok(BTreeMap::new());
    };
    let table = require_table(path, document, item, "features")?;
    let mut result = BTreeMap::new();
    for (name, item) in table.iter() {
        validate_feature(path, document.line_of_item(item), name)?;
        let members = string_array(path, document, item, &format!("features.{name}"))?;
        for member in &members {
            validate_feature_reference(path, document.line_of_item(item), member)?;
        }
        result.insert(name.to_owned(), members);
    }
    Ok(result)
}

fn parse_patches(path: &Path, document: &Document, root: &Path) -> Result<Vec<PathPatch>> {
    let Some(item) = document.root().get("patch") else {
        return Ok(Vec::new());
    };
    let patch = require_table(path, document, item, "patch")?;
    for (source, item) in patch.iter() {
        if source != "crates-io" {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("patch source `{source}` is not supported in Stage 2"),
                "use `[patch.crates-io]` with exact local path replacements",
            ));
        }
    }
    let Some(item) = patch.get("crates-io") else {
        return Ok(Vec::new());
    };
    let crates_io = require_table(path, document, item, "patch.crates-io")?;
    let mut result = Vec::new();
    for (alias, item) in crates_io.iter() {
        let table = item.as_inline_table().ok_or_else(|| {
            type_error(
                path,
                document.line_of_item(item),
                &format!("patch.crates-io.{alias}"),
                "an inline path table",
            )
        })?;
        for (key, value) in table.iter() {
            if !matches!(key, "path" | "package") {
                return Err(Error::at(
                    path,
                    document.line_of_value(value),
                    format!("patch key `{key}` is not supported in Stage 2"),
                    "run `lorry vendor` to pin and materialize a Git patch, or use only `path` and optional `package`",
                ));
            }
        }
        let declared = table.get("path").and_then(Value::as_str).ok_or_else(|| {
            Error::at(
                path,
                document.line_of_item(item),
                format!("patch `{alias}` is missing string key `path`"),
                "use `{ path = \"relative/source\" }` or an absolute local path",
            )
        })?;
        validate_dependency_path(
            path,
            document.line_of_item(item),
            &format!("patch.crates-io.{alias}.path"),
            declared,
        )?;
        let package = table
            .get("package")
            .and_then(Value::as_str)
            .unwrap_or(alias);
        validate_package_name(path, document.line_of_item(item), package)?;
        result.push(PathPatch {
            alias: alias.to_owned(),
            package: package.to_owned(),
            path: resolve_declared_path(root, declared),
        });
    }
    Ok(result)
}

fn parse_rust_lints(
    path: &Path,
    document: &Document,
    mode: ManifestMode,
) -> Result<BTreeMap<String, Lint>> {
    let Some(item) = document.root().get("lints") else {
        return Ok(BTreeMap::new());
    };
    let lints = require_table(path, document, item, "lints")?;
    for (key, item) in lints.iter() {
        if key != "rust" && mode == ManifestMode::Root {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("lint namespace `lints.{key}` is not supported in Stage 2"),
                "configure Rust lints under `[lints.rust]`",
            ));
        }
    }
    let Some(item) = lints.get("rust") else {
        return Ok(BTreeMap::new());
    };
    let rust = require_table(path, document, item, "lints.rust")?;
    let mut result = BTreeMap::new();
    for (name, item) in rust.iter() {
        let lint = if let Some(level) = item.as_str() {
            Lint {
                level: validate_lint_level(path, document.line_of_item(item), level)?,
                priority: 0,
                check_cfg: Vec::new(),
            }
        } else if item.as_inline_table().is_some() || item.as_table().is_some() {
            let lookup = match item {
                Item::Value(Value::InlineTable(table)) => DependencyTable::Inline(table),
                Item::Table(table) => DependencyTable::Regular(table),
                _ => unreachable!(),
            };
            for (key, value) in lookup.entries() {
                if !matches!(key, "level" | "priority" | "check-cfg") {
                    return Err(Error::at(
                        path,
                        value.line(document),
                        format!("unknown lint configuration key `{key}`"),
                        "use only `level` and optional `priority`",
                    ));
                }
            }
            let level = lookup
                .get("level")
                .and_then(TomlNode::as_str)
                .ok_or_else(|| {
                    Error::at(
                        path,
                        document.line_of_item(item),
                        format!("lint `{name}` is missing string key `level`"),
                        "set a supported rustc lint level",
                    )
                })?;
            Lint {
                level: validate_lint_level(path, document.line_of_item(item), level)?,
                priority: lookup
                    .get("priority")
                    .map(|value| {
                        value.as_integer().ok_or_else(|| {
                            type_error(
                                path,
                                value.line(document),
                                &format!("lints.rust.{name}.priority"),
                                "an integer",
                            )
                        })
                    })
                    .transpose()?
                    .unwrap_or(0),
                check_cfg: match lookup.get("check-cfg") {
                    Some(value) => string_values(
                        path,
                        document,
                        value.as_array().ok_or_else(|| {
                            type_error(
                                path,
                                value.line(document),
                                &format!("lints.rust.{name}.check-cfg"),
                                "an array of strings",
                            )
                        })?,
                        &format!("lints.rust.{name}.check-cfg"),
                    )?,
                    None => Vec::new(),
                },
            }
        } else {
            return Err(type_error(
                path,
                document.line_of_item(item),
                &format!("lints.rust.{name}"),
                "a level string or inline table",
            ));
        };
        result.insert(name.to_owned(), lint);
    }
    Ok(result)
}

fn parse_profiles(path: &Path, document: &Document) -> Result<(DevProfile, ReleaseProfile)> {
    let Some(item) = document.root().get("profile") else {
        return Ok((DevProfile::default(), ReleaseProfile::default()));
    };
    let profiles = require_table(path, document, item, "profile")?;
    for (key, item) in profiles.iter() {
        if !matches!(key, "dev" | "release") {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("custom profile `profile.{key}` is not supported in Stage 2"),
                "use only supported dev and release profile keys",
            ));
        }
    }
    let dev = match profiles.get("dev") {
        Some(dev) => parse_dev(
            path,
            document,
            require_table(path, document, dev, "profile.dev")?,
        )?,
        None => DevProfile::default(),
    };
    let release = match profiles.get("release") {
        Some(release) => parse_release(
            path,
            document,
            require_table(path, document, release, "profile.release")?,
        )?,
        None => ReleaseProfile::default(),
    };
    Ok((dev, release))
}

fn parse_dev(path: &Path, document: &Document, table: &Table) -> Result<DevProfile> {
    for (key, item) in table.iter() {
        if key != "panic" {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("unsupported dev profile key `profile.dev.{key}`"),
                "the dev profile supports only panic",
            ));
        }
    }
    Ok(DevProfile {
        panic_abort: parse_panic_abort(path, document, table, "profile.dev")?,
    })
}

fn parse_release(path: &Path, document: &Document, table: &Table) -> Result<ReleaseProfile> {
    for (key, item) in table.iter() {
        if !matches!(key, "panic" | "lto" | "strip" | "codegen-units") {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("unsupported Stage-2 release profile key `profile.release.{key}`"),
                "Stage 2 supports only panic, lto, strip, and codegen-units",
            ));
        }
    }
    let panic_abort = parse_panic_abort(path, document, table, "profile.release")?;
    let lto = match table.get("lto") {
        None => Lto::Default,
        Some(item) if item.as_bool() == Some(false) => Lto::Default,
        Some(item) if item.as_bool() == Some(true) => Lto::True,
        Some(item) if item.as_str() == Some("fat") => Lto::Fat,
        Some(item) if item.as_str() == Some("thin") => Lto::Thin,
        Some(item) if item.as_str() == Some("off") => Lto::Off,
        Some(item) => {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                "unsupported value for `profile.release.lto`",
                "choose false, true, `fat`, `thin`, or `off`",
            ));
        }
    };
    let strip = match table.get("strip") {
        None => Strip::None,
        Some(item) if item.as_bool() == Some(false) => Strip::None,
        Some(item) if item.as_bool() == Some(true) => Strip::Symbols,
        Some(item) if item.as_str() == Some("none") => Strip::None,
        Some(item) if item.as_str() == Some("debuginfo") => Strip::Debuginfo,
        Some(item) if item.as_str() == Some("symbols") => Strip::Symbols,
        Some(item) => {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                "unsupported value for `profile.release.strip`",
                "choose false, true, `none`, `debuginfo`, or `symbols`",
            ));
        }
    };
    let codegen_units = match table.get("codegen-units") {
        None => None,
        Some(item) => match item.as_integer() {
            Some(value) if value > 0 && value <= u32::MAX as i64 => Some(value as u32),
            _ => {
                return Err(Error::at(
                    path,
                    document.line_of_item(item),
                    "`profile.release.codegen-units` must be an integer from 1 through 4294967295",
                    "use a positive codegen unit count",
                ));
            }
        },
    };
    Ok(ReleaseProfile {
        panic_abort,
        lto,
        strip,
        codegen_units,
    })
}

fn parse_panic_abort(
    path: &Path,
    document: &Document,
    table: &Table,
    profile: &str,
) -> Result<bool> {
    Ok(match table.get("panic") {
        None => false,
        Some(item) if item.as_str() == Some("unwind") => false,
        Some(item) if item.as_str() == Some("abort") => true,
        Some(item) => {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("unsupported `{profile}.panic` value"),
                "choose `unwind` or `abort`",
            ));
        }
    })
}

#[cfg(test)]
fn validate_lock_source(manifest: &Manifest, path: &Path, source: &str) -> Result<Lockfile> {
    let document = Document::parse(path, "Cargo lockfile", source.to_owned())?;
    parse_lock_document(manifest, path, &document, true)
}

fn parse_lock_document(
    manifest: &Manifest,
    path: &Path,
    document: &Document,
    require_current_root: bool,
) -> Result<Lockfile> {
    for (key, item) in document.root().iter() {
        if !matches!(key, "version" | "package") {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("unsupported root Cargo.lock key `{key}`"),
                "use Cargo.lock format version 4",
            ));
        }
    }
    let version = document.root().get("version").ok_or_else(|| {
        Error::failure(format!(
            "lockfile `{}` is missing `version = 4`",
            path.display()
        ))
    })?;
    if version.as_integer() != Some(4) {
        return Err(Error::at(
            path,
            document.line_of_item(version),
            "unsupported Cargo.lock format; expected `version = 4`",
            "regenerate the lockfile with a current Cargo or `lorry vendor`",
        ));
    }
    let package_item = document.root().get("package").ok_or_else(|| {
        Error::failure(format!(
            "lockfile `{}` contains no package records",
            path.display()
        ))
    })?;
    let tables = package_item.as_array_of_tables().ok_or_else(|| {
        type_error(
            path,
            document.line_of_item(package_item),
            "package",
            "an array of tables",
        )
    })?;
    let mut packages = Vec::new();
    let mut identities = BTreeSet::new();
    for table in tables.iter() {
        for (key, item) in table.iter() {
            if !matches!(
                key,
                "name" | "version" | "source" | "checksum" | "dependencies"
            ) {
                return Err(Error::at(
                    path,
                    document.line_of_item(item),
                    format!("unsupported Cargo.lock package key `{key}`"),
                    "use only Cargo.lock v4 package identity and dependency fields",
                ));
            }
        }
        let name = required_string(path, document, table, "package", "name")?;
        validate_package_name(path, document.line_of_table(table), &name)?;
        let version_text = required_string(path, document, table, "package", "version")?;
        let version = parse_version(path, item_line(document, table, "version"), &version_text)?;
        let source = optional_string(path, document, table, "package", "source")?;
        if source.as_deref().is_some_and(|value| {
            value != CRATES_IO_SOURCE
                && (require_current_root || !value.starts_with("git+https://"))
        }) {
            return Err(Error::at(
                path,
                item_line(document, table, "source"),
                format!(
                    "unsupported Cargo.lock source `{}`",
                    source.as_deref().unwrap()
                ),
                "run `lorry vendor` to materialize a root Git patch; builds support crates.io and local path package nodes only",
            ));
        }
        let checksum = optional_string(path, document, table, "package", "checksum")?;
        match (&source, &checksum) {
            (Some(_), Some(value)) if is_sha256(value) => {}
            (Some(source), None) if !require_current_root && source.starts_with("git+https://") => {
            }
            (Some(_), _) => {
                return Err(Error::at(
                    path,
                    item_line(document, table, "checksum"),
                    format!(
                        "registry package `{name} {version_text}` needs a lowercase SHA-256 checksum"
                    ),
                    "use Cargo's authoritative crates.io checksum",
                ));
            }
            (None, Some(_)) => {
                return Err(Error::at(
                    path,
                    item_line(document, table, "checksum"),
                    format!("path package `{name} {version_text}` cannot have a checksum"),
                    "remove source/checksum from path package lock nodes",
                ));
            }
            (None, None) => {}
        }
        let dependencies = optional_string_array(path, document, table, "package", "dependencies")?
            .unwrap_or_default();
        let identity = (name.clone(), version.original.clone(), source.clone());
        if !identities.insert(identity) {
            return Err(Error::at(
                path,
                document.line_of_table(table),
                format!("duplicate Cargo.lock package `{name} {version_text}`"),
                "keep one package node for each exact source identity",
            ));
        }
        packages.push(LockedPackage {
            name,
            version,
            source,
            checksum,
            dependencies,
        });
    }
    let roots = packages
        .iter()
        .filter(|package| {
            package.name == manifest.name
                && package.version.original == manifest.version.original
                && package.source.is_none()
        })
        .count();
    if require_current_root && roots != 1 {
        return Err(Error::failure(format!(
            "Cargo.lock is stale: expected one root path package `{} {}`, found {roots}",
            manifest.name, manifest.version.original
        )));
    }
    Ok(Lockfile { packages })
}

#[derive(Clone, Copy)]
enum DependencyTable<'a> {
    Regular(&'a Table),
    Inline(&'a InlineTable),
}

impl<'a> DependencyTable<'a> {
    fn get(self, key: &str) -> Option<TomlNode<'a>> {
        match self {
            Self::Regular(table) => table.get(key).map(TomlNode::Item),
            Self::Inline(table) => table.get(key).map(TomlNode::Value),
        }
    }

    fn entries(self) -> Vec<(&'a str, TomlNode<'a>)> {
        match self {
            Self::Regular(table) => table
                .iter()
                .map(|(key, item)| (key, TomlNode::Item(item)))
                .collect(),
            Self::Inline(table) => table
                .iter()
                .map(|(key, value)| (key, TomlNode::Value(value)))
                .collect(),
        }
    }
}

#[derive(Clone, Copy)]
enum TomlNode<'a> {
    Item(&'a Item),
    Value(&'a Value),
}

impl<'a> TomlNode<'a> {
    fn as_str(self) -> Option<&'a str> {
        match self {
            Self::Item(item) => item.as_str(),
            Self::Value(value) => value.as_str(),
        }
    }

    fn as_bool(self) -> Option<bool> {
        match self {
            Self::Item(item) => item.as_bool(),
            Self::Value(value) => value.as_bool(),
        }
    }

    fn as_integer(self) -> Option<i64> {
        match self {
            Self::Item(item) => item.as_integer(),
            Self::Value(value) => value.as_integer(),
        }
    }

    fn as_array(self) -> Option<&'a Array> {
        match self {
            Self::Item(item) => item.as_array(),
            Self::Value(value) => value.as_array(),
        }
    }

    fn line(self, document: &Document) -> usize {
        match self {
            Self::Item(item) => document.line_of_item(item),
            Self::Value(value) => document.line_of_value(value),
        }
    }
}

fn lookup_bool(
    path: &Path,
    document: &Document,
    table: &DependencyTable<'_>,
    dependency: &str,
    key: &str,
) -> Result<Option<bool>> {
    match table.get(key) {
        None => Ok(None),
        Some(item) => item.as_bool().map(Some).ok_or_else(|| {
            type_error(
                path,
                item.line(document),
                &format!("dependencies.{dependency}.{key}"),
                "a boolean",
            )
        }),
    }
}

fn required_string(
    path: &Path,
    document: &Document,
    table: &Table,
    table_name: &str,
    key: &str,
) -> Result<String> {
    optional_string(path, document, table, table_name, key)?.ok_or_else(|| {
        Error::at(
            path,
            document.line_of_table(table),
            format!("table `[{table_name}]` is missing required string `{key}`"),
            format!("add `{key} = \"...\"` to `[{table_name}]`"),
        )
    })
}

fn optional_string(
    path: &Path,
    document: &Document,
    table: &Table,
    table_name: &str,
    key: &str,
) -> Result<Option<String>> {
    match table.get(key) {
        None => Ok(None),
        Some(item) => item.as_str().map(str::to_owned).map(Some).ok_or_else(|| {
            type_error(
                path,
                document.line_of_item(item),
                &format!("{table_name}.{key}"),
                "a string",
            )
        }),
    }
}

fn optional_bool(
    path: &Path,
    document: &Document,
    table: &Table,
    table_name: &str,
    key: &str,
) -> Result<Option<bool>> {
    match table.get(key) {
        None => Ok(None),
        Some(item) => item.as_bool().map(Some).ok_or_else(|| {
            type_error(
                path,
                document.line_of_item(item),
                &format!("{table_name}.{key}"),
                "a boolean",
            )
        }),
    }
}

fn optional_string_or_false(
    path: &Path,
    document: &Document,
    table: &Table,
    table_name: &str,
    key: &str,
) -> Result<Option<String>> {
    match table.get(key) {
        None => Ok(None),
        Some(item) if item.as_bool() == Some(false) => Ok(None),
        Some(item) => item.as_str().map(str::to_owned).map(Some).ok_or_else(|| {
            type_error(
                path,
                document.line_of_item(item),
                &format!("{table_name}.{key}"),
                "a string or false",
            )
        }),
    }
}

fn optional_string_array(
    path: &Path,
    document: &Document,
    table: &Table,
    table_name: &str,
    key: &str,
) -> Result<Option<Vec<String>>> {
    table
        .get(key)
        .map(|item| string_array(path, document, item, &format!("{table_name}.{key}")))
        .transpose()
}

fn string_array(path: &Path, document: &Document, item: &Item, name: &str) -> Result<Vec<String>> {
    let array = item.as_array().ok_or_else(|| {
        type_error(
            path,
            document.line_of_item(item),
            name,
            "an array of strings",
        )
    })?;
    string_values(path, document, array, name)
}

fn node_string_array(
    path: &Path,
    document: &Document,
    node: TomlNode<'_>,
    name: &str,
) -> Result<Vec<String>> {
    let array = node
        .as_array()
        .ok_or_else(|| type_error(path, node.line(document), name, "an array of strings"))?;
    string_values(path, document, array, name)
}

fn string_values(
    path: &Path,
    document: &Document,
    array: &Array,
    name: &str,
) -> Result<Vec<String>> {
    array
        .iter()
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                type_error(
                    path,
                    document.line_of_value(value),
                    name,
                    "an array containing only strings",
                )
            })
        })
        .collect()
}

fn require_table<'a>(
    path: &Path,
    document: &Document,
    item: &'a Item,
    name: &str,
) -> Result<&'a Table> {
    item.as_table()
        .ok_or_else(|| type_error(path, document.line_of_item(item), name, "a TOML table"))
}

fn item_line(document: &Document, table: &Table, key: &str) -> usize {
    table.get(key).map_or_else(
        || document.line_of_table(table),
        |item| document.line_of_item(item),
    )
}

fn parse_version(path: &Path, line: usize, version: &str) -> Result<Version> {
    let parsed = SemVersion::parse(version).map_err(|error| {
        Error::at(
            path,
            line,
            format!("invalid semantic package version `{version}`: {error}"),
            "use a semantic version with major.minor.patch components",
        )
    })?;
    Ok(Version {
        original: version.to_owned(),
        major: parsed.major,
        minor: parsed.minor,
        patch: parsed.patch,
        pre: parsed.pre.to_string(),
        build: parsed.build.to_string(),
    })
}

fn parse_requirement(path: &Path, line: usize, name: &str, value: &str) -> Result<VersionReq> {
    VersionReq::parse(value).map_err(|error| {
        Error::at(
            path,
            line,
            format!("invalid version requirement `{value}` for dependency `{name}`: {error}"),
            "use a Cargo-compatible semantic version requirement",
        )
    })
}

fn validate_package_name(path: &Path, line: usize, name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        && name.bytes().any(|byte| byte.is_ascii_alphabetic());
    if !valid {
        return Err(Error::at(
            path,
            line,
            format!("unsupported Stage-2 package name `{name}`"),
            "use 1–64 ASCII letters, digits, `-`, or `_`, including at least one letter",
        ));
    }
    Ok(())
}

fn validate_crate_name(path: &Path, line: usize, name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(Error::at(
            path,
            line,
            format!("unsupported Rust crate name `{name}`"),
            "use ASCII letters, digits, and underscores",
        ));
    }
    Ok(())
}

fn validate_feature(path: &Path, line: usize, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'+'))
    {
        return Err(Error::at(
            path,
            line,
            format!("unsupported feature name `{value}`"),
            "use a non-empty ASCII feature name",
        ));
    }
    Ok(())
}

fn validate_feature_reference(path: &Path, line: usize, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 512
        || value.bytes().any(|byte| {
            !byte.is_ascii_graphic() || matches!(byte, b'\\' | b'[' | b']' | b'{' | b'}')
        })
    {
        return Err(Error::at(
            path,
            line,
            format!("unsupported feature reference `{value}`"),
            "use a feature, `dep:name`, `name/feature`, or `name?/feature` reference",
        ));
    }
    Ok(())
}

fn validate_target_selector(path: &Path, line: usize, value: &str) -> Result<()> {
    let valid_cfg = value.starts_with("cfg(") && value.ends_with(')') && value.len() > 5;
    let valid_triple = !value.is_empty()
        && !value.ends_with(".json")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !valid_cfg && !valid_triple {
        return Err(Error::at(
            path,
            line,
            format!("unsupported target dependency selector `{value}`"),
            "use a target triple or non-empty `cfg(...)` expression",
        ));
    }
    Ok(())
}

fn validate_relative_path(path: &Path, line: usize, name: &str, value: &str) -> Result<()> {
    let candidate = Path::new(value);
    if value.is_empty() || candidate.is_absolute() || value.as_bytes().contains(&0) {
        return Err(Error::at(
            path,
            line,
            format!("`{name}` must be a non-empty relative path"),
            "use a path relative to the package manifest",
        ));
    }
    Ok(())
}

fn validate_dependency_path(path: &Path, line: usize, name: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.as_bytes().contains(&0) {
        return Err(Error::at(
            path,
            line,
            format!("`{name}` must be a non-empty filesystem path"),
            "use an absolute path or a path relative to the package manifest",
        ));
    }
    Ok(())
}

fn resolve_declared_path(root: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() {
        path.to_owned()
    } else {
        root.join(path)
    }
}

fn validate_lint_level(path: &Path, line: usize, value: &str) -> Result<String> {
    if matches!(value, "allow" | "warn" | "force-warn" | "deny" | "forbid") {
        Ok(value.to_owned())
    } else {
        Err(Error::at(
            path,
            line,
            format!("unsupported rustc lint level `{value}`"),
            "choose allow, warn, force-warn, deny, or forbid",
        ))
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn unsupported_key(path: &Path, document: &Document, item: &Item, name: &str) -> Error {
    Error::at(
        path,
        document.line_of_item(item),
        format!("unsupported Stage-2 manifest key `{name}`"),
        "remove the key or use a later Lorry stage",
    )
}

fn type_error(path: &Path, line: usize, name: &str, expected: &str) -> Error {
    Error::at(
        path,
        line,
        format!("`{name}` must be {expected}"),
        "use the supported TOML value type",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toolchain::CfgSet;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_VENDOR_FIXTURE: AtomicU64 = AtomicU64::new(0);

    const RED: &str = r#"
[package]
name = "red"
version = "0.1.0"
edition = "2024"
license = "MIT OR Apache-2.0"
authors = ["A", "B"]

[package.metadata.anything]
opaque = { stage = 2 }

[dependencies]

[profile.dev]
panic = "abort"

[profile.release]
panic = "abort"
lto = "fat"
strip = true
codegen-units = 1
"#;

    fn parsed(source: &str) -> Result<Manifest> {
        Manifest::parse(
            Path::new("/tmp/pkg"),
            Path::new("/tmp/pkg/Cargo.toml"),
            source,
        )
    }

    #[test]
    fn parses_dependency_free_manifest_compatibly() {
        let manifest = parsed(RED).unwrap();
        assert_eq!(manifest.name, "red");
        assert_eq!(manifest.crate_name, "red");
        assert_eq!(manifest.edition, Edition::E2024);
        assert_eq!(manifest.resolver, Resolver::V3);
        assert_eq!(manifest.metadata.authors, ["A", "B"]);
        assert!(manifest.dev.panic_abort);
        assert!(manifest.release.panic_abort);
        assert_eq!(manifest.release.lto, Lto::Fat);
        assert_eq!(manifest.release.strip, Strip::Symbols);
        assert_eq!(manifest.release.codegen_units, Some(1));
    }

    #[test]
    fn dependency_hints_are_recognized_inert_metadata() {
        let root = Path::new("/dependency");
        let path = root.join("Cargo.toml");
        let source = "[package]\nname = \"hinted\"\nversion = \"1.0.0\"\nedition = \"2024\"\n\
                      [hints]\nmostly-unused = true\nfuture-hint = \"ignored\"\n";
        let document = Document::parse(&path, "Cargo manifest", source.to_owned()).unwrap();
        let manifest =
            Manifest::parse_document(root, &path, &document, ManifestMode::Dependency).unwrap();
        assert_eq!(manifest.name, "hinted");
        assert!(manifest.dependencies.is_empty());
        assert!(manifest.features.is_empty());
    }

    #[test]
    fn parses_stage_two_manifest_models() {
        let source = r#"
[package]
name = "demo"
version = "1.2.3-alpha.1+build"
edition = "2021"
resolver = "2"
build = false

[lib]
name = "demo_lib"
path = "src/library.rs"

[[bin]]
name = "demo"
path = "src/program.rs"
bench = false
doc = false

[dependencies]
serde = { version = "=1.0.228", default-features = false, features = [
    "std",
] }
local-name = { package = "real-name", path = "../real" }

[target.'cfg(target_os = "motor")'.dependencies]
motor = "0.16"

[features]
default = ["serde/std", "dep:local-name"]
"fast+mode" = []

[patch.crates-io]
ring = { path = ".lorry/vendor/ring/source" }

[lints.rust]
unsafe_code = { level = "forbid", priority = 1 }
"#;
        let manifest = parsed(source).unwrap();
        assert_eq!(manifest.dependencies.len(), 3);
        assert_eq!(manifest.dependencies[0].package, "serde");
        assert!(!manifest.dependencies[0].default_features);
        assert!(matches!(
            manifest.dependencies[1].source,
            DependencySource::Path(_)
        ));
        assert_eq!(manifest.dependencies[1].requirement, VersionReq::STAR);
        assert_eq!(
            manifest.dependencies[2].target.as_deref(),
            Some("cfg(target_os = \"motor\")")
        );
        assert_eq!(manifest.features["default"].len(), 2);
        assert!(manifest.features.contains_key("fast+mode"));
        assert_eq!(manifest.patches[0].package, "ring");
        assert_eq!(manifest.rust_lints["unsafe_code"].priority, 1);
    }

    #[test]
    fn discovers_and_overrides_multiple_binary_targets() {
        let id = NEXT_VENDOR_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "lorry-manifest-binaries-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("src/bin/worker")).unwrap();
        fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(root.join("src/bin/tool.rs"), "fn main() {}\n").unwrap();
        fs::write(root.join("src/bin/worker/main.rs"), "fn main() {}\n").unwrap();
        fs::write(root.join("src/custom.rs"), "fn main() {}\n").unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\
             edition = \"2024\"\ndefault-run = \"worker\"\n\
             [[bin]]\nname = \"tool\"\npath = \"src/custom.rs\"\n",
        )
        .unwrap();
        fs::write(
            root.join("Cargo.lock"),
            "version = 4\n[[package]]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();

        let manifest = Manifest::load(&root).unwrap();
        assert_eq!(manifest.default_run.as_deref(), Some("worker"));
        assert_eq!(
            manifest
                .binaries
                .iter()
                .map(|target| target.name.as_str())
                .collect::<Vec<_>>(),
            ["demo", "tool", "worker"]
        );
        assert_eq!(manifest.binaries[1].path, root.join("src/custom.rs"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn selects_explicit_workspace_members_and_shared_inputs() {
        let id = NEXT_VENDOR_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "lorry-manifest-workspace-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        for member in ["app", "shared"] {
            fs::create_dir_all(root.join(member).join("src")).unwrap();
        }
        fs::write(root.join("app/src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(root.join("shared/src/lib.rs"), "pub fn shared() {}\n").unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"app\", \"shared\"]\nresolver = \"2\"\n\
             [profile.dev]\npanic = \"abort\"\n\
             [profile.release]\nlto = \"thin\"\ncodegen-units = 2\n",
        )
        .unwrap();
        fs::write(
            root.join("app/Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\
             [dependencies]\nshared = { path = \"../shared\" }\n",
        )
        .unwrap();
        fs::write(
            root.join("shared/Cargo.toml"),
            "[package]\nname = \"shared\"\nversion = \"0.2.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(
            root.join("Cargo.lock"),
            "version = 4\n\
             [[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"shared\"]\n\
             [[package]]\nname = \"shared\"\nversion = \"0.2.0\"\n",
        )
        .unwrap();

        let from_root = Manifest::load_selected(&root, Some("app")).unwrap();
        let from_member = Manifest::load(&root.join("app")).unwrap();
        assert_eq!(from_root, from_member);
        assert_eq!(from_root.root, root.join("app"));
        assert_eq!(from_root.workspace_root, root);
        assert_eq!(from_root.resolver, Resolver::V2);
        assert!(from_root.dev.panic_abort);
        assert_eq!(from_root.release.lto, Lto::Thin);
        assert_eq!(from_root.release.codegen_units, Some(2));
        assert!(from_root.lock.is_some());
        assert!(Manifest::load_selected(&from_root.workspace_root, None).is_err());
        assert!(Manifest::load_selected(&from_root.workspace_root, Some("missing")).is_err());
        fs::write(
            from_root.workspace_root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"app\", \"shared\"]\ndefault-members = [\"app\"]\n",
        )
        .unwrap();
        assert!(Manifest::load_selected(&from_root.workspace_root, Some("app")).is_err());
        fs::remove_dir_all(from_root.workspace_root).unwrap();
    }

    #[test]
    fn parses_dependency_only_graph_tables_without_widening_roots() {
        let source = r#"
[package]
name = "dependency"
version = "1.2.3"
edition = "2021"
build = "build.rs"
links = "native"
autolib = false
autobins = false
autoexamples = false
autotests = false
autobenches = false

[lib]
name = "dependency"
path = "src/lib.rs"
bench = true

[dependencies]
normal = "1"

[build-dependencies]
builder = "2"

[dev-dependencies]
ignored = "3"

[target.'cfg(unix)'.build-dependencies]
target-builder = "4"

[target.'cfg(windows)'.dev-dependencies]
target-ignored = "5"

[lints.clippy]
all = "warn"

[lints.rust.unexpected_cfgs]
level = "allow"
check-cfg = ["cfg(custom)"]

[[test]]
name = "ignored-test"
path = "tests/ignored.rs"

[workspace]
members = ["ignored-member"]
"#;
        let document = Document::parse(
            Path::new("/dependency/Cargo.toml"),
            "dependency manifest",
            source.to_owned(),
        )
        .unwrap();
        let manifest = Manifest::parse_document(
            Path::new("/dependency"),
            Path::new("/dependency/Cargo.toml"),
            &document,
            ManifestMode::Dependency,
        )
        .unwrap();
        assert_eq!(manifest.links.as_deref(), Some("native"));
        assert!(manifest.build_script.is_some());
        assert_eq!(manifest.dependencies.len(), 3);
        assert_eq!(
            manifest
                .dependencies
                .iter()
                .filter(|dependency| dependency.kind == DependencyKind::Build)
                .count(),
            2
        );
        assert!(
            manifest
                .dependencies
                .iter()
                .all(|dependency| dependency.package != "ignored"
                    && dependency.package != "target-ignored")
        );
        assert_eq!(
            manifest.rust_lints["unexpected_cfgs"].check_cfg,
            ["cfg(custom)"]
        );
        assert!(parsed(source).is_err());
    }

    #[test]
    fn parses_the_seeded_ring_dependency_manifest_when_requested() {
        let Some(repository) = std::env::var_os("LORRY_TEST_SEEDED_REPOSITORY") else {
            return;
        };
        let root = PathBuf::from(repository).join(
            "objects/seeded-git/sha256/77/\
             776e07288265b7ececb54ef5ed914c3a6093f00b49bd4d12d34764325659b351/source",
        );
        let manifest = Manifest::load_path_dependency(&root).unwrap();
        assert_eq!(manifest.name, "ring");
        assert_eq!(manifest.version.original, "0.17.14");
        assert_eq!(manifest.links.as_deref(), Some("ring_core_0_17_14_"));
        assert!(manifest.build_script.is_some());
        assert!(manifest.dependencies.iter().any(
            |dependency| dependency.package == "cc" && dependency.kind == DependencyKind::Build
        ));
        assert!(
            manifest
                .dependencies
                .iter()
                .all(|dependency| dependency.kind != DependencyKind::Dev)
        );
    }

    #[test]
    fn parses_every_retained_stage_two_dependency_manifest_when_requested() {
        let Some(repository) = std::env::var_os("LORRY_TEST_SEEDED_REPOSITORY") else {
            return;
        };
        let objects = PathBuf::from(repository).join("objects/crates-io/sha256");
        let mut parsed = 0;
        for prefix in fs::read_dir(objects).unwrap() {
            for object in fs::read_dir(prefix.unwrap().path()).unwrap() {
                let root = object.unwrap().path().join("source");
                if !root.join("Cargo.toml").is_file() {
                    continue;
                }
                Manifest::load_path_dependency(&root).unwrap_or_else(|error| {
                    panic!("failed to parse `{}`: {error}", root.display())
                });
                parsed += 1;
            }
        }
        assert_eq!(parsed, 45);
    }

    #[test]
    fn loads_lorrys_frozen_stage_two_manifest_and_lock() {
        let root = Path::new(".");
        assert!(root.join("Cargo.toml").is_file());
        let manifest = Manifest::load(root).unwrap();
        assert_eq!(manifest.name, "lorry");
        assert_eq!(manifest.dependencies.len(), 9);
        assert!(manifest.dependencies.iter().any(|dependency| {
            dependency.package == "moto-rt"
                && dependency.target.as_deref() == Some("cfg(target_os = \"motor\")")
                && matches!(dependency.source, DependencySource::Path(_))
        }));
        assert!(manifest.dependencies.iter().any(|dependency| {
            dependency.package == "libc"
                && dependency.target.as_deref() == Some("cfg(target_os = \"linux\")")
                && matches!(dependency.source, DependencySource::CratesIo)
        }));
        assert_eq!(manifest.lock.as_ref().unwrap().packages.len(), 40);
    }

    #[test]
    fn vendor_loading_accepts_a_missing_or_stale_v4_lock() {
        let id = NEXT_VENDOR_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("lorry-vendor-manifest-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"vendor-root\"\nversion = \"0.2.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), "").unwrap();

        assert!(Manifest::load(&root).is_err());
        assert!(Manifest::load_for_vendor(&root).unwrap().lock.is_none());

        fs::write(
            root.join("Cargo.lock"),
            "version = 4\n\n\
             [[package]]\nname = \"vendor-root\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        assert!(Manifest::load(&root).is_err());
        assert_eq!(
            Manifest::load_for_vendor(&root)
                .unwrap()
                .lock
                .unwrap()
                .packages[0]
                .version
                .original,
            "0.1.0"
        );

        fs::write(root.join("Cargo.lock"), "version = 3\n").unwrap();
        assert!(Manifest::load_for_vendor(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn discovers_sorted_direct_integration_test_targets() {
        let id = NEXT_VENDOR_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "lorry-integration-targets-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("tests/nested")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"integration-root\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(
            root.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"integration-root\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), "").unwrap();
        fs::write(root.join("tests/z.rs"), "").unwrap();
        fs::write(root.join("tests/a-b.rs"), "").unwrap();
        fs::write(root.join("tests/readme.txt"), "").unwrap();
        fs::write(root.join("tests/nested/main.rs"), "").unwrap();

        let manifest = Manifest::load(&root).unwrap();
        assert_eq!(
            manifest
                .integration_tests
                .iter()
                .map(|target| target.name.as_str())
                .collect::<Vec<_>>(),
            ["a-b", "z"]
        );
        assert_eq!(
            manifest.integration_tests[0].path,
            root.join("tests/a-b.rs")
        );

        fs::write(root.join("tests/a_b.rs"), "").unwrap();
        assert!(Manifest::load(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_linked_integration_test_entries() {
        use std::os::unix::fs::symlink;

        let id = NEXT_VENDOR_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "lorry-linked-integration-targets-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("tests")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"integration-root\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(
            root.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"integration-root\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), "").unwrap();
        fs::write(root.join("outside.rs"), "").unwrap();
        symlink(root.join("outside.rs"), root.join("tests/linked.rs")).unwrap();

        assert!(Manifest::load(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn accepts_unversioned_relative_and_absolute_path_dependencies() {
        let relative = parsed(&RED.replace(
            "[dependencies]",
            "[dependencies]\nlocal = { path = \"../local\" }",
        ))
        .unwrap();
        assert_eq!(relative.dependencies[0].requirement, VersionReq::STAR);
        assert!(matches!(
            relative.dependencies[0].source,
            DependencySource::Path(_)
        ));

        let absolute = parsed(&RED.replace(
            "[dependencies]",
            "[dependencies]\nlocal = { path = \"/opt/local\" }",
        ))
        .unwrap();
        assert_eq!(
            absolute.dependencies[0].source,
            DependencySource::Path(PathBuf::from("/opt/local"))
        );

        let target = parsed(&RED.replace(
            "[dependencies]",
            "[dependencies]\nfirst = { path = \"../first\" }\n\
                 renamed = { package = \"second\", path = \"/opt/second\" }",
        ))
        .unwrap();
        assert_eq!(target.dependencies.len(), 2);
        assert!(target.dependencies.iter().all(|dependency| {
            dependency.requirement == VersionReq::STAR
                && matches!(dependency.source, DependencySource::Path(_))
        }));
        assert_eq!(target.dependencies[0].package, "first");
        assert_eq!(target.dependencies[1].alias, "renamed");
        assert_eq!(target.dependencies[1].package, "second");
    }

    #[test]
    fn rejects_unknown_and_unsupported_build_semantics() {
        for source in [
            format!("{RED}\n[dev-dependencies]\nhelper = \"1\"\n"),
            RED.replace(
                "[dependencies]",
                "[dependencies]\nthing = { version = \"1\", git = \"https://example.test/x\" }",
            ),
            RED.replace(
                "[dependencies]",
                "[dependencies]\nthing = { package = \"other\" }",
            ),
        ] {
            let error = parsed(&source).unwrap_err();
            assert!(
                error.to_string().contains("supported")
                    || error.to_string().contains("unknown")
                    || error.to_string().contains("missing"),
                "{error}"
            );
        }
    }

    #[test]
    fn parses_a_procedural_macro_library() {
        let root = Path::new("/dependency");
        let path = root.join("Cargo.toml");
        let source = format!("{RED}\n[lib]\nproc-macro = true\n");
        let document = Document::parse(&path, "Cargo manifest", source).unwrap();
        let manifest =
            Manifest::parse_document(root, &path, &document, ManifestMode::Dependency).unwrap();
        assert!(manifest.library.unwrap().proc_macro);

        let error = parsed(&format!("{RED}\n[lib]\nproc-macro = true\n")).unwrap_err();
        assert!(error.to_string().contains("as the root"), "{error}");
    }

    #[test]
    fn rejects_root_target_dev_dependencies_only_for_matching_targets() {
        let source = format!("{RED}\n[target.'cfg(unix)'.dev-dependencies]\nlibc = \"0.2\"\n");
        let manifest = parsed(&source).unwrap();
        let linux = TargetInfo {
            triple: "x86_64-unknown-linux-gnu".to_owned(),
            cfg: CfgSet::parse("target_os=\"linux\"\nunix\n").unwrap(),
        };
        let error = manifest.require_supported_target(&linux).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("target.cfg(unix).dev-dependencies"),
            "{error}"
        );

        let motor = TargetInfo {
            triple: "x86_64-unknown-motor".to_owned(),
            cfg: CfgSet::parse("target_os=\"motor\"\n").unwrap(),
        };
        manifest.require_supported_target(&motor).unwrap();
    }

    #[test]
    fn rejects_malformed_values_duplicates_and_semver() {
        for input in [
            RED.replace("name = \"red\"", "name = \"unterminated"),
            RED.replace("version = \"0.1.0\"", "version = \"1\""),
            RED.replace("edition = \"2024\"", "edition = \"2050\""),
            RED.replace("name = \"red\"", "name = \"red\"\nname = \"again\""),
            RED.replace("codegen-units = 1", "codegen-units = 0"),
        ] {
            assert!(parsed(&input).is_err());
        }
    }

    #[test]
    fn validates_full_version_four_lockfile() {
        let mut manifest =
            parsed(&RED.replace("[dependencies]", "[dependencies]\nserde = \"=1.0.228\"")).unwrap();
        manifest.name = "red".to_owned();
        let valid = r#"
version = 4

[[package]]
name = "red"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "9a8e94ea7f378bd32cbbd37198a4a91436180c5bb472411e48b5ec2e2124ae9e"
"#;
        let lock = validate_lock_source(&manifest, Path::new("Cargo.lock"), valid).unwrap();
        assert_eq!(lock.packages.len(), 2);

        for invalid in [
            valid.replace("version = 4", "version = 3"),
            valid.replace("name = \"red\"", "name = \"other\""),
            valid.replace(
                "registry+https://github.com/rust-lang/crates.io-index",
                "git+https://example.test/repo",
            ),
            format!(
                "{valid}\n[[package]]\nname = \"serde\"\nversion = \"1.0.228\"\nsource = \"{CRATES_IO_SOURCE}\"\nchecksum = \"9a8e94ea7f378bd32cbbd37198a4a91436180c5bb472411e48b5ec2e2124ae9e\"\n"
            ),
        ] {
            assert!(validate_lock_source(&manifest, Path::new("Cargo.lock"), &invalid).is_err());
        }
    }
}
