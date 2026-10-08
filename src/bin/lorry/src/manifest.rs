use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use semver::{Version as SemVersion, VersionReq};
use toml_edit::{Array, InlineTable, Item, Table, Value};

use crate::diagnostic::{Error, Result};
use crate::identity::CargoDebugInfo;
use crate::sparse::DependencyKind;
use crate::toml::Document;

mod inheritance;
pub(crate) mod profiles;
mod selection;
mod source;
mod targets;
pub(crate) use selection::PackageSelection;
pub(crate) use source::{Documents, SourceWorkspace};
pub(crate) use targets::{Target, TargetKind};

const MANIFEST_NAME: &str = "Cargo.toml";
const LOCK_NAME: &str = "Cargo.lock";
const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
const MAX_WORKSPACE_MEMBERS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Manifest {
    pub root: PathBuf,
    /// Selected packages and members may access editable source trees.
    pub editable: bool,
    pub workspace_root: PathBuf,
    /// Workspace members by name, with their canonical directories.
    pub workspace_members: BTreeMap<String, PathBuf>,
    pub path: PathBuf,
    pub warnings: Vec<String>,
    pub name: String,
    pub version: Version,
    pub edition: Edition,
    pub metadata: PackageMetadata,
    pub default_run: Option<String>,
    /// The selected profile; build commands apply it after loading.
    pub profile: Profile,
    pub profile_directory: Option<String>,
    pub profile_name: Option<String>,
    /// Dependencies drop unresolved explicit targets; members reject them.
    unresolved_target: Option<Error>,
    pub resolver: Resolver,
    pub links: Option<String>,
    pub build_script: Option<PathBuf>,
    pub library: Option<LibraryTarget>,
    /// Non-library targets, ordered by kind and then by name.
    pub targets: Vec<Target>,
    pub dependencies: Vec<Dependency>,
    pub features: BTreeMap<String, Vec<String>>,
    pub patches: Vec<Patch>,
    pub rust_lints: BTreeMap<String, Lint>,
    pub clippy_lints: BTreeMap<String, Lint>,
    pub rustdoc_lints: BTreeMap<String, Lint>,
    pub lock: Option<Lockfile>,
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
    pub custom: serde_json::Value,
    pub hints: Option<serde_json::Value>,
    pub authors: Vec<String>,
    pub keywords: Vec<String>,
    pub categories: Vec<String>,
    pub description: String,
    pub homepage: String,
    pub documentation: String,
    pub repository: String,
    pub license: String,
    pub license_file: String,
    pub readme: String,
    pub rust_version: String,
    pub publish: Option<Vec<String>>,
    pub include: Option<Vec<String>>,
    pub exclude: Option<Vec<String>>,
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
    Default,
    None,
    Debuginfo,
    Symbols,
}

/// One resolved Cargo profile; its defaults are those of `dev`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Profile {
    pub panic_abort: bool,
    pub opt_level: &'static str,
    pub debug: Option<CargoDebugInfo>,
    pub lto: Lto,
    pub strip: Strip,
    pub codegen_units: Option<u32>,
    pub debug_assertions: bool,
    pub overflow_checks: bool,
    pub incremental: bool,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            panic_abort: false,
            opt_level: "0",
            debug: None,
            lto: Lto::Default,
            strip: Strip::Default,
            codegen_units: None,
            debug_assertions: true,
            overflow_checks: true,
            incremental: true,
        }
    }
}

#[cfg(test)]
impl Profile {
    pub(crate) fn release() -> Self {
        Self {
            opt_level: "3",
            debug_assertions: false,
            overflow_checks: false,
            incremental: false,
            ..Self::default()
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LibraryTarget {
    pub name: String,
    pub path: PathBuf,
    pub proc_macro: bool,
    pub crate_types: Vec<String>,
    pub test: bool,
    pub bench: bool,
    pub doctest: bool,
    pub doc: bool,
    pub harness: bool,
}

impl LibraryTarget {
    pub(crate) fn requires_upstream_objects(&self) -> bool {
        self.crate_types.iter().any(|kind| {
            matches!(
                kind.as_str(),
                "staticlib" | "dylib" | "cdylib" | "proc-macro"
            )
        })
    }

    pub(crate) fn dynamic(&self) -> bool {
        self.crate_types
            .iter()
            .any(|kind| matches!(kind.as_str(), "dylib" | "cdylib"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dependency {
    pub alias: String,
    pub package: String,
    /// An explicit package key supplies a Cargo alias even if the names agree.
    pub renamed: bool,
    pub requirement: VersionReq,
    pub version_specified: bool,
    pub git_path_source: Option<String>,
    pub source: DependencySource,
    pub optional: bool,
    pub default_features: bool,
    pub features: Vec<String>,
    pub target: Option<String>,
    pub kind: DependencyKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DependencySource {
    CratesIo,
    Path(PathBuf),
    Git(GitDependency),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitDependency {
    pub url: String,
    pub selector: GitSelector,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitSelector {
    Head,
    Branch(String),
    Tag(String),
    Revision(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Patch {
    pub alias: String,
    pub package: String,
    pub source: PatchSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PatchSource {
    Path(PathBuf),
    Git(GitDependency),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lint {
    pub level: String,
    pub priority: i64,
    pub check_cfg: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lockfile {
    pub format: crate::lockfile::Format,
    pub packages: Vec<LockedPackage>,
}

impl Lockfile {
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let document = Document::load(path, "Cargo lockfile")?;
        parse_lock_document(None, path, &document)
    }

    fn require_root(&self, manifest: &Manifest) -> Result<()> {
        let roots = self
            .packages
            .iter()
            .filter(|package| {
                package.name == manifest.name
                    && package.version.original == manifest.version.original
                    && package.source.is_none()
            })
            .count();
        if roots != 1 {
            return Err(Error::failure(format!(
                "Cargo.lock is stale: expected one root path package `{} {}`, found {roots}",
                manifest.name, manifest.version.original
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedPackage {
    pub name: String,
    pub version: Version,
    pub source: Option<String>,
    pub checksum: Option<String>,
    pub dependencies: Vec<String>,
}

impl Manifest {
    /// Cargo's target name for the build script: `build-script-<file stem>`.
    pub fn build_script_name(&self) -> Option<String> {
        let stem = self.build_script.as_ref()?.file_stem()?.to_str()?;
        Some(format!("build-script-{stem}"))
    }

    pub fn report_warnings<'a>(
        manifests: impl IntoIterator<Item = &'a Self>,
        verbosity: crate::cli::Verbosity,
    ) {
        if verbosity == crate::cli::Verbosity::Quiet {
            return;
        }
        let warnings = manifests
            .into_iter()
            .flat_map(|manifest| &manifest.warnings)
            .collect::<BTreeSet<_>>();
        for warning in warnings {
            eprintln!("warning: {warning}");
        }
    }

    pub(crate) fn targets_of(&self, kind: TargetKind) -> impl Iterator<Item = &Target> + Clone {
        self.targets
            .iter()
            .filter(move |target| target.kind == kind)
    }

    pub(crate) fn target(&self, kind: TargetKind, name: &str) -> Option<&Target> {
        self.targets_of(kind).find(|target| target.name == name)
    }

    fn require_member_targets(&self) -> Result<()> {
        self.unresolved_target.clone().map_or(Ok(()), Err)
    }

    // Tests load the one package that a build in `current` selects by default.
    #[cfg(test)]
    pub(crate) fn load_for_build(current: &Path) -> Result<Self> {
        let (_, mut selected) =
            SourceWorkspace::load_compilation(current, None, &PackageSelection::default())?;
        assert_eq!(selected.len(), 1, "test fixture must select one package");
        Ok(selected.pop().unwrap())
    }

    // Vendor sees source-level rules and an optional, possibly stale lock.
    #[cfg(test)]
    pub(crate) fn load_for_vendor(current: &Path) -> Result<Self> {
        let mut workspace = SourceWorkspace::load(current, None)?;
        workspace.load_context(false)?;
        assert_eq!(
            workspace.default_members.len(),
            1,
            "test fixture must select one package"
        );
        let root = workspace.default_members.pop().unwrap();
        Ok(workspace
            .packages
            .into_iter()
            .find(|package| package.root == root)
            .unwrap())
    }

    // A selected member also obeys the build-only rules of a root manifest,
    // checked in parse order on the documents and lock already loaded.
    pub(crate) fn load_compilation_member(
        source: &Self,
        documents: &source::Documents,
    ) -> Result<Self> {
        let path = &source.path;
        let document = documents.load(path, "Cargo workspace member manifest")?;
        let inherited = dependency_workspace_package(&source.root, documents)?;
        let member = inherited
            .as_ref()
            .is_some_and(|workspace| workspace.path != *path);
        validate_manifest_tables(path, &document, ManifestMode::Root, member)?;
        let package = document.root().get("package").and_then(Item::as_table);
        validate_package_keys(path, &document, package.unwrap(), ManifestMode::Root)?;
        let lints = inheritance::lint_table(path, &document, inherited.as_ref())?;
        parse_lint_namespace(lints.as_ref(), ManifestMode::Root, "rust")?;
        let mut manifest = source.clone();
        resolve_target_defaults(&mut manifest, true)?;
        let lock = match manifest.lock.take() {
            Some(lock) => lock,
            None => {
                let lock_path = manifest.workspace_root.join(LOCK_NAME);
                if !lock_path.is_file() {
                    return Err(Error::failure(format!(
                        "required lockfile `{}` is missing",
                        lock_path.display()
                    ))
                    .with_help(
                        "create a version-4 Cargo.lock; build commands never resolve or write it",
                    ));
                }
                Lockfile::load(&lock_path)?
            }
        };
        lock.require_root(&manifest)?;
        manifest.lock = Some(lock);
        Ok(manifest)
    }

    pub fn with_lock_source(mut self, source: String) -> Result<Self> {
        let path = self.root.join(LOCK_NAME);
        let document = Document::parse(&path, "Cargo lockfile", source)?;
        self.lock = Some(parse_lock_document(Some(&self), &path, &document)?);
        Ok(self)
    }

    pub fn load_path_dependency(root: &Path) -> Result<Self> {
        Self::load_path_dependency_in(root, &source::Documents::default())
    }

    pub(crate) fn load_path_dependency_in(
        root: &Path,
        documents: &source::Documents,
    ) -> Result<Self> {
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
        let document = documents.load(&path, "Cargo path dependency manifest")?;
        let inherited = dependency_workspace_package(&root, documents)?;
        let mut manifest = Self::parse_document_with_inheritance(
            &root,
            &path,
            &document,
            ManifestMode::Dependency,
            inherited.as_ref(),
        )?;
        manifest.root = root;
        manifest.path = manifest.root.join(MANIFEST_NAME);
        resolve_target_defaults(&mut manifest, true)?;
        Ok(manifest)
    }

    /// Loads a registry package. It is published with any workspace
    /// inheritance resolved, so unlike a path or Git package it never reads
    /// an enclosing directory's manifest, such as one planted in a shared
    /// temporary directory above an extracted archive.
    pub(crate) fn load_registry_dependency(root: &Path, describe: bool) -> Result<Self> {
        let root = fs::canonicalize(root).map_err(|error| {
            Error::failure(format!(
                "failed to canonicalize registry package `{}`: {error}",
                root.display()
            ))
        })?;
        let path = root.join(MANIFEST_NAME);
        let document = Document::load(&path, "Cargo registry package manifest")?;
        let mode = if describe {
            ManifestMode::Source
        } else {
            ManifestMode::Dependency
        };
        let mut manifest =
            Self::parse_document_with_inheritance(&root, &path, &document, mode, None)?;
        manifest.path = root.join(MANIFEST_NAME);
        resolve_target_defaults(&mut manifest, !describe)?;
        if describe {
            manifest.workspace_root.clone_from(&root);
            manifest.editable = false;
        }
        manifest.root = root;
        Ok(manifest)
    }

    pub(crate) fn load_source_dependency(root: &Path) -> Result<Self> {
        let root = fs::canonicalize(root).map_err(|error| {
            Error::failure(format!(
                "failed to canonicalize source package `{}`: {error}",
                root.display()
            ))
        })?;
        let mut manifest = source::load_package(&root, &root, &source::Documents::default())?;
        manifest.editable = false;
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

    #[cfg(test)]
    fn parse_document(
        root: &Path,
        path: &Path,
        document: &Document,
        mode: ManifestMode,
    ) -> Result<Self> {
        Self::parse_document_with_inheritance(root, path, document, mode, None)
    }

    fn parse_document_with_inheritance(
        root: &Path,
        path: &Path,
        document: &Document,
        mode: ManifestMode,
        inherited: Option<&InheritedPackage>,
    ) -> Result<Self> {
        let member = inherited.is_some_and(|workspace| workspace.path != path);
        validate_manifest_tables(path, document, mode, member)?;
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
        let version_text = required_package_string(
            path,
            document,
            package,
            "version",
            inherited.and_then(|values| values.version.as_deref()),
        )?;
        let version = parse_version(path, item_line(document, package, "version"), &version_text)?;
        let edition = parse_edition(
            path,
            document,
            package.get("edition"),
            document.line_of_table(package),
            inherited.and_then(|values| values.edition.as_deref()),
        )?;
        let resolver = parse_resolver(
            path,
            document,
            package.get("resolver"),
            edition,
            document.line_of_table(package),
        )?;
        let metadata = parse_package_metadata(root, path, document, package, inherited)?;

        let links = optional_string(path, document, package, "package", "links")?;
        let build_script = parse_build_script(path, document, package, root)?;
        let library = parse_library(path, document, root, &name)?;
        let mut warnings = Vec::new();
        let package_targets = targets::Package {
            root,
            path,
            document,
            table: package,
            name: &name,
            edition,
            has_library: library.is_some(),
        };
        let mut targets = Vec::new();
        let mut unresolved_target = None;
        for kind in TargetKind::ALL {
            // Dependency binaries are neither built nor described.
            if kind != TargetKind::Bin || mode != ManifestMode::Dependency {
                targets.extend(targets::parse(
                    &package_targets,
                    kind,
                    &mut warnings,
                    &mut unresolved_target,
                )?);
            }
        }
        let mut dependencies = Vec::new();
        let mut fields = DependencyFields {
            path,
            document,
            root,
            inherited,
            edition,
            warnings: &mut warnings,
        };
        if let Some(item) = document.root().get("dependencies") {
            let table = require_table(path, document, item, "dependencies")?;
            parse_dependency_table(
                &mut fields,
                table,
                None,
                DependencyKind::Normal,
                &mut dependencies,
            )?;
        }
        if let Some(item) = document.root().get("build-dependencies") {
            let table = require_table(path, document, item, "build-dependencies")?;
            parse_dependency_table(
                &mut fields,
                table,
                None,
                DependencyKind::Build,
                &mut dependencies,
            )?;
        }
        validate_ignored_dev_dependencies(path, document)?;
        if mode != ManifestMode::Dependency
            && let Some(item) = document.root().get("dev-dependencies")
        {
            let table = require_table(path, document, item, "dev-dependencies")?;
            parse_dependency_table(
                &mut fields,
                table,
                None,
                DependencyKind::Dev,
                &mut dependencies,
            )?;
        }
        parse_target_dependencies(&mut fields, mode, &mut dependencies)?;
        let features = parse_features(path, document)?;
        let patches = if mode == ManifestMode::Root && !member {
            parse_patches(path, document, root)?
        } else {
            Vec::new()
        };
        let lint_table = inheritance::lint_table(path, document, inherited)?;
        let rust_lints = parse_lint_namespace(lint_table.as_ref(), mode, "rust")?;
        let clippy_lints = parse_lint_namespace(lint_table.as_ref(), mode, "clippy")?;
        let rustdoc_lints = parse_lint_namespace(lint_table.as_ref(), mode, "rustdoc")?;
        if mode == ManifestMode::Root && !member {
            profiles::validate(path, document)?;
        }

        Ok(Self {
            root: root.to_path_buf(),
            workspace_root: root.to_path_buf(),
            editable: mode != ManifestMode::Dependency,
            workspace_members: std::iter::once((name.clone(), root.to_path_buf())).collect(),
            path: path.to_path_buf(),
            warnings,
            name,
            version,
            edition,
            metadata,
            default_run: optional_string(path, document, package, "package", "default-run")?,
            profile: Profile::default(),
            unresolved_target,
            profile_directory: None,
            profile_name: None,
            resolver,
            links,
            build_script,
            library,
            targets,
            dependencies,
            features,
            patches,
            rust_lints,
            clippy_lints,
            rustdoc_lints,
            lock: None,
        })
    }
}

fn discover_manifest(current: &Path, manifest_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = manifest_path {
        return canonical_manifest(&current.join(path));
    }
    let current = fs::canonicalize(current).map_err(|error| {
        Error::failure(format!(
            "failed to canonicalize invocation directory `{}`: {error}",
            current.display()
        ))
    })?;
    for directory in current.ancestors() {
        let path = directory.join(MANIFEST_NAME);
        if path.is_file() {
            return canonical_manifest(&path);
        }
    }
    Err(Error::failure(format!(
        "could not find Cargo.toml in `{}` or any parent directory",
        current.display()
    )))
}

fn canonical_manifest(manifest_path: &Path) -> Result<PathBuf> {
    let path = fs::canonicalize(manifest_path).map_err(|error| {
        Error::failure(format!(
            "failed to canonicalize manifest path `{}`: {error}",
            manifest_path.display()
        ))
    })?;
    if path.file_name().and_then(|name| name.to_str()) != Some(MANIFEST_NAME) {
        return Err(Error::failure(format!(
            "manifest path `{}` does not name Cargo.toml",
            manifest_path.display()
        )));
    }
    Ok(path)
}

fn validate_virtual_workspace(path: &Path, document: &Document) -> Result<()> {
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
    Ok(())
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
    {
        return Err(Error::at(
            path,
            document.line_of_item(document.root().get("workspace").unwrap()),
            format!("unsupported workspace member path `{member}`"),
            "use a descendant path without `..`",
        ));
    }
    let declared = root.join(candidate);
    let canonical = fs::canonicalize(&declared).map_err(|error| {
        Error::failure(format!(
            "failed to resolve workspace member `{}`: {error}",
            declared.display()
        ))
    })?;
    if !canonical.starts_with(root) {
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
    Source,
}

struct InheritedPackage {
    version: Option<String>,
    edition: Option<String>,
    rust_version: Option<String>,
    path: PathBuf,
    document: std::rc::Rc<Document>,
}

fn dependency_workspace_package(
    root: &Path,
    documents: &source::Documents,
) -> Result<Option<InheritedPackage>> {
    let Some(workspace) = source::nearest_workspace(root, documents)? else {
        return Ok(None);
    };
    let path = workspace.root.join(MANIFEST_NAME);
    let document = workspace.document;
    let table = require_table(
        &path,
        &document,
        document.root().get("workspace").unwrap(),
        "workspace",
    )?;
    let package = table
        .get("package")
        .map(|item| require_table(&path, &document, item, "workspace.package"))
        .transpose()?;
    let field = |key| {
        package
            .map(|package| optional_string(&path, &document, package, "workspace.package", key))
            .transpose()
            .map(Option::flatten)
    };
    Ok(Some(InheritedPackage {
        version: field("version")?,
        edition: field("edition")?,
        rust_version: field("rust-version")?,
        path,
        document,
    }))
}

fn workspace_resolver(
    root: &Path,
    path: &Path,
    document: &Document,
    documents: &source::Documents,
) -> Result<Resolver> {
    let workspace = require_table(
        path,
        document,
        document.root().get("workspace").unwrap(),
        "workspace",
    )?;
    if let Some(item) = workspace.get("resolver") {
        return parse_resolver(path, document, Some(item), Edition::E2015, 1);
    }
    let Some(item) = document.root().get("package") else {
        return Ok(Resolver::V1);
    };
    let package = require_table(path, document, item, "package")?;
    let inherited = dependency_workspace_package(root, documents)?;
    let edition = parse_edition(
        path,
        document,
        package.get("edition"),
        1,
        inherited
            .as_ref()
            .and_then(|values| values.edition.as_deref()),
    )?;
    parse_resolver(path, document, package.get("resolver"), edition, 1)
}

fn workspace_metadata(document: &Document) -> serde_json::Value {
    document
        .root()
        .get("workspace")
        .and_then(Item::as_table)
        .and_then(|workspace| workspace.get("metadata"))
        .map(crate::toml::json)
        .unwrap_or_default()
}

fn validate_manifest_tables(
    path: &Path,
    document: &Document,
    mode: ManifestMode,
    member: bool,
) -> Result<()> {
    for (key, item) in document.root().iter() {
        let supported = (member && key == "replace")
            || matches!(
                (mode, key),
                (
                    ManifestMode::Root,
                    "package"
                        | "dependencies"
                        | "build-dependencies"
                        | "dev-dependencies"
                        | "target"
                        | "features"
                        | "patch"
                        | "profile"
                        | "lib"
                        | "bin"
                        | "test"
                        | "example"
                        | "bench"
                        | "badges"
                        | "lints"
                        | "workspace"
                ) | (
                    // Source descriptions accept every table that a dependency may
                    // use, which includes every table of a root package.
                    ManifestMode::Dependency | ManifestMode::Source,
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
                        | "patch"
                )
            );
        if !supported {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("unsupported manifest table or key `{key}`"),
                "remove it; Lorry does not support its build semantics",
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
        "autolib",
        "autobins",
        "autotests",
        "autoexamples",
        "autobenches",
        "metadata",
    ];
    let dependency = matches!(mode, ManifestMode::Dependency | ManifestMode::Source);
    for (key, item) in package.iter() {
        if !ROOT_ALLOWED.contains(&key) && !(dependency && key == "links") {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("unsupported manifest key `package.{key}`"),
                "remove the key; Lorry does not support its build semantics",
            ));
        }
    }
    for key in [
        "autolib",
        "autobins",
        "autotests",
        "autoexamples",
        "autobenches",
    ] {
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
    if dependency
        && let Some(item) = package.get("links")
        && item.as_str().is_none()
    {
        return Err(type_error(
            path,
            document.line_of_item(item),
            "package.links",
            "a string",
        ));
    }
    Ok(())
}

fn parse_package_metadata(
    root: &Path,
    path: &Path,
    document: &Document,
    package: &Table,
    inherited: Option<&InheritedPackage>,
) -> Result<PackageMetadata> {
    let fields = inheritance::PackageFields::new(path, document, package, inherited);
    Ok(PackageMetadata {
        hints: document.root().get("hints").map(|item| {
            let table = require_table(path, document, item, "hints")?;
            Ok::<_, Error>(serde_json::json!({"mostly-unused": table.get("mostly-unused").map(crate::toml::json).unwrap_or_default()}))
        }).transpose()?,
        custom: package
            .get("metadata")
            .map(crate::toml::json)
            .unwrap_or_default(),
        authors: fields.array("authors")?.unwrap_or_default(),
        keywords: fields.array("keywords")?.unwrap_or_default(),
        categories: fields.array("categories")?.unwrap_or_default(),
        description: fields.string("description")?.unwrap_or_default(),
        homepage: fields.string("homepage")?.unwrap_or_default(),
        documentation: fields.string("documentation")?.unwrap_or_default(),
        repository: fields.string("repository")?.unwrap_or_default(),
        license: fields.string("license")?.unwrap_or_default(),
        license_file: fields.file("license-file", root)?,
        readme: fields.readme(root)?,
        rust_version: optional_package_string(
            path,
            document,
            package,
            "rust-version",
            inherited.and_then(|values| values.rust_version.as_deref()),
        )?
        .unwrap_or_default(),
        publish: fields.publish()?,
        include: fields.array("include")?,
        exclude: fields.array("exclude")?,
    })
}

fn parse_edition(
    path: &Path,
    document: &Document,
    item: Option<&Item>,
    default_line: usize,
    inherited: Option<&str>,
) -> Result<Edition> {
    let Some(item) = item else {
        return Ok(Edition::E2015);
    };
    let line = document.line_of_item(item).max(default_line);
    let value = inherited_package_value(path, document, item, "edition", inherited)?;
    match value.as_deref() {
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
            if Path::new(value).file_stem().is_none() {
                return Err(Error::at(
                    path,
                    document.line_of_item(item),
                    "`package.build` must name a file",
                    "use the path of the build script's source file",
                ));
            }
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
) -> Result<Option<LibraryTarget>> {
    let Some(item) = document.root().get("lib") else {
        if document
            .root()
            .get("package")
            .and_then(Item::as_table)
            .and_then(|package| package.get("autolib"))
            .and_then(Item::as_bool)
            == Some(false)
        {
            return Ok(None);
        }
        return Ok(root.join("src/lib.rs").is_file().then(|| LibraryTarget {
            name: package_name.replace('-', "_"),
            path: root.join("src/lib.rs"),
            proc_macro: false,
            crate_types: vec!["lib".to_owned()],
            test: true,
            bench: true,
            doctest: true,
            doc: true,
            harness: true,
        }));
    };
    let table = require_table(path, document, item, "lib")?;
    for (key, item) in table.iter() {
        if !matches!(
            key,
            "name"
                | "path"
                | "test"
                | "doctest"
                | "crate-type"
                | "bench"
                | "doc"
                | "proc-macro"
                | "doc-scrape-examples"
                | "harness"
        ) {
            return Err(unsupported_key(path, document, item, &format!("lib.{key}")));
        }
        if matches!(key, "bench" | "doc" | "doc-scrape-examples") && item.as_bool().is_none() {
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
    let declared_crate_types = table
        .get("crate-type")
        .map(|item| string_array(path, document, item, "lib.crate-type"))
        .transpose()?;
    if let Some(values) = &declared_crate_types
        && (values.is_empty()
            || values.iter().any(|value| {
                !matches!(
                    value.as_str(),
                    "lib" | "rlib" | "staticlib" | "dylib" | "cdylib"
                )
            }))
    {
        return Err(Error::at(
            path,
            document.line_of_item(table.get("crate-type").unwrap()),
            "custom library crate types are not supported",
            "use a supported Rust library crate type",
        ));
    }
    if let Some(types) = &declared_crate_types
        && types.iter().any(|kind| kind == "dylib")
        && types.iter().any(|kind| kind == "cdylib")
    {
        return Err(Error::failure(
            "library cannot set both `dylib` and `cdylib` crate types",
        ));
    }
    let proc_macro = optional_bool(path, document, table, "lib", "proc-macro")?.unwrap_or(false);
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
    let crate_types = if proc_macro {
        vec!["proc-macro".to_owned()]
    } else {
        declared_crate_types.unwrap_or_else(|| vec!["lib".to_owned()])
    };
    let doctestable = crate_types
        .iter()
        .any(|kind| matches!(kind.as_str(), "lib" | "rlib" | "proc-macro"));
    Ok(Some(LibraryTarget {
        name,
        path: root.join(relative),
        proc_macro,
        crate_types,
        test: optional_bool(path, document, table, "lib", "test")?.unwrap_or(true),
        bench: optional_bool(path, document, table, "lib", "bench")?.unwrap_or(true),
        doctest: optional_bool(path, document, table, "lib", "doctest")?.unwrap_or(true)
            && doctestable,
        doc: optional_bool(path, document, table, "lib", "doc")?.unwrap_or(true),
        harness: optional_bool(path, document, table, "lib", "harness")?.unwrap_or(true),
    }))
}

fn resolve_target_defaults(manifest: &mut Manifest, check_sources: bool) -> Result<()> {
    if check_sources
        && let Some(library) = &manifest.library
        && !library.path.is_file()
    {
        return Err(Error::failure(format!(
            "library target `{}` does not exist",
            library.path.display()
        )));
    }
    for target in &manifest.targets {
        // Missing example and bench sources fail only when compiled.
        if check_sources
            && manifest.editable
            && matches!(target.kind, TargetKind::Bin | TargetKind::Test)
            && !target.path.is_file()
        {
            return Err(Error::failure(format!(
                "{} target `{}` does not exist",
                target.kind.description(),
                target.path.display()
            )));
        }
    }
    if manifest.library.is_none()
        && manifest
            .targets
            .iter()
            .all(|target| target.kind == TargetKind::Test)
    {
        return Err(Error::failure(format!(
            "package `{}` has no supported library or binary target",
            manifest.name
        ))
        .with_help("add `src/lib.rs`, `src/main.rs`, or one supported `[[bin]]`"));
    }
    if let Some(default) = &manifest.default_run
        && manifest.target(TargetKind::Bin, default).is_none()
    {
        return Err(Error::failure(format!(
            "package.default-run names unknown binary target `{default}`"
        ))
        .with_help("choose one of the package's binary target names"));
    }
    Ok(())
}

struct DependencyFields<'a> {
    path: &'a Path,
    document: &'a Document,
    root: &'a Path,
    inherited: Option<&'a InheritedPackage>,
    edition: Edition,
    warnings: &'a mut Vec<String>,
}

fn parse_dependency_table(
    fields: &mut DependencyFields<'_>,
    table: &Table,
    target: Option<&str>,
    kind: DependencyKind,
    output: &mut Vec<Dependency>,
) -> Result<()> {
    for (alias, item) in table.iter() {
        validate_package_name(fields.path, fields.document.line_of_item(item), alias)?;
        output.push(parse_dependency(fields, alias, item, target, kind)?);
    }
    Ok(())
}

fn parse_dependency(
    fields: &mut DependencyFields<'_>,
    alias: &str,
    item: &Item,
    target: Option<&str>,
    kind: DependencyKind,
) -> Result<Dependency> {
    let path = fields.path;
    let document = fields.document;
    let root = fields.root;
    if let Some(requirement) = item.as_str() {
        return Ok(Dependency {
            alias: alias.to_owned(),
            package: alias.to_owned(),
            renamed: false,
            requirement: parse_requirement(path, document.line_of_item(item), alias, requirement)?,
            version_specified: true,
            git_path_source: None,
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
    if lookup.get("workspace").is_some() {
        return inheritance::dependency(fields, alias, &lookup, line, target, kind);
    }
    const ALLOWED: &[&str] = &[
        "version",
        "path",
        "git",
        "branch",
        "tag",
        "rev",
        "package",
        "optional",
        "default-features",
        "default_features",
        "features",
    ];
    for (key, value) in lookup.entries() {
        if !ALLOWED.contains(&key) {
            let unsupported = if matches!(
                key,
                "registry" | "registry-index" | "workspace" | "artifact" | "lib"
            ) {
                format!("dependency source or mode `{key}` is not supported")
            } else {
                format!("unknown dependency key `{key}`")
            };
            return Err(Error::at(
                path,
                value.line(document),
                unsupported,
                "use a crates.io version, Git source, or local path dependency",
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
    let path_source = lookup.get("path");
    let git_source = lookup.get("git");
    if path_source.is_some() && git_source.is_some() {
        return Err(Error::at(
            path,
            line,
            format!("dependency `{alias}` declares both path and Git sources"),
            "choose exactly one dependency source",
        ));
    }
    let source = match (path_source, git_source) {
        (Some(value), None) => {
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
        (None, Some(value)) => {
            let url = value.as_str().ok_or_else(|| {
                type_error(
                    path,
                    value.line(document),
                    &format!("dependencies.{alias}.git"),
                    "a string",
                )
            })?;
            validate_git_url(path, value.line(document), url)?;
            let selectors = ["branch", "tag", "rev"]
                .into_iter()
                .filter_map(|key| lookup.get(key).map(|value| (key, value)))
                .collect::<Vec<_>>();
            if selectors.len() > 1 {
                return Err(Error::at(
                    path,
                    line,
                    format!("Git dependency `{alias}` selects more than one revision"),
                    "use only one of branch, tag, or rev",
                ));
            }
            let selector = match selectors.as_slice() {
                [] => GitSelector::Head,
                [(key, value)] => {
                    let revision = value.as_str().ok_or_else(|| {
                        type_error(
                            path,
                            value.line(document),
                            &format!("dependencies.{alias}.{key}"),
                            "a string",
                        )
                    })?;
                    validate_git_revision(path, value.line(document), revision)?;
                    match *key {
                        "branch" => GitSelector::Branch(revision.to_owned()),
                        "tag" => GitSelector::Tag(revision.to_owned()),
                        "rev" => GitSelector::Revision(revision.to_owned()),
                        _ => unreachable!(),
                    }
                }
                _ => unreachable!(),
            };
            DependencySource::Git(GitDependency {
                url: url.to_owned(),
                selector,
            })
        }
        (None, None) => DependencySource::CratesIo,
        (Some(_), Some(_)) => unreachable!(),
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
        None if matches!(source, DependencySource::Path(_) | DependencySource::Git(_)) => {
            VersionReq::STAR
        }
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
        renamed: lookup.get("package").is_some(),
        requirement,
        version_specified: lookup.get("version").is_some(),
        git_path_source: None,
        source,
        optional: lookup_bool(path, document, &lookup, alias, "optional")?.unwrap_or(false),
        default_features: dependency_default_features(fields, &lookup, alias)?.unwrap_or(true),
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

fn dependency_default_features(
    fields: &mut DependencyFields<'_>,
    lookup: &DependencyTable<'_>,
    alias: &str,
) -> Result<Option<bool>> {
    let modern = lookup_bool(
        fields.path,
        fields.document,
        lookup,
        alias,
        "default-features",
    )?;
    let legacy = lookup_bool(
        fields.path,
        fields.document,
        lookup,
        alias,
        "default_features",
    )?;
    if legacy.is_some() {
        if fields.edition == Edition::E2024 {
            return Err(Error::at(
                fields.path,
                lookup
                    .get("default_features")
                    .unwrap()
                    .line(fields.document),
                format!(
                    "`default_features` is unsupported as of the 2024 edition (in the `{alias}` dependency)"
                ),
                "use `default-features` instead",
            ));
        }
        let message = if modern.is_some() {
            format!(
                "`default_features` is redundant with `default-features`, preferring `default-features` in the `{alias}` dependency"
            )
        } else {
            format!(
                "`default_features` is deprecated in favor of `default-features` and will not work in the 2024 edition (in the `{alias}` dependency)"
            )
        };
        fields
            .warnings
            .push(format!("{}: {message}", fields.path.display()));
    }
    Ok(modern.or(legacy))
}

fn validate_git_url(path: &Path, line: usize, url: &str) -> Result<()> {
    if !url.starts_with("https://")
        || !url.is_ascii()
        || url
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
        || url.contains(['#', '?'])
        || url[8..].contains('@')
    {
        return Err(Error::at(
            path,
            line,
            format!("Git URL `{url}` is not a canonical anonymous HTTPS URL"),
            "use an anonymous https:// URL without a query or fragment",
        ));
    }
    Ok(())
}

fn validate_git_revision(path: &Path, line: usize, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 1024
        || value.starts_with('-')
        || value.bytes().any(|byte| byte.is_ascii_control())
        || value.contains("..")
        || value.contains(['~', '^', ':', '?', '*', '[', '\\', ' '])
        || value.ends_with(['.', '/'])
        || value.contains("@{")
    {
        return Err(Error::at(
            path,
            line,
            format!("Git revision `{value}` is not safe"),
            "use a branch, tag, or revision without Git revision operators",
        ));
    }
    Ok(())
}

fn parse_target_dependencies(
    fields: &mut DependencyFields<'_>,
    mode: ManifestMode,
    output: &mut Vec<Dependency>,
) -> Result<()> {
    let path = fields.path;
    let document = fields.document;
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
                (_, "build-dependencies") => Some(DependencyKind::Build),
                (ManifestMode::Root | ManifestMode::Source, "dev-dependencies") => {
                    Some(DependencyKind::Dev)
                }
                (ManifestMode::Dependency, "dev-dependencies") => None,
                _ => {
                    return Err(Error::at(
                        path,
                        document.line_of_item(item),
                        format!("unsupported manifest key `target.{selector}.{key}`"),
                        "use dependencies, build-dependencies, or dev-dependencies",
                    ));
                }
            };
            let dependencies =
                require_table(path, document, item, &format!("target.{selector}.{key}"))?;
            if let Some(kind) = kind {
                parse_dependency_table(fields, dependencies, Some(selector), kind, output)?;
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

fn parse_patches(path: &Path, document: &Document, root: &Path) -> Result<Vec<Patch>> {
    let Some(item) = document.root().get("patch") else {
        return Ok(Vec::new());
    };
    let patch = require_table(path, document, item, "patch")?;
    for (source, item) in patch.iter() {
        if source != "crates-io" {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("patch source `{source}` is not supported"),
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
        validate_package_name(path, document.line_of_item(item), alias)?;
        let table = item.as_inline_table().ok_or_else(|| {
            type_error(
                path,
                document.line_of_item(item),
                &format!("patch.crates-io.{alias}"),
                "an inline path or Git table",
            )
        })?;
        let package = match table.get("package") {
            Some(value) => value.as_str().ok_or_else(|| {
                type_error(
                    path,
                    document.line_of_value(value),
                    &format!("patch.crates-io.{alias}.package"),
                    "a string",
                )
            })?,
            None => alias,
        };
        validate_package_name(path, document.line_of_item(item), package)?;

        let source = match (table.get("path"), table.get("git")) {
            (Some(_), Some(_)) => {
                return Err(Error::at(
                    path,
                    document.line_of_item(item),
                    format!("patch `{alias}` declares both path and Git sources"),
                    "choose exactly one patch source",
                ));
            }
            (Some(value), None) => {
                for (key, value) in table.iter() {
                    if !matches!(key, "path" | "package") {
                        return Err(Error::at(
                            path,
                            document.line_of_value(value),
                            format!("path patch `{alias}` contains unsupported key `{key}`"),
                            "use only path and optional package",
                        ));
                    }
                }
                let declared = value.as_str().ok_or_else(|| {
                    type_error(
                        path,
                        document.line_of_value(value),
                        &format!("patch.crates-io.{alias}.path"),
                        "a string",
                    )
                })?;
                validate_dependency_path(
                    path,
                    document.line_of_value(value),
                    &format!("patch.crates-io.{alias}.path"),
                    declared,
                )?;
                PatchSource::Path(resolve_declared_path(root, declared))
            }
            (None, Some(value)) => {
                for (key, value) in table.iter() {
                    if !matches!(key, "git" | "branch" | "tag" | "rev" | "package") {
                        return Err(Error::at(
                            path,
                            document.line_of_value(value),
                            format!("Git patch `{alias}` contains unsupported key `{key}`"),
                            "use only git, one optional branch/tag/rev, and optional package",
                        ));
                    }
                }
                let url = value.as_str().ok_or_else(|| {
                    type_error(
                        path,
                        document.line_of_value(value),
                        &format!("patch.crates-io.{alias}.git"),
                        "a string",
                    )
                })?;
                validate_git_url(path, document.line_of_value(value), url)?;
                let selectors = ["branch", "tag", "rev"]
                    .into_iter()
                    .filter_map(|key| table.get(key).map(|value| (key, value)))
                    .collect::<Vec<_>>();
                if selectors.len() > 1 {
                    return Err(Error::at(
                        path,
                        document.line_of_item(item),
                        format!("Git patch `{alias}` selects more than one revision"),
                        "use only one of branch, tag, or rev",
                    ));
                }
                let selector = match selectors.as_slice() {
                    [] => GitSelector::Head,
                    [(key, value)] => {
                        let revision = value.as_str().ok_or_else(|| {
                            type_error(
                                path,
                                document.line_of_value(value),
                                &format!("patch.crates-io.{alias}.{key}"),
                                "a string",
                            )
                        })?;
                        validate_git_revision(path, document.line_of_value(value), revision)?;
                        match *key {
                            "branch" => GitSelector::Branch(revision.to_owned()),
                            "tag" => GitSelector::Tag(revision.to_owned()),
                            "rev" => GitSelector::Revision(revision.to_owned()),
                            _ => unreachable!(),
                        }
                    }
                    _ => unreachable!(),
                };
                PatchSource::Git(GitDependency {
                    url: url.to_owned(),
                    selector,
                })
            }
            (None, None) => {
                return Err(Error::at(
                    path,
                    document.line_of_item(item),
                    format!("patch `{alias}` is missing a source"),
                    "add exactly one path or git key",
                ));
            }
        };
        result.push(Patch {
            alias: alias.to_owned(),
            package: package.to_owned(),
            source,
        });
    }
    Ok(result)
}

fn parse_lint_namespace(
    field: Option<&inheritance::Field<'_>>,
    mode: ManifestMode,
    namespace: &str,
) -> Result<BTreeMap<String, Lint>> {
    let Some(field) = field else {
        return Ok(BTreeMap::new());
    };
    let path = field.path;
    let document = field.document;
    let lints = require_table(path, document, field.item, "lints")?;
    for (key, item) in lints.iter() {
        if !matches!(key, "rust" | "clippy" | "rustdoc" | "workspace") && mode == ManifestMode::Root
        {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("lint namespace `lints.{key}` is not supported"),
                "configure lints under rust, clippy, or rustdoc namespaces",
            ));
        }
    }
    let Some(item) = lints.get(namespace) else {
        return Ok(BTreeMap::new());
    };
    let table = require_table(path, document, item, &format!("lints.{namespace}"))?;
    let mut result = BTreeMap::new();
    for (name, item) in table.iter() {
        if name.contains("::") {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("`lints.{namespace}.{name}` is not a valid lint name"),
                "use an unqualified lint name in its namespace table",
            ));
        }
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
                if !matches!(key, "level" | "priority")
                    && !(key == "check-cfg" && namespace == "rust")
                {
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
                                &format!("lints.{namespace}.{name}.priority"),
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
                                &format!("lints.{namespace}.{name}.check-cfg"),
                                "an array of strings",
                            )
                        })?,
                        &format!("lints.{namespace}.{name}.check-cfg"),
                    )?,
                    None => Vec::new(),
                },
            }
        } else {
            return Err(type_error(
                path,
                document.line_of_item(item),
                &format!("lints.{namespace}.{name}"),
                "a level string or inline table",
            ));
        };
        result.insert(name.to_owned(), lint);
    }
    Ok(result)
}

fn parse_profile(
    path: &Path,
    document: &Document,
    table: &Table,
    profile: &str,
    default_opt: &'static str,
) -> Result<Profile> {
    let panic_abort = parse_panic_abort(path, document, table, profile)?;
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
                format!("unsupported value for `{profile}.lto`"),
                "choose false, true, `fat`, `thin`, or `off`",
            ));
        }
    };
    let strip = match table.get("strip") {
        None => Strip::Default,
        Some(item) if item.as_bool() == Some(false) => Strip::None,
        Some(item) if item.as_bool() == Some(true) => Strip::Symbols,
        Some(item) if item.as_str() == Some("none") => Strip::None,
        Some(item) if item.as_str() == Some("debuginfo") => Strip::Debuginfo,
        Some(item) if item.as_str() == Some("symbols") => Strip::Symbols,
        Some(item) => {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("unsupported value for `{profile}.strip`"),
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
                    format!(
                        "`{profile}.codegen-units` must be an integer from 1 through 4294967295"
                    ),
                    "use a positive codegen unit count",
                ));
            }
        },
    };
    Ok(Profile {
        opt_level: parse_opt_level(path, document, table, profile, default_opt)?,
        debug: parse_profile_debug(path, document, table, profile)?,
        panic_abort,
        lto,
        strip,
        codegen_units,
        debug_assertions: optional_bool(path, document, table, profile, "debug-assertions")?
            .unwrap_or(default_opt == "0"),
        overflow_checks: optional_bool(path, document, table, profile, "overflow-checks")?
            .unwrap_or(default_opt == "0"),
        incremental: optional_bool(path, document, table, profile, "incremental")?
            .unwrap_or(default_opt == "0"),
    })
}

fn parse_opt_level(
    path: &Path,
    document: &Document,
    table: &Table,
    profile: &str,
    default: &'static str,
) -> Result<&'static str> {
    let Some(item) = table.get("opt-level") else {
        return Ok(default);
    };
    let text = item
        .as_integer()
        .map(|value| value.to_string())
        .or_else(|| {
            item.as_str()
                .filter(|value| matches!(*value, "s" | "z"))
                .map(str::to_owned)
        });
    match text.as_deref() {
        Some("0") => Ok("0"),
        Some("1") => Ok("1"),
        Some("2") => Ok("2"),
        Some("3") => Ok("3"),
        Some("s") => Ok("s"),
        Some("z") => Ok("z"),
        _ => Err(Error::at(
            path,
            document.line_of_item(item),
            format!("unsupported `{profile}.opt-level`"),
            "choose 0, 1, 2, 3, `s`, or `z`",
        )),
    }
}

fn parse_profile_debug(
    path: &Path,
    document: &Document,
    table: &Table,
    profile: &str,
) -> Result<Option<CargoDebugInfo>> {
    let Some(item) = table.get("debug") else {
        return Ok(None);
    };
    let text = item
        .as_bool()
        .map(|value| if value { "full" } else { "none" })
        .or_else(|| {
            item.as_integer().and_then(|value| match value {
                0 => Some("none"),
                1 => Some("limited"),
                2 => Some("full"),
                _ => None,
            })
        })
        .or_else(|| item.as_str());
    let value = match text {
        Some("none") => CargoDebugInfo::None,
        Some("limited") => CargoDebugInfo::Limited,
        Some("full") => CargoDebugInfo::Full,
        Some("line-tables-only") => CargoDebugInfo::LineTablesOnly,
        Some("line-directives-only") => CargoDebugInfo::LineDirectivesOnly,
        _ => {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("unsupported `{profile}.debug`"),
                "choose false, true, 0, 1, 2, `none`, `limited`, `full`, `line-tables-only`, or `line-directives-only`",
            ));
        }
    };
    Ok(Some(value))
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
    parse_lock_document(Some(manifest), path, &document)
}

fn parse_lock_document(
    manifest: Option<&Manifest>,
    path: &Path,
    document: &Document,
) -> Result<Lockfile> {
    for (key, item) in document.root().iter() {
        if !matches!(key, "version" | "package" | "metadata") {
            return Err(Error::at(
                path,
                document.line_of_item(item),
                format!("unsupported root Cargo.lock key `{key}`"),
                "use a supported Cargo.lock format",
            ));
        }
    }
    let mut format = match document.root().get("version") {
        None => crate::lockfile::Format::V1,
        Some(version) if version.as_integer() == Some(3) => crate::lockfile::Format::V3,
        Some(version) if version.as_integer() == Some(4) => crate::lockfile::Format::V4,
        Some(version) => {
            return Err(Error::at(
                path,
                document.line_of_item(version),
                "unsupported Cargo.lock format; expected `version = 3` or `version = 4`, or a legacy lock without a version field",
                "regenerate the lockfile with a current Cargo",
            ));
        }
    };
    let metadata = document
        .root()
        .get("metadata")
        .map(|item| require_table(path, document, item, "metadata"))
        .transpose()?;
    let tables = document
        .root()
        .get("package")
        .map(|package_item| {
            package_item.as_array_of_tables().ok_or_else(|| {
                type_error(
                    path,
                    document.line_of_item(package_item),
                    "package",
                    "an array of tables",
                )
            })
        })
        .transpose()?;
    let mut packages = Vec::new();
    let mut identities = BTreeSet::new();
    for table in tables.into_iter().flat_map(|tables| tables.iter()) {
        for (key, item) in table.iter() {
            if !matches!(
                key,
                "name" | "version" | "source" | "checksum" | "dependencies"
            ) {
                return Err(Error::at(
                    path,
                    document.line_of_item(item),
                    format!("unsupported Cargo.lock package key `{key}`"),
                    "use only supported Cargo.lock package identity and dependency fields",
                ));
            }
        }
        let name = required_string(path, document, table, "package", "name")?;
        validate_package_name(path, document.line_of_table(table), &name)?;
        let version_text = required_string(path, document, table, "package", "version")?;
        let version = parse_version(path, item_line(document, table, "version"), &version_text)?;
        let source = optional_string(path, document, table, "package", "source")?;
        if source.as_deref().is_some_and(|value| {
            value != CRATES_IO_SOURCE && crate::git::parse_locked_source(value).is_err()
        }) {
            return Err(Error::at(
                path,
                item_line(document, table, "source"),
                format!(
                    "unsupported Cargo.lock source `{}`",
                    source.as_deref().unwrap()
                ),
                "use crates.io, a canonical pinned anonymous HTTPS Git source, or a local path package",
            ));
        }
        let mut checksum = optional_string(path, document, table, "package", "checksum")?;
        if checksum.is_some() && format == crate::lockfile::Format::V1 {
            format = crate::lockfile::Format::V2;
        }
        if let Some(source) = &source
            && checksum.is_none()
            && let Some(metadata) = metadata
        {
            let key = format!(
                "checksum {name} {version_text} ({})",
                crate::lockfile::encode_source(source, crate::lockfile::Format::V1, false)?
            );
            if let Some(item) = metadata.get(&key) {
                let value = item.as_str().ok_or_else(|| {
                    type_error(path, document.line_of_item(item), &key, "a checksum string")
                })?;
                if value != "<none>" {
                    checksum = Some(value.to_owned());
                }
            }
        }
        match (&source, &checksum) {
            (Some(_), Some(value)) if is_sha256(value) => {}
            (Some(source), None) if crate::git::parse_locked_source(source).is_ok() => {}
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
        if format == crate::lockfile::Format::V1
            && dependencies
                .iter()
                .any(|reference| reference.split_whitespace().nth(1).is_none())
        {
            format = crate::lockfile::Format::V2;
        }
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
    let lock = Lockfile { format, packages };
    if let Some(manifest) = manifest {
        lock.require_root(manifest)?;
    }
    Ok(lock)
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

fn required_package_string(
    path: &Path,
    document: &Document,
    package: &Table,
    key: &str,
    inherited: Option<&str>,
) -> Result<String> {
    optional_package_string(path, document, package, key, inherited)?.ok_or_else(|| {
        Error::at(
            path,
            document.line_of_table(package),
            format!("table `[package]` is missing required string `{key}`"),
            format!("add `{key} = \"...\"` to `[package]`"),
        )
    })
}

fn optional_package_string(
    path: &Path,
    document: &Document,
    package: &Table,
    key: &str,
    inherited: Option<&str>,
) -> Result<Option<String>> {
    package
        .get(key)
        .map(|item| inherited_package_value(path, document, item, key, inherited))
        .transpose()
        .map(Option::flatten)
}

fn inherited_package_value(
    path: &Path,
    document: &Document,
    item: &Item,
    key: &str,
    inherited: Option<&str>,
) -> Result<Option<String>> {
    if let Some(value) = item.as_str() {
        return Ok(Some(value.to_owned()));
    }
    let workspace = match item {
        Item::Table(table) if table.len() == 1 => table.get("workspace").and_then(Item::as_bool),
        Item::Value(Value::InlineTable(table)) if table.len() == 1 => {
            table.get("workspace").and_then(Value::as_bool)
        }
        _ => None,
    };
    if workspace != Some(true) {
        return Err(type_error(
            path,
            document.line_of_item(item),
            &format!("package.{key}"),
            "a string or `workspace = true`",
        ));
    }
    inherited.map(str::to_owned).map(Some).ok_or_else(|| {
        Error::at(
            path,
            document.line_of_item(item),
            format!("package.{key} inherits a missing workspace.package.{key}"),
            format!("define workspace.package.{key} as a string"),
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
            format!("unsupported package name `{name}`"),
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
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'+' | b'.'))
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
    if matches!(value, "allow" | "warn" | "deny" | "forbid") {
        Ok(value.to_owned())
    } else {
        Err(Error::at(
            path,
            line,
            format!("unsupported rustc lint level `{value}`"),
            "choose allow, warn, deny, or forbid",
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
        format!("unsupported manifest key `{name}`"),
        "remove the key; Lorry does not support it",
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

    fn target_names(manifest: &Manifest, kind: TargetKind) -> Vec<&str> {
        manifest
            .targets_of(kind)
            .map(|target| target.name.as_str())
            .collect()
    }

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
        assert_eq!(manifest.edition, Edition::E2024);
        assert_eq!(manifest.resolver, Resolver::V3);
        assert_eq!(manifest.metadata.authors, ["A", "B"]);
    }

    #[test]
    fn legacy_dependency_defaults_follow_cargo_editions_and_precedence() {
        for edition in ["2015", "2018", "2021", "2024"] {
            for (keys, expected) in [
                ("default_features = false", false),
                ("default_features = false, default-features = true", true),
            ] {
                let source = format!(
                    "[package]\nname = 'probe'\nversion = '1.0.0'\nedition = '{edition}'\n\
                     [dependencies]\ndep = {{ version = '1', {keys} }}\n"
                );
                let result = parsed(&source);
                if edition == "2024" {
                    assert!(
                        result
                            .unwrap_err()
                            .render()
                            .contains("unsupported as of the 2024 edition")
                    );
                } else {
                    let manifest = result.unwrap();
                    assert_eq!(manifest.dependencies[0].default_features, expected);
                    assert_eq!(manifest.warnings.len(), 1);
                    assert!(manifest.warnings[0].contains(if expected {
                        "redundant"
                    } else {
                        "deprecated"
                    }));
                }
            }
        }
        for keys in [
            "default_features = 'false'",
            "default_features = 0\ndefault-features = true",
        ] {
            assert!(
                parsed(&format!(
                    "[package]\nname = 'probe'\nversion = '1.0.0'\nedition = '2021'\n\
                 [dependencies.dep]\nversion = '1'\n{keys}\n"
                ))
                .unwrap_err()
                .render()
                .contains("a boolean")
            );
        }
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
    fn library_documentation_scraping_is_inert_for_builds() {
        let root = Path::new("/dependency");
        let path = root.join("Cargo.toml");
        for value in ["true", "false", "\"invalid\""] {
            let source = format!("{RED}\n[lib]\ndoc-scrape-examples = {value}\n");
            let document = Document::parse(&path, "Cargo manifest", source).unwrap();
            for mode in [ManifestMode::Root, ManifestMode::Dependency] {
                let result = Manifest::parse_document(root, &path, &document, mode);
                if value == "\"invalid\"" {
                    assert!(result.unwrap_err().render().contains("a boolean"));
                } else {
                    let library = result.unwrap().library.unwrap();
                    assert_eq!(library.path, root.join("src/lib.rs"));
                    assert_eq!(library.crate_types, ["lib"]);
                }
            }
        }
    }

    #[test]
    fn library_and_binary_benchmark_flags_are_independent_of_tests() {
        for flags in [
            "",
            "test = false\nbench = true\ndoc = true\n",
            "bench = false\n",
        ] {
            let manifest = parsed(&format!(
                "{RED}\n[lib]\n{flags}\n[[bin]]\nname = \"runner\"\npath = \"src/main.rs\"\n{flags}"
            ))
            .unwrap();
            let library = manifest.library.unwrap();
            let binary = &manifest.targets[0];
            assert_eq!(library.bench, !flags.contains("bench = false"));
            assert_eq!(binary.bench, library.bench);
            assert_eq!(library.test, !flags.contains("test = false"));
            assert_eq!(binary.test, library.test);
            assert!(library.doc && binary.doc);
        }
        for section in [
            "[lib]",
            "[[bin]]\nname = \"runner\"\npath = \"src/main.rs\"",
        ] {
            for key in ["bench", "doc"] {
                let error =
                    parsed(&format!("{RED}\n{section}\n{key} = \"invalid\"\n")).unwrap_err();
                assert!(error.render().contains("a boolean"));
            }
        }
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
"embedded-io-v0.7" = []

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
        assert!(manifest.features.contains_key("embedded-io-v0.7"));
        assert_eq!(manifest.patches[0].package, "ring");
        assert!(matches!(manifest.patches[0].source, PatchSource::Path(_)));
        assert_eq!(manifest.rust_lints["unsafe_code"].priority, 1);
    }

    #[test]
    fn parses_clippy_lints_for_roots_and_dependencies() {
        let source = format!(
            "{RED}\n[lints.clippy]\nall = {{ level = \"deny\", priority = -1 }}\n\
             needless_return = \"allow\"\n"
        );
        let path = Path::new("/fixture/Cargo.toml");
        let document = Document::parse(path, "Cargo manifest", source).unwrap();
        for mode in [ManifestMode::Root, ManifestMode::Dependency] {
            let manifest =
                Manifest::parse_document(Path::new("/fixture"), path, &document, mode).unwrap();
            assert_eq!(manifest.clippy_lints["all"].level, "deny");
            assert_eq!(manifest.clippy_lints["all"].priority, -1);
            assert_eq!(manifest.clippy_lints["needless_return"].level, "allow");
        }
        for configuration in [
            "needless_return = \"force-warn\"",
            "needless_return = { level = \"warn\", priority = \"first\" }",
            "\"clippy::needless_return\" = \"warn\"",
        ] {
            let source = format!("{RED}\n[lints.clippy]\n{configuration}\n");
            assert!(parsed(&source).is_err(), "accepted {configuration}");
        }
    }

    #[test]
    fn parses_direct_git_dependency_semantics() {
        let source = RED.replace(
            "[dependencies]",
            "[dependencies]\n\
             remote = { git = \"https://example.com/repo.git\", branch = \"stable\", \
             package = \"actual\", version = \"^1.2\", optional = true, \
             default-features = false, features = [\"fast\"] }",
        );
        let manifest = parsed(&source).unwrap();
        let dependency = &manifest.dependencies[0];
        assert_eq!(dependency.alias, "remote");
        assert_eq!(dependency.package, "actual");
        assert_eq!(dependency.requirement, VersionReq::parse("^1.2").unwrap());
        assert!(dependency.optional);
        assert!(!dependency.default_features);
        assert_eq!(dependency.features, ["fast"]);
        assert_eq!(
            dependency.source,
            DependencySource::Git(GitDependency {
                url: "https://example.com/repo.git".to_owned(),
                selector: GitSelector::Branch("stable".to_owned()),
            })
        );

        for declaration in [
            "{ git = \"https://example.com/repo.git\", path = \"../repo\" }",
            "{ git = \"https://example.com/repo.git\", branch = \"a\", tag = \"b\" }",
            "{ git = \"https://user@example.com/repo.git\" }",
        ] {
            let invalid = RED.replace(
                "[dependencies]",
                &format!("[dependencies]\nremote = {declaration}"),
            );
            assert!(parsed(&invalid).is_err(), "accepted `{declaration}`");
        }
    }

    #[test]
    fn parses_path_and_git_patch_sources() {
        let source = "[package]\nname = \"root\"\nversion = \"0.1.0\"\n\
                      [patch.crates-io]\n\
                      local = { path = \"../local\", package = \"actual-local\" }\n\
                      remote = { git = \"https://example.com/repo.git\", branch = \"motor\", package = \"actual-remote\" }\n";
        let manifest = parsed(source).unwrap();
        assert_eq!(manifest.patches[0].package, "actual-local");
        assert!(matches!(manifest.patches[0].source, PatchSource::Path(_)));
        assert_eq!(manifest.patches[1].package, "actual-remote");
        assert_eq!(
            manifest.patches[1].source,
            PatchSource::Git(GitDependency {
                url: "https://example.com/repo.git".to_owned(),
                selector: GitSelector::Branch("motor".to_owned()),
            })
        );

        for declaration in [
            "{ git = \"https://example.com/repo.git\", path = \"../repo\" }",
            "{ git = \"https://example.com/repo.git\", branch = \"a\", tag = \"b\" }",
            "{ git = \"https://user@example.com/repo.git\" }",
            "{ path = \"../repo\", branch = \"main\" }",
        ] {
            let invalid = format!(
                "[package]\nname = \"root\"\nversion = \"0.1.0\"\n\
                 [patch.crates-io]\nremote = {declaration}\n"
            );
            assert!(parsed(&invalid).is_err(), "accepted `{declaration}`");
        }
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
             [[bin]]\nname = \"tool\"\npath = \"src/custom.rs\"\ndoc = false\n",
        )
        .unwrap();
        fs::write(
            root.join("Cargo.lock"),
            "version = 4\n[[package]]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();

        let manifest = Manifest::load_for_build(&root).unwrap();
        assert_eq!(manifest.default_run.as_deref(), Some("worker"));
        assert_eq!(
            target_names(&manifest, TargetKind::Bin),
            ["demo", "tool", "worker"]
        );
        assert_eq!(manifest.targets[1].path, root.join("src/custom.rs"));
        assert!(manifest.targets[0].doc);
        assert!(!manifest.targets[1].doc);
        assert!(manifest.targets[2].doc);
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
             [profile.release]\nlto = \"thin\"\ncodegen-units = 2\n\
             [patch.crates-io]\nshared = { path = \"shared\" }\n",
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

        let compile = |current: &Path,
                       manifest_path: Option<&Path>,
                       packages: &[&str],
                       workspace,
                       exclude: &[&str]| {
            let selection = PackageSelection {
                packages: packages.iter().map(|name| (*name).to_owned()).collect(),
                workspace,
                exclude: exclude.iter().map(|name| (*name).to_owned()).collect(),
            };
            SourceWorkspace::load_compilation(current, manifest_path, &selection)
                .map(|(_, selected)| selected)
        };
        let names = |selected: Vec<Manifest>| {
            selected
                .into_iter()
                .map(|member| member.name)
                .collect::<Vec<_>>()
        };
        let [from_root] = compile(&root, None, &["app"], false, &[])
            .unwrap()
            .try_into()
            .unwrap();
        let from_member = Manifest::load_for_build(&root.join("app")).unwrap();
        assert_eq!(from_root, from_member);
        for manifest_path in [root.join("app/Cargo.toml"), PathBuf::from("app/Cargo.toml")] {
            assert_eq!(
                compile(&root, Some(&manifest_path), &["app"], false, &[]).unwrap(),
                std::slice::from_ref(&from_root)
            );
        }
        assert_eq!(from_root.root, root.join("app"));
        assert_eq!(from_root.workspace_root, root);
        assert_eq!(from_root.resolver, Resolver::V2);
        let member_workspace = SourceWorkspace::load(&root.join("app"), None).unwrap();
        for (name, panic_abort, lto, codegen_units) in [
            ("dev", true, Lto::Default, None),
            ("release", false, Lto::Thin, Some(2)),
        ] {
            let mut member = from_root.clone();
            profiles::SelectedProfile::load(&member_workspace, name)
                .unwrap()
                .apply(&mut member);
            assert_eq!(member.profile.panic_abort, panic_abort);
            assert_eq!(member.profile.lto, lto);
            assert_eq!(member.profile.codegen_units, codegen_units);
        }
        assert!(from_root.lock.is_some());
        let shared = Manifest::load_for_build(&root.join("shared")).unwrap();
        for selection in [
            PackageSelection::default(),
            PackageSelection {
                workspace: true,
                ..PackageSelection::default()
            },
            PackageSelection {
                packages: vec!["app".into(), "shared".into()],
                ..PackageSelection::default()
            },
        ] {
            let (workspace, selected) =
                SourceWorkspace::load_compilation(&root, None, &selection).unwrap();
            assert_eq!(workspace.root, root);
            assert_eq!(selected, [from_root.clone(), shared.clone()]);
        }
        let (_, selected) = SourceWorkspace::load_compilation(
            &root.join("app"),
            None,
            &PackageSelection::default(),
        )
        .unwrap();
        assert_eq!(selected.as_slice(), std::slice::from_ref(&from_root));
        let (_, selected) = SourceWorkspace::load_compilation(
            &root,
            Some(Path::new("app/Cargo.toml")),
            &PackageSelection::default(),
        )
        .unwrap();
        assert_eq!(selected.as_slice(), std::slice::from_ref(&from_root));
        let (_, selected) = SourceWorkspace::load_compilation(
            &root,
            None,
            &PackageSelection {
                workspace: true,
                exclude: vec!["app".into()],
                ..PackageSelection::default()
            },
        )
        .unwrap();
        assert_eq!(selected, [shared]);
        let selected = |packages: &[&str], workspace, exclude: &[&str]| {
            compile(&root, None, packages, workspace, exclude)
        };
        assert!(selected(&["missing"], false, &[]).is_err());
        assert_eq!(
            names(selected(&["app", "app@0.1"], false, &[]).unwrap()),
            ["app"]
        );
        assert_eq!(names(selected(&[], true, &["sha*"]).unwrap()), ["app"]);
        assert_eq!(
            names(selected(&["missing"], true, &["shared"]).unwrap()),
            ["app"]
        );
        assert!(
            selected(&["missing"], true, &[])
                .unwrap_err()
                .to_string()
                .contains("did not match")
        );
        let mut workspace = SourceWorkspace::load(&root, None).unwrap();
        assert!(
            workspace
                .packages
                .iter()
                .all(|member| member.lock.is_none())
        );
        workspace.load_locked_context().unwrap();
        for member in &workspace.packages {
            assert_eq!(member.workspace_root, root);
            assert_eq!(member.workspace_members, from_root.workspace_members);
            assert_eq!(member.lock, from_root.lock);
            assert_eq!(member.patches, from_root.patches);
            assert_eq!(member.patches.len(), 1);
        }
        let selection = PackageSelection {
            packages: vec!["app".to_owned(), "app@0.1".to_owned(), "sha*".to_owned()],
            ..PackageSelection::default()
        };
        let (roots, warnings) = selection
            .select(
                workspace
                    .packages
                    .iter()
                    .map(|member| (member.name.as_str(), &member.version, member.root.as_path())),
                workspace.default_members.iter().map(PathBuf::as_path),
            )
            .unwrap();
        assert_eq!(roots, [root.join("app"), root.join("shared")]);
        assert!(warnings.is_empty());
        let unmatched = selected(&[], true, &["shared", "missing"]).unwrap();
        assert!(
            unmatched[0]
                .warnings
                .iter()
                .any(|warning| warning.contains("excluded package selector `missing`"))
        );
        assert!(
            selected(&[], true, &["*"])
                .unwrap_err()
                .to_string()
                .contains("no packages")
        );
        assert!(
            selected(&["app"], false, &["shared"])
                .unwrap_err()
                .to_string()
                .contains("--exclude")
        );
        // From a member directory, a virtual root manifest path selects every member.
        for (manifest, packages, expected) in [
            ("app/Cargo.toml", &["shared"][..], &["shared"][..]),
            ("Cargo.toml", &[], &["app", "shared"]),
        ] {
            let manifest = root.join(manifest);
            let selected = compile(&from_root.root, Some(&manifest), packages, false, &[]);
            assert_eq!(names(selected.unwrap()), expected);
        }
        fs::write(
            from_root.workspace_root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"app\", \"shared\"]\ndefault-members = [\"app\"]\n",
        )
        .unwrap();
        assert_eq!(
            Manifest::load_for_build(&from_root.workspace_root)
                .unwrap()
                .name,
            "app"
        );
        fs::remove_dir_all(from_root.workspace_root).unwrap();
    }

    #[test]
    fn root_build_dependencies_match_source_manifest_declarations() {
        let root = Path::new("/workspace/member");
        let path = root.join("Cargo.toml");
        let source = "[package]\nname = \"member\"\nversion = \"1.0.0\"\nedition = \"2024\"\n\
                      build = \"build.rs\"\n[build-dependencies]\nbuilder = \"1\"\n\
                      [target.'cfg(unix)'.build-dependencies]\ntarget-builder = \"2\"\n";
        let manifest = Manifest::parse(root, &path, source).unwrap();
        let document = Document::parse(&path, "Cargo manifest", source.to_owned()).unwrap();
        let description =
            Manifest::parse_document(root, &path, &document, ManifestMode::Source).unwrap();
        assert_eq!(manifest.dependencies, description.dependencies);
        assert_eq!(manifest.dependencies.len(), 2);
        assert!(
            manifest
                .dependencies
                .iter()
                .all(|dependency| dependency.kind == DependencyKind::Build)
        );
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
crate-type = ["rlib"]
test = false
doctest = false
doc = false

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
        assert_eq!(manifest.targets.len(), 1);
        assert_eq!(manifest.targets[0].name, "ignored-test");
        assert_eq!(
            manifest.targets[0].path,
            Path::new("/dependency/tests/ignored.rs")
        );
        let library = manifest.library.as_ref().unwrap();
        assert_eq!(library.crate_types, ["rlib"]);
        assert!(!library.test);
        assert!(!library.doctest);
        assert!(!library.doc);
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
    fn ignores_root_only_patch_tables_in_dependency_manifests() {
        let source = "[package]\nname = \"dependency\"\nversion = \"1.0.0\"\n\
                      [patch.crates-io]\nother = { path = \"../other\" }\n";
        let manifest = Manifest::parse_dependency(
            Path::new("/dependency"),
            Path::new("/dependency/Cargo.toml"),
            source,
        )
        .unwrap();
        assert!(manifest.patches.is_empty());
    }

    #[test]
    fn loads_inherited_dependency_workspace_package_fields() {
        let id = NEXT_VENDOR_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "lorry-inherited-dependency-{}-{id}",
            std::process::id()
        ));
        let member = root.join("member");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(member.join("src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion.workspace = true\n\
             edition.workspace = true\nrust-version.workspace = true\n\
             [workspace]\nmembers = [\"member\"]\n\
             [workspace.package]\nversion = \"1.2.3\"\nedition = \"2021\"\n\
             rust-version = \"1.64.0\"\n",
        )
        .unwrap();
        fs::write(
            member.join("Cargo.toml"),
            "[package]\nname = \"member\"\nversion.workspace = true\n\
             edition.workspace = true\nrust-version.workspace = true\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), "").unwrap();
        fs::write(member.join("src/lib.rs"), "").unwrap();

        for package in [&root, &member] {
            let manifest = Manifest::load_path_dependency(package).unwrap();
            assert_eq!(manifest.version.original, "1.2.3");
            assert_eq!(manifest.edition, Edition::E2021);
            assert_eq!(manifest.metadata.rust_version, "1.64.0");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn loads_lorrys_frozen_stage_two_manifest_and_lock() {
        let root = Path::new(".");
        assert!(root.join("Cargo.toml").is_file());
        let manifest = Manifest::load_for_build(root).unwrap();
        assert_eq!(manifest.name, "lorry");
        assert_eq!(manifest.dependencies.len(), 14);
        assert!(manifest.dependencies.iter().any(|dependency| {
            dependency.package == "moto-rt"
                && dependency.target.as_deref() == Some("cfg(target_os = \"motor\")")
                && matches!(dependency.source, DependencySource::CratesIo)
        }));
        assert!(manifest.dependencies.iter().any(|dependency| {
            dependency.package == "moto-sys"
                && dependency.target.as_deref() == Some("cfg(target_os = \"motor\")")
                && matches!(dependency.source, DependencySource::CratesIo)
        }));
        assert!(manifest.dependencies.iter().any(|dependency| {
            dependency.package == "libc"
                && dependency.target.as_deref() == Some("cfg(target_os = \"linux\")")
                && matches!(dependency.source, DependencySource::CratesIo)
        }));
        assert!(manifest.dependencies.iter().any(|dependency| {
            dependency.package == "gix"
                && dependency
                    .features
                    .iter()
                    .any(|feature| feature == "attributes")
        }));
        assert!(
            manifest
                .dependencies
                .iter()
                .any(|dependency| dependency.package == "gix-dir")
        );
        assert_eq!(manifest.lock.as_ref().unwrap().packages.len(), 164);
    }

    #[test]
    fn vendor_loading_accepts_a_missing_stale_or_v3_lock() {
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

        assert!(Manifest::load_for_build(&root).is_err());
        assert!(Manifest::load_for_vendor(&root).unwrap().lock.is_none());

        fs::write(
            root.join("Cargo.lock"),
            "version = 4\n\n\
             [[package]]\nname = \"vendor-root\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        assert!(Manifest::load_for_build(&root).is_err());
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

        fs::write(
            root.join("Cargo.lock"),
            "version = 3\n\n\
             [[package]]\nname = \"vendor-root\"\nversion = \"0.2.0\"\n",
        )
        .unwrap();
        assert!(Manifest::load_for_build(&root).is_ok());
        assert!(Manifest::load_for_vendor(&root).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn discovers_sorted_integration_test_targets() {
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

        let manifest = Manifest::load_for_build(&root).unwrap();
        assert_eq!(
            target_names(&manifest, TargetKind::Test),
            ["a-b", "nested", "z"]
        );
        assert_eq!(manifest.targets[0].path, root.join("tests/a-b.rs"));

        let path = root.join("Cargo.toml");
        let source = fs::read_to_string(&path).unwrap();
        for declarations in [
            "[[test]]\nname = \"z\"\npath = \"tests/z.rs\"\n[[test]]\nname = \"extra\"\npath = \"tests/z.rs\"\n",
            "[[test]]\nname = \"extra\"\npath = \"tests/z.rs\"\n[[test]]\nname = \"z\"\npath = \"tests/z.rs\"\n",
            "[[test]]\nname = \"extra\"\npath = \"tests/z.rs\"\n",
        ] {
            fs::write(&path, format!("{source}\n{declarations}")).unwrap();
            let manifest = Manifest::load_for_build(&root).unwrap();
            let cargo = std::process::Command::new(env!("CARGO"))
                .args(["metadata", "--offline", "--no-deps", "--format-version=1"])
                .env("CARGO_HOME", root.join("cargo-home"))
                .env("RUSTC", Path::new(env!("CARGO")).with_file_name("rustc"))
                .current_dir(&root)
                .output()
                .unwrap();
            assert!(
                cargo.status.success(),
                "{}",
                String::from_utf8_lossy(&cargo.stderr)
            );
            let cargo: serde_json::Value = serde_json::from_slice(&cargo.stdout).unwrap();
            let cargo_tests = cargo["packages"][0]["targets"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|target| target["kind"] == serde_json::json!(["test"]))
                .map(|target| {
                    (
                        target["name"].as_str().unwrap(),
                        PathBuf::from(target["src_path"].as_str().unwrap()),
                    )
                })
                .collect::<Vec<_>>();
            let tests = manifest
                .targets_of(TargetKind::Test)
                .map(|target| (target.name.as_str(), target.path.clone()))
                .collect::<Vec<_>>();
            assert_eq!(tests, cargo_tests, "{declarations}");
        }

        fs::write(root.join("tests/a_b.rs"), "").unwrap();
        assert!(Manifest::load_for_build(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn auxiliary_benchmark_flags_match_cargo_roots() {
        let id = NEXT_VENDOR_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("lorry-benchmark-flags-{}-{id}", std::process::id()));
        for directory in ["src", "tests", "examples", "benches"] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        for source in [
            "src/lib.rs",
            "src/main.rs",
            "tests/selected.rs",
            "tests/default.rs",
            "examples/selected.rs",
            "examples/default.rs",
            "benches/selected.rs",
            "benches/disabled.rs",
        ] {
            fs::write(root.join(source), "").unwrap();
        }
        let source = r#"[package]
name = "flags"
version = "1.0.0"
edition = "2024"
[[test]]
name = "selected"
test = false
bench = true
[[example]]
name = "selected"
bench = true
[[bench]]
name = "disabled"
bench = false
"#;
        fs::write(root.join("Cargo.toml"), source).unwrap();
        let manifest = Manifest::load_source_dependency(&root).unwrap();
        let mut expected = vec![
            ("lib".to_owned(), "flags".to_owned()),
            ("bin".to_owned(), "flags".to_owned()),
        ];
        expected.extend(
            manifest
                .targets
                .iter()
                .filter(|target| target.kind != TargetKind::Bin && target.bench)
                .map(|target| (target.kind.as_str().to_owned(), target.name.clone())),
        );
        expected.sort();
        let output = std::process::Command::new(env!("CARGO"))
            .args([
                "-Z",
                "unstable-options",
                "check",
                "--unit-graph",
                "--offline",
                "--benches",
            ])
            .env("CARGO_HOME", root.join("cargo-home"))
            .env("RUSTC", Path::new(env!("CARGO")).with_file_name("rustc"))
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let graph: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let mut actual = graph["roots"]
            .as_array()
            .unwrap()
            .iter()
            .map(|index| {
                let target = &graph["units"][index.as_u64().unwrap() as usize]["target"];
                (
                    target["kind"][0].as_str().unwrap().to_owned(),
                    target["name"].as_str().unwrap().to_owned(),
                )
            })
            .collect::<Vec<_>>();
        actual.sort();
        assert_eq!(expected.len(), 5);
        assert_eq!(expected, actual);
        for kind in ["test", "example", "bench"] {
            fs::write(root.join("Cargo.toml"), format!("{source}\n[[{kind}]]\nname = \"invalid\"\npath = \"src/main.rs\"\nbench = \"true\"\n")).unwrap();
            assert!(
                Manifest::load_source_dependency(&root)
                    .unwrap_err()
                    .render()
                    .contains("must be a boolean")
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn source_metadata_describes_missing_explicit_target_files_like_cargo() {
        let id = NEXT_VENDOR_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("lorry-missing-targets-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname=\"demo\"\nversion=\"1.0.0\"\nedition=\"2021\"\n[workspace]\n\
            [lib]\npath=\"missing/lib.rs\"\n\
            [[bin]]\nname=\"program\"\npath=\"missing/main.rs\"\n\
            [[test]]\nname=\"integration\"\npath=\"missing/test.rs\"\nrequired-features=[\"extra\"]\ntest=false\ndoc=true\nharness=false\n\
            [[example]]\nname=\"sample\"\npath=\"missing/example.rs\"\n\
            [[bench]]\nname=\"benchmark\"\npath=\"missing/bench.rs\"\n",
        )
        .unwrap();
        let cargo = std::process::Command::new(env!("CARGO"))
            .args(["metadata", "--offline", "--no-deps", "--format-version=1"])
            .env("CARGO_HOME", root.join("cargo-home"))
            .env("RUSTC", Path::new(env!("CARGO")).with_file_name("rustc"))
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(
            cargo.status.success(),
            "{}",
            String::from_utf8_lossy(&cargo.stderr)
        );
        let cargo: serde_json::Value = serde_json::from_slice(&cargo.stdout).unwrap();
        let manifest = Manifest::load_source_dependency(&root).unwrap();
        let targets = cargo["packages"][0]["targets"].as_array().unwrap();
        assert_eq!(targets.len(), 5);
        let test = manifest.targets_of(TargetKind::Test).next().unwrap();
        assert_eq!(test.required_features.as_ref().unwrap(), &["extra"]);
        assert!(!test.test && test.doc && !test.harness);
        let cargo_test = targets
            .iter()
            .find(|target| target["name"] == "integration")
            .unwrap();
        assert_eq!(
            cargo_test["required-features"],
            serde_json::json!(["extra"])
        );
        assert_eq!(cargo_test["test"], test.test);
        assert_eq!(cargo_test["doc"], test.doc);
        let mut paths = vec![manifest.library.as_ref().unwrap().path.clone()];
        paths.extend(manifest.targets.iter().map(|target| target.path.clone()));
        for path in paths {
            assert!(
                targets
                    .iter()
                    .any(|target| target["src_path"].as_str() == path.to_str())
            );
        }
        // Compilation still diagnoses its missing library input.
        assert!(
            Manifest::load_path_dependency(&root)
                .unwrap_err()
                .to_string()
                .contains("library target")
        );
        fs::write(root.join("lib.rs"), "").unwrap();
        let text = fs::read_to_string(root.join("Cargo.toml"))
            .unwrap()
            .replace("missing/lib.rs", "lib.rs");
        fs::write(root.join("Cargo.toml"), text).unwrap();
        let dependency = Manifest::load_path_dependency(&root).unwrap();
        assert_eq!(
            dependency
                .targets
                .iter()
                .map(|target| target.kind)
                .collect::<Vec<_>>(),
            [TargetKind::Example, TargetKind::Test, TargetKind::Bench]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn explicit_dependency_test_overrides_its_normalized_discovery() {
        let id = NEXT_VENDOR_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "lorry-explicit-dependency-test-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("tests")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"dependency\"\nversion = \"1.0.0\"\nautotests = true\n\n\
             [[test]]\nname = \"auto-test\"\npath = \"tests/auto_test.rs\"\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), "").unwrap();
        fs::write(root.join("tests/auto_test.rs"), "").unwrap();
        fs::create_dir_all(root.join("tests/directory-test")).unwrap();
        fs::write(root.join("tests/directory-test/main.rs"), "").unwrap();

        let manifest = Manifest::load_path_dependency(&root).unwrap();
        assert_eq!(
            target_names(&manifest, TargetKind::Test),
            ["auto-test", "directory-test"]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dependency_target_names_follow_cargo_rules() {
        let root = target_fixture("dependency-target-names");
        fs::create_dir_all(root.join("examples")).unwrap();
        fs::create_dir_all(root.join("tests")).unwrap();
        // prettyplease ships such an example and disables example discovery.
        fs::write(root.join("examples/output.pretty.rs"), "fn main() {}\n").unwrap();
        let long = "t".repeat(70);
        fs::write(root.join(format!("tests/{long}.rs")), "").unwrap();
        fs::write(
            root.join("Cargo.toml"),
            format!(
                "[package]\nname = \"dep\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\
                 autoexamples = false\n[[test]]\nname = \"{long}\"\n"
            ),
        )
        .unwrap();
        let manifest = Manifest::load_path_dependency(&root).unwrap();
        assert!(
            manifest
                .targets
                .iter()
                .all(|target| target.kind != TargetKind::Example)
        );
        assert!(manifest.targets.iter().any(|target| target.name == long));
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"dep\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\
             [[test]]\nname = \"../escape\"\n",
        )
        .unwrap();
        let error = Manifest::load_path_dependency(&root).unwrap_err().render();
        assert!(error.contains("unsupported target name"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn registry_packages_ignore_enclosing_manifests() {
        let parent = target_fixture("registry-enclosing");
        // Another user could plant this in a shared temporary directory.
        fs::write(parent.join("Cargo.toml"), "[workspace\nbroken").unwrap();
        let package = parent.join("demo-1.0.0");
        fs::create_dir_all(package.join("src")).unwrap();
        fs::write(package.join("src/lib.rs"), "").unwrap();
        fs::write(
            package.join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        for describe in [false, true] {
            let manifest = Manifest::load_registry_dependency(&package, describe).unwrap();
            assert_eq!(manifest.name, "demo");
        }
        assert!(Manifest::load_path_dependency(&package).is_err());
        fs::remove_dir_all(parent).unwrap();
    }

    fn target_fixture(name: &str) -> PathBuf {
        let id = NEXT_VENDOR_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("lorry-{name}-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "").unwrap();
        root
    }

    fn cargo_metadata_targets(root: &Path) -> std::process::Output {
        std::process::Command::new(env!("CARGO"))
            .args(["metadata", "--offline", "--no-deps", "--format-version=1"])
            .env("CARGO_HOME", root.join("cargo-home"))
            .env("RUSTC", Path::new(env!("CARGO")).with_file_name("rustc"))
            .current_dir(root)
            .output()
            .unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn infers_and_merges_targets_like_cargo() {
        use std::os::unix::fs::symlink;

        let root = target_fixture("target-inference");
        fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::create_dir_all(root.join("outside/linked-dir")).unwrap();
        fs::create_dir_all(root.join("bench-sources")).unwrap();
        fs::write(root.join("outside/linked.rs"), "fn main() {}\n").unwrap();
        fs::write(root.join("outside/linked-dir/main.rs"), "fn main() {}\n").unwrap();
        symlink(root.join("bench-sources"), root.join("benches")).unwrap();
        let mut explicit = String::new();
        for (kind, directory) in [
            ("bin", "src/bin"),
            ("example", "examples"),
            ("test", "tests"),
            ("bench", "benches"),
        ] {
            // An explicit name selects `sub/main.rs`; an explicit path hides `plain`.
            explicit.push_str(&format!(
                "[[{kind}]]\nname = \"sub\"\n[[{kind}]]\nname = \"renamed\"\npath = \"{directory}/plain.rs\"\n"
            ));
            let directory = root.join(directory);
            for entry in ["sub", ".hidden-dir", "no-main"] {
                fs::create_dir_all(directory.join(entry)).unwrap();
            }
            for file in [
                "plain.rs",
                ".hidden.rs",
                "sub/main.rs",
                ".hidden-dir/main.rs",
                "no-main/lib.rs",
                "notes.txt",
                "no-extension",
            ] {
                fs::write(directory.join(file), "fn main() {}\n").unwrap();
            }
            symlink(root.join("outside/linked.rs"), directory.join("linked.rs")).unwrap();
            symlink(
                root.join("outside/linked-dir"),
                directory.join("linked-dir"),
            )
            .unwrap();
        }
        let disabled =
            "autobins = false\nautoexamples = false\nautotests = false\nautobenches = false\n";
        for (edition, auto, tables) in [
            ("2021", "", ""),
            ("2021", "", explicit.as_str()),
            ("2021", disabled, explicit.as_str()),
            ("2021", disabled, ""),
            ("2015", "", explicit.as_str()),
        ] {
            fs::write(
                root.join("Cargo.toml"),
                format!("[package]\nname = \"infer\"\nversion = \"1.0.0\"\nedition = \"{edition}\"\n{auto}[workspace]\n{tables}"),
            )
            .unwrap();
            let manifest = Manifest::load_source_dependency(&root).unwrap();
            let lorry = manifest
                .targets
                .iter()
                .map(|target| {
                    (
                        target.kind.as_str(),
                        target.name.as_str(),
                        target.path.clone(),
                    )
                })
                .collect::<Vec<_>>();
            let cargo = cargo_metadata_targets(&root);
            assert!(
                cargo.status.success(),
                "{}",
                String::from_utf8_lossy(&cargo.stderr)
            );
            let cargo: serde_json::Value = serde_json::from_slice(&cargo.stdout).unwrap();
            let cargo = cargo["packages"][0]["targets"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|target| target["kind"][0] != "lib")
                .map(|target| {
                    (
                        target["kind"][0].as_str().unwrap(),
                        target["name"].as_str().unwrap(),
                        PathBuf::from(target["src_path"].as_str().unwrap()),
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(lorry, cargo, "edition {edition}, {auto}{tables}");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn explicit_targets_follow_cargo_requirements() {
        let root = target_fixture("explicit-targets");
        let header = "[package]\nname = \"explicit\"\nversion = \"1.0.0\"\nedition = \"2024\"\n[workspace]\n";
        let load = |tables: &str| {
            fs::write(root.join("Cargo.toml"), format!("{header}{tables}")).unwrap();
            Manifest::load_source_dependency(&root)
        };
        // A file in place of a target directory holds no targets in Cargo.
        fs::write(root.join("tests"), "").unwrap();
        assert!(load("").unwrap().targets.is_empty());
        assert!(cargo_metadata_targets(&root).status.success());
        fs::remove_file(root.join("tests")).unwrap();
        for (kind, directory) in [
            ("bin", "src/bin"),
            ("example", "examples"),
            ("test", "tests"),
            ("bench", "benches"),
        ] {
            // Only an unresolved binary fails in a dependency, as in Cargo.
            let missing = load(&format!("[[{kind}]]\nname = \"missing\"\n"));
            assert_eq!(missing.is_err(), kind == "bin", "{kind}");
            assert!(load(&format!("[[{kind}]]\npath = \"src/lib.rs\"\n")).is_err());

            // A file and a directory with the same name collide in Cargo too.
            fs::create_dir_all(root.join(directory).join("twin")).unwrap();
            fs::write(root.join(directory).join("twin.rs"), "").unwrap();
            fs::write(root.join(directory).join("twin/main.rs"), "").unwrap();
            assert!(
                load("").unwrap_err().render().contains("duplicate"),
                "{kind}"
            );
            assert!(!cargo_metadata_targets(&root).status.success());
            fs::remove_dir_all(root.join(directory)).unwrap();
        }

        let manifest = load(
            "[[bin]]\nname = \"tool\"\npath = \"src/lib.rs\"\nedition = \"2018\"\ndoctest = false\n\
             [[test]]\nname = \"check\"\npath = \"src/lib.rs\"\ncrate-type = [\"lib\"]\n",
        )
        .unwrap();
        assert_eq!(manifest.targets[0].edition, Edition::E2018);
        assert_eq!(manifest.targets[1].crate_types, ["bin"]);
        assert!(manifest.warnings[0].contains("`edition` is set on bin `tool`"));
        let error =
            load("[[bin]]\nname = \"tool\"\npath = \"src/lib.rs\"\ncrate-type = [\"lib\"]\n")
                .unwrap_err();
        assert!(error.render().contains("unsupported bin crate-type"));

        fs::create_dir_all(root.join("src/bin")).unwrap();
        for index in 0..1_025 {
            fs::write(root.join(format!("src/bin/b{index}.rs")), "").unwrap();
        }
        let error = load("").unwrap_err();
        assert!(error.render().contains("more than 1024 binary targets"));
        fs::remove_file(root.join("src/bin/b0.rs")).unwrap();
        assert_eq!(load("").unwrap().targets.len(), 1_024);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dependencies_drop_unresolved_explicit_targets_like_cargo() {
        let root = target_fixture("unresolved-targets");
        // Published crates may declare targets whose files the archive excludes.
        let dependency = root.join("vendor/dep");
        fs::create_dir_all(dependency.join("src")).unwrap();
        fs::write(dependency.join("src/lib.rs"), "").unwrap();
        fs::write(
            dependency.join(".cargo-checksum.json"),
            format!("{{\"files\":{{}},\"package\":\"{}\"}}", "0".repeat(64)),
        )
        .unwrap();
        fs::write(
            dependency.join("Cargo.toml"),
            "[package]\nname = \"dep\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\
             [[test]]\nname = \"excluded-test\"\n[[example]]\nname = \"excluded-example\"\n\
             [[bench]]\nname = \"excluded-bench\"\nharness = false\n",
        )
        .unwrap();
        let app = root.join("app");
        fs::create_dir_all(app.join("src")).unwrap();
        fs::create_dir_all(app.join(".cargo")).unwrap();
        fs::write(
            app.join(".cargo/config.toml"),
            format!(
                "[source.crates-io]\nreplace-with = \"vendored\"\n\
                 [source.vendored]\ndirectory = \"{}\"\n",
                root.join("vendor").display()
            ),
        )
        .unwrap();
        fs::write(
            app.join("Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\
             [workspace]\n[dependencies]\ndep = \"1.0.0\"\n",
        )
        .unwrap();
        fs::write(app.join("src/main.rs"), "fn main() {}\n").unwrap();
        let cargo = |directory: &Path, command: &[&str]| {
            std::process::Command::new(env!("CARGO"))
                .args(command)
                .arg("--offline")
                .env("CARGO_HOME", root.join("cargo-home"))
                .env("CARGO_TARGET_DIR", root.join("target"))
                .env("RUSTC", Path::new(env!("CARGO")).with_file_name("rustc"))
                .current_dir(directory)
                .output()
                .unwrap()
        };
        // Cargo builds the registry dependency and omits the targets.
        let build = cargo(&app, &["check"]);
        assert!(
            build.status.success(),
            "{}",
            String::from_utf8_lossy(&build.stderr)
        );
        let metadata = cargo(&app, &["metadata", "--format-version=1"]);
        let metadata: serde_json::Value = serde_json::from_slice(&metadata.stdout).unwrap();
        let dependency_targets = metadata["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|package| package["name"] == "dep")
            .unwrap()["targets"]
            .as_array()
            .unwrap()
            .len();
        assert_eq!(dependency_targets, 1);
        for manifest in [
            Manifest::load_path_dependency(&dependency).unwrap(),
            Manifest::load_source_dependency(&dependency).unwrap(),
        ] {
            assert!(manifest.library.is_some() && manifest.targets.is_empty());
        }
        // As a member, Cargo and Lorry both reject the package.
        assert!(!cargo(&dependency, &["check"]).status.success());
        let Err(error) = SourceWorkspace::load(&dependency, None) else {
            panic!("a member must reject an unresolved explicit target");
        };
        assert!(error.render().contains("cannot infer source path"));
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
            RED.replace(
                "[dependencies]",
                "[dependencies]\nthing = { version = \"1\", registry = \"alternate\" }",
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
        let document = Document::parse(&path, "Cargo manifest", source.clone()).unwrap();
        let manifest =
            Manifest::parse_document(root, &path, &document, ManifestMode::Dependency).unwrap();
        assert!(manifest.library.unwrap().proc_macro);

        assert!(parsed(&source).unwrap().library.unwrap().proc_macro);
    }

    #[test]
    fn retains_root_dev_dependencies() {
        let source = format!("{RED}\n[target.'cfg(unix)'.dev-dependencies]\nlibc = \"0.2\"\n");
        let manifest = parsed(&source).unwrap();
        assert_eq!(manifest.dependencies.len(), 1);
        assert_eq!(manifest.dependencies[0].kind, DependencyKind::Dev);
        assert_eq!(
            manifest.dependencies[0].target.as_deref(),
            Some("cfg(unix)")
        );
        let regular = parsed(&format!("{RED}\n[dev-dependencies]\nhelper = \"1\"\n")).unwrap();
        assert_eq!(regular.dependencies[0].kind, DependencyKind::Dev);
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
    fn validates_full_version_three_and_four_lockfiles() {
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
        let version_three = valid.replace("version = 4", "version = 3");
        assert_eq!(
            validate_lock_source(&manifest, Path::new("Cargo.lock"), &version_three)
                .unwrap()
                .packages
                .len(),
            2
        );
        let version_two = valid.replace("version = 4\n", "");
        let loaded =
            validate_lock_source(&manifest, Path::new("Cargo.lock"), &version_two).unwrap();
        assert_eq!(loaded.format, crate::lockfile::Format::V2);
        let version_one = version_two.replace("dependencies = [\"serde\"]", &format!("dependencies = [\"serde 1.0.228 ({CRATES_IO_SOURCE})\"]"))
            .replace("checksum = \"9a8e94ea7f378bd32cbbd37198a4a91436180c5bb472411e48b5ec2e2124ae9e\"", &format!("[metadata]\n\"checksum serde 1.0.228 ({CRATES_IO_SOURCE})\" = \"9a8e94ea7f378bd32cbbd37198a4a91436180c5bb472411e48b5ec2e2124ae9e\""));
        let loaded =
            validate_lock_source(&manifest, Path::new("Cargo.lock"), &version_one).unwrap();
        assert_eq!(loaded.format, crate::lockfile::Format::V1);
        assert!(
            loaded
                .packages
                .iter()
                .find(|package| package.name == "serde")
                .unwrap()
                .checksum
                .is_some()
        );
        for invalid in [
            version_one.replace(
                "9a8e94ea7f378bd32cbbd37198a4a91436180c5bb472411e48b5ec2e2124ae9e",
                "invalid",
            ),
            version_one.replace(
                "\" = \"9a8e94ea7f378bd32cbbd37198a4a91436180c5bb472411e48b5ec2e2124ae9e\"",
                "\" = 9",
            ),
            version_one.replace("checksum serde 1.0.228", "checksum other 1.0.228"),
        ] {
            assert!(validate_lock_source(&manifest, Path::new("Cargo.lock"), &invalid).is_err());
        }
        let unsupported = valid.replace("version = 4", "version = 2");
        let error = validate_lock_source(&manifest, Path::new("Cargo.lock"), &unsupported)
            .unwrap_err()
            .render();
        assert!(error.contains("expected `version = 3` or `version = 4`"));
        assert!(!error.contains("lorry vendor"));

        for invalid in [
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
