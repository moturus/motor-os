use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::atomic::AtomicFile;
use crate::config::{NativeToolRole, Policy, PolicyAction, PolicyRule};
use crate::diagnostic::{Error, Result};
use crate::hash::{Sha256, hex};
use crate::manifest::{LockedPackage, Lockfile, Manifest, Resolver};
use crate::policy::{Admission, PackageEvidence};
use crate::resolver::{CompileKind, PackageKey, Resolution, ResolvedSource};
use crate::toml::Document;
use toml_edit::{Item, Table};

pub const RELATIVE_PATH: &str = ".lorry/dependencies-v2.toml";

/// Derives compact grants for registry and Git packages that execute
/// build-time code.
pub fn capabilities_from(
    selected: &Resolution,
    evidence: &BTreeMap<PackageKey, PackageEvidence>,
    admission: &Admission,
) -> Result<Vec<Capability>> {
    let mut capabilities = Vec::new();
    for package in &selected.packages {
        let checksum = match &package.source {
            ResolvedSource::CratesIo { checksum } => hex(checksum),
            ResolvedSource::Git { cargo_source, .. } => source_digest(cargo_source),
            ResolvedSource::Path { .. } => continue,
        };
        let package_evidence = evidence.get(&package.key).ok_or_else(|| {
            Error::failure(format!(
                "cannot grant capabilities without evidence for `{} {}`",
                package.key.name, package.key.version
            ))
        })?;
        if !package_evidence.build_script && !package_evidence.proc_macro {
            continue;
        }
        let mut native_tools = admission
            .packages
            .get(&package.key)
            .map(|admission| admission.native_tools.iter().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        native_tools.sort_by_key(|role| native_tool_name(*role));
        capabilities.push(Capability {
            package: package.key.name.clone(),
            version: package.key.version.to_string(),
            checksum,
            build_script: package_evidence.build_script,
            proc_macro: package_evidence.proc_macro,
            native_tools,
            caller_env: admission
                .packages
                .get(&package.key)
                .map(|admission| admission.caller_env.iter().cloned().collect())
                .unwrap_or_default(),
        });
    }
    capabilities.sort_by(|a, b| {
        (&a.package, &a.version, &a.checksum).cmp(&(&b.package, &b.version, &b.checksum))
    });
    Ok(capabilities)
}

fn require_keys(path: &Path, table: &Table, required: &[&str], optional: &[&str]) -> Result<()> {
    for key in required {
        if !table.contains_key(key) {
            return Err(Error::failure(format!(
                "dependency state `{}` is missing `{key}`",
                path.display()
            )));
        }
    }
    for (key, _) in table.iter() {
        if !required.contains(&key) && !optional.contains(&key) {
            return Err(Error::failure(format!(
                "dependency state `{}` contains unknown key `{key}`",
                path.display()
            )));
        }
    }
    Ok(())
}

fn required_item<'a>(path: &Path, table: &'a Table, key: &str) -> Result<&'a Item> {
    table.get(key).ok_or_else(|| {
        Error::failure(format!(
            "dependency state `{}` is missing `{key}`",
            path.display()
        ))
    })
}

fn required_string(path: &Path, table: &Table, key: &str) -> Result<String> {
    required_item(path, table, key)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| {
            Error::failure(format!(
                "`{key}` in dependency state `{}` must be a string",
                path.display()
            ))
        })
}

fn required_strings(path: &Path, table: &Table, key: &str) -> Result<Vec<String>> {
    let array = required_item(path, table, key)?.as_array().ok_or_else(|| {
        Error::failure(format!(
            "`{key}` in dependency state `{}` must be an array",
            path.display()
        ))
    })?;
    array
        .iter()
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                Error::failure(format!(
                    "`{key}` in dependency state `{}` must contain only strings",
                    path.display()
                ))
            })
        })
        .collect()
}

pub(crate) fn native_tool_name(role: NativeToolRole) -> &'static str {
    match role {
        NativeToolRole::CCompiler => "c-compiler",
        NativeToolRole::CxxCompiler => "cxx-compiler",
        NativeToolRole::Archiver => "archiver",
    }
}

fn source_digest(source: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(source.as_bytes());
    hex(&digest.finish())
}

pub use review::{
    Capability, CompactState, Context, ContextPackage, Review, ReviewScope, UnitKind,
};
#[cfg(test)]
pub use review::{LockedRegistry, SourceEvidence};

mod review {
    use super::*;

    const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;
    const MAX_COMPACT_BYTES: usize = 4 * 1024 * 1024;
    const MAX_ITEMS: usize = 1_000_000;
    const MAX_STRING_BYTES: usize = 65_536;
    const MAX_CONTEXTS: usize = 64;
    const MAX_TABLES: usize = 4_096;
    const MAX_CONTEXT_PACKAGES: usize = 65_536;
    const MAX_EDGES: usize = 131_072;
    const MAX_FEATURES: usize = 262_144;
    const COMPACT_FORMAT_VERSION: u64 = 3;
    const REVIEW_FORMAT_VERSION: u64 = 4;
    // Single-package review records; vendor replaces them with a workspace review.
    const RETIRED_REVIEW_FORMAT_VERSION: i64 = 3;

    /// Empty package selection means the whole workspace. Names and feature
    /// requests are normalized so the same scope reconstructs the same review.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    pub struct ReviewScope {
        pub packages: Vec<String>,
        pub features: Vec<String>,
        pub all_features: bool,
        pub no_default_features: bool,
    }

    impl ReviewScope {
        pub(crate) fn description(&self) -> String {
            let packages = if self.packages.is_empty() {
                "all workspace members".to_owned()
            } else {
                self.packages.join(", ")
            };
            let defaults = if self.no_default_features {
                "no default features"
            } else {
                "default features"
            };
            let features = if self.all_features {
                "all features".to_owned()
            } else if self.features.is_empty() {
                "no additional feature requests".to_owned()
            } else {
                format!("features: {}", self.features.join(", "))
            };
            format!("Review scope: {packages}; {defaults}; {features}")
        }

        fn validate(&self) -> Result<()> {
            limit(self.packages.len(), 64, "reviewed members")?;
            limit(
                self.features.len(),
                MAX_FEATURES,
                "reviewed feature requests",
            )?;
            ordered(&self.packages, "reviewed members")?;
            ordered(&self.features, "reviewed feature requests")?;
            for name in &self.packages {
                nonempty(name, "reviewed member name")?;
                if !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                {
                    return Err(invalid("contains an invalid reviewed member name"));
                }
            }
            for feature in &self.features {
                nonempty(feature, "reviewed feature request")?;
            }
            Ok(())
        }

        fn parse(path: &Path, table: &Table) -> Result<Self> {
            require_keys(
                path,
                table,
                &[
                    "packages",
                    "features",
                    "all-features",
                    "no-default-features",
                ],
                &[],
            )?;
            let boolean = |key| {
                required_item(path, table, key)?
                    .as_bool()
                    .ok_or_else(|| invalid(format!("review scope `{key}` must be a boolean")))
            };
            let scope = Self {
                packages: required_strings(path, table, "packages")?,
                features: required_strings(path, table, "features")?,
                all_features: boolean("all-features")?,
                no_default_features: boolean("no-default-features")?,
            };
            scope.validate()?;
            Ok(scope)
        }

        fn write(&self, writer: &mut Writer) -> Result<()> {
            self.validate()?;
            writer.raw("\n[review-scope]\n")?;
            writer.strings("packages", &self.packages)?;
            writer.strings("features", &self.features)?;
            writer.boolean("all-features", self.all_features)?;
            writer.boolean("no-default-features", self.no_default_features)
        }
    }

    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct Context {
        pub host: String,
        pub target: String,
    }

    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub enum ReferenceSource {
        CratesIo,
        Git,
        Path,
    }

    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct DependencyReference {
        pub source: ReferenceSource,
        pub name: String,
        pub version: String,
    }

    /// Admitted packages come from crates.io or Git. A registry package is
    /// identified by its archive checksum, a Git package by its Cargo source.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SourceKind {
        Registry,
        Git,
    }

    impl SourceKind {
        /// The part of review table names that names this kind.
        fn table(self) -> &'static str {
            match self {
                Self::Registry => "registry",
                Self::Git => "git",
            }
        }

        /// The key that holds a package's `id` in review tables.
        fn id_key(self) -> &'static str {
            match self {
                Self::Registry => "checksum",
                Self::Git => "source",
            }
        }

        /// The prefix of messages about this kind.
        fn label(self) -> &'static str {
            match self {
                Self::Registry => "",
                Self::Git => "Git ",
            }
        }

        fn validate(self, name: &str, version: &str, id: &str) -> Result<()> {
            match self {
                Self::Registry => identity(name, version, id),
                Self::Git => {
                    nonempty(name, "Git package name")?;
                    canonical_version(version)?;
                    crate::git::parse_locked_source(id)
                        .map(drop)
                        .map_err(|error| invalid(format!("has an invalid Git source: {error}")))
                }
            }
        }

        /// Capability grants name a Git package by a digest of its source.
        fn grants(self, id: &str, capability: &Capability) -> bool {
            match self {
                Self::Registry => id == capability.checksum,
                Self::Git => source_digest(id) == capability.checksum,
            }
        }
    }

    /// A crates.io or Git package in Cargo.lock. `id` is the checksum or the
    /// Git source.
    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct Locked<D> {
        pub name: String,
        pub version: String,
        pub id: String,
        pub dependencies: Vec<D>,
    }

    impl<D> Locked<D> {
        fn key(&self) -> (&str, &str, &str) {
            (&self.name, &self.version, &self.id)
        }
    }

    /// Registry dependencies name their source. Git dependencies keep the
    /// Cargo.lock spelling.
    pub type LockedRegistry = Locked<DependencyReference>;
    pub type LockedGit = Locked<String>;

    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub enum UnitKind {
        Host,
        Target,
    }

    /// A crates.io or Git package that one reviewed context selects.
    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct ContextPackage {
        pub host: String,
        pub target: String,
        pub name: String,
        pub version: String,
        pub id: String,
        pub compile_kinds: Vec<UnitKind>,
        pub host_features: Vec<String>,
        pub target_features: Vec<String>,
    }

    impl ContextPackage {
        fn key(&self) -> (&str, &str, &str, &str, &str) {
            (
                &self.host,
                &self.target,
                &self.name,
                &self.version,
                &self.id,
            )
        }

        fn package(&self) -> (&str, &str, &str) {
            (&self.name, &self.version, &self.id)
        }
    }

    /// Verified evidence for a selected crates.io or Git package.
    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct SourceEvidence {
        pub name: String,
        pub version: String,
        pub id: String,
        pub license: String,
        pub source_tree_sha256: String,
        pub build_script: bool,
        pub proc_macro: bool,
    }

    impl SourceEvidence {
        fn key(&self) -> (&str, &str, &str) {
            (&self.name, &self.version, &self.id)
        }
    }

    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct Capability {
        pub package: String,
        pub version: String,
        pub checksum: String,
        pub build_script: bool,
        pub proc_macro: bool,
        pub native_tools: Vec<NativeToolRole>,
        pub caller_env: Vec<String>,
    }

    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    pub struct Review {
        pub scope: ReviewScope,
        pub resolver_version: u64,
        pub contexts: Vec<Context>,
        pub locked_registry: Vec<LockedRegistry>,
        pub locked_git: Vec<LockedGit>,
        pub context_registry: Vec<ContextPackage>,
        pub context_git: Vec<ContextPackage>,
        pub registry_sources: Vec<SourceEvidence>,
        pub git_sources: Vec<SourceEvidence>,
        pub capabilities: Vec<Capability>,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct CompactState {
        pub scope: ReviewScope,
        pub review_sha256: String,
        pub contexts: Vec<Context>,
        pub capabilities: Vec<Capability>,
    }

    impl CompactState {
        pub fn path(root: &Path) -> PathBuf {
            root.join(RELATIVE_PATH)
        }

        /// Strictly parses the project's compact state. A missing file is not
        /// an error: Lorry-registry builds then reject crates.io and Git
        /// packages, and Cargo-registry builds rely on policy alone.
        pub fn load(root: &Path) -> Result<Option<Self>> {
            Self::document(root)?
                .map(|(path, document)| Self::from_document(&path, &document))
                .transpose()
        }

        /// Loads the state a new workspace review replaces. A retired record
        /// counts as absent, so vendor can follow its own rejection advice.
        pub fn load_replaceable(root: &Path) -> Result<Option<Self>> {
            match Self::document(root)? {
                Some((_, document)) if retired(&document) => Ok(None),
                Some((path, document)) => Self::from_document(&path, &document).map(Some),
                None => Ok(None),
            }
        }

        /// Reports whether the state is a regular file without parsing it.
        pub fn exists(root: &Path) -> Result<bool> {
            let path = Self::path(root);
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                    Err(Error::failure(format!(
                        "Lorry dependency state `{}` is not a regular file",
                        path.display()
                    )))
                }
                Ok(_) => Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(Error::failure(format!(
                    "failed to inspect Lorry dependency state `{}`: {error}",
                    path.display()
                ))),
            }
        }

        fn document(root: &Path) -> Result<Option<(PathBuf, Document)>> {
            if !Self::exists(root)? {
                return Ok(None);
            }
            let path = Self::path(root);
            let document = Document::load(&path, "Lorry compact dependency state")?;
            Ok(Some((path, document)))
        }

        #[cfg(test)]
        pub fn parse(path: &Path, source: String) -> Result<Self> {
            let document = Document::parse(path, "Lorry compact dependency state", source)?;
            Self::from_document(path, &document)
        }

        pub fn write(&self, root: &Path) -> Result<()> {
            let directory = root.join(".lorry");
            match fs::symlink_metadata(&directory) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                    return Err(Error::failure(format!(
                        "Lorry state directory `{}` is not a real directory",
                        directory.display()
                    )));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&directory).map_err(|error| {
                        Error::failure(format!(
                            "failed to create Lorry state directory `{}`: {error}",
                            directory.display()
                        ))
                    })?;
                    #[cfg(unix)]
                    fs::set_permissions(
                        &directory,
                        std::os::unix::fs::PermissionsExt::from_mode(0o700),
                    )
                    .map_err(|error| {
                        Error::failure(format!(
                            "failed to make Lorry state directory `{}` private: {error}",
                            directory.display()
                        ))
                    })?;
                }
                Err(error) => {
                    return Err(Error::failure(format!(
                        "failed to inspect Lorry state directory `{}`: {error}",
                        directory.display()
                    )));
                }
            }
            let mut staged = AtomicFile::new(&Self::path(root))?;
            staged.write_all(&self.render()?)?;
            staged.commit()
        }

        pub fn require_context(&self, host: &str, target: &str) -> Result<()> {
            if self
                .contexts
                .iter()
                .any(|context| context.host == host && context.target == target)
            {
                Ok(())
            } else {
                Err(Error::failure(format!(
                    "Lorry dependency state does not admit build context `{host} -> {target}`"
                ))
                .with_help(
                    "run `lorry vendor [--accept-all]` on this host with the target in the configured \
                     `[vendor].targets` set",
                ))
            }
        }

        fn from_document(path: &Path, document: &Document) -> Result<Self> {
            if retired(document) {
                return Err(Error::failure(format!(
                    "Lorry dependency state `{}` uses the retired single-package review format 3",
                    path.display()
                ))
                .with_help(
                    "run `lorry vendor --locked` again at the workspace root to review the workspace",
                ));
            }
            require_keys(
                path,
                document.root(),
                &[
                    "format-version",
                    "review-format-version",
                    "review-sha256",
                    "review-scope",
                    "context",
                ],
                &["capability"],
            )?;
            compact_version(
                path,
                document.root(),
                "format-version",
                COMPACT_FORMAT_VERSION,
            )?;
            compact_version(
                path,
                document.root(),
                "review-format-version",
                REVIEW_FORMAT_VERSION,
            )?;
            let scope = ReviewScope::parse(
                path,
                required_item(path, document.root(), "review-scope")?
                    .as_table()
                    .ok_or_else(|| invalid("review scope must be a table"))?,
            )?;
            let state = Self {
                scope,
                review_sha256: required_string(path, document.root(), "review-sha256")?,
                contexts: parse_compact_contexts(path, document)?,
                capabilities: parse_compact_capabilities(path, document)?,
            };
            state.render()?;
            Ok(state)
        }

        pub fn render(&self) -> Result<Vec<u8>> {
            self.validate()?;
            let mut writer = Writer::compact();
            writer.raw("# Generated by Lorry. Do not edit.\n")?;
            writer.integer("format-version", COMPACT_FORMAT_VERSION)?;
            writer.integer("review-format-version", REVIEW_FORMAT_VERSION)?;
            writer.string("review-sha256", &self.review_sha256)?;
            self.scope.write(&mut writer)?;
            write_contexts(&mut writer, &self.contexts)?;
            write_capabilities(&mut writer, &self.capabilities)?;
            writer.finish()
        }

        pub fn validate(&self) -> Result<()> {
            digest(&self.review_sha256, "review digest")?;
            self.scope.validate()?;
            validate_contexts(&self.contexts)?;
            validate_capabilities(&self.capabilities)
        }
    }

    impl Review {
        /// Builds the graph portion of the canonical document from the root
        /// resolver and the lockfile. Scope and contexts come from compact
        /// state or the vendor candidate; context resolution, source evidence,
        /// and capabilities are later builder stages.
        pub fn from_graph(
            manifest: &Manifest,
            lock: &Lockfile,
            contexts: Vec<Context>,
        ) -> Result<Self> {
            let review = Self {
                resolver_version: match manifest.resolver {
                    Resolver::V1 => 1,
                    Resolver::V2 => 2,
                    Resolver::V3 => 3,
                },
                contexts,
                locked_registry: locked_graph(lock)?,
                locked_git: locked_git_graph(lock)?,
                ..Self::default()
            };
            review.validate()?;
            Ok(review)
        }

        /// Records one reviewed context's independently resolved registry and
        /// Git selection and its verified source evidence. Path packages keep
        /// their independent rules and never enter admission.
        pub fn add_context_resolution(
            &mut self,
            context: &Context,
            resolution: &Resolution,
            evidence: &BTreeMap<PackageKey, PackageEvidence>,
        ) -> Result<()> {
            if !self.contexts.contains(context) {
                return Err(invalid(format!(
                    "cannot record a resolution for unreviewed context `{} -> {}`",
                    context.host, context.target
                )));
            }
            for package in &resolution.packages {
                let (kind, id) = match &package.source {
                    ResolvedSource::CratesIo { checksum } => (SourceKind::Registry, hex(checksum)),
                    ResolvedSource::Git { cargo_source, .. } => {
                        (SourceKind::Git, cargo_source.clone())
                    }
                    ResolvedSource::Path { .. } => continue,
                };
                let version = package.key.version.to_string();
                let package_evidence = evidence.get(&package.key).ok_or_else(|| {
                    invalid(format!(
                        "is missing verified evidence for `{} {version}`",
                        package.key.name
                    ))
                })?;
                let mut compile_kinds: Vec<UnitKind> = package
                    .compile_kinds
                    .iter()
                    .map(|kind| match kind {
                        CompileKind::Host => UnitKind::Host,
                        CompileKind::Target => UnitKind::Target,
                    })
                    .collect();
                compile_kinds.sort();
                let (selected, sources) = match kind {
                    SourceKind::Registry => {
                        (&mut self.context_registry, &mut self.registry_sources)
                    }
                    SourceKind::Git => (&mut self.context_git, &mut self.git_sources),
                };
                selected.push(ContextPackage {
                    host: context.host.clone(),
                    target: context.target.clone(),
                    name: package.key.name.clone(),
                    version: version.clone(),
                    id: id.clone(),
                    compile_kinds,
                    host_features: package.host_features.iter().cloned().collect(),
                    target_features: package.target_features.iter().cloned().collect(),
                });
                let source = SourceEvidence {
                    name: package.key.name.clone(),
                    version,
                    id,
                    license: package_evidence.license.clone(),
                    source_tree_sha256: hex(&package_evidence.source_tree_sha256),
                    build_script: package_evidence.build_script,
                    proc_macro: package_evidence.proc_macro,
                };
                match sources.binary_search_by(|value| value.key().cmp(&source.key())) {
                    Ok(index) if sources[index] == source => {}
                    Ok(_) => {
                        return Err(invalid(format!(
                            "has conflicting {}evidence for `{} {}`",
                            kind.label(),
                            source.name,
                            source.version
                        )));
                    }
                    Err(index) => sources.insert(index, source),
                }
            }
            self.context_registry.sort_by(|a, b| a.key().cmp(&b.key()));
            self.context_git.sort_by(|a, b| a.key().cmp(&b.key()));
            Ok(())
        }

        /// Adopts the compact capability grants and validates the completed
        /// document.
        pub fn complete(&mut self, capabilities: Vec<Capability>) -> Result<()> {
            self.capabilities = capabilities;
            self.validate()
        }

        /// The lowercase SHA-256 commitment over the exact canonical bytes.
        pub fn commitment(&self) -> Result<String> {
            Ok(sha256(&self.render()?))
        }

        /// Synthesizes exact generated allow rules from reconstructed
        /// evidence and explicit capabilities. Explicit configured denies
        /// retain precedence through ordinary policy evaluation.
        pub fn apply_to_policy(&self, policy: &mut Policy, root: &Path) -> Result<()> {
            for (kind, _, sources) in self.kinds() {
                for (index, source) in sources.iter().enumerate() {
                    let id = match kind {
                        SourceKind::Registry => format!("lorry-state-{index:05}"),
                        SourceKind::Git => format!("lorry-state-git-{index:05}"),
                    };
                    if policy.rules.contains_key(&id) {
                        return Err(Error::failure(format!(
                            "configured policy rule `{id}` conflicts with generated dependency state"
                        )));
                    }
                    let capability = self.capabilities.iter().find(|capability| {
                        capability.package == source.name
                            && capability.version == source.version
                            && kind.grants(&source.id, capability)
                    });
                    let version = semver::VersionReq::parse(&format!("={}", source.version))
                        .map_err(|error| {
                            Error::failure(format!(
                                "dependency state has invalid exact {}version for `{} {}`: {error}",
                                kind.label(),
                                source.name,
                                source.version
                            ))
                        })?;
                    policy.rules.insert(
                        id,
                        PolicyRule {
                            action: PolicyAction::Allow,
                            name: Some(source.name.clone()),
                            version: Some(version),
                            source: Some(
                                match kind {
                                    SourceKind::Registry => "crates.io",
                                    SourceKind::Git => "git",
                                }
                                .to_owned(),
                            ),
                            checksum: (kind == SourceKind::Registry).then(|| source.id.clone()),
                            source_tree_sha256: Some(source.source_tree_sha256.clone()),
                            license: Some(source.license.clone()),
                            allow_build_script: capability.is_some_and(|value| value.build_script),
                            allow_proc_macro: capability.is_some_and(|value| value.proc_macro),
                            native_tools: capability
                                .map(|capability| capability.native_tools.iter().copied().collect())
                                .unwrap_or_default(),
                            caller_env: capability
                                .map(|value| value.caller_env.iter().cloned().collect())
                                .unwrap_or_default(),
                            provenance: CompactState::path(root),
                        },
                    );
                }
            }
            Ok(())
        }

        /// Each source kind with its context selections and source evidence.
        fn kinds(&self) -> [(SourceKind, &[ContextPackage], &[SourceEvidence]); 2] {
            [
                (
                    SourceKind::Registry,
                    &self.context_registry,
                    &self.registry_sources,
                ),
                (SourceKind::Git, &self.context_git, &self.git_sources),
            ]
        }

        pub fn render(&self) -> Result<Vec<u8>> {
            self.validate()?;
            let mut writer = Writer::new();
            writer.integer("review-format-version", REVIEW_FORMAT_VERSION)?;
            writer.integer("source-tree-format-version", 1)?;
            writer.integer("cargo-lock-format-version", 4)?;
            writer.integer("resolver-version", self.resolver_version)?;
            self.scope.write(&mut writer)?;
            write_contexts(&mut writer, &self.contexts)?;
            for value in &self.locked_registry {
                writer.table("locked-registry")?;
                write_identity(&mut writer, SourceKind::Registry, value.key())?;
                writer.dependencies(&value.dependencies)?;
            }
            for value in &self.locked_git {
                writer.table("locked-git")?;
                write_identity(&mut writer, SourceKind::Git, value.key())?;
                writer.strings("dependencies", &value.dependencies)?;
            }
            for (kind, selected, _) in self.kinds() {
                for value in selected {
                    writer.table(&format!("context-{}", kind.table()))?;
                    writer.string("host", &value.host)?;
                    writer.string("target", &value.target)?;
                    write_identity(&mut writer, kind, value.package())?;
                    writer.names("compile-kinds", &value.compile_kinds, unit_kind_name)?;
                    writer.strings("host-features", &value.host_features)?;
                    writer.strings("target-features", &value.target_features)?;
                }
            }
            for (kind, _, sources) in self.kinds() {
                for value in sources {
                    writer.table(&format!("{}-source", kind.table()))?;
                    write_identity(&mut writer, kind, value.key())?;
                    writer.string("license", &value.license)?;
                    writer.string("source-tree-sha256", &value.source_tree_sha256)?;
                    writer.boolean("build-script", value.build_script)?;
                    writer.boolean("proc-macro", value.proc_macro)?;
                }
            }
            write_capabilities(&mut writer, &self.capabilities)?;
            writer.finish()
        }

        pub fn validate(&self) -> Result<()> {
            self.scope.validate()?;
            validate_contexts(&self.contexts)?;
            validate_capabilities(&self.capabilities)?;
            if !(1..=3).contains(&self.resolver_version) {
                return Err(invalid("has an unsupported resolver version"));
            }
            limit(self.locked_registry.len(), MAX_TABLES, "locked packages")?;
            limit(self.locked_git.len(), MAX_TABLES, "locked Git packages")?;
            ordered_by(
                &self.locked_registry,
                |a, b| a.key().cmp(&b.key()),
                "locked packages",
            )?;
            ordered_by(
                &self.locked_git,
                |a, b| a.key().cmp(&b.key()),
                "locked Git packages",
            )?;
            for value in &self.locked_registry {
                ordered(&value.dependencies, "locked dependency references")?;
            }
            for value in &self.locked_git {
                ordered(&value.dependencies, "locked Git dependency references")?;
            }
            for (kind, selected, sources) in self.kinds() {
                let label = kind.label();
                limit(
                    selected.len(),
                    MAX_CONTEXT_PACKAGES,
                    &format!("context {label}package memberships"),
                )?;
                limit(
                    sources.len(),
                    MAX_TABLES,
                    &format!("{label}source evidence"),
                )?;
                ordered_by(
                    selected,
                    |a, b| a.key().cmp(&b.key()),
                    &format!("context {label}packages"),
                )?;
                ordered_by(
                    sources,
                    |a, b| a.key().cmp(&b.key()),
                    &format!("{label}source evidence"),
                )?;
                for value in selected {
                    if value.compile_kinds.is_empty() {
                        return Err(invalid(format!(
                            "contains a context {label}package with no compile kind"
                        )));
                    }
                    ordered(&value.compile_kinds, &format!("{label}compile kinds"))?;
                    ordered(&value.host_features, &format!("{label}host features"))?;
                    ordered(&value.target_features, &format!("{label}target features"))?;
                }
            }
            self.validate_values()?;
            self.validate_relationships()
        }

        fn validate_values(&self) -> Result<()> {
            let mut edges = 0;
            let mut features = 0;
            for value in &self.locked_registry {
                SourceKind::Registry.validate(&value.name, &value.version, &value.id)?;
                add(
                    &mut edges,
                    value.dependencies.len(),
                    MAX_EDGES,
                    "dependency edges",
                )?;
                for dependency in &value.dependencies {
                    nonempty(&dependency.name, "dependency-reference name")?;
                    canonical_version(&dependency.version)?;
                }
            }
            for value in &self.locked_git {
                SourceKind::Git.validate(&value.name, &value.version, &value.id)?;
                add(
                    &mut edges,
                    value.dependencies.len(),
                    MAX_EDGES,
                    "dependency edges",
                )?;
            }
            for (kind, selected, sources) in self.kinds() {
                for value in selected {
                    kind.validate(&value.name, &value.version, &value.id)?;
                    for values in [&value.host_features, &value.target_features] {
                        add(&mut features, values.len(), MAX_FEATURES, "features")?;
                    }
                }
                for value in sources {
                    kind.validate(&value.name, &value.version, &value.id)?;
                    digest(
                        &value.source_tree_sha256,
                        &format!("{}source-tree digest", kind.label()),
                    )?;
                }
            }
            Ok(())
        }

        fn validate_relationships(&self) -> Result<()> {
            let contexts: BTreeSet<_> = self
                .contexts
                .iter()
                .map(|value| (&*value.host, &*value.target))
                .collect();
            let mut locked_versions = BTreeSet::new();
            for value in &self.locked_registry {
                if !locked_versions.insert((&*value.name, &*value.version)) {
                    return Err(invalid("repeats a crates.io package name and version"));
                }
            }
            for value in &self.locked_registry {
                for dependency in &value.dependencies {
                    if dependency.source == ReferenceSource::CratesIo
                        && !locked_versions.contains(&(&*dependency.name, &*dependency.version))
                    {
                        return Err(invalid("contains an unresolved crates.io lock edge"));
                    }
                }
            }
            let locked: [BTreeSet<_>; 2] = [
                self.locked_registry.iter().map(Locked::key).collect(),
                self.locked_git.iter().map(Locked::key).collect(),
            ];
            for ((kind, selected, sources), locked) in self.kinds().into_iter().zip(&locked) {
                let label = kind.label();
                let mut packages = BTreeSet::new();
                for value in selected {
                    if !contexts.contains(&(&*value.host, &*value.target)) {
                        return Err(invalid(format!(
                            "contains a {label}package for an unreviewed context"
                        )));
                    }
                    if !locked.contains(&value.package()) {
                        return Err(invalid(format!(
                            "contains a context {label}package absent from Cargo.lock"
                        )));
                    }
                    packages.insert(value.package());
                }
                limit(
                    packages.len(),
                    MAX_TABLES,
                    &format!("distinct selected {label}packages"),
                )?;
                if sources
                    .iter()
                    .map(SourceEvidence::key)
                    .collect::<BTreeSet<_>>()
                    != packages
                {
                    return Err(invalid(format!(
                        "{label}source evidence does not equal selected {label}packages"
                    )));
                }
            }
            for capability in &self.capabilities {
                let valid = self.kinds().into_iter().any(|(kind, _, sources)| {
                    sources.iter().any(|value| {
                        value.name == capability.package
                            && value.version == capability.version
                            && kind.grants(&value.id, capability)
                            && (!capability.build_script || value.build_script)
                            && (!capability.proc_macro || value.proc_macro)
                    })
                });
                if !valid {
                    return Err(invalid(
                        "contains a capability without matching executable-code evidence",
                    ));
                }
            }
            Ok(())
        }
    }

    fn capability_key(value: &Capability) -> (&str, &str, &str) {
        (&value.package, &value.version, &value.checksum)
    }

    fn validate_contexts(values: &[Context]) -> Result<()> {
        limit(values.len(), MAX_CONTEXTS, "reviewed contexts")?;
        if values.is_empty() {
            return Err(invalid("has no context"));
        }
        ordered(values, "contexts")?;
        for value in values {
            nonempty(&value.host, "context host")?;
            nonempty(&value.target, "context target")?;
        }
        Ok(())
    }

    fn validate_capabilities(values: &[Capability]) -> Result<()> {
        limit(values.len(), MAX_TABLES, "capabilities")?;
        ordered_by(
            values,
            |a, b| capability_key(a).cmp(&capability_key(b)),
            "capabilities",
        )?;
        for value in values {
            identity(&value.package, &value.version, &value.checksum)?;
            ordered_by(
                &value.native_tools,
                |a, b| native_tool_name(*a).cmp(native_tool_name(*b)),
                "native-tool roles",
            )?;
            if !value.build_script && !value.proc_macro {
                return Err(invalid(
                    "contains a capability without an executable-code grant",
                ));
            }
            if !value.build_script && !value.native_tools.is_empty() {
                return Err(invalid(
                    "contains native-tool grants without a build-script grant",
                ));
            }
            ordered(&value.caller_env, "caller environment names")?;
            for name in &value.caller_env {
                crate::build_script::validate_caller_environment_name(name)?;
            }
            if !value.build_script && !value.caller_env.is_empty() {
                return Err(invalid(
                    "contains caller environment grants without a build-script grant",
                ));
            }
        }
        Ok(())
    }

    fn unit_kind_name(value: UnitKind) -> &'static str {
        match value {
            UnitKind::Host => "host",
            UnitKind::Target => "target",
        }
    }

    impl std::fmt::Display for UnitKind {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(unit_kind_name(*self))
        }
    }

    fn reference_source_name(value: ReferenceSource) -> &'static str {
        match value {
            ReferenceSource::CratesIo => "crates.io",
            ReferenceSource::Git => "git",
            ReferenceSource::Path => "path",
        }
    }

    /// The canonical `source name version` spelling of a locked dependency.
    impl std::fmt::Display for DependencyReference {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let source = reference_source_name(self.source);
            write!(formatter, "{source} {} {}", self.name, self.version)
        }
    }

    fn write_identity(
        writer: &mut Writer,
        kind: SourceKind,
        (name, version, id): (&str, &str, &str),
    ) -> Result<()> {
        writer.string("name", name)?;
        writer.string("version", version)?;
        writer.string(kind.id_key(), id)
    }

    fn write_contexts(writer: &mut Writer, values: &[Context]) -> Result<()> {
        for value in values {
            writer.table("context")?;
            writer.string("host", &value.host)?;
            writer.string("target", &value.target)?;
        }
        Ok(())
    }

    fn write_capabilities(writer: &mut Writer, values: &[Capability]) -> Result<()> {
        for value in values {
            writer.table("capability")?;
            writer.string("package", &value.package)?;
            writer.string("version", &value.version)?;
            writer.string("checksum", &value.checksum)?;
            writer.boolean("build-script", value.build_script)?;
            writer.boolean("proc-macro", value.proc_macro)?;
            writer.names("native-tools", &value.native_tools, native_tool_name)?;
            if !value.caller_env.is_empty() {
                writer.strings("caller-env", &value.caller_env)?;
            }
        }
        Ok(())
    }

    fn retired(document: &Document) -> bool {
        document
            .root()
            .get("review-format-version")
            .and_then(Item::as_integer)
            == Some(RETIRED_REVIEW_FORMAT_VERSION)
    }

    fn compact_version(path: &Path, table: &Table, key: &str, expected: u64) -> Result<()> {
        if required_item(path, table, key)?.as_integer() == Some(expected as i64) {
            Ok(())
        } else {
            Err(Error::failure(format!(
                "unsupported `{key}` in compact dependency state `{}`",
                path.display()
            )))
        }
    }

    fn parse_compact_contexts(path: &Path, document: &Document) -> Result<Vec<Context>> {
        let tables = required_item(path, document.root(), "context")?
            .as_array_of_tables()
            .ok_or_else(|| {
                Error::failure(format!(
                    "`context` in `{}` must be an array of tables",
                    path.display()
                ))
            })?;
        tables
            .iter()
            .map(|table| {
                require_keys(path, table, &["host", "target"], &[])?;
                Ok(Context {
                    host: required_string(path, table, "host")?,
                    target: required_string(path, table, "target")?,
                })
            })
            .collect()
    }

    fn parse_compact_capabilities(path: &Path, document: &Document) -> Result<Vec<Capability>> {
        let Some(item) = document.root().get("capability") else {
            return Ok(Vec::new());
        };
        let tables = item.as_array_of_tables().ok_or_else(|| {
            Error::failure(format!(
                "`capability` in `{}` must be an array of tables",
                path.display()
            ))
        })?;
        tables
            .iter()
            .map(|table| {
                require_keys(
                    path,
                    table,
                    &[
                        "package",
                        "version",
                        "checksum",
                        "build-script",
                        "proc-macro",
                        "native-tools",
                    ],
                    &["caller-env"],
                )?;
                let native_tools = required_strings(path, table, "native-tools")?
                    .into_iter()
                    .map(|value| match value.as_str() {
                        "archiver" => Ok(NativeToolRole::Archiver),
                        "c-compiler" => Ok(NativeToolRole::CCompiler),
                        "cxx-compiler" => Ok(NativeToolRole::CxxCompiler),
                        _ => Err(Error::failure(format!(
                            "compact dependency state `{}` has unsupported native-tool role `{value}`",
                            path.display()
                        ))),
                    })
                    .collect::<Result<Vec<_>>>()?;
                let build_script = required_item(path, table, "build-script")?
                    .as_bool()
                    .ok_or_else(|| {
                        Error::failure(format!(
                            "`build-script` in `{}` must be a boolean",
                            path.display()
                        ))
                    })?;
                let proc_macro = required_item(path, table, "proc-macro")?
                    .as_bool()
                    .ok_or_else(|| {
                        Error::failure(format!(
                            "`proc-macro` in `{}` must be a boolean",
                            path.display()
                        ))
                    })?;
                Ok(Capability {
                    package: required_string(path, table, "package")?,
                    version: required_string(path, table, "version")?,
                    checksum: required_string(path, table, "checksum")?,
                    build_script,
                    proc_macro,
                    native_tools,
                    caller_env: if table.contains_key("caller-env") {
                        required_strings(path, table, "caller-env")?
                    } else { Vec::new() },
                })
            })
            .collect()
    }

    fn limit(actual: usize, maximum: usize, description: &str) -> Result<()> {
        if actual > maximum {
            Err(invalid(format!(
                "{description} exceed the limit of {maximum}"
            )))
        } else {
            Ok(())
        }
    }

    fn add(total: &mut usize, count: usize, maximum: usize, description: &str) -> Result<()> {
        *total = total
            .checked_add(count)
            .ok_or_else(|| invalid(format!("{description} overflowed")))?;
        limit(*total, maximum, description)
    }

    fn nonempty(value: &str, description: &str) -> Result<()> {
        if value.is_empty() {
            Err(invalid(format!("contains an empty {description}")))
        } else {
            Ok(())
        }
    }

    fn canonical_version(value: &str) -> Result<()> {
        let parsed = semver::Version::parse(value)
            .map_err(|error| invalid(format!("has invalid version `{value}`: {error}")))?;
        if parsed.to_string() != value {
            return Err(invalid(format!("has noncanonical version `{value}`")));
        }
        Ok(())
    }

    const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

    fn locked_graph(lock: &Lockfile) -> Result<Vec<LockedRegistry>> {
        let mut nodes: BTreeMap<&str, Vec<(&LockedPackage, ReferenceSource)>> = BTreeMap::new();
        for package in &lock.packages {
            let source = match package.source.as_deref() {
                None => ReferenceSource::Path,
                Some(CRATES_IO_SOURCE) => ReferenceSource::CratesIo,
                Some(other) if crate::git::parse_locked_source(other).is_ok() => {
                    ReferenceSource::Git
                }
                Some(other) => {
                    return Err(invalid(format!(
                        "cannot reference unsupported Cargo.lock source `{other}`"
                    )));
                }
            };
            nodes
                .entry(&package.name)
                .or_default()
                .push((package, source));
        }
        let mut result = Vec::new();
        for package in &lock.packages {
            if package.source.as_deref() != Some(CRATES_IO_SOURCE) {
                continue;
            }
            let checksum = package.checksum.clone().ok_or_else(|| {
                invalid(format!(
                    "is missing the checksum of `{} {}`",
                    package.name, package.version.original
                ))
            })?;
            let mut dependencies = package
                .dependencies
                .iter()
                .map(|spelling| resolve_reference(&nodes, spelling, lock.format))
                .collect::<Result<Vec<_>>>()?;
            dependencies.sort();
            result.push(LockedRegistry {
                name: package.name.clone(),
                version: package.version.original.clone(),
                id: checksum,
                dependencies,
            });
        }
        result.sort_by(|a, b| a.key().cmp(&b.key()));
        Ok(result)
    }

    fn locked_git_graph(lock: &Lockfile) -> Result<Vec<LockedGit>> {
        let mut result = Vec::new();
        for package in &lock.packages {
            let Some(source) = package.source.as_deref() else {
                continue;
            };
            if crate::git::parse_locked_source(source).is_err() {
                continue;
            }
            result.push(LockedGit {
                name: package.name.clone(),
                version: package.version.original.clone(),
                id: source.to_owned(),
                dependencies: sorted_set(
                    &package.dependencies,
                    "locked Git dependency references",
                )?,
            });
        }
        result.sort_by(|a, b| a.key().cmp(&b.key()));
        Ok(result)
    }

    // A lock dependency spelling is `NAME`, `NAME VERSION`, or
    // `NAME VERSION (SOURCE)`; every spelling must select exactly one node.
    fn resolve_reference(
        nodes: &BTreeMap<&str, Vec<(&LockedPackage, ReferenceSource)>>,
        spelling: &str,
        format: crate::lockfile::Format,
    ) -> Result<DependencyReference> {
        let mut fields = spelling.split(' ');
        let name = fields.next().unwrap_or_default();
        let version = fields.next();
        let source = fields
            .next()
            .map(|value| {
                value
                    .strip_prefix('(')
                    .and_then(|value| value.strip_suffix(')'))
                    .ok_or_else(|| {
                        invalid(format!(
                            "has a malformed Cargo.lock dependency source in `{spelling}`"
                        ))
                    })
            })
            .transpose()?;
        if name.is_empty() || fields.next().is_some() {
            return Err(invalid(format!(
                "has a malformed Cargo.lock dependency `{spelling}`"
            )));
        }
        let candidates: Vec<_> = nodes
            .get(name)
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter(|(package, _)| version.is_none_or(|value| package.version.original == value))
            .filter(|(package, _)| {
                source.is_none_or(|value| {
                    package.source.as_deref().is_some_and(|locked| {
                        crate::offline::lock_source_matches(value, locked, format)
                    })
                })
            })
            .collect();
        match candidates.as_slice() {
            [(package, source)] => Ok(DependencyReference {
                source: *source,
                name: package.name.clone(),
                version: package.version.original.clone(),
            }),
            [] => Err(invalid(format!(
                "has an unresolved Cargo.lock dependency `{spelling}`"
            ))),
            _ => Err(invalid(format!(
                "has an ambiguous Cargo.lock dependency `{spelling}`"
            ))),
        }
    }

    fn sorted_set(values: &[String], description: &str) -> Result<Vec<String>> {
        let mut values = values.to_vec();
        values.sort();
        ordered(&values, description)?;
        Ok(values)
    }

    fn identity(name: &str, version: &str, checksum: &str) -> Result<()> {
        nonempty(name, "package name")?;
        canonical_version(version)?;
        digest(checksum, "package checksum")
    }

    fn digest(value: &str, description: &str) -> Result<()> {
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(())
        } else {
            Err(invalid(format!(
                "has an invalid lowercase SHA-256 {description}"
            )))
        }
    }

    fn ordered<T: Ord>(values: &[T], description: &str) -> Result<()> {
        ordered_by(values, Ord::cmp, description)
    }

    fn ordered_by<T>(
        values: &[T],
        compare: impl Fn(&T, &T) -> std::cmp::Ordering,
        description: &str,
    ) -> Result<()> {
        if values
            .windows(2)
            .any(|pair| compare(&pair[0], &pair[1]).is_ge())
        {
            Err(invalid(format!("{description} are not sorted and unique")))
        } else {
            Ok(())
        }
    }

    pub fn sha256(bytes: &[u8]) -> String {
        let mut digest = Sha256::new();
        digest.update(bytes);
        hex(&digest.finish())
    }

    pub struct Writer {
        output: Vec<u8>,
        items: usize,
        max_bytes: usize,
    }

    impl Writer {
        pub fn new() -> Self {
            Self::with_max_bytes(MAX_REPORT_BYTES)
        }

        pub fn compact() -> Self {
            Self::with_max_bytes(MAX_COMPACT_BYTES)
        }

        fn with_max_bytes(max_bytes: usize) -> Self {
            Self {
                output: Vec::new(),
                items: 0,
                max_bytes,
            }
        }

        pub fn finish(self) -> Result<Vec<u8>> {
            if !self.output.ends_with(b"\n") || self.output.ends_with(b"\n\n") {
                return Err(invalid("must have exactly one final LF"));
            }
            Ok(self.output)
        }

        pub fn table(&mut self, name: &str) -> Result<()> {
            self.raw("\n[[")?;
            self.raw(name)?;
            self.raw("]]\n")
        }

        pub fn integer(&mut self, key: &str, value: u64) -> Result<()> {
            self.item()?;
            self.raw(key)?;
            self.raw(" = ")?;
            self.raw(&value.to_string())?;
            self.raw("\n")
        }

        pub fn string(&mut self, key: &str, value: &str) -> Result<()> {
            self.item()?;
            self.raw(key)?;
            self.raw(" = ")?;
            self.quoted(value)?;
            self.raw("\n")
        }

        pub fn boolean(&mut self, key: &str, value: bool) -> Result<()> {
            self.item()?;
            self.raw(key)?;
            self.raw(if value { " = true\n" } else { " = false\n" })
        }

        pub fn strings(&mut self, key: &str, values: &[String]) -> Result<()> {
            self.raw(key)?;
            self.raw(" = [")?;
            for (index, value) in values.iter().enumerate() {
                self.item()?;
                if index != 0 {
                    self.raw(", ")?;
                }
                self.quoted(value)?;
            }
            self.raw("]\n")
        }

        pub fn names<T: Copy>(
            &mut self,
            key: &str,
            values: &[T],
            name: fn(T) -> &'static str,
        ) -> Result<()> {
            self.raw(key)?;
            self.raw(" = [")?;
            for (index, value) in values.iter().enumerate() {
                self.item()?;
                if index != 0 {
                    self.raw(", ")?;
                }
                self.quoted(name(*value))?;
            }
            self.raw("]\n")
        }

        pub fn dependencies(&mut self, values: &[DependencyReference]) -> Result<()> {
            self.raw("dependencies = [")?;
            if values.is_empty() {
                return self.raw("]\n");
            }
            self.raw("\n")?;
            for value in values {
                self.item()?;
                self.raw("    ")?;
                self.quoted(&value.to_string())?;
                self.raw(",\n")?;
            }
            self.raw("]\n")
        }

        fn raw(&mut self, value: &str) -> Result<()> {
            if self.output.len().saturating_add(value.len()) > self.max_bytes {
                return Err(invalid(format!(
                    "exceeds the byte limit of {}",
                    self.max_bytes
                )));
            }
            self.output.extend_from_slice(value.as_bytes());
            Ok(())
        }

        fn item(&mut self) -> Result<()> {
            self.items = self
                .items
                .checked_add(1)
                .ok_or_else(|| invalid("item count overflowed"))?;
            if self.items > MAX_ITEMS {
                return Err(invalid(format!(
                    "scalar fields and array elements exceed the limit of {MAX_ITEMS}"
                )));
            }
            Ok(())
        }

        fn quoted(&mut self, value: &str) -> Result<()> {
            if value.len() > MAX_STRING_BYTES {
                return Err(invalid(format!(
                    "a decoded string exceeds the byte limit of {MAX_STRING_BYTES}"
                )));
            }
            self.raw("\"")?;
            for character in value.chars() {
                match character {
                    '"' => self.raw("\\\"")?,
                    '\\' => self.raw("\\\\")?,
                    '\n' => self.raw("\\n")?,
                    '\r' => self.raw("\\r")?,
                    '\t' => self.raw("\\t")?,
                    character if character.is_control() => {
                        let escape = if character as u32 <= 0xffff {
                            format!("\\u{:04X}", character as u32)
                        } else {
                            format!("\\U{:08X}", character as u32)
                        };
                        self.raw(&escape)?;
                    }
                    character => self.raw(character.encode_utf8(&mut [0; 4]))?,
                }
            }
            self.raw("\"")
        }
    }

    fn invalid(message: impl std::fmt::Display) -> Error {
        Error::failure(format!("canonical dependency review {message}"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::resolver::{PackageSourceKey, ResolvedPackage};

        fn empty_review() -> Review {
            Review {
                resolver_version: 2,
                contexts: vec![Context {
                    host: "x86_64-unknown-linux-gnu".to_owned(),
                    target: "x86_64-unknown-motor".to_owned(),
                }],
                ..Review::default()
            }
        }

        fn compact_state() -> CompactState {
            CompactState {
                scope: ReviewScope::default(),
                review_sha256: "44".repeat(32),
                contexts: empty_review().contexts,
                capabilities: Vec::new(),
            }
        }

        #[test]
        fn workspace_scope_round_trips_and_is_part_of_the_commitment() {
            let scope = ReviewScope {
                packages: vec!["app".to_owned(), "helper".to_owned()],
                features: vec!["app/extra".to_owned()],
                all_features: false,
                no_default_features: true,
            };
            let mut compact = compact_state();
            compact.scope = scope.clone();
            let bytes = compact.render().unwrap();
            let text = String::from_utf8(bytes).unwrap();
            assert!(text.contains("review-format-version = 4"));
            assert_eq!(
                CompactState::parse(Path::new("state.toml"), text.clone()).unwrap(),
                compact
            );
            let unscoped = text.split_once("\n[review-scope]").unwrap().0.to_owned()
                + &text[text.find("\n[[context]]").unwrap()..];
            assert!(CompactState::parse(Path::new("state.toml"), unscoped).is_err());
            assert!(
                CompactState::parse(
                    Path::new("state.toml"),
                    text.replace(
                        "packages = [\"app\", \"helper\"]",
                        "packages = [\"app\", \"app\"]"
                    ),
                )
                .is_err()
            );
            let mut review = empty_review();
            review.scope = scope;
            let first = review.commitment().unwrap();
            review.scope.no_default_features = false;
            assert_ne!(review.commitment().unwrap(), first);
        }

        fn capability() -> Capability {
            Capability {
                package: "demo".to_owned(),
                version: "1.0.0".to_owned(),
                checksum: "11".repeat(32),
                build_script: true,
                proc_macro: false,
                native_tools: vec![NativeToolRole::Archiver, NativeToolRole::CCompiler],
                caller_env: Vec::new(),
            }
        }

        fn registry_review() -> Review {
            let mut review = empty_review();
            let checksum = "11".repeat(32);
            review.locked_registry.push(LockedRegistry {
                name: "demo".to_owned(),
                version: "1.0.0".to_owned(),
                id: checksum.clone(),
                dependencies: Vec::new(),
            });
            review.context_registry.push(ContextPackage {
                host: review.contexts[0].host.clone(),
                target: review.contexts[0].target.clone(),
                name: "demo".to_owned(),
                version: "1.0.0".to_owned(),
                id: checksum.clone(),
                compile_kinds: vec![UnitKind::Target],
                host_features: Vec::new(),
                target_features: vec!["enabled".to_owned()],
            });
            review.registry_sources.push(SourceEvidence {
                name: "demo".to_owned(),
                version: "1.0.0".to_owned(),
                id: checksum,
                license: "MIT".to_owned(),
                source_tree_sha256: "22".repeat(32),
                build_script: true,
                proc_macro: false,
            });
            review
        }

        #[test]
        fn validates_review_structure_and_ordering() {
            empty_review().validate().unwrap();

            let mut review = empty_review();
            review.contexts.push(review.contexts[0].clone());
            assert!(review.validate().is_err());
        }

        #[test]
        fn validates_compact_state_identity_and_contexts() {
            let mut state = compact_state();
            state.validate().unwrap();

            state.contexts.push(state.contexts[0].clone());
            assert!(state.validate().is_err());
            state = compact_state();
            state.review_sha256 = "AA".repeat(32);
            assert!(state.validate().is_err());
        }

        #[test]
        fn validates_compact_capability_grants() {
            let mut state = compact_state();
            state.capabilities.push(capability());
            state.validate().unwrap();

            state.capabilities[0].native_tools.reverse();
            assert!(state.validate().is_err());
            state.capabilities[0].native_tools.reverse();
            state.capabilities[0].build_script = false;
            assert!(state.validate().is_err());
            state.capabilities[0].native_tools.clear();
            state.capabilities[0].proc_macro = true;
            state.validate().unwrap();
        }

        #[test]
        fn cxx_tool_grants_round_trip_and_bind_the_review() {
            let mut state = compact_state();
            let mut grant = capability();
            grant.native_tools.push(NativeToolRole::CxxCompiler);
            state.capabilities.push(grant.clone());
            let text = String::from_utf8(state.render().unwrap()).unwrap();
            assert!(
                text.contains("native-tools = [\"archiver\", \"c-compiler\", \"cxx-compiler\"]")
            );
            assert_eq!(
                CompactState::parse(Path::new("state.toml"), text).unwrap(),
                state
            );
            let mut review = registry_review();
            review.capabilities.push(grant);
            let before = review.commitment().unwrap();
            review.capabilities[0].native_tools.pop();
            assert_ne!(before, review.commitment().unwrap());
        }

        #[test]
        fn caller_grants_round_trip_and_bind_the_review_commitment() {
            let mut state = compact_state();
            state.capabilities.push(capability());
            let old = String::from_utf8(state.render().unwrap()).unwrap();
            assert!(!old.contains("caller-env"));
            assert!(
                CompactState::parse(Path::new("state.toml"), old)
                    .unwrap()
                    .capabilities[0]
                    .caller_env
                    .is_empty()
            );
            state.capabilities[0].caller_env = vec!["EMPTY".into(), "PUBLIC".into()];
            let bytes = state.render().unwrap();
            assert_eq!(
                CompactState::parse(Path::new("state.toml"), String::from_utf8(bytes).unwrap())
                    .unwrap(),
                state
            );
            let mut review = registry_review();
            review.complete(vec![capability()]).unwrap();
            let old = review.commitment().unwrap();
            review.capabilities[0].caller_env = vec!["PUBLIC".into()];
            assert_ne!(old, review.commitment().unwrap());
            let mut policy = Policy::default();
            review
                .apply_to_policy(&mut policy, Path::new("/workspace"))
                .unwrap();
            assert_eq!(
                policy.rules["lorry-state-00000"].caller_env,
                ["PUBLIC".into()].into()
            );
            let source = "git+https://example.test/repo#0123456789012345678901234567890123456789";
            review.git_sources.push(SourceEvidence {
                name: "git-demo".into(),
                version: "1.0.0".into(),
                id: source.into(),
                license: "MIT".into(),
                source_tree_sha256: "22".repeat(32),
                build_script: true,
                proc_macro: false,
            });
            let mut grant = capability();
            grant.package = "git-demo".into();
            grant.checksum = source_digest(source);
            grant.caller_env = vec!["GIT_INPUT".into()];
            review.capabilities.push(grant);
            let mut policy = Policy::default();
            review
                .apply_to_policy(&mut policy, Path::new("/workspace"))
                .unwrap();
            assert_eq!(
                policy.rules["lorry-state-git-00000"].caller_env,
                ["GIT_INPUT".into()].into()
            );
        }

        #[test]
        fn caller_grants_reject_noncanonical_or_controlled_names() {
            let mut state = compact_state();
            state.capabilities.push(capability());
            for names in [
                vec!["PUBLIC", "EMPTY"],
                vec!["PUBLIC", "PUBLIC"],
                vec!["PATH"],
                vec!["9BAD"],
                vec!["CC_TARGET"],
                vec!["RUSTC"],
            ] {
                state.capabilities[0].caller_env =
                    names.iter().map(|name| (*name).into()).collect();
                assert!(state.validate().is_err(), "{names:?}");
            }
            state.capabilities[0].caller_env = vec!["PUBLIC".into()];
            state.capabilities[0].native_tools.clear();
            state.capabilities[0].build_script = false;
            state.capabilities[0].proc_macro = true;
            assert!(state.validate().is_err());
        }

        #[test]
        fn renders_canonical_compact_state() {
            let mut state = compact_state();
            state.capabilities.push(capability());
            let expected = br#"# Generated by Lorry. Do not edit.
format-version = 3
review-format-version = 4
review-sha256 = "4444444444444444444444444444444444444444444444444444444444444444"

[review-scope]
packages = []
features = []
all-features = false
no-default-features = false

[[context]]
host = "x86_64-unknown-linux-gnu"
target = "x86_64-unknown-motor"

[[capability]]
package = "demo"
version = "1.0.0"
checksum = "1111111111111111111111111111111111111111111111111111111111111111"
build-script = true
proc-macro = false
native-tools = ["archiver", "c-compiler"]
"#;
            assert_eq!(state.render().unwrap(), expected);
            assert_eq!(
                CompactState::parse(
                    Path::new("dependencies-v2.toml"),
                    String::from_utf8(expected.to_vec()).unwrap()
                )
                .unwrap(),
                state
            );
        }

        #[test]
        fn compact_parser_accepts_formatting_but_rejects_semantic_drift() {
            let mut state = compact_state();
            state.capabilities.push(capability());
            let source = String::from_utf8(state.render().unwrap()).unwrap();
            let path = Path::new("dependencies-v2.toml");
            let formatted = source.replacen(
                "format-version = 3",
                "# retained reviewer comment\nformat-version=3 # spacing is insignificant",
                1,
            );
            assert_eq!(CompactState::parse(path, formatted).unwrap(), state);

            let invalid = [
                source.replace("format-version = 3", "format-version = 4"),
                source.replace("review-format-version = 4\n", ""),
                source.replace(&"44".repeat(32), "invalid"),
                source.replace("\n[[context]]", "\nunknown = true\n\n[[context]]"),
                source.replace(
                    "target = \"x86_64-unknown-motor\"",
                    "unknown = true\ntarget = \"x86_64-unknown-motor\"",
                ),
                source.replace("build-script = true", "build-script = \"true\""),
                source.replace(
                    "[\"archiver\", \"c-compiler\"]",
                    "[\"c-compiler\", \"archiver\"]",
                ),
                source.replace("\"archiver\"", "\"linker\""),
            ];
            for source in invalid {
                assert!(CompactState::parse(path, source).is_err());
            }
        }

        #[test]
        fn validates_review_identities_and_relationships() {
            let mut review = registry_review();
            review.validate().unwrap();

            review.context_registry[0].host = "unreviewed-host".to_owned();
            assert!(review.validate().is_err());
            review.context_registry[0].host = review.contexts[0].host.clone();
            review.registry_sources.clear();
            assert!(review.validate().is_err());
        }

        #[test]
        fn rejects_unresolved_edges_and_unsupported_capabilities() {
            let mut review = registry_review();
            review.locked_registry[0]
                .dependencies
                .push(DependencyReference {
                    source: ReferenceSource::CratesIo,
                    name: "missing".to_owned(),
                    version: "1.0.0".to_owned(),
                });
            assert!(review.validate().is_err());
            review.locked_registry[0].dependencies.clear();
            review.capabilities.push(Capability {
                package: "demo".to_owned(),
                version: "1.0.0".to_owned(),
                checksum: "11".repeat(32),
                build_script: true,
                proc_macro: false,
                native_tools: Vec::new(),
                caller_env: Vec::new(),
            });
            review.validate().unwrap();
            review.capabilities[0].build_script = false;
            assert!(review.validate().is_err());
            review.capabilities[0].build_script = true;
            review.registry_sources[0].build_script = false;
            assert!(review.validate().is_err());
        }

        #[test]
        fn rejects_noncanonical_identities_and_aggregate_overflow() {
            let mut review = registry_review();
            review.locked_registry[0].version = "1.0".to_owned();
            assert!(review.validate().is_err());

            let mut total = MAX_FEATURES;
            assert!(add(&mut total, 1, MAX_FEATURES, "features").is_err());
        }

        const BASE_MANIFEST: &str = r#"[package]
name = "root"
version = "0.1.0"

[dependencies]
libc = { version = "=0.2.186", features = ["std", "extra"] }

[target.'cfg( unix )'.dependencies]
cc = "1.0"

[features]
default = ["extra"]
extra = []

[patch.crates-io]
patched = { path = "patched", package = "upstream" }
"#;

        const BASE_LOCK: &str = r#"version = 4

[[package]]
name = "cc"
version = "1.0.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[[package]]
name = "helper"
version = "0.1.0"

[[package]]
name = "libc"
version = "0.2.186"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
dependencies = [
 "cc 1.0.5 (registry+https://github.com/rust-lang/crates.io-index)",
 "helper",
]

[[package]]
name = "root"
version = "0.1.0"
dependencies = ["cc", "libc"]
"#;

        struct Project(PathBuf);

        impl Project {
            fn new(manifest: &str, lock: &str) -> Self {
                static NEXT: std::sync::atomic::AtomicUsize =
                    std::sync::atomic::AtomicUsize::new(0);
                let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("lorry-review-graph-{}-{id}", std::process::id()));
                let _ = fs::remove_dir_all(&path);
                fs::create_dir_all(path.join("src")).unwrap();
                fs::write(path.join("src/lib.rs"), "pub fn root() {}\n").unwrap();
                fs::write(path.join("Cargo.toml"), manifest).unwrap();
                fs::write(path.join("Cargo.lock"), lock).unwrap();
                Self(path)
            }

            fn review(&self) -> Result<Review> {
                let manifest = Manifest::load_for_build(&self.0)?;
                let lock = manifest.lock.clone().unwrap();
                Review::from_graph(&manifest, &lock, empty_review().contexts)
            }
        }

        impl Drop for Project {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        #[test]
        fn builds_the_graph_review_from_manifest_and_lockfile() {
            let review = Project::new(BASE_MANIFEST, BASE_LOCK).review().unwrap();
            assert_eq!(review.resolver_version, 1);
            assert_eq!(review.locked_registry.len(), 2);
            assert_eq!(review.locked_registry[0].name, "cc");
            assert_eq!(
                review.locked_registry[1].dependencies,
                [
                    DependencyReference {
                        source: ReferenceSource::CratesIo,
                        name: "cc".to_owned(),
                        version: "1.0.5".to_owned(),
                    },
                    DependencyReference {
                        source: ReferenceSource::Path,
                        name: "helper".to_owned(),
                        version: "0.1.0".to_owned(),
                    },
                ]
            );
        }

        #[test]
        fn graph_review_is_independent_of_formatting_and_ordering() {
            let permuted_manifest = r#"[features]
extra = []
default = ["extra"]

[patch.crates-io]
patched = { package = "upstream", path = "patched" }

[package]
name = "root"
version = "0.1.0"

[target.'cfg(unix)'.dependencies]
cc = "1.0"

[dependencies]
libc = { features = ["extra", "std"], version = "=0.2.186" }
"#;
            let permuted_lock = r#"version = 4

[[package]]
name = "root"
version = "0.1.0"
dependencies = ["libc", "cc"]

[[package]]
name = "libc"
version = "0.2.186"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
dependencies = ["helper 0.1.0", "cc 1.0.5"]

[[package]]
name = "helper"
version = "0.1.0"

[[package]]
name = "cc"
version = "1.0.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#;
            let base = Project::new(BASE_MANIFEST, BASE_LOCK).review().unwrap();
            let permuted = Project::new(permuted_manifest, permuted_lock)
                .review()
                .unwrap();
            assert_eq!(base.render().unwrap(), permuted.render().unwrap());
        }

        #[test]
        fn graph_mutations_change_the_commitment() {
            let helper_node = "[[package]]\nname = \"helper\"\nversion = \"0.1.0\"";
            let variants = [
                (BASE_MANIFEST.to_owned(), BASE_LOCK.to_owned()),
                (
                    BASE_MANIFEST.to_owned(),
                    BASE_LOCK.replace(&"bb".repeat(32), &"cc".repeat(32)),
                ),
                (
                    BASE_MANIFEST.to_owned(),
                    BASE_LOCK.replace("\n \"helper\",", ""),
                ),
                (
                    BASE_MANIFEST.to_owned(),
                    BASE_LOCK.replace(
                        helper_node,
                        &format!(
                            "{helper_node}\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{}\"",
                            "dd".repeat(32)
                        ),
                    ),
                ),
            ];
            let hashes: BTreeSet<String> = variants
                .iter()
                .map(|(manifest, lock)| {
                    sha256(
                        &Project::new(manifest, lock)
                            .review()
                            .unwrap()
                            .render()
                            .unwrap(),
                    )
                })
                .collect();
            assert_eq!(hashes.len(), variants.len());
        }

        #[test]
        fn rejects_unresolvable_lock_references() {
            let manifest = "[package]\nname = \"root\"\nversion = \"0.1.0\"\n";
            let lock = |dependency: &str| {
                format!(
                    "version = 4\n\n\
                     [[package]]\nname = \"dual\"\nversion = \"1.0.0\"\n\n\
                     [[package]]\nname = \"dual\"\nversion = \"2.0.0\"\n\
                     source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
                     checksum = \"{}\"\n\n\
                     [[package]]\nname = \"root\"\nversion = \"0.1.0\"\n\n\
                     [[package]]\nname = \"user\"\nversion = \"1.0.0\"\n\
                     source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
                     checksum = \"{}\"\ndependencies = [\"{dependency}\"]\n",
                    "55".repeat(32),
                    "66".repeat(32)
                )
            };
            assert!(
                Project::new(manifest, &lock("dual 2.0.0"))
                    .review()
                    .unwrap()
                    .locked_registry
                    .iter()
                    .any(|package| package.name == "user")
            );
            for dependency in ["dual", "ghost", "a b c d", "cc 1.0.5 registry"] {
                assert!(
                    Project::new(manifest, &lock(dependency)).review().is_err(),
                    "{dependency}"
                );
            }

            use crate::manifest::Version;
            let package = |source: Option<&str>, checksum: Option<String>| LockedPackage {
                name: "demo".to_owned(),
                version: Version {
                    original: "1.0.0".to_owned(),
                    major: 1,
                    minor: 0,
                    patch: 0,
                    pre: String::new(),
                    build: String::new(),
                },
                source: source.map(str::to_owned),
                checksum,
                dependencies: Vec::new(),
            };
            let git = Lockfile {
                format: crate::lockfile::Format::V4,
                packages: vec![package(Some("git+https://example.com/demo"), None)],
            };
            assert!(locked_graph(&git).is_err());
            let unchecksummed = Lockfile {
                format: crate::lockfile::Format::V4,
                packages: vec![package(Some(CRATES_IO_SOURCE), None)],
            };
            assert!(locked_graph(&unchecksummed).is_err());
        }

        #[test]
        fn registry_graph_resolves_git_references_without_commits() {
            let project = Project::new(
                "[package]\nname = \"root\"\nversion = \"0.1.0\"\n",
                &format!(
                    "version = 4\n\n[[package]]\nname = \"root\"\nversion = \"0.1.0\"\n\
                     [[package]]\nname = \"git\"\nversion = \"1.0.0\"\n\
                     source = \"git+https://example.com/demo?branch=master#{}\"\n\
                     [[package]]\nname = \"user\"\nversion = \"1.0.0\"\n\
                     source = \"{CRATES_IO_SOURCE}\"\nchecksum = \"{}\"\n\
                     dependencies = [\"git 1.0.0 (git+https://example.com/demo?branch=master)\"]\n",
                    "0".repeat(40),
                    "1".repeat(64),
                ),
            );
            let mut lock = Manifest::load_for_build(&project.0).unwrap().lock.unwrap();
            for format in [crate::lockfile::Format::V3, crate::lockfile::Format::V4] {
                lock.format = format;
                assert_eq!(
                    locked_graph(&lock).unwrap()[0].dependencies[0].source,
                    ReferenceSource::Git
                );
            }
            lock.packages
                .iter_mut()
                .find(|package| package.name == "user")
                .unwrap()
                .dependencies[0] = "git 1.0.0 (git+https://example.com/demo)".to_owned();
            for format in [crate::lockfile::Format::V1, crate::lockfile::Format::V2] {
                lock.format = format;
                assert_eq!(
                    locked_graph(&lock).unwrap()[0].dependencies[0].source,
                    ReferenceSource::Git
                );
            }
            lock.format = crate::lockfile::Format::V4;
            assert!(locked_graph(&lock).is_err());
        }

        fn resolved(
            name: &str,
            version: &str,
            checksum: u8,
            kinds: &[CompileKind],
            host_features: &[&str],
            target_features: &[&str],
        ) -> ResolvedPackage {
            ResolvedPackage {
                key: PackageKey {
                    name: name.to_owned(),
                    version: semver::Version::parse(version).unwrap(),
                    source: PackageSourceKey::CratesIo,
                },
                source: ResolvedSource::CratesIo {
                    checksum: [checksum; 32],
                },
                local_manifest: None,
                feature_sets: BTreeMap::new(),
                compile_kinds: kinds.iter().copied().collect(),
                target_features: target_features
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                host_features: host_features
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                edges: Vec::new(),
                lock_edges: Vec::new(),
            }
        }

        fn package_evidence(license: &str, build_script: bool) -> PackageEvidence {
            PackageEvidence {
                license: license.to_owned(),
                build_script,
                proc_macro: false,
                newly_acquired: false,
                archive_bytes: None,
                extracted_bytes: 0,
                file_count: 0,
                source_tree_sha256: [0x22; 32],
            }
        }

        fn contexts() -> (Context, Context) {
            (
                Context {
                    host: "x86_64-unknown-linux-gnu".to_owned(),
                    target: "x86_64-unknown-linux-gnu".to_owned(),
                },
                Context {
                    host: "x86_64-unknown-linux-gnu".to_owned(),
                    target: "x86_64-unknown-motor".to_owned(),
                },
            )
        }

        fn completed_review(project: &Project, libc_features: &[&str]) -> Review {
            let manifest = Manifest::load_for_build(&project.0).unwrap();
            let lock = manifest.lock.clone().unwrap();
            let (native, cross) = contexts();
            let mut review =
                Review::from_graph(&manifest, &lock, vec![native.clone(), cross.clone()]).unwrap();

            let cc = resolved(
                "cc",
                "1.0.5",
                0xaa,
                &[CompileKind::Host],
                &["host-only"],
                &[],
            );
            let libc = resolved(
                "libc",
                "0.2.186",
                0xbb,
                &[CompileKind::Target, CompileKind::Host],
                &[],
                libc_features,
            );
            let root = ResolvedPackage {
                key: PackageKey {
                    name: "root".to_owned(),
                    version: semver::Version::parse("0.1.0").unwrap(),
                    source: PackageSourceKey::Path(PathBuf::from("root")),
                },
                source: ResolvedSource::Path {
                    logical_root: PathBuf::from("root"),
                    physical_root: PathBuf::from("root"),
                    source_tree_sha256: [0; 32],
                    patched_crates_io: false,
                },
                local_manifest: None,
                feature_sets: BTreeMap::new(),
                compile_kinds: [CompileKind::Target].into_iter().collect(),
                target_features: BTreeSet::new(),
                host_features: BTreeSet::new(),
                edges: Vec::new(),
                lock_edges: Vec::new(),
            };
            let mut evidence = BTreeMap::new();
            evidence.insert(cc.key.clone(), package_evidence("MIT", true));
            evidence.insert(
                libc.key.clone(),
                package_evidence("MIT OR Apache-2.0", false),
            );

            let packages = |values: &[&ResolvedPackage]| Resolution {
                root_edges: Vec::new(),
                packages: values.iter().map(|value| (*value).clone()).collect(),
            };
            review
                .add_context_resolution(&native, &packages(&[&cc, &root]), &evidence)
                .unwrap();
            review
                .add_context_resolution(&cross, &packages(&[&libc, &cc]), &evidence)
                .unwrap();
            review
                .complete(vec![Capability {
                    package: "cc".to_owned(),
                    version: "1.0.5".to_owned(),
                    checksum: "aa".repeat(32),
                    build_script: true,
                    proc_macro: false,
                    native_tools: Vec::new(),
                    caller_env: Vec::new(),
                }])
                .unwrap();
            review
        }

        #[test]
        fn completes_the_review_with_contexts_evidence_and_capabilities() {
            let project = Project::new(BASE_MANIFEST, BASE_LOCK);
            let review = completed_review(&project, &["extra"]);

            assert_eq!(review.context_registry.len(), 3);
            assert_eq!(
                review.context_registry[0].target,
                "x86_64-unknown-linux-gnu"
            );
            assert_eq!(review.context_registry[0].name, "cc");
            assert_eq!(review.context_registry[0].compile_kinds, [UnitKind::Host]);
            assert_eq!(review.context_registry[0].host_features, ["host-only"]);
            assert_eq!(review.context_registry[2].name, "libc");
            assert_eq!(
                review.context_registry[2].compile_kinds,
                [UnitKind::Host, UnitKind::Target]
            );
            assert_eq!(review.context_registry[2].target_features, ["extra"]);
            assert_eq!(review.registry_sources.len(), 2);
            assert_eq!(review.registry_sources[1].license, "MIT OR Apache-2.0");
            assert!(!review.registry_sources[1].build_script);
            assert!(
                review
                    .context_registry
                    .iter()
                    .all(|value| value.name != "root")
            );

            let features_changed = completed_review(&project, &["extra", "shared"]);
            assert_ne!(
                sha256(&review.render().unwrap()),
                sha256(&features_changed.render().unwrap())
            );
        }

        #[test]
        fn rejects_missing_conflicting_and_drifted_context_evidence() {
            let project = Project::new(BASE_MANIFEST, BASE_LOCK);
            let manifest = Manifest::load_for_build(&project.0).unwrap();
            let lock = manifest.lock.clone().unwrap();
            let (native, cross) = contexts();
            let build = || {
                Review::from_graph(&manifest, &lock, vec![native.clone(), cross.clone()]).unwrap()
            };
            let cc = resolved("cc", "1.0.5", 0xaa, &[CompileKind::Host], &[], &[]);
            let resolution = Resolution {
                root_edges: Vec::new(),
                packages: vec![cc.clone()],
            };
            let mut evidence = BTreeMap::new();
            evidence.insert(cc.key.clone(), package_evidence("MIT", true));

            let unreviewed = Context {
                host: "x86_64-unknown-motor".to_owned(),
                target: "x86_64-unknown-motor".to_owned(),
            };
            assert!(
                build()
                    .add_context_resolution(&unreviewed, &resolution, &evidence)
                    .is_err()
            );
            assert!(
                build()
                    .add_context_resolution(&native, &resolution, &BTreeMap::new())
                    .is_err()
            );

            let mut conflicting = build();
            conflicting
                .add_context_resolution(&native, &resolution, &evidence)
                .unwrap();
            let mut changed = BTreeMap::new();
            changed.insert(cc.key.clone(), package_evidence("Apache-2.0", true));
            assert!(
                conflicting
                    .add_context_resolution(&cross, &resolution, &changed)
                    .is_err()
            );

            let mut drifted = build();
            let moved = resolved("cc", "1.0.5", 0xcc, &[CompileKind::Host], &[], &[]);
            let mut moved_evidence = BTreeMap::new();
            moved_evidence.insert(moved.key.clone(), package_evidence("MIT", true));
            drifted
                .add_context_resolution(
                    &native,
                    &Resolution {
                        root_edges: Vec::new(),
                        packages: vec![moved],
                    },
                    &moved_evidence,
                )
                .unwrap();
            assert!(drifted.complete(Vec::new()).is_err());
        }

        #[test]
        fn renders_and_hashes_representative_review_golden() {
            let mut review = registry_review();
            review.scope = ReviewScope {
                packages: vec!["app".to_owned()],
                features: vec!["app/extra".to_owned()],
                all_features: false,
                no_default_features: false,
            };
            review.locked_registry[0].dependencies = vec![
                DependencyReference {
                    source: ReferenceSource::CratesIo,
                    name: "leaf".to_owned(),
                    version: "1.0.0".to_owned(),
                },
                DependencyReference {
                    source: ReferenceSource::Path,
                    name: "helper".to_owned(),
                    version: "0.1.0".to_owned(),
                },
            ];
            review.locked_registry.push(LockedRegistry {
                name: "leaf".to_owned(),
                version: "1.0.0".to_owned(),
                id: "33".repeat(32),
                dependencies: Vec::new(),
            });
            review.context_registry[0].compile_kinds = vec![UnitKind::Host, UnitKind::Target];
            review.capabilities.push(Capability {
                package: "demo".to_owned(),
                version: "1.0.0".to_owned(),
                checksum: "11".repeat(32),
                build_script: true,
                proc_macro: false,
                native_tools: vec![NativeToolRole::Archiver, NativeToolRole::CCompiler],
                caller_env: Vec::new(),
            });

            let bytes = review.render().unwrap();
            let expected = br#"review-format-version = 4
source-tree-format-version = 1
cargo-lock-format-version = 4
resolver-version = 2

[review-scope]
packages = ["app"]
features = ["app/extra"]
all-features = false
no-default-features = false

[[context]]
host = "x86_64-unknown-linux-gnu"
target = "x86_64-unknown-motor"

[[locked-registry]]
name = "demo"
version = "1.0.0"
checksum = "1111111111111111111111111111111111111111111111111111111111111111"
dependencies = [
    "crates.io leaf 1.0.0",
    "path helper 0.1.0",
]

[[locked-registry]]
name = "leaf"
version = "1.0.0"
checksum = "3333333333333333333333333333333333333333333333333333333333333333"
dependencies = []

[[context-registry]]
host = "x86_64-unknown-linux-gnu"
target = "x86_64-unknown-motor"
name = "demo"
version = "1.0.0"
checksum = "1111111111111111111111111111111111111111111111111111111111111111"
compile-kinds = ["host", "target"]
host-features = []
target-features = ["enabled"]

[[registry-source]]
name = "demo"
version = "1.0.0"
checksum = "1111111111111111111111111111111111111111111111111111111111111111"
license = "MIT"
source-tree-sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
build-script = true
proc-macro = false

[[capability]]
package = "demo"
version = "1.0.0"
checksum = "1111111111111111111111111111111111111111111111111111111111111111"
build-script = true
proc-macro = false
native-tools = ["archiver", "c-compiler"]
"#;
            assert_eq!(bytes, expected);
            assert_eq!(
                sha256(&bytes),
                "bf7f482431fb470e05d678449ebb0895538a74c3ab957bee3be417ead45f6236"
            );
        }

        #[test]
        fn renders_and_hashes_git_review_golden() {
            let source = "git+https://example.test/repo#0123456789012345678901234567890123456789";
            let mut review = empty_review();
            review.locked_git.push(LockedGit {
                name: "git-demo".to_owned(),
                version: "1.0.0".to_owned(),
                id: source.to_owned(),
                dependencies: vec!["leaf".to_owned()],
            });
            review.context_git.push(ContextPackage {
                host: review.contexts[0].host.clone(),
                target: review.contexts[0].target.clone(),
                name: "git-demo".to_owned(),
                version: "1.0.0".to_owned(),
                id: source.to_owned(),
                compile_kinds: vec![UnitKind::Target],
                host_features: Vec::new(),
                target_features: vec!["std".to_owned()],
            });
            review.git_sources.push(SourceEvidence {
                name: "git-demo".to_owned(),
                version: "1.0.0".to_owned(),
                id: source.to_owned(),
                license: "MIT".to_owned(),
                source_tree_sha256: "22".repeat(32),
                build_script: false,
                proc_macro: true,
            });
            let bytes = review.render().unwrap();
            let expected = br#"review-format-version = 4
source-tree-format-version = 1
cargo-lock-format-version = 4
resolver-version = 2

[review-scope]
packages = []
features = []
all-features = false
no-default-features = false

[[context]]
host = "x86_64-unknown-linux-gnu"
target = "x86_64-unknown-motor"

[[locked-git]]
name = "git-demo"
version = "1.0.0"
source = "git+https://example.test/repo#0123456789012345678901234567890123456789"
dependencies = ["leaf"]

[[context-git]]
host = "x86_64-unknown-linux-gnu"
target = "x86_64-unknown-motor"
name = "git-demo"
version = "1.0.0"
source = "git+https://example.test/repo#0123456789012345678901234567890123456789"
compile-kinds = ["target"]
host-features = []
target-features = ["std"]

[[git-source]]
name = "git-demo"
version = "1.0.0"
source = "git+https://example.test/repo#0123456789012345678901234567890123456789"
license = "MIT"
source-tree-sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
build-script = false
proc-macro = true
"#;
            assert_eq!(bytes, expected);
            assert_eq!(
                sha256(&bytes),
                "54d75e09db707a9c0bd471620f5753e419f7dd803eaa24c05f1c78dfe85fb4fa"
            );
        }

        #[test]
        fn renders_and_hashes_empty_registry_review_golden() {
            let bytes = empty_review().render().unwrap();
            let expected = b"review-format-version = 4\n\
source-tree-format-version = 1\n\
cargo-lock-format-version = 4\n\
resolver-version = 2\n\
\n\
[review-scope]\n\
packages = []\n\
features = []\n\
all-features = false\n\
no-default-features = false\n\
\n\
[[context]]\n\
host = \"x86_64-unknown-linux-gnu\"\n\
target = \"x86_64-unknown-motor\"\n";
            assert_eq!(bytes, expected);
            assert_eq!(
                sha256(&bytes),
                "e71c1f4298aba2759f97d2a070ee64e86fbf4b1bae6461d8f165ecc4a7d3387a"
            );
        }

        #[test]
        fn renders_scalars_arrays_and_toml_escapes() {
            let mut writer = Writer::new();
            writer.boolean("enabled", false).unwrap();
            writer
                .strings(
                    "values",
                    &["quote\"slash\\line\n".to_owned(), "café".to_owned()],
                )
                .unwrap();
            assert_eq!(
                writer.finish().unwrap(),
                b"enabled = false\nvalues = [\"quote\\\"slash\\\\line\\n\", \"caf\xC3\xA9\"]\n"
            );
        }

        #[test]
        fn enforces_fixed_review_resource_limits() {
            let mut writer = Writer::new();
            assert!(
                writer
                    .string("value", &"x".repeat(MAX_STRING_BYTES + 1))
                    .is_err()
            );

            let mut writer = Writer {
                output: Vec::new(),
                items: MAX_ITEMS,
                max_bytes: MAX_REPORT_BYTES,
            };
            assert!(writer.boolean("enabled", true).is_err());

            let mut writer = Writer {
                output: vec![b'x'; MAX_REPORT_BYTES],
                items: 0,
                max_bytes: MAX_REPORT_BYTES,
            };
            assert!(writer.raw("x").is_err());

            let mut writer = Writer::compact();
            writer.output = vec![b'x'; MAX_COMPACT_BYTES];
            assert!(writer.raw("x").is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PolicyDefault;
    use crate::resolver::{FeatureContext, PackageSourceKey, ResolvedEdge, ResolvedPackage};
    use crate::sparse::DependencyKind;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("lorry-admission-state-{}-{id}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn context() -> Context {
        Context {
            host: "x86_64-unknown-linux-gnu".to_owned(),
            target: "x86_64-unknown-motor".to_owned(),
        }
    }

    fn state() -> CompactState {
        CompactState {
            scope: ReviewScope::default(),
            review_sha256: "44".repeat(32),
            contexts: vec![context()],
            capabilities: vec![Capability {
                package: "libc".to_owned(),
                version: "0.2.186".to_owned(),
                checksum: "33".repeat(32),
                build_script: true,
                proc_macro: false,
                native_tools: Vec::new(),
                caller_env: Vec::new(),
            }],
        }
    }

    fn reviewed() -> Review {
        let mut review = Review {
            resolver_version: 2,
            contexts: vec![context()],
            ..Review::default()
        };
        review.locked_registry.push(LockedRegistry {
            name: "libc".to_owned(),
            version: "0.2.186".to_owned(),
            id: "33".repeat(32),
            dependencies: Vec::new(),
        });
        review.context_registry.push(ContextPackage {
            host: review.contexts[0].host.clone(),
            target: review.contexts[0].target.clone(),
            name: "libc".to_owned(),
            version: "0.2.186".to_owned(),
            id: "33".repeat(32),
            compile_kinds: vec![UnitKind::Target],
            host_features: Vec::new(),
            target_features: Vec::new(),
        });
        review.registry_sources.push(SourceEvidence {
            name: "libc".to_owned(),
            version: "0.2.186".to_owned(),
            id: "33".repeat(32),
            license: "MIT OR Apache-2.0".to_owned(),
            source_tree_sha256: "44".repeat(32),
            build_script: true,
            proc_macro: false,
        });
        review
            .complete(vec![Capability {
                package: "libc".to_owned(),
                version: "0.2.186".to_owned(),
                checksum: "33".repeat(32),
                build_script: true,
                proc_macro: false,
                native_tools: Vec::new(),
                caller_env: Vec::new(),
            }])
            .unwrap();
        review
    }

    #[test]
    fn writes_and_loads_compact_state() {
        let fixture = Fixture::new();
        assert_eq!(CompactState::load(&fixture.0).unwrap(), None);
        let expected = state();
        expected.write(&fixture.0).unwrap();
        assert_eq!(CompactState::load(&fixture.0).unwrap(), Some(expected));

        let mut source =
            String::from_utf8(fs::read(CompactState::path(&fixture.0)).unwrap()).unwrap();
        source.push_str("unknown = true\n");
        fs::write(CompactState::path(&fixture.0), source).unwrap();
        assert!(CompactState::load(&fixture.0).is_err());
    }

    #[test]
    fn rejects_a_retired_format_3_record_but_lets_vendor_replace_it() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.0.join(".lorry")).unwrap();
        fs::write(
            CompactState::path(&fixture.0),
            format!(
                "format-version = 3\nreview-format-version = 3\nreview-sha256 = \"{}\"\n\n\
                 [[context]]\nhost = \"x86_64-unknown-linux-gnu\"\ntarget = \"x86_64-unknown-motor\"\n",
                "44".repeat(32)
            ),
        )
        .unwrap();
        let error = CompactState::load(&fixture.0).unwrap_err().render();
        assert!(
            error.contains("retired single-package review format 3"),
            "{error}"
        );
        assert!(error.contains("run `lorry vendor --locked` again at the workspace root"));
        assert_eq!(CompactState::load_replaceable(&fixture.0).unwrap(), None);
    }

    #[test]
    fn requires_an_exact_reviewed_context() {
        let state = state();
        state
            .require_context("x86_64-unknown-linux-gnu", "x86_64-unknown-motor")
            .unwrap();
        assert!(
            state
                .require_context("x86_64-unknown-motor", "x86_64-unknown-motor")
                .is_err()
        );
        assert!(
            state
                .require_context("x86_64-unknown-linux-gnu", "x86_64-unknown-linux-gnu")
                .is_err()
        );
    }

    #[test]
    fn synthesizes_capability_scoped_allow_rules() {
        let fixture = Fixture::new();
        let review = reviewed();
        let mut policy = Policy {
            default: PolicyDefault::Deny,
            ..Policy::default()
        };
        review.apply_to_policy(&mut policy, &fixture.0).unwrap();
        let rule = policy.rules.get("lorry-state-00000").unwrap();
        assert_eq!(rule.name.as_deref(), Some("libc"));
        assert_eq!(rule.checksum.as_deref(), Some(&*"33".repeat(32)));
        assert!(rule.allow_build_script);

        let mut ungranted = reviewed();
        ungranted.capabilities.clear();
        ungranted.registry_sources[0].build_script = false;
        let mut policy = Policy::default();
        ungranted.apply_to_policy(&mut policy, &fixture.0).unwrap();
        assert!(
            !policy
                .rules
                .get("lorry-state-00000")
                .unwrap()
                .allow_build_script
        );
    }

    #[test]
    fn no_format_1_admission_path_remains() {
        fn scan(directory: &Path, hits: &mut Vec<PathBuf>) {
            for entry in fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let name = entry.file_name();
                if entry.file_type().unwrap().is_dir() {
                    if name != "target" && name != ".cargo" {
                        scan(&path, hits);
                    }
                    continue;
                }
                let extension = path.extension().and_then(|value| value.to_str());
                if matches!(extension, Some("rs" | "toml" | "sh"))
                    && fs::read_to_string(&path)
                        .is_ok_and(|source| source.contains(concat!("dependencies-v", "1")))
                {
                    hits.push(path);
                }
            }
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut hits = Vec::new();
        scan(&root.join("src"), &mut hits);
        scan(&root.join("tests"), &mut hits);
        scan(&root.join(".lorry"), &mut hits);
        assert_eq!(hits, Vec::<PathBuf>::new());
    }

    #[test]
    fn generated_allow_never_overrides_an_explicit_deny() {
        let fixture = Fixture::new();
        let mut policy = Policy {
            default: PolicyDefault::Deny,
            ..Policy::default()
        };
        policy.rules.insert(
            "administrator-deny".to_owned(),
            PolicyRule {
                action: PolicyAction::Deny,
                name: Some("libc".to_owned()),
                version: None,
                source: Some("crates.io".to_owned()),
                checksum: None,
                source_tree_sha256: None,
                license: None,
                allow_build_script: false,
                allow_proc_macro: false,
                native_tools: BTreeSet::new(),
                caller_env: Default::default(),
                provenance: fixture.0.join("policy.toml"),
            },
        );
        reviewed().apply_to_policy(&mut policy, &fixture.0).unwrap();
        let package = ResolvedPackage {
            key: PackageKey {
                name: "libc".to_owned(),
                version: semver::Version::parse("0.2.186").unwrap(),
                source: PackageSourceKey::CratesIo,
            },
            source: ResolvedSource::CratesIo {
                checksum: [0x33; 32],
            },
            local_manifest: None,
            feature_sets: BTreeMap::from([(FeatureContext::Unified, BTreeSet::new())]),
            compile_kinds: BTreeSet::from([CompileKind::Target]),
            target_features: BTreeSet::new(),
            host_features: BTreeSet::new(),
            edges: Vec::new(),
            lock_edges: Vec::new(),
        };
        let root_edge = ResolvedEdge {
            dependency_index: 0,
            alias: "libc".to_owned(),
            target: None,
            kind: DependencyKind::Normal,
            parent_compile_kind: None,
            compile_kind: CompileKind::Target,
            context: FeatureContext::Unified,
            package: package.key.clone(),
        };
        let error = crate::policy::preflight_workspace(
            &policy,
            &Resolution {
                root_edges: vec![root_edge],
                packages: vec![package],
            },
        )
        .unwrap_err();
        assert!(error.render().contains("administrator-deny"));
    }
}
