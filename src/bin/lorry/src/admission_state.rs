use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::atomic::AtomicFile;
use crate::config::{NativeToolRole, Policy, PolicyAction, PolicyRule};
use crate::diagnostic::{Error, Result};
use crate::hash::{Sha256, hex};
use crate::manifest::{DependencySource, LockedPackage, Lockfile, Manifest, Resolver};
use crate::policy::{Admission, PackageEvidence};
use crate::resolver::{CompileKind, PackageKey, Resolution, ResolvedSource};
use crate::sparse::DependencyKind;
use crate::toml::Document;
use toml_edit::{Item, Table};

pub const RELATIVE_PATH: &str = ".lorry/dependencies-v2.toml";

/// Derives compact grants for registry packages that execute build-time code.
pub fn capabilities_from(
    selected: &Resolution,
    evidence: &BTreeMap<PackageKey, PackageEvidence>,
    admission: &Admission,
) -> Result<Vec<Capability>> {
    let mut capabilities = Vec::new();
    for package in &selected.packages {
        let ResolvedSource::CratesIo { checksum } = &package.source else {
            continue;
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
        let native_tools = admission
            .packages
            .get(&package.key)
            .map(|admission| admission.native_tools.iter().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        capabilities.push(Capability {
            package: package.key.name.clone(),
            version: package.key.version.to_string(),
            checksum: hex(checksum),
            build_script: package_evidence.build_script,
            proc_macro: package_evidence.proc_macro,
            native_tools,
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

fn native_tool_name(role: NativeToolRole) -> &'static str {
    match role {
        NativeToolRole::CCompiler => "c-compiler",
        NativeToolRole::Archiver => "archiver",
    }
}

pub use review::{Capability, CompactState, Context, Review};
#[cfg(test)]
pub use review::{ContextRegistry, LockedRegistry, RegistrySource, UnitKind};

#[allow(dead_code)]
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
    const MAX_CFG_NODES: usize = 4_096;
    const MAX_CFG_DEPTH: usize = 64;
    const COMPACT_FORMAT_VERSION: u64 = 3;
    const REVIEW_FORMAT_VERSION: u64 = 2;

    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct Context {
        pub host: String,
        pub target: String,
    }

    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub enum ReviewKind {
        Build,
        Development,
        Normal,
    }

    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct DirectRegistry {
        pub alias: String,
        pub package: String,
        pub requirement: String,
        pub kind: ReviewKind,
        pub target: Option<String>,
        pub optional: bool,
        pub default_features: bool,
        pub features: Vec<String>,
    }

    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct RootFeature {
        pub name: String,
        pub values: Vec<String>,
    }

    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct CratesIoPatch {
        pub alias: String,
        pub package: String,
    }

    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub enum ReferenceSource {
        CratesIo,
        Path,
    }

    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct DependencyReference {
        pub source: ReferenceSource,
        pub name: String,
        pub version: String,
    }

    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct LockedRegistry {
        pub name: String,
        pub version: String,
        pub checksum: String,
        pub dependencies: Vec<DependencyReference>,
    }

    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub enum UnitKind {
        Host,
        Target,
    }

    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct ContextRegistry {
        pub host: String,
        pub target: String,
        pub name: String,
        pub version: String,
        pub checksum: String,
        pub compile_kinds: Vec<UnitKind>,
        pub host_features: Vec<String>,
        pub target_features: Vec<String>,
    }

    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct RegistrySource {
        pub name: String,
        pub version: String,
        pub checksum: String,
        pub license: String,
        pub source_tree_sha256: String,
        pub build_script: bool,
        pub proc_macro: bool,
    }

    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    pub struct Capability {
        pub package: String,
        pub version: String,
        pub checksum: String,
        pub build_script: bool,
        pub proc_macro: bool,
        pub native_tools: Vec<NativeToolRole>,
    }

    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    pub struct Review {
        pub resolver_version: u64,
        pub contexts: Vec<Context>,
        pub direct_registry: Vec<DirectRegistry>,
        pub root_features: Vec<RootFeature>,
        pub crates_io_patches: Vec<CratesIoPatch>,
        pub locked_registry: Vec<LockedRegistry>,
        pub context_registry: Vec<ContextRegistry>,
        pub registry_sources: Vec<RegistrySource>,
        pub capabilities: Vec<Capability>,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct CompactState {
        pub review_sha256: String,
        pub contexts: Vec<Context>,
        pub capabilities: Vec<Capability>,
    }

    impl CompactState {
        pub fn path(root: &Path) -> PathBuf {
            root.join(RELATIVE_PATH)
        }

        /// Strictly parses the project's compact state. A missing file is not
        /// an error: the project then has no registry admission and every
        /// registry package fails closed at policy.
        pub fn load(root: &Path) -> Result<Option<Self>> {
            let path = Self::path(root);
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                    return Err(Error::failure(format!(
                        "Lorry dependency state `{}` is not a regular file",
                        path.display()
                    )));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => {
                    return Err(Error::failure(format!(
                        "failed to inspect Lorry dependency state `{}`: {error}",
                        path.display()
                    )));
                }
            }
            let document = Document::load(&path, "Lorry compact dependency state")?;
            Self::from_document(&path, &document).map(Some)
        }

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
                    "run `lorry vendor` on this host with the target in the configured \
                     `[vendor].targets` set",
                ))
            }
        }

        fn from_document(path: &Path, document: &Document) -> Result<Self> {
            require_keys(
                path,
                document.root(),
                &[
                    "format-version",
                    "review-format-version",
                    "review-sha256",
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
            let state = Self {
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
            write_contexts(&mut writer, &self.contexts)?;
            write_capabilities(&mut writer, &self.capabilities)?;
            writer.finish()
        }

        pub fn validate(&self) -> Result<()> {
            digest(&self.review_sha256, "review digest")?;
            validate_contexts(&self.contexts)?;
            validate_capabilities(&self.capabilities)
        }
    }

    impl Review {
        /// Builds the graph portion of the canonical document from the parsed
        /// manifest and lockfile. Contexts come from compact state or the
        /// vendor candidate set; context resolution, source evidence, and
        /// capabilities are later builder stages.
        pub fn from_graph(
            manifest: &Manifest,
            lock: &Lockfile,
            contexts: Vec<Context>,
        ) -> Result<Self> {
            let mut review = Self {
                resolver_version: match manifest.resolver {
                    Resolver::V1 => 1,
                    Resolver::V2 => 2,
                    Resolver::V3 => 3,
                },
                contexts,
                ..Self::default()
            };
            for dependency in &manifest.dependencies {
                if dependency.source != DependencySource::CratesIo {
                    continue;
                }
                review.direct_registry.push(DirectRegistry {
                    alias: dependency.alias.clone(),
                    package: dependency.package.clone(),
                    requirement: dependency.requirement.to_string(),
                    kind: match dependency.kind {
                        DependencyKind::Build => ReviewKind::Build,
                        DependencyKind::Dev => ReviewKind::Development,
                        DependencyKind::Normal => ReviewKind::Normal,
                    },
                    target: dependency
                        .target
                        .as_deref()
                        .map(canonical_target_selector)
                        .transpose()?,
                    optional: dependency.optional,
                    default_features: dependency.default_features,
                    features: sorted_set(&dependency.features, "direct dependency features")?,
                });
            }
            review.direct_registry.sort();
            for (name, values) in &manifest.features {
                review.root_features.push(RootFeature {
                    name: name.clone(),
                    values: sorted_set(values, "root feature values")?,
                });
            }
            for patch in &manifest.patches {
                review.crates_io_patches.push(CratesIoPatch {
                    alias: patch.alias.clone(),
                    package: patch.package.clone(),
                });
            }
            review.crates_io_patches.sort();
            review.locked_registry = locked_graph(lock)?;
            review.validate()?;
            Ok(review)
        }

        /// Records one reviewed context's independently resolved registry
        /// selection and its verified source evidence. Path packages keep
        /// their independent rules and never enter registry admission.
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
                let ResolvedSource::CratesIo { checksum } = &package.source else {
                    continue;
                };
                let checksum = hex(checksum);
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
                self.context_registry.push(ContextRegistry {
                    host: context.host.clone(),
                    target: context.target.clone(),
                    name: package.key.name.clone(),
                    version: version.clone(),
                    checksum: checksum.clone(),
                    compile_kinds,
                    host_features: package.host_features.iter().cloned().collect(),
                    target_features: package.target_features.iter().cloned().collect(),
                });
                let source = RegistrySource {
                    name: package.key.name.clone(),
                    version,
                    checksum,
                    license: package_evidence.license.clone(),
                    source_tree_sha256: hex(&package_evidence.source_tree_sha256),
                    build_script: package_evidence.build_script,
                    proc_macro: package_evidence.proc_macro,
                };
                let position = self.registry_sources.binary_search_by(|value| {
                    key(&value.name, &value.version, &value.checksum).cmp(&key(
                        &source.name,
                        &source.version,
                        &source.checksum,
                    ))
                });
                match position {
                    Ok(index) if self.registry_sources[index] == source => {}
                    Ok(_) => {
                        return Err(invalid(format!(
                            "has conflicting evidence for `{} {}`",
                            source.name, source.version
                        )));
                    }
                    Err(index) => self.registry_sources.insert(index, source),
                }
            }
            self.context_registry
                .sort_by(|a, b| context_package_key(a).cmp(&context_package_key(b)));
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
            for (index, source) in self.registry_sources.iter().enumerate() {
                let id = format!("lorry-state-{index:05}");
                if policy.rules.contains_key(&id) {
                    return Err(Error::failure(format!(
                        "configured policy rule `{id}` conflicts with generated dependency state"
                    )));
                }
                let capability = self.capabilities.iter().find(|capability| {
                    capability_key(capability)
                        == key(&source.name, &source.version, &source.checksum)
                });
                policy.rules.insert(
                    id,
                    PolicyRule {
                        action: PolicyAction::Allow,
                        name: Some(source.name.clone()),
                        version: Some(
                            semver::VersionReq::parse(&format!("={}", source.version)).map_err(
                                |error| {
                                    Error::failure(format!(
                                        "dependency state has invalid exact version for `{} {}`: {error}",
                                        source.name, source.version
                                    ))
                                },
                            )?,
                        ),
                        source: Some("crates.io".to_owned()),
                        checksum: Some(source.checksum.clone()),
                        source_tree_sha256: Some(source.source_tree_sha256.clone()),
                        license: Some(source.license.clone()),
                        allow_build_script: capability.is_some_and(|value| value.build_script),
                        allow_proc_macro: capability.is_some_and(|value| value.proc_macro),
                        native_tools: capability
                            .map(|capability| capability.native_tools.iter().copied().collect())
                            .unwrap_or_default(),
                        provenance: CompactState::path(root),
                    },
                );
            }
            Ok(())
        }

        pub fn render(&self) -> Result<Vec<u8>> {
            self.validate()?;
            let mut writer = Writer::new();
            writer.integer("review-format-version", REVIEW_FORMAT_VERSION)?;
            writer.integer("source-tree-format-version", 1)?;
            writer.integer("cargo-lock-format-version", 4)?;
            writer.integer("resolver-version", self.resolver_version)?;
            write_contexts(&mut writer, &self.contexts)?;
            for value in &self.direct_registry {
                writer.table("direct-registry")?;
                writer.string("alias", &value.alias)?;
                writer.string("package", &value.package)?;
                writer.string("requirement", &value.requirement)?;
                writer.string("kind", review_kind_name(value.kind))?;
                if let Some(target) = &value.target {
                    writer.string("target", target)?;
                }
                writer.boolean("optional", value.optional)?;
                writer.boolean("default-features", value.default_features)?;
                writer.strings("features", &value.features)?;
            }
            for value in &self.root_features {
                writer.table("root-feature")?;
                writer.string("name", &value.name)?;
                writer.strings("values", &value.values)?;
            }
            for value in &self.crates_io_patches {
                writer.table("crates-io-patch")?;
                writer.string("alias", &value.alias)?;
                writer.string("package", &value.package)?;
            }
            for value in &self.locked_registry {
                writer.table("locked-registry")?;
                write_identity(&mut writer, &value.name, &value.version, &value.checksum)?;
                writer.dependencies(&value.dependencies)?;
            }
            for value in &self.context_registry {
                writer.table("context-registry")?;
                writer.string("host", &value.host)?;
                writer.string("target", &value.target)?;
                write_identity(&mut writer, &value.name, &value.version, &value.checksum)?;
                writer.names("compile-kinds", &value.compile_kinds, unit_kind_name)?;
                writer.strings("host-features", &value.host_features)?;
                writer.strings("target-features", &value.target_features)?;
            }
            for value in &self.registry_sources {
                writer.table("registry-source")?;
                write_identity(&mut writer, &value.name, &value.version, &value.checksum)?;
                writer.string("license", &value.license)?;
                writer.string("source-tree-sha256", &value.source_tree_sha256)?;
                writer.boolean("build-script", value.build_script)?;
                writer.boolean("proc-macro", value.proc_macro)?;
            }
            write_capabilities(&mut writer, &self.capabilities)?;
            writer.finish()
        }

        pub fn validate(&self) -> Result<()> {
            validate_contexts(&self.contexts)?;
            validate_capabilities(&self.capabilities)?;
            limit(
                self.direct_registry.len(),
                MAX_TABLES,
                "direct dependencies",
            )?;
            limit(self.root_features.len(), MAX_TABLES, "root features")?;
            limit(self.crates_io_patches.len(), MAX_TABLES, "patches")?;
            limit(self.locked_registry.len(), MAX_TABLES, "locked packages")?;
            limit(
                self.context_registry.len(),
                MAX_CONTEXT_PACKAGES,
                "context package memberships",
            )?;
            limit(self.registry_sources.len(), MAX_TABLES, "source evidence")?;
            if !(1..=3).contains(&self.resolver_version) {
                return Err(invalid("has an unsupported resolver version"));
            }
            ordered(&self.direct_registry, "direct dependencies")?;
            ordered_by(
                &self.root_features,
                |a, b| a.name.cmp(&b.name),
                "root features",
            )?;
            ordered(&self.crates_io_patches, "patches")?;
            ordered_by(
                &self.locked_registry,
                |a, b| {
                    key(&a.name, &a.version, &a.checksum).cmp(&key(
                        &b.name,
                        &b.version,
                        &b.checksum,
                    ))
                },
                "locked packages",
            )?;
            ordered_by(
                &self.context_registry,
                |a, b| context_package_key(a).cmp(&context_package_key(b)),
                "context packages",
            )?;
            ordered_by(
                &self.registry_sources,
                |a, b| {
                    key(&a.name, &a.version, &a.checksum).cmp(&key(
                        &b.name,
                        &b.version,
                        &b.checksum,
                    ))
                },
                "source evidence",
            )?;
            for value in &self.direct_registry {
                ordered(&value.features, "direct dependency features")?;
            }
            for value in &self.root_features {
                ordered(&value.values, "root feature values")?;
            }
            for value in &self.locked_registry {
                ordered(&value.dependencies, "locked dependency references")?;
            }
            for value in &self.context_registry {
                if value.compile_kinds.is_empty() {
                    return Err(invalid("contains a context package with no compile kind"));
                }
                ordered(&value.compile_kinds, "compile kinds")?;
                ordered(&value.host_features, "host features")?;
                ordered(&value.target_features, "target features")?;
            }
            self.validate_values()?;
            self.validate_relationships()
        }

        fn validate_values(&self) -> Result<()> {
            let mut edges = 0;
            let mut features = 0;
            for value in &self.direct_registry {
                nonempty(&value.alias, "direct dependency alias")?;
                nonempty(&value.package, "direct dependency package")?;
                canonical_requirement(&value.requirement)?;
                if let Some(target) = &value.target
                    && canonical_target_selector(target)? != *target
                {
                    return Err(invalid(format!(
                        "has a noncanonical target selector `{target}`"
                    )));
                }
                add(
                    &mut features,
                    value.features.len(),
                    MAX_FEATURES,
                    "features",
                )?;
            }
            for value in &self.root_features {
                nonempty(&value.name, "root feature name")?;
                add(&mut features, value.values.len(), MAX_FEATURES, "features")?;
            }
            for value in &self.crates_io_patches {
                nonempty(&value.alias, "patch alias")?;
                nonempty(&value.package, "patch package")?;
            }
            for value in &self.locked_registry {
                identity(&value.name, &value.version, &value.checksum)?;
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
            for value in &self.context_registry {
                identity(&value.name, &value.version, &value.checksum)?;
                add(
                    &mut features,
                    value.host_features.len(),
                    MAX_FEATURES,
                    "features",
                )?;
                add(
                    &mut features,
                    value.target_features.len(),
                    MAX_FEATURES,
                    "features",
                )?;
            }
            for value in &self.registry_sources {
                identity(&value.name, &value.version, &value.checksum)?;
                digest(&value.source_tree_sha256, "source-tree digest")?;
            }
            Ok(())
        }

        fn validate_relationships(&self) -> Result<()> {
            let contexts: BTreeSet<_> = self
                .contexts
                .iter()
                .map(|value| (&*value.host, &*value.target))
                .collect();
            let locked: BTreeSet<_> = self
                .locked_registry
                .iter()
                .map(|value| key(&value.name, &value.version, &value.checksum))
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

            let mut selected = BTreeSet::new();
            for value in &self.context_registry {
                if !contexts.contains(&(&*value.host, &*value.target)) {
                    return Err(invalid("contains a package for an unreviewed context"));
                }
                let identity = key(&value.name, &value.version, &value.checksum);
                if !locked.contains(&identity) {
                    return Err(invalid("contains a context package absent from Cargo.lock"));
                }
                selected.insert(identity);
            }
            limit(
                selected.len(),
                MAX_TABLES,
                "distinct selected registry packages",
            )?;
            let sources: BTreeSet<_> = self
                .registry_sources
                .iter()
                .map(|value| key(&value.name, &value.version, &value.checksum))
                .collect();
            if sources != selected {
                return Err(invalid("source evidence does not equal selected packages"));
            }
            for capability in &self.capabilities {
                let identity = capability_key(capability);
                let source = self
                    .registry_sources
                    .iter()
                    .find(|value| key(&value.name, &value.version, &value.checksum) == identity);
                if !source.is_some_and(|value| {
                    (!capability.build_script || value.build_script)
                        && (!capability.proc_macro || value.proc_macro)
                }) {
                    return Err(invalid(
                        "contains a capability without matching executable-code evidence",
                    ));
                }
            }
            Ok(())
        }
    }

    fn key<'a>(a: &'a str, b: &'a str, c: &'a str) -> (&'a str, &'a str, &'a str) {
        (a, b, c)
    }

    fn context_package_key(value: &ContextRegistry) -> (&str, &str, &str, &str, &str) {
        (
            &value.host,
            &value.target,
            &value.name,
            &value.version,
            &value.checksum,
        )
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
        }
        Ok(())
    }

    fn review_kind_name(value: ReviewKind) -> &'static str {
        match value {
            ReviewKind::Build => "build",
            ReviewKind::Development => "development",
            ReviewKind::Normal => "normal",
        }
    }

    fn unit_kind_name(value: UnitKind) -> &'static str {
        match value {
            UnitKind::Host => "host",
            UnitKind::Target => "target",
        }
    }

    fn reference_source_name(value: ReferenceSource) -> &'static str {
        match value {
            ReferenceSource::CratesIo => "crates.io",
            ReferenceSource::Path => "path",
        }
    }

    fn write_identity(
        writer: &mut Writer,
        name: &str,
        version: &str,
        checksum: &str,
    ) -> Result<()> {
        writer.string("name", name)?;
        writer.string("version", version)?;
        writer.string("checksum", checksum)
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
        }
        Ok(())
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
                    &[],
                )?;
                let native_tools = required_strings(path, table, "native-tools")?
                    .into_iter()
                    .map(|value| match value.as_str() {
                        "archiver" => Ok(NativeToolRole::Archiver),
                        "c-compiler" => Ok(NativeToolRole::CCompiler),
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

    fn canonical_requirement(value: &str) -> Result<()> {
        let parsed = semver::VersionReq::parse(value)
            .map_err(|error| invalid(format!("has invalid requirement `{value}`: {error}")))?;
        if parsed.to_string() != value {
            return Err(invalid(format!("has noncanonical requirement `{value}`")));
        }
        Ok(())
    }

    fn canonical_target_selector(value: &str) -> Result<String> {
        let Some(prefixed) = value.strip_prefix("cfg(") else {
            let triple = !value.is_empty()
                && !value.ends_with(".json")
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
            if !triple {
                return Err(invalid(format!(
                    "has an unsupported plain target selector `{value}`"
                )));
            }
            return Ok(value.to_owned());
        };
        let Some(expression) = prefixed.strip_suffix(')') else {
            return Err(invalid(format!(
                "has an unterminated cfg target selector `{value}`"
            )));
        };
        let mut parser = SelectorParser {
            source: expression.as_bytes(),
            position: 0,
            nodes: 0,
        };
        let rendered = parser.expression(1)?;
        parser.space();
        if parser.position != parser.source.len() {
            return Err(parser.error("unexpected trailing cfg syntax"));
        }
        Ok(format!("cfg({rendered})"))
    }

    // Mirrors the operational cfg evaluator's grammar but is frozen with the
    // review format: reviewed canonical bytes must not change when the
    // evaluator does.
    struct SelectorParser<'a> {
        source: &'a [u8],
        position: usize,
        nodes: usize,
    }

    impl SelectorParser<'_> {
        fn expression(&mut self, depth: usize) -> Result<String> {
            limit(depth, MAX_CFG_DEPTH, "cfg-expression nesting levels")?;
            self.nodes += 1;
            limit(self.nodes, MAX_CFG_NODES, "cfg-expression nodes")?;
            self.space();
            let name = self.identifier()?;
            self.space();
            if self.take(b'=') {
                self.space();
                let value = self.string()?;
                return Ok(format!("{name}=\"{value}\""));
            }
            if !self.take(b'(') {
                return Ok(name);
            }
            let mut children = Vec::new();
            loop {
                self.space();
                if self.take(b')') {
                    break;
                }
                children.push(self.expression(depth + 1)?);
                self.space();
                if self.take(b')') {
                    break;
                }
                if !self.take(b',') {
                    return Err(self.error("expected `,` or `)`"));
                }
            }
            match name.as_str() {
                "all" | "any" => {
                    children.sort();
                    children.dedup();
                    Ok(format!("{name}({})", children.join(",")))
                }
                "not" if children.len() == 1 => Ok(format!("not({})", children[0])),
                "not" => Err(self.error("`not` requires exactly one argument")),
                _ => Err(self.error(format!("unknown cfg predicate `{name}`"))),
            }
        }

        fn identifier(&mut self) -> Result<String> {
            let start = self.position;
            while self
                .source
                .get(self.position)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                self.position += 1;
            }
            if start == self.position {
                return Err(self.error("expected cfg identifier"));
            }
            Ok(String::from_utf8(self.source[start..self.position].to_vec()).unwrap())
        }

        fn string(&mut self) -> Result<String> {
            if !self.take(b'"') {
                return Err(self.error("expected quoted cfg value"));
            }
            let start = self.position;
            while self
                .source
                .get(self.position)
                .is_some_and(|byte| *byte != b'"')
            {
                if self.source[self.position] == b'\\' {
                    return Err(self.error("cfg string escapes are not supported"));
                }
                self.position += 1;
            }
            if !self.take(b'"') {
                return Err(self.error("unterminated cfg value"));
            }
            Ok(String::from_utf8(self.source[start..self.position - 1].to_vec()).unwrap())
        }

        fn space(&mut self) {
            while self
                .source
                .get(self.position)
                .is_some_and(u8::is_ascii_whitespace)
            {
                self.position += 1;
            }
        }

        fn take(&mut self, byte: u8) -> bool {
            if self.source.get(self.position) == Some(&byte) {
                self.position += 1;
                true
            } else {
                false
            }
        }

        fn error(&self, message: impl std::fmt::Display) -> Error {
            invalid(format!(
                "has an invalid cfg target selector at byte {}: {message}",
                self.position
            ))
        }
    }

    const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

    fn locked_graph(lock: &Lockfile) -> Result<Vec<LockedRegistry>> {
        let mut nodes: BTreeMap<&str, Vec<(&LockedPackage, ReferenceSource)>> = BTreeMap::new();
        for package in &lock.packages {
            let source = match package.source.as_deref() {
                None => ReferenceSource::Path,
                Some(CRATES_IO_SOURCE) => ReferenceSource::CratesIo,
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
                .map(|spelling| resolve_reference(&nodes, spelling))
                .collect::<Result<Vec<_>>>()?;
            dependencies.sort();
            result.push(LockedRegistry {
                name: package.name.clone(),
                version: package.version.original.clone(),
                checksum,
                dependencies,
            });
        }
        result.sort_by(|a, b| {
            key(&a.name, &a.version, &a.checksum).cmp(&key(&b.name, &b.version, &b.checksum))
        });
        Ok(result)
    }

    // A lock dependency spelling is `NAME`, `NAME VERSION`, or
    // `NAME VERSION (SOURCE)`; every spelling must select exactly one node.
    fn resolve_reference(
        nodes: &BTreeMap<&str, Vec<(&LockedPackage, ReferenceSource)>>,
        spelling: &str,
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
                source.is_none_or(|value| package.source.as_deref() == Some(value))
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
                self.quoted(&format!(
                    "{} {} {}",
                    reference_source_name(value.source),
                    value.name,
                    value.version
                ))?;
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
                review_sha256: "44".repeat(32),
                contexts: empty_review().contexts,
                capabilities: Vec::new(),
            }
        }

        fn capability() -> Capability {
            Capability {
                package: "demo".to_owned(),
                version: "1.0.0".to_owned(),
                checksum: "11".repeat(32),
                build_script: true,
                proc_macro: false,
                native_tools: vec![NativeToolRole::Archiver, NativeToolRole::CCompiler],
            }
        }

        fn registry_review() -> Review {
            let mut review = empty_review();
            let checksum = "11".repeat(32);
            review.locked_registry.push(LockedRegistry {
                name: "demo".to_owned(),
                version: "1.0.0".to_owned(),
                checksum: checksum.clone(),
                dependencies: Vec::new(),
            });
            review.context_registry.push(ContextRegistry {
                host: review.contexts[0].host.clone(),
                target: review.contexts[0].target.clone(),
                name: "demo".to_owned(),
                version: "1.0.0".to_owned(),
                checksum: checksum.clone(),
                compile_kinds: vec![UnitKind::Target],
                host_features: Vec::new(),
                target_features: vec!["enabled".to_owned()],
            });
            review.registry_sources.push(RegistrySource {
                name: "demo".to_owned(),
                version: "1.0.0".to_owned(),
                checksum,
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
        fn renders_canonical_compact_state() {
            let mut state = compact_state();
            state.capabilities.push(capability());
            let expected = br#"# Generated by Lorry. Do not edit.
format-version = 3
review-format-version = 2
review-sha256 = "4444444444444444444444444444444444444444444444444444444444444444"

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
            let formatted = source.replace(
                "format-version = 3",
                "# retained reviewer comment\nformat-version=3 # spacing is insignificant",
            );
            assert_eq!(CompactState::parse(path, formatted).unwrap(), state);

            let invalid = [
                source.replace("format-version = 3", "format-version = 4"),
                source.replace("review-format-version = 2\n", ""),
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
        fn rejects_noncanonical_nested_ordering() {
            let mut review = empty_review();
            review.direct_registry.push(DirectRegistry {
                alias: "demo".to_owned(),
                package: "demo".to_owned(),
                requirement: "=1.0.0".to_owned(),
                kind: ReviewKind::Normal,
                target: None,
                optional: false,
                default_features: true,
                features: vec!["z".to_owned(), "a".to_owned()],
            });
            assert!(review.validate().is_err());
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
            review = registry_review();
            review.direct_registry.push(DirectRegistry {
                alias: "demo".to_owned(),
                package: "demo".to_owned(),
                requirement: "1.0.0".to_owned(),
                kind: ReviewKind::Normal,
                target: None,
                optional: false,
                default_features: true,
                features: Vec::new(),
            });
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
                let manifest = Manifest::load(&self.0)?;
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
            assert_eq!(review.direct_registry.len(), 2);
            assert_eq!(review.direct_registry[0].alias, "cc");
            assert_eq!(review.direct_registry[0].requirement, "^1.0");
            assert_eq!(
                review.direct_registry[0].target.as_deref(),
                Some("cfg(unix)")
            );
            assert_eq!(review.direct_registry[1].alias, "libc");
            assert_eq!(review.direct_registry[1].features, ["extra", "std"]);
            assert_eq!(review.root_features.len(), 2);
            assert_eq!(review.crates_io_patches[0].package, "upstream");
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
                    BASE_MANIFEST.replace("=0.2.186", "=0.2.185"),
                    BASE_LOCK.to_owned(),
                ),
                (
                    BASE_MANIFEST.replace("[\"std\", \"extra\"]", "[\"std\"]"),
                    BASE_LOCK.to_owned(),
                ),
                (
                    BASE_MANIFEST.replace("default = [\"extra\"]", "default = []"),
                    BASE_LOCK.to_owned(),
                ),
                (
                    BASE_MANIFEST.replace("\"upstream\"", "\"upstream2\""),
                    BASE_LOCK.to_owned(),
                ),
                (
                    BASE_MANIFEST.replace("cfg( unix )", "cfg( windows )"),
                    BASE_LOCK.to_owned(),
                ),
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
                packages: vec![package(Some("git+https://example.com/demo"), None)],
            };
            assert!(locked_graph(&git).is_err());
            let unchecksummed = Lockfile {
                packages: vec![package(Some(CRATES_IO_SOURCE), None)],
            };
            assert!(locked_graph(&unchecksummed).is_err());
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
            let manifest = Manifest::load(&project.0).unwrap();
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
                    required_patch: None,
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
            let manifest = Manifest::load(&project.0).unwrap();
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
        fn canonicalizes_cfg_selectors_and_plain_triples() {
            let canonical = |value: &str| canonical_target_selector(value).unwrap();
            assert_eq!(
                canonical("cfg(all( unix, target_os = \"linux\" ))"),
                "cfg(all(target_os=\"linux\",unix))"
            );
            assert_eq!(
                canonical("cfg(any(target_os=\"linux\" , unix ,))"),
                canonical("cfg(any(unix,target_os=\"linux\"))")
            );
            assert_eq!(canonical("cfg(all(unix,unix))"), "cfg(all(unix))");
            assert_eq!(
                canonical("cfg(not( all( any() , unix ) ))"),
                "cfg(not(all(any(),unix)))"
            );
            assert_eq!(canonical("x86_64-unknown-motor"), "x86_64-unknown-motor");
            for value in [
                "cfg(all(target_os=\"linux\",unix))",
                "cfg(any())",
                "x86_64-unknown-motor",
            ] {
                assert_eq!(canonical(&canonical(value)), canonical(value));
            }
        }

        #[test]
        fn rejects_invalid_selectors_and_enforces_cfg_bounds() {
            for value in [
                "",
                "custom-target.json",
                "bad triple",
                "cfg(unix",
                "cfg()",
                "cfg(unix) ",
                "cfg(unix windows)",
                "cfg(not())",
                "cfg(not(unix,windows))",
                "cfg(version(\"1.0\"))",
                "cfg(target_os=linux)",
                "cfg(target_os=\"a\\\"b\")",
                "cfg(target_os=\"open)",
            ] {
                assert!(canonical_target_selector(value).is_err(), "{value}");
            }

            let nested =
                |count: usize| format!("cfg({}unix{})", "not(".repeat(count), ")".repeat(count));
            assert!(canonical_target_selector(&nested(MAX_CFG_DEPTH - 1)).is_ok());
            assert!(canonical_target_selector(&nested(MAX_CFG_DEPTH)).is_err());

            let wide = |count: usize| {
                let children: Vec<String> = (0..count).map(|index| format!("k{index}")).collect();
                format!("cfg(any({}))", children.join(","))
            };
            assert!(canonical_target_selector(&wide(MAX_CFG_NODES - 1)).is_ok());
            assert!(canonical_target_selector(&wide(MAX_CFG_NODES)).is_err());
        }

        #[test]
        fn target_selector_mutations_change_the_commitment() {
            let with_target = |target: &str| {
                let mut review = empty_review();
                review.direct_registry.push(DirectRegistry {
                    alias: "demo".to_owned(),
                    package: "demo".to_owned(),
                    requirement: "=1.0.0".to_owned(),
                    kind: ReviewKind::Normal,
                    target: Some(target.to_owned()),
                    optional: false,
                    default_features: true,
                    features: Vec::new(),
                });
                review
            };
            assert!(with_target("cfg( unix )").render().is_err());
            assert!(with_target("cfg(all(unix,unix))").render().is_err());

            let variants = [
                "cfg(unix)",
                "cfg(linux)",
                "cfg(not(unix))",
                "cfg(target_os=\"linux\")",
                "cfg(target_os=\"motor\")",
            ];
            let hashes: BTreeSet<String> = variants
                .iter()
                .map(|target| sha256(&with_target(target).render().unwrap()))
                .collect();
            assert_eq!(hashes.len(), variants.len());
        }

        #[test]
        fn renders_and_hashes_representative_review_golden() {
            let mut review = registry_review();
            let direct = |alias: &str, kind, target| DirectRegistry {
                alias: alias.to_owned(),
                package: "demo".to_owned(),
                requirement: "=1.0.0".to_owned(),
                kind,
                target,
                optional: false,
                default_features: true,
                features: Vec::new(),
            };
            review.direct_registry = vec![
                direct("a", ReviewKind::Build, None),
                direct("b", ReviewKind::Development, None),
                direct("c", ReviewKind::Normal, Some("cfg(unix)".to_owned())),
            ];
            review.root_features.push(RootFeature {
                name: "default".to_owned(),
                values: vec!["feature-a".to_owned()],
            });
            review.crates_io_patches.push(CratesIoPatch {
                alias: "patched".to_owned(),
                package: "demo".to_owned(),
            });
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
                checksum: "33".repeat(32),
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
            });

            let bytes = review.render().unwrap();
            let expected = br#"review-format-version = 2
source-tree-format-version = 1
cargo-lock-format-version = 4
resolver-version = 2

[[context]]
host = "x86_64-unknown-linux-gnu"
target = "x86_64-unknown-motor"

[[direct-registry]]
alias = "a"
package = "demo"
requirement = "=1.0.0"
kind = "build"
optional = false
default-features = true
features = []

[[direct-registry]]
alias = "b"
package = "demo"
requirement = "=1.0.0"
kind = "development"
optional = false
default-features = true
features = []

[[direct-registry]]
alias = "c"
package = "demo"
requirement = "=1.0.0"
kind = "normal"
target = "cfg(unix)"
optional = false
default-features = true
features = []

[[root-feature]]
name = "default"
values = ["feature-a"]

[[crates-io-patch]]
alias = "patched"
package = "demo"

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
                "a879ddf6011e8809535372a36bf82e82ebc09c93befd0b0d315ba27f9c4a3da2"
            );
        }

        #[test]
        fn renders_and_hashes_empty_registry_review_golden() {
            let bytes = empty_review().render().unwrap();
            let expected = b"review-format-version = 2\n\
source-tree-format-version = 1\n\
cargo-lock-format-version = 4\n\
resolver-version = 2\n\
\n\
[[context]]\n\
host = \"x86_64-unknown-linux-gnu\"\n\
target = \"x86_64-unknown-motor\"\n";
            assert_eq!(bytes, expected);
            assert_eq!(
                sha256(&bytes),
                "994a9622523d9f525900e2b3729932c72e90dce7ffd251a37bb07894555f4efc"
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
            review_sha256: "44".repeat(32),
            contexts: vec![context()],
            capabilities: vec![Capability {
                package: "libc".to_owned(),
                version: "0.2.186".to_owned(),
                checksum: "33".repeat(32),
                build_script: true,
                proc_macro: false,
                native_tools: Vec::new(),
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
            checksum: "33".repeat(32),
            dependencies: Vec::new(),
        });
        review.context_registry.push(ContextRegistry {
            host: review.contexts[0].host.clone(),
            target: review.contexts[0].target.clone(),
            name: "libc".to_owned(),
            version: "0.2.186".to_owned(),
            checksum: "33".repeat(32),
            compile_kinds: vec![UnitKind::Target],
            host_features: Vec::new(),
            target_features: Vec::new(),
        });
        review.registry_sources.push(RegistrySource {
            name: "libc".to_owned(),
            version: "0.2.186".to_owned(),
            checksum: "33".repeat(32),
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
            kind: DependencyKind::Normal,
            compile_kind: CompileKind::Target,
            context: FeatureContext::Unified,
            package: package.key.clone(),
        };
        let error = crate::policy::preflight(
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
