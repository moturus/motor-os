#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use semver::{Version, VersionReq};

use crate::cargo_registry::CargoRegistry;
use crate::config::IncompatibleRustVersions;
use crate::diagnostic::{Error, Result};
use crate::hash::{decode_hex, hex};
use crate::manifest::{
    DependencySource, GitDependency, Lockfile, Manifest, Resolver as ResolverVersion,
};
use crate::policy::PackageLimit;
use crate::repository::RepositorySet;
use crate::source_tree::{DEFAULT_LIMITS as DEFAULT_TREE_LIMITS, Exclusions, Tree};
use crate::sparse::{Dependency, DependencyKind, Record, RustVersion};
use crate::toolchain::CfgSet;

pub(crate) mod workspace;
#[cfg(test)]
use workspace::resolve_complete_workspace;

#[derive(Clone, Debug, Default)]
pub struct Catalog {
    fetch_hint: bool,
    descriptive_sources: bool,
    records: BTreeMap<String, Vec<Candidate>>,
    paths: BTreeMap<PathBuf, PackageKey>,
    locked_repository: Option<LockedRepository>,
    proc_macros: BTreeSet<PackageKey>,
    workspace_members: BTreeMap<String, PathBuf>,
    workspace_root: PathBuf,
}

impl Catalog {
    pub(crate) fn use_fetch_hint(&mut self) {
        self.fetch_hint = true;
    }
    pub fn from_locked_repository(
        manifest: &Manifest,
        repositories: &RepositorySet,
    ) -> Result<Self> {
        Ok(Self {
            locked_repository: Some(LockedRepository {
                source: LockedRegistrySource::Lorry(repositories.clone()),
                packages: locked_registry_packages(manifest)?,
            }),
            ..Self::default()
        })
    }

    pub fn allow_unlocked_registry_candidates(&mut self) {
        self.locked_repository = None;
    }

    pub fn from_locked_cargo_registry(
        manifest: &Manifest,
        registry: &CargoRegistry,
    ) -> Result<Self> {
        Ok(Self {
            locked_repository: Some(LockedRepository {
                source: LockedRegistrySource::Cargo(registry.clone()),
                packages: locked_registry_packages(manifest)?,
            }),
            ..Self::default()
        })
    }

    pub fn insert(&mut self, record: Record) -> Result<()> {
        let records = self.records.entry(record.name.clone()).or_default();
        if records.iter().any(|existing| {
            matches!(existing.source, ResolvedSource::CratesIo { .. })
                && same_semver_identity(&existing.record.version, &record.version)
        }) {
            return Err(Error::failure(format!(
                "sparse catalog contains duplicate package version `{} {}`",
                record.name, record.version
            )));
        }
        let key = PackageKey {
            name: record.name.clone(),
            version: record.version.clone(),
            source: PackageSourceKey::CratesIo,
        };
        records.push(Candidate {
            dependencies: record
                .dependencies
                .iter()
                .cloned()
                .map(|dependency| CandidateDependency {
                    dependency,
                    source: RequirementSource::CratesIo,
                })
                .collect(),
            source: ResolvedSource::CratesIo {
                checksum: record.checksum,
            },
            local_manifest: None,
            proc_macro: self.proc_macros.contains(&key),
            record,
        });
        records.sort_unstable_by(|left, right| right.record.version.cmp(&left.record.version));
        Ok(())
    }

    pub fn annotate_proc_macro(&mut self, key: &PackageKey, proc_macro: bool) -> Result<bool> {
        let mut previous = self.proc_macros.contains(key);
        if proc_macro {
            self.proc_macros.insert(key.clone());
        } else {
            self.proc_macros.remove(key);
        }
        for candidate in self.records.get_mut(&key.name).into_iter().flatten() {
            if candidate.record.version == key.version && candidate.source.key() == key.source {
                previous = candidate.proc_macro;
                candidate.proc_macro = proc_macro;
            }
        }
        Ok(previous != proc_macro)
    }

    fn records(&self, name: &str) -> &[Candidate] {
        self.records.get(name).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn contains_registry(&self, name: &str, version: &Version) -> bool {
        self.records(name).iter().any(|candidate| {
            matches!(candidate.source, ResolvedSource::CratesIo { .. })
                && candidate.record.version == *version
        })
    }

    pub fn contains_crates_io_candidate(&self, name: &str, requirement: &VersionReq) -> bool {
        self.records(name).iter().any(|candidate| {
            requirement.matches(&candidate.version)
                && matches!(
                    candidate.source,
                    ResolvedSource::CratesIo { .. }
                        | ResolvedSource::Path {
                            patched_crates_io: true,
                            ..
                        }
                        | ResolvedSource::Git {
                            patched_crates_io: true,
                            ..
                        }
                )
        })
    }

    pub(crate) fn insert_path_patch(
        &mut self,
        manifest: Manifest,
        logical_root: PathBuf,
        physical_root: PathBuf,
        source_tree_sha256: [u8; 32],
    ) -> Result<()> {
        let candidate = local_candidate(
            manifest,
            logical_root,
            physical_root,
            source_tree_sha256,
            true,
        )?;
        let records = self.records.entry(candidate.name.clone()).or_default();
        if records.iter().any(|existing| {
            matches!(
                existing.source,
                ResolvedSource::Path {
                    patched_crates_io: true,
                    ..
                } | ResolvedSource::Git {
                    patched_crates_io: true,
                    ..
                }
            ) && same_semver_identity(&existing.version, &candidate.version)
        }) {
            return Err(Error::failure(format!(
                "multiple path patches provide `{} {}`",
                candidate.name, candidate.version
            )));
        }
        records.push(candidate);
        records.sort_unstable_by(|left, right| right.record.version.cmp(&left.record.version));
        Ok(())
    }

    pub(crate) fn insert_git(&mut self, manifest: Manifest, source: ResolvedSource) -> Result<()> {
        let ResolvedSource::Git {
            logical_root,
            physical_root,
            source_tree_sha256,
            cargo_source,
            ..
        } = &source
        else {
            return Err(Error::failure(
                "internal Git candidate has a non-Git source",
            ));
        };
        let cargo_source = cargo_source.clone();
        let mut candidate = local_candidate(
            manifest,
            logical_root.clone(),
            physical_root.clone(),
            *source_tree_sha256,
            false,
        )?;
        candidate.source = source;
        let records = self.records.entry(candidate.name.clone()).or_default();
        if records.iter().any(|existing| {
            existing.version == candidate.version
                && matches!(
                    &existing.source,
                    ResolvedSource::Git { cargo_source: existing, .. } if existing == &cargo_source
                )
        }) {
            return Err(Error::failure(format!(
                "Git source repeats package `{} {}`",
                candidate.name, candidate.version
            )));
        }
        records.push(candidate);
        records.sort_unstable_by(|left, right| right.record.version.cmp(&left.record.version));
        Ok(())
    }

    pub(crate) fn insert_git_patch(
        &mut self,
        manifest: Manifest,
        mut source: ResolvedSource,
    ) -> Result<()> {
        let ResolvedSource::Git {
            patched_crates_io, ..
        } = &mut source
        else {
            return Err(Error::failure(
                "internal Git patch candidate has a non-Git source",
            ));
        };
        *patched_crates_io = true;
        self.insert_git(manifest, source)
    }

    fn prepare(&mut self, dependency: &mut CandidateDependency) -> Result<()> {
        match &dependency.source {
            RequirementSource::CratesIo => return self.prepare_registry(dependency),
            RequirementSource::Git(git) => {
                if self.records(&dependency.package).iter().any(|candidate| {
                    dependency.requirement.matches(&candidate.version)
                        && source_matches(&candidate.source, &dependency.source)
                }) {
                    return Ok(());
                }
                return Err(Error::failure(format!(
                    "locked Git dependency `{}` from `{}` is unavailable; run `lorry vendor [--accept-all]`",
                    dependency.package, git.url
                )));
            }
            RequirementSource::Path(_) => {}
        }
        let RequirementSource::Path(declared) = &mut dependency.source else {
            unreachable!();
        };
        let canonical = fs::canonicalize(&*declared).map_err(|error| {
            Error::failure(format!(
                "failed to resolve local path dependency `{}`: {error}",
                declared.display()
            ))
        })?;
        *declared = canonical.clone();
        if self.paths.contains_key(&canonical) {
            return Ok(());
        }

        let mut manifest = if self.descriptive_sources {
            Manifest::load_source_dependency(&canonical)?
        } else {
            Manifest::load_path_dependency(&canonical)?
        };
        manifest.editable = self
            .workspace_members
            .values()
            .any(|member| *member == canonical);
        if manifest.editable {
            manifest.workspace_root.clone_from(&self.workspace_root);
            manifest
                .workspace_members
                .clone_from(&self.workspace_members);
        }
        let version = Version::parse(&manifest.version.original).map_err(|error| {
            Error::failure(format!(
                "invalid local package version `{} {}`: {error}",
                manifest.name, manifest.version.original
            ))
        })?;
        let sha256 = if manifest.editable {
            crate::member_source::snapshot(&manifest, true)?.sha256
        } else {
            Tree::scan(&canonical, DEFAULT_TREE_LIMITS, Exclusions::GitAndTarget)?.sha256
        };
        let key = PackageKey {
            name: manifest.name.clone(),
            version: version.clone(),
            source: PackageSourceKey::Path(canonical.clone()),
        };
        if self.paths.insert(canonical.clone(), key.clone()).is_some() {
            return Ok(());
        }
        let candidate = local_candidate(manifest, canonical.clone(), canonical, sha256, false)?;
        debug_assert_eq!(candidate.version, version);
        let records = self.records.entry(candidate.name.clone()).or_default();
        records.push(candidate);
        records.sort_unstable_by(|left, right| right.record.version.cmp(&left.record.version));
        Ok(())
    }

    fn prepare_registry(&mut self, dependency: &CandidateDependency) -> Result<()> {
        let Some(repository) = &self.locked_repository else {
            return Ok(());
        };
        let locked = repository
            .packages
            .get(&dependency.package)
            .into_iter()
            .flatten()
            .filter(|package| dependency.requirement.matches(&package.version))
            .cloned()
            .collect::<Vec<_>>();
        let source = repository.source.clone();

        let has_patch_candidate = self.records(&dependency.package).iter().any(|candidate| {
            dependency.requirement.matches(&candidate.version)
                && matches!(
                    candidate.source,
                    ResolvedSource::Path {
                        patched_crates_io: true,
                        ..
                    } | ResolvedSource::Git {
                        patched_crates_io: true,
                        ..
                    }
                )
        });
        let mut available = self.records(&dependency.package).iter().any(|candidate| {
            locked.iter().any(|package| {
                package.version == candidate.version
                    && matches!(
                        candidate.source,
                        ResolvedSource::CratesIo { checksum }
                            if hex(&checksum) == package.checksum
                    )
            })
        });
        let mut missing = Vec::new();
        for package in locked {
            if self.records(&dependency.package).iter().any(|candidate| {
                candidate.version == package.version
                    && matches!(
                        candidate.source,
                        ResolvedSource::CratesIo { checksum }
                            if hex(&checksum) == package.checksum
                    )
            }) {
                continue;
            }
            let record = match &source {
                LockedRegistrySource::Lorry(repositories) => {
                    let Some(object) = repositories.lookup_registry(&package.checksum)? else {
                        missing.push(package);
                        continue;
                    };
                    if object.name != dependency.package || object.version != package.version {
                        return Err(Error::failure(format!(
                            "repository object `{}` identifies `{} {}`, but Cargo.lock selects `{} {}`",
                            package.checksum,
                            object.name,
                            object.version,
                            dependency.package,
                            package.version
                        )));
                    }
                    object.index
                }
                LockedRegistrySource::Cargo(registry) => {
                    let package = if self.descriptive_sources {
                        registry.load_description(
                            &dependency.package,
                            &package.version,
                            &package.checksum,
                        )?
                    } else {
                        registry.load(&dependency.package, &package.version, &package.checksum)?
                    };
                    package.record()?
                }
            };
            self.insert(record)?;
            available = true;
        }
        if available || has_patch_candidate {
            return Ok(());
        }
        if missing.is_empty() {
            return Err(Error::failure(format!(
                "Cargo.lock has no crates.io package `{}` matching `{}`; run `lorry vendor [--accept-all]` to update Cargo.lock",
                dependency.package, dependency.requirement
            )));
        }
        let identities = missing
            .iter()
            .map(|package| format!("{} {}", dependency.package, package.version))
            .collect::<Vec<_>>()
            .join(", ");
        let (location, action) = match source {
            LockedRegistrySource::Lorry(_) if self.fetch_hint => (
                "the configured Lorry repositories",
                "; run `lorry fetch` to acquire the missing locked package",
            ),
            LockedRegistrySource::Lorry(_) => (
                "the configured Lorry repositories",
                "; run `lorry vendor [--accept-all]` to acquire the missing package",
            ),
            LockedRegistrySource::Cargo(_) => (
                "Cargo's registry cache",
                "; run Cargo for this locked package first because Lorry does not fetch or repair Cargo's cache",
            ),
        };
        Err(Error::failure(format!(
            "locked crates.io package{} {identities} {} unavailable in {location}{action}",
            if missing.len() == 1 { "" } else { "s" },
            if missing.len() == 1 { "is" } else { "are" },
        )))
    }
}

#[derive(Clone, Debug)]
struct LockedRepository {
    source: LockedRegistrySource,
    packages: BTreeMap<String, Vec<LockedRegistryPackage>>,
}

#[derive(Clone, Debug)]
enum LockedRegistrySource {
    Lorry(RepositorySet),
    Cargo(CargoRegistry),
}

#[derive(Clone, Debug)]
struct LockedRegistryPackage {
    version: Version,
    checksum: String,
}

fn locked_registry_packages(
    manifest: &Manifest,
) -> Result<BTreeMap<String, Vec<LockedRegistryPackage>>> {
    let lock = manifest.lock.as_ref().ok_or_else(|| {
        Error::failure("Cargo.lock is missing")
            .with_help("create a version-4 Cargo.lock before building")
    })?;
    let mut packages: BTreeMap<String, Vec<LockedRegistryPackage>> = BTreeMap::new();
    for package in &lock.packages {
        let (Some(source), Some(checksum)) = (&package.source, &package.checksum) else {
            continue;
        };
        if source != "registry+https://github.com/rust-lang/crates.io-index" {
            continue;
        }
        let version = Version::parse(&package.version.original).map_err(|error| {
            Error::failure(format!(
                "invalid locked version `{} {}`: {error}",
                package.name, package.version.original
            ))
        })?;
        packages
            .entry(package.name.clone())
            .or_default()
            .push(LockedRegistryPackage {
                version,
                checksum: checksum.clone(),
            });
    }
    for versions in packages.values_mut() {
        versions.sort_unstable_by(|left, right| right.version.cmp(&left.version));
    }
    Ok(packages)
}

fn local_candidate(
    manifest: Manifest,
    logical_root: PathBuf,
    physical_root: PathBuf,
    source_tree_sha256: [u8; 32],
    patched_crates_io: bool,
) -> Result<Candidate> {
    let version = Version::parse(&manifest.version.original).map_err(|error| {
        Error::failure(format!(
            "invalid local package version `{} {}`: {error}",
            manifest.name, manifest.version.original
        ))
    })?;
    let dependencies = manifest
        .dependencies
        .iter()
        .map(|dependency| {
            Ok(CandidateDependency {
                dependency: Dependency {
                    alias: dependency.alias.clone(),
                    package: dependency.package.clone(),
                    requirement: dependency.requirement.clone(),
                    features: dependency.features.clone(),
                    optional: dependency.optional,
                    default_features: dependency.default_features,
                    target: dependency.target.clone(),
                    kind: dependency.kind,
                },
                source: match &dependency.source {
                    DependencySource::CratesIo => RequirementSource::CratesIo,
                    DependencySource::Path(path) => RequirementSource::Path(path.clone()),
                    DependencySource::Git(git) => RequirementSource::Git(git.clone()),
                },
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let rust_version = if manifest.metadata.rust_version.is_empty() {
        None
    } else {
        Some(parse_local_rust_version(
            &manifest.name,
            &manifest.metadata.rust_version,
        )?)
    };
    let record = Record {
        name: manifest.name.clone(),
        version,
        dependencies: dependencies
            .iter()
            .map(|dependency| dependency.dependency.clone())
            .collect(),
        checksum: source_tree_sha256,
        features: manifest.features.clone(),
        features2: BTreeMap::new(),
        yanked: false,
        links: manifest.links.clone(),
        schema: 1,
        rust_version,
        published: None,
        exact_bytes: Vec::new(),
    };
    Ok(Candidate {
        record,
        dependencies,
        source: ResolvedSource::Path {
            logical_root,
            physical_root,
            source_tree_sha256,
            patched_crates_io,
        },
        proc_macro: manifest
            .library
            .as_ref()
            .is_some_and(|library| library.proc_macro),
        local_manifest: Some(manifest),
    })
}

#[derive(Clone, Debug)]
struct Candidate {
    record: Record,
    dependencies: Vec<CandidateDependency>,
    source: ResolvedSource,
    local_manifest: Option<Manifest>,
    proc_macro: bool,
}

impl std::ops::Deref for Candidate {
    type Target = Record;

    fn deref(&self) -> &Self::Target {
        &self.record
    }
}

#[derive(Clone, Debug)]
struct CandidateDependency {
    dependency: Dependency,
    source: RequirementSource,
}

impl std::ops::Deref for CandidateDependency {
    type Target = Dependency;

    fn deref(&self) -> &Self::Target {
        &self.dependency
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RequirementSource {
    CratesIo,
    Path(PathBuf),
    Git(GitDependency),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockedPreference {
    pub name: String,
    pub version: Version,
    pub checksum: Option<[u8; 32]>,
}

impl LockedPreference {
    pub fn from_lockfile(lock: Option<&Lockfile>) -> Result<Vec<Self>> {
        let mut preferences = Vec::new();
        for package in lock.into_iter().flat_map(|lock| &lock.packages) {
            let (Some(source), Some(checksum)) = (&package.source, &package.checksum) else {
                continue;
            };
            if source != "registry+https://github.com/rust-lang/crates.io-index" {
                continue;
            }
            let version = Version::parse(&package.version.original).map_err(|error| {
                Error::failure(format!(
                    "invalid locked version `{} {}`: {error}",
                    package.name, package.version.original
                ))
            })?;
            let checksum = decode_hex(checksum).map_err(|error| {
                Error::failure(format!(
                    "invalid locked checksum for `{} {version}`: {error}",
                    package.name
                ))
            })?;
            preferences.push(Self {
                name: package.name.clone(),
                version,
                checksum: Some(checksum),
            });
        }
        Ok(preferences)
    }

    pub fn from_resolution(resolution: &Resolution) -> Vec<Self> {
        resolution
            .packages
            .iter()
            .filter_map(|package| {
                let ResolvedSource::CratesIo { checksum } = package.source else {
                    return None;
                };
                Some(Self {
                    name: package.key.name.clone(),
                    version: package.key.version.clone(),
                    checksum: Some(checksum),
                })
            })
            .collect()
    }

    pub fn force_version(
        preferences: &mut Vec<Self>,
        name: &str,
        old: Option<&Version>,
        version: Version,
    ) {
        if let Some(old) = old {
            preferences.retain(|preference| {
                preference.name != name || !same_semver_identity(&preference.version, old)
            });
        }
        preferences.push(Self {
            name: name.to_owned(),
            version,
            checksum: None,
        });
    }
}

#[derive(Clone, Debug)]
pub struct Options {
    pub resolver: ResolverVersion,
    pub incompatible_rust_versions: Option<IncompatibleRustVersions>,
    pub rust_versions: Vec<Version>,
    pub package_limit: PackageLimit,
    pub max_depth: u64,
}

impl Options {
    fn rust_policy(&self) -> IncompatibleRustVersions {
        self.incompatible_rust_versions
            .unwrap_or(match self.resolver {
                ResolverVersion::V3 => IncompatibleRustVersions::Fallback,
                ResolverVersion::V1 | ResolverVersion::V2 => IncompatibleRustVersions::Allow,
            })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TargetSelection<'a> {
    pub target_triple: &'a str,
    pub target_cfg: &'a CfgSet,
    pub host_triple: &'a str,
    pub host_cfg: &'a CfgSet,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FeatureContext {
    Unified,
    Target(String),
    Host,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolvedSource {
    CratesIo {
        checksum: [u8; 32],
    },
    Path {
        logical_root: PathBuf,
        physical_root: PathBuf,
        source_tree_sha256: [u8; 32],
        patched_crates_io: bool,
    },
    Git {
        cargo_source: String,
        git_url: String,
        requested_revision: String,
        resolved_commit: String,
        git_tree: String,
        repository_tree_sha256: [u8; 32],
        package_path: String,
        logical_root: PathBuf,
        physical_root: PathBuf,
        source_tree_sha256: [u8; 32],
        patched_crates_io: bool,
    },
}

impl ResolvedSource {
    fn key(&self) -> PackageSourceKey {
        match self {
            Self::CratesIo { .. } => PackageSourceKey::CratesIo,
            Self::Path { logical_root, .. } => PackageSourceKey::Path(logical_root.clone()),
            Self::Git { cargo_source, .. } => PackageSourceKey::Git(cargo_source.clone()),
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PackageSourceKey {
    CratesIo,
    Path(PathBuf),
    Git(String),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PackageKey {
    pub name: String,
    pub version: Version,
    pub source: PackageSourceKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedEdge {
    pub dependency_index: usize,
    pub alias: String,
    pub kind: DependencyKind,
    /// The declaration's platform condition; sparse and manifest indexes differ.
    pub target: Option<String>,
    /// Compilation context of the package declaring this dependency.
    /// This differs from `compile_kind` when a target library uses a host
    /// procedural macro.
    pub parent_compile_kind: Option<CompileKind>,
    /// Compilation context of the dependency package.
    pub compile_kind: CompileKind,
    pub context: FeatureContext,
    pub package: PackageKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedPackage {
    pub key: PackageKey,
    pub source: ResolvedSource,
    pub local_manifest: Option<Manifest>,
    pub feature_sets: BTreeMap<FeatureContext, BTreeSet<String>>,
    pub compile_kinds: BTreeSet<CompileKind>,
    pub target_features: BTreeSet<String>,
    pub host_features: BTreeSet<String>,
    pub edges: Vec<ResolvedEdge>,
    pub lock_edges: Vec<ResolvedEdge>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Resolution {
    pub root_edges: Vec<ResolvedEdge>,
    pub packages: Vec<ResolvedPackage>,
}

pub fn merge_resolutions(resolutions: impl IntoIterator<Item = Resolution>) -> Result<Resolution> {
    let mut root_edges = Vec::new();
    let mut packages = BTreeMap::<PackageKey, ResolvedPackage>::new();
    for resolution in resolutions {
        for edge in resolution.root_edges {
            if !root_edges.contains(&edge) {
                root_edges.push(edge);
            }
        }
        for package in resolution.packages {
            let Some(existing) = packages.get_mut(&package.key) else {
                packages.insert(package.key.clone(), package);
                continue;
            };
            if existing.source != package.source
                || existing.local_manifest != package.local_manifest
            {
                return Err(Error::failure(format!(
                    "target resolutions disagree about source identity for `{} {}`",
                    package.key.name, package.key.version
                )));
            }
            for (context, features) in package.feature_sets {
                existing
                    .feature_sets
                    .entry(context)
                    .or_default()
                    .extend(features);
            }
            existing.compile_kinds.extend(package.compile_kinds);
            existing.target_features.extend(package.target_features);
            existing.host_features.extend(package.host_features);
            for edge in package.edges {
                if !existing.edges.contains(&edge) {
                    existing.edges.push(edge);
                }
            }
            for edge in package.lock_edges {
                if !existing.lock_edges.contains(&edge) {
                    existing.lock_edges.push(edge);
                }
            }
        }
    }
    Ok(Resolution {
        root_edges,
        packages: packages.into_values().collect(),
    })
}

pub fn resolve(
    manifest: &Manifest,
    catalog: &Catalog,
    options: &Options,
    locked: &[LockedPreference],
) -> Result<Resolution> {
    let mut catalog = catalog.clone();
    resolve_with_scope(
        manifest,
        &mut catalog,
        options,
        locked,
        Scope::Complete,
        &mut |_, _, _| Ok(()),
    )
}

pub fn resolve_selected(
    manifest: &Manifest,
    catalog: &Catalog,
    options: &Options,
    locked: &[LockedPreference],
    selection: TargetSelection<'_>,
) -> Result<Resolution> {
    let mut catalog = catalog.clone();
    resolve_with_scope(
        manifest,
        &mut catalog,
        options,
        locked,
        Scope::Selected(selection),
        &mut |_, _, _| Ok(()),
    )
}

pub fn resolve_dynamic(
    manifest: &Manifest,
    catalog: &mut Catalog,
    options: &Options,
    locked: &[LockedPreference],
    loader: &mut dyn FnMut(&str, &VersionReq, &mut Catalog) -> Result<()>,
) -> Result<Resolution> {
    resolve_with_scope(manifest, catalog, options, locked, Scope::Complete, loader)
}

pub fn resolve_selected_dynamic(
    manifest: &Manifest,
    catalog: &mut Catalog,
    options: &Options,
    locked: &[LockedPreference],
    selection: TargetSelection<'_>,
    loader: &mut dyn FnMut(&str, &VersionReq, &mut Catalog) -> Result<()>,
) -> Result<Resolution> {
    resolve_with_scope(
        manifest,
        catalog,
        options,
        locked,
        Scope::Selected(selection),
        loader,
    )
}

fn resolve_with_scope(
    manifest: &Manifest,
    catalog: &mut Catalog,
    options: &Options,
    locked: &[LockedPreference],
    scope: Scope<'_>,
    loader: &mut dyn FnMut(&str, &VersionReq, &mut Catalog) -> Result<()>,
) -> Result<Resolution> {
    catalog
        .workspace_members
        .clone_from(&manifest.workspace_members);
    catalog.workspace_root.clone_from(&manifest.workspace_root);
    validate_locked_checksums(catalog, locked)?;
    let requirements = root_requirements(manifest, matches!(scope, Scope::Complete))?;
    let mut queue = VecDeque::new();
    for requirement in requirements {
        if !scope.matches(
            CompileKind::Target,
            requirement.dependency.target.as_deref(),
        )? {
            continue;
        }
        queue.push_back(Event {
            parent: None,
            parent_compile_kind: None,
            dependency_index: requirement.index,
            context: root_context(options.resolver, scope, &requirement.dependency),
            compile_kind: CompileKind::Target,
            dependency: requirement.dependency,
            depth: 1,
            ancestors: BTreeSet::new(),
        });
    }
    solve_request(queue, catalog, options, locked, scope, loader)
}

fn solve_request(
    queue: VecDeque<Event>,
    catalog: &mut Catalog,
    options: &Options,
    locked: &[LockedPreference],
    scope: Scope<'_>,
    loader: &mut dyn FnMut(&str, &VersionReq, &mut Catalog) -> Result<()>,
) -> Result<Resolution> {
    let state = solve(
        State::default(),
        queue,
        catalog,
        options,
        locked,
        scope,
        loader,
    )
    .map_err(|failure| {
        if failure.package_limit {
            options.package_limit.error()
        } else {
            Error::failure(format!("dependency resolution failed: {}", failure.message))
        }
    })?;
    Ok(state.into_resolution())
}

#[derive(Clone, Copy)]
enum Scope<'a> {
    Complete,
    WorkspaceComplete,
    Selected(TargetSelection<'a>),
    WorkspaceSelected {
        selection: TargetSelection<'a>,
        complete: &'a Resolution,
        dev_members: &'a BTreeSet<PathBuf>,
    },
    WorkspaceMetadata {
        complete: &'a Resolution,
    },
}

impl<'a> Scope<'a> {
    fn matches(self, compile_kind: CompileKind, selector: Option<&str>) -> Result<bool> {
        let Some(selector) = selector else {
            return Ok(true);
        };
        let selection = match self {
            Self::Selected(selection) | Self::WorkspaceSelected { selection, .. } => selection,
            _ => return Ok(true),
        };
        let (triple, cfg) = match compile_kind {
            CompileKind::Target => (selection.target_triple, selection.target_cfg),
            CompileKind::Host => (selection.host_triple, selection.host_cfg),
        };
        if selector.starts_with("cfg(") {
            cfg.matches_selector(selector)
        } else {
            Ok(selector == triple)
        }
    }

    fn locked_package(self, event: &Event) -> std::result::Result<Option<&'a PackageKey>, Failure> {
        let complete = match self {
            Self::WorkspaceSelected { complete, .. } | Self::WorkspaceMetadata { complete } => {
                complete
            }
            _ => return Ok(None),
        };
        let Some(parent) = &event.parent else {
            return Ok(None);
        };
        let package = complete
            .packages
            .iter()
            .find(|package| &package.key == parent)
            .ok_or_else(|| {
                Failure::fatal("selected dependency parent is absent from the complete resolution")
            })?;
        let mut matching = package
            .lock_edges
            .iter()
            .filter(|edge| edge.dependency_index == event.dependency_index);
        let edge = matching.next().ok_or_else(|| {
            Failure::fatal(format!(
                "complete resolution omits dependency `{}` of `{}`",
                event.dependency.alias, parent.name,
            ))
        })?;
        if matching.any(|other| other.package != edge.package) {
            return Err(Failure::fatal(
                "complete resolution has conflicting dependency identities",
            ));
        }
        Ok(Some(&edge.package))
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CompileKind {
    Target,
    Host,
}

#[derive(Clone)]
struct RootRequirement {
    index: usize,
    dependency: CandidateDependency,
}

fn root_requirements(manifest: &Manifest, all_features: bool) -> Result<Vec<RootRequirement>> {
    root_requirements_and_features(manifest, all_features).map(|(requirements, _)| requirements)
}

pub fn selected_root_features(manifest: &Manifest) -> Result<BTreeSet<String>> {
    root_requirements_and_features(manifest, false).map(|(_, features)| features)
}

fn root_requirements_and_features(
    manifest: &Manifest,
    all_features: bool,
) -> Result<(Vec<RootRequirement>, BTreeSet<String>)> {
    let mut enabled = BTreeSet::new();
    for (index, dependency) in manifest.dependencies.iter().enumerate() {
        if !dependency.optional {
            enabled.insert(index);
        }
    }

    let namespaced = manifest
        .features
        .values()
        .flatten()
        .filter_map(|reference| reference.strip_prefix("dep:"))
        .collect::<BTreeSet<_>>();
    let mut active = BTreeSet::new();
    if all_features {
        active.extend(manifest.features.keys().cloned());
        for dependency in &manifest.dependencies {
            if dependency.optional && !namespaced.contains(dependency.alias.as_str()) {
                active.insert(dependency.alias.clone());
            }
        }
    } else if manifest.features.contains_key("default") {
        active.insert("default".to_owned());
    }

    let mut expanded = BTreeSet::new();
    let mut dependency_features: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    while let Some(feature) = active
        .iter()
        .find(|feature| !expanded.contains(*feature))
        .cloned()
    {
        expanded.insert(feature.clone());
        if let Some(references) = manifest.features.get(&feature) {
            for reference in references {
                expand_root_reference(
                    manifest,
                    reference,
                    &mut active,
                    &mut enabled,
                    &mut dependency_features,
                )?;
            }
        } else {
            enable_root_alias(manifest, &feature, &mut enabled)?;
        }
    }

    let weak = manifest
        .features
        .iter()
        .filter(|(feature, _)| active.contains(*feature))
        .flat_map(|(_, references)| references)
        .filter_map(|reference| {
            let (dependency, feature) = reference.split_once('/')?;
            dependency
                .strip_suffix('?')
                .map(|dependency| (dependency, feature))
        })
        .collect::<Vec<_>>();
    for (dependency, feature) in weak {
        if manifest
            .dependencies
            .iter()
            .enumerate()
            .any(|(index, value)| value.alias == dependency && enabled.contains(&index))
        {
            dependency_features
                .entry(dependency.to_owned())
                .or_default()
                .insert(feature.to_owned());
        }
    }

    let mut output = Vec::new();
    for (index, dependency) in manifest.dependencies.iter().enumerate() {
        if !enabled.contains(&index) {
            continue;
        }
        let mut features = dependency.features.clone();
        if let Some(additional) = dependency_features.get(&dependency.alias) {
            for feature in additional {
                if !features.contains(feature) {
                    features.push(feature.clone());
                }
            }
        }
        output.push(RootRequirement {
            index,
            dependency: CandidateDependency {
                dependency: Dependency {
                    alias: dependency.alias.clone(),
                    package: dependency.package.clone(),
                    requirement: dependency.requirement.clone(),
                    features,
                    optional: false,
                    default_features: dependency.default_features,
                    target: dependency.target.clone(),
                    kind: DependencyKind::Normal,
                },
                source: match &dependency.source {
                    DependencySource::CratesIo => RequirementSource::CratesIo,
                    DependencySource::Path(path) => RequirementSource::Path(path.clone()),
                    DependencySource::Git(git) => RequirementSource::Git(git.clone()),
                },
            },
        });
    }
    Ok((output, active))
}

fn expand_root_reference(
    manifest: &Manifest,
    reference: &str,
    active: &mut BTreeSet<String>,
    enabled: &mut BTreeSet<usize>,
    dependency_features: &mut BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    if let Some(dependency) = reference.strip_prefix("dep:") {
        return enable_root_alias(manifest, dependency, enabled);
    }
    if let Some((dependency, feature)) = reference.split_once('/') {
        if let Some(dependency) = dependency.strip_suffix('?') {
            return require_root_dependency_alias(manifest, dependency);
        }
        enable_root_dependency(manifest, dependency, enabled)?;
        dependency_features
            .entry(dependency.to_owned())
            .or_default()
            .insert(feature.to_owned());
        return Ok(());
    }
    if manifest.features.contains_key(reference) {
        active.insert(reference.to_owned());
        Ok(())
    } else {
        enable_root_alias(manifest, reference, enabled)
    }
}

fn require_root_dependency_alias(manifest: &Manifest, alias: &str) -> Result<()> {
    if manifest
        .dependencies
        .iter()
        .any(|dependency| dependency.alias == alias)
    {
        Ok(())
    } else {
        Err(Error::failure(format!(
            "root feature references unknown dependency `{alias}`"
        )))
    }
}

fn enable_root_dependency(
    manifest: &Manifest,
    alias: &str,
    enabled: &mut BTreeSet<usize>,
) -> Result<()> {
    require_root_dependency_alias(manifest, alias)?;
    for (index, dependency) in manifest.dependencies.iter().enumerate() {
        if dependency.alias == alias && dependency.optional {
            enabled.insert(index);
        }
    }
    Ok(())
}

fn enable_root_alias(
    manifest: &Manifest,
    alias: &str,
    enabled: &mut BTreeSet<usize>,
) -> Result<()> {
    let mut found = false;
    for (index, dependency) in manifest.dependencies.iter().enumerate() {
        if dependency.alias == alias && dependency.optional {
            enabled.insert(index);
            found = true;
        }
    }
    if found {
        Ok(())
    } else {
        Err(Error::failure(format!(
            "root feature references unknown optional dependency or feature `{alias}`"
        )))
    }
}

#[derive(Clone)]
struct Event {
    parent: Option<PackageKey>,
    parent_compile_kind: Option<CompileKind>,
    dependency_index: usize,
    dependency: CandidateDependency,
    context: FeatureContext,
    compile_kind: CompileKind,
    depth: u64,
    ancestors: BTreeSet<PackageKey>,
}

#[derive(Clone, Debug, Default)]
struct Activation {
    active: BTreeSet<String>,
    requested_dependencies: BTreeSet<String>,
    enabled_optional: BTreeSet<String>,
    dependency_features: BTreeMap<String, BTreeSet<String>>,
    weak_dependencies: BTreeSet<usize>,
    sent: BTreeMap<(CompileKind, usize), Sent>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Sent {
    features: BTreeSet<String>,
    default_features: bool,
}

#[derive(Clone)]
struct Node {
    // Candidate data is immutable; only branch-local selection state needs copying.
    record: Arc<Candidate>,
    activations: BTreeMap<FeatureContext, Activation>,
    compile_kinds: BTreeSet<CompileKind>,
    edges: BTreeMap<(CompileKind, CompileKind, FeatureContext, usize), PackageKey>,
}

#[derive(Clone, Default)]
struct State {
    nodes: BTreeMap<PackageKey, Node>,
    links: BTreeMap<String, PackageKey>,
    root_edges: BTreeMap<(CompileKind, FeatureContext, usize), PackageKey>,
    root_declarations: BTreeMap<usize, CandidateDependency>,
}

impl State {
    fn into_resolution(self) -> Resolution {
        let selected = self
            .nodes
            .iter()
            .map(|(key, node)| (key.clone(), node.record.source.clone()))
            .collect::<Vec<_>>();
        let mut packages = Vec::with_capacity(self.nodes.len());
        for (key, node) in self.nodes {
            let feature_sets = node
                .activations
                .iter()
                .map(|(context, activation)| (context.clone(), activation.active.clone()))
                .collect::<BTreeMap<_, _>>();
            let unified = feature_sets.get(&FeatureContext::Unified);
            let target_features = unified.cloned().unwrap_or_default();
            let target_features = feature_sets
                .iter()
                .filter(|(context, _)| matches!(context, FeatureContext::Target(_)))
                .fold(target_features, |mut features, (_, active)| {
                    features.extend(active.iter().cloned());
                    features
                });
            let host_features = unified
                .or_else(|| feature_sets.get(&FeatureContext::Host))
                .cloned()
                .unwrap_or_default();
            let edges = node
                .edges
                .iter()
                .map(
                    |((parent_kind, compile_kind, context, dependency_index), package)| {
                        let dependency = &node.record.dependencies[*dependency_index];
                        ResolvedEdge {
                            dependency_index: *dependency_index,
                            alias: dependency.alias.clone(),
                            kind: dependency.kind,
                            target: dependency.target.clone(),
                            parent_compile_kind: Some(*parent_kind),
                            compile_kind: *compile_kind,
                            context: context.clone(),
                            package: package.clone(),
                        }
                    },
                )
                .collect();
            let mut lock_edges = node.edges;
            for (context, activation) in &node.activations {
                for dependency_index in &activation.weak_dependencies {
                    let dependency = &node.record.dependencies[*dependency_index];
                    if let Some(package) = selected
                        .iter()
                        .filter(|(key, source)| {
                            key.name == dependency.package
                                && dependency.requirement.matches(&key.version)
                                && source_matches(source, &dependency.source)
                        })
                        .max_by(|left, right| left.0.version.cmp(&right.0.version))
                    {
                        lock_edges
                            .entry((
                                CompileKind::Target,
                                CompileKind::Target,
                                context.clone(),
                                *dependency_index,
                            ))
                            .or_insert_with(|| package.0.clone());
                    }
                }
            }
            let lock_edges = lock_edges
                .into_iter()
                .map(
                    |((parent_kind, compile_kind, context, dependency_index), package)| {
                        let dependency = &node.record.dependencies[dependency_index];
                        ResolvedEdge {
                            dependency_index,
                            alias: dependency.alias.clone(),
                            kind: dependency.kind,
                            target: dependency.target.clone(),
                            parent_compile_kind: Some(parent_kind),
                            compile_kind,
                            context,
                            package,
                        }
                    },
                )
                .collect();
            let record = Arc::unwrap_or_clone(node.record);
            packages.push(ResolvedPackage {
                key,
                source: record.source,
                local_manifest: record.local_manifest,
                feature_sets,
                compile_kinds: node.compile_kinds,
                target_features,
                host_features,
                edges,
                lock_edges,
            });
        }
        let root_edges = self
            .root_edges
            .into_iter()
            .map(|((compile_kind, context, dependency_index), package)| {
                let dependency = &self.root_declarations[&dependency_index];
                ResolvedEdge {
                    dependency_index,
                    alias: dependency.alias.clone(),
                    kind: dependency.kind,
                    target: dependency.target.clone(),
                    parent_compile_kind: None,
                    compile_kind,
                    context,
                    package,
                }
            })
            .collect();
        Resolution {
            root_edges,
            packages,
        }
    }
}

#[derive(Clone, Debug)]
struct Failure {
    message: String,
    fatal: bool,
    package_limit: bool,
}

impl Failure {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            fatal: false,
            package_limit: false,
        }
    }

    fn fatal(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            fatal: true,
            package_limit: false,
        }
    }

    // The limit is policy, not a constraint: backtracking to a smaller graph
    // would silently choose different versions than Cargo.
    fn package_limit() -> Self {
        Self {
            message: String::new(),
            fatal: true,
            package_limit: true,
        }
    }
}

fn solve(
    state: State,
    mut queue: VecDeque<Event>,
    catalog: &mut Catalog,
    options: &Options,
    locked: &[LockedPreference],
    scope: Scope<'_>,
    loader: &mut dyn FnMut(&str, &VersionReq, &mut Catalog) -> Result<()>,
) -> std::result::Result<State, Failure> {
    let Some(mut event) = queue.pop_front() else {
        return Ok(state);
    };
    let locked_package = scope.locked_package(&event)?;
    if event.dependency.source == RequirementSource::CratesIo {
        loader(
            &event.dependency.package,
            &event.dependency.requirement,
            catalog,
        )
        .map_err(|error| Failure::fatal(error.to_string()))?;
    }
    catalog
        .prepare(&mut event.dependency)
        .map_err(|error| Failure::new(error.to_string()))?;
    if event.depth > options.max_depth {
        return Err(Failure::new(format!(
            "`{}` exceeds dependency depth {}",
            event.dependency.package, options.max_depth
        )));
    }
    let matching_selected = state
        .nodes
        .iter()
        .filter(|(key, node)| {
            key.name == event.dependency.package
                && event.dependency.requirement.matches(&key.version)
                && source_matches(&node.record.source, &event.dependency.source)
                && locked_package.is_none_or(|locked| locked == *key)
        })
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    let mut last_failure = None;
    for key in matching_selected {
        let mut candidate_state = state.clone();
        let mut candidate_queue = queue.clone();
        match fulfill(
            &mut candidate_state,
            &mut candidate_queue,
            &event,
            &key,
            options,
            scope,
        )
        .and_then(|()| {
            solve(
                candidate_state,
                candidate_queue,
                catalog,
                options,
                locked,
                scope,
                loader,
            )
        }) {
            Ok(state) => return Ok(state),
            Err(failure) if failure.fatal => return Err(failure),
            Err(failure) => last_failure = Some(failure),
        }
    }

    let candidates = candidates(catalog, &event, options, locked);
    for record in candidates {
        let key = PackageKey {
            name: record.name.clone(),
            version: record.version.clone(),
            source: record.source.key(),
        };
        if locked_package.is_some_and(|locked| locked != &key) {
            continue;
        }
        if state.nodes.iter().any(|(key, node)| {
            key.name == record.name
                && source_matches(&node.record.source, &event.dependency.source)
                && semver_compatible(&key.version, &record.version)
        }) {
            if last_failure.is_none() {
                last_failure = Some(Failure::new(format!(
                    "compatible requirements for `{}` cannot be unified",
                    record.name
                )));
            }
            continue;
        }
        let limit = &options.package_limit;
        if limit.counts(&key)
            && state.nodes.keys().filter(|node| limit.counts(node)).count() as u64 >= limit.max
        {
            return Err(Failure::package_limit());
        }
        let mut candidate_state = state.clone();
        if let Some(links) = &record.links {
            if let Some(existing) = candidate_state.links.get(links) {
                last_failure = Some(Failure::new(format!(
                    "packages `{}` and `{}` both link native library `{links}`",
                    existing.name, key.name
                )));
                continue;
            }
            candidate_state.links.insert(links.clone(), key.clone());
        }
        candidate_state.nodes.insert(
            key.clone(),
            Node {
                record: Arc::new(record),
                activations: BTreeMap::new(),
                compile_kinds: BTreeSet::new(),
                edges: BTreeMap::new(),
            },
        );
        let mut candidate_queue = queue.clone();
        match fulfill(
            &mut candidate_state,
            &mut candidate_queue,
            &event,
            &key,
            options,
            scope,
        )
        .and_then(|()| {
            solve(
                candidate_state,
                candidate_queue,
                catalog,
                options,
                locked,
                scope,
                loader,
            )
        }) {
            Ok(state) => return Ok(state),
            Err(failure) if failure.fatal => return Err(failure),
            Err(failure) => last_failure = Some(failure),
        }
    }

    Err(last_failure.unwrap_or_else(|| {
        Failure::new(format!(
            "no version of `{}` matches `{}`",
            event.dependency.package, event.dependency.requirement
        ))
    }))
}

fn fulfill(
    state: &mut State,
    queue: &mut VecDeque<Event>,
    event: &Event,
    key: &PackageKey,
    options: &Options,
    scope: Scope<'_>,
) -> std::result::Result<(), Failure> {
    let mut event = event.clone();
    if event.dependency.kind == DependencyKind::Normal
        && state
            .nodes
            .get(key)
            .is_some_and(|node| node.record.proc_macro)
    {
        event.compile_kind = CompileKind::Host;
        event.context = normalize_scope_context(options.resolver, scope, FeatureContext::Host);
    }
    if event.ancestors.contains(key) {
        return Err(Failure::new(format!(
            "dependency cycle reaches `{} {}` again",
            key.name, key.version
        )));
    }
    if let Some(parent) = &event.parent {
        let node = state
            .nodes
            .get_mut(parent)
            .ok_or_else(|| Failure::new("dependency parent disappeared during resolution"))?;
        let edge = (
            event.parent_compile_kind.ok_or_else(|| {
                Failure::new("dependency event omitted its parent compilation context")
            })?,
            event.compile_kind,
            event.context.clone(),
            event.dependency_index,
        );
        if node
            .edges
            .insert(edge, key.clone())
            .is_some_and(|existing| existing != *key)
        {
            return Err(Failure::new(format!(
                "dependency edge from `{}` changed selected package",
                parent.name
            )));
        }
    } else {
        // Root declarations belong to the resolution request, so package
        // projection does not depend on one privileged selected manifest.
        state
            .root_declarations
            .entry(event.dependency_index)
            .or_insert_with(|| event.dependency.clone());
        let edge = (
            event.compile_kind,
            event.context.clone(),
            event.dependency_index,
        );
        if state
            .root_edges
            .insert(edge, key.clone())
            .is_some_and(|existing| existing != *key)
        {
            return Err(Failure::new(
                "root dependency edge changed selected package",
            ));
        }
    }
    activate(state, queue, key, &event, options, scope)
}

fn activate(
    state: &mut State,
    queue: &mut VecDeque<Event>,
    key: &PackageKey,
    event: &Event,
    options: &Options,
    scope: Scope<'_>,
) -> std::result::Result<(), Failure> {
    let record = state
        .nodes
        .get(key)
        .ok_or_else(|| Failure::new("selected package disappeared during activation"))?
        .record
        .clone();
    let node = state.nodes.get_mut(key).unwrap();
    node.compile_kinds.insert(event.compile_kind);
    let activation = node.activations.entry(event.context.clone()).or_default();

    if event.dependency.default_features && record.features.contains_key("default") {
        activation.active.insert("default".to_owned());
    }
    for feature in &event.dependency.features {
        if event.parent.is_none() && feature.contains('/') {
            activation.requested_dependencies.insert(feature.clone());
        } else if defines_feature(&record, feature) {
            activation.active.insert(feature.clone());
        } else {
            return Err(Failure::new(format!(
                "`{}` {} does not define requested feature `{feature}`",
                record.name, record.version,
            )));
        }
    }

    let mut expanded = BTreeSet::new();
    let mut weak = Vec::new();
    for reference in activation.requested_dependencies.clone() {
        expand_feature_reference(&record, activation, &reference, &reference, &mut weak)?;
    }
    while let Some(feature) = activation
        .active
        .iter()
        .find(|feature| !expanded.contains(*feature))
        .cloned()
    {
        expanded.insert(feature.clone());
        let Some(references) = record.features.get(&feature) else {
            activation.enabled_optional.insert(feature);
            continue;
        };
        for reference in references {
            expand_feature_reference(&record, activation, reference, &feature, &mut weak)?;
        }
    }
    for (dependency, dependency_feature) in weak {
        if activation.enabled_optional.contains(&dependency)
            || record
                .dependencies
                .iter()
                .any(|candidate| candidate.alias == dependency && !candidate.optional)
        {
            activation
                .dependency_features
                .entry(dependency)
                .or_default()
                .insert(dependency_feature);
        } else {
            for (index, candidate) in record.dependencies.iter().enumerate() {
                if candidate.alias == dependency {
                    activation.weak_dependencies.insert(index);
                }
            }
        }
    }

    for (index, dependency) in record.dependencies.iter().enumerate() {
        let include_dev = record
            .local_manifest
            .as_ref()
            .is_some_and(|manifest| match scope {
                Scope::WorkspaceComplete | Scope::WorkspaceMetadata { .. } => manifest.editable,
                Scope::WorkspaceSelected { dev_members, .. } => {
                    dev_members.contains(&manifest.root)
                }
                _ => false,
            });
        if (dependency.kind == DependencyKind::Dev && !include_dev)
            || (dependency.optional && !activation.enabled_optional.contains(&dependency.alias))
        {
            continue;
        }
        if !scope
            .matches(event.compile_kind, dependency.target.as_deref())
            .map_err(|error| Failure::new(error.to_string()))?
        {
            continue;
        }
        let child_compile_kind = match dependency.kind {
            DependencyKind::Build => CompileKind::Host,
            DependencyKind::Normal | DependencyKind::Dev => event.compile_kind,
        };
        let child_context = match options.resolver {
            ResolverVersion::V1 => FeatureContext::Unified,
            ResolverVersion::V2 | ResolverVersion::V3 => match dependency.kind {
                DependencyKind::Build => FeatureContext::Host,
                DependencyKind::Normal | DependencyKind::Dev => {
                    child_target_context(scope, event.context.clone(), dependency.target.as_deref())
                }
            },
        };
        let mut features = dependency.features.iter().cloned().collect::<BTreeSet<_>>();
        if let Some(additional) = activation.dependency_features.get(&dependency.alias) {
            features.extend(additional.iter().cloned());
        }
        let sent = Sent {
            features,
            default_features: dependency.default_features,
        };
        let sent_key = (event.compile_kind, index);
        if activation.sent.get(&sent_key) == Some(&sent) {
            continue;
        }
        activation.sent.insert(sent_key, sent.clone());
        let mut dependency = dependency.clone();
        dependency.dependency.features = sent.features.into_iter().collect();
        // Cargo's package-cycle prohibition excludes development edges.
        let ancestors = if dependency.kind == DependencyKind::Dev {
            BTreeSet::new()
        } else {
            let mut ancestors = event.ancestors.clone();
            ancestors.insert(key.clone());
            ancestors
        };
        queue.push_back(Event {
            parent: Some(key.clone()),
            parent_compile_kind: Some(event.compile_kind),
            dependency_index: index,
            dependency,
            context: normalize_scope_context(options.resolver, scope, child_context),
            compile_kind: child_compile_kind,
            depth: event.depth.saturating_add(1),
            ancestors,
        });
    }
    Ok(())
}

fn defines_feature(record: &Candidate, feature: &str) -> bool {
    record.features.contains_key(feature)
        || (record
            .dependencies
            .iter()
            .any(|dependency| dependency.optional && dependency.alias == feature)
            && !record
                .features
                .values()
                .flatten()
                .any(|reference| reference.strip_prefix("dep:") == Some(feature)))
}

fn expand_feature_reference(
    record: &Candidate,
    activation: &mut Activation,
    reference: &str,
    feature: &str,
    weak: &mut Vec<(String, String)>,
) -> std::result::Result<(), Failure> {
    if let Some(dependency) = reference.strip_prefix("dep:") {
        if !record
            .dependencies
            .iter()
            .any(|candidate| candidate.optional && candidate.alias == dependency)
        {
            return Err(Failure::new(format!(
                "`{}` {} feature `{feature}` references unknown optional dependency `{dependency}`",
                record.name, record.version
            )));
        }
        activation.enabled_optional.insert(dependency.to_owned());
    } else if let Some((dependency, dependency_feature)) = reference.split_once('/') {
        if let Some(dependency) = dependency.strip_suffix('?') {
            if !record
                .dependencies
                .iter()
                .any(|candidate| candidate.alias == dependency)
            {
                return Err(Failure::new(format!(
                    "`{}` {} feature `{feature}` references unknown dependency `{dependency}`",
                    record.name, record.version
                )));
            }
            weak.push((dependency.to_owned(), dependency_feature.to_owned()));
        } else {
            if !record
                .dependencies
                .iter()
                .any(|candidate| candidate.alias == dependency)
            {
                return Err(Failure::new(format!(
                    "`{}` {} feature `{feature}` references unknown dependency `{dependency}`",
                    record.name, record.version
                )));
            }
            activation.enabled_optional.insert(dependency.to_owned());
            if record
                .dependencies
                .iter()
                .any(|candidate| candidate.alias == dependency && candidate.optional)
                && defines_feature(record, dependency)
            {
                activation.active.insert(dependency.to_owned());
            }
            activation
                .dependency_features
                .entry(dependency.to_owned())
                .or_default()
                .insert(dependency_feature.to_owned());
        }
    } else if defines_feature(record, reference) {
        activation.active.insert(reference.to_owned());
    } else {
        return Err(Failure::new(format!(
            "`{}` {} feature `{feature}` references unknown `{reference}`",
            record.name, record.version
        )));
    }

    Ok(())
}

fn candidates(
    catalog: &Catalog,
    event: &Event,
    options: &Options,
    locked: &[LockedPreference],
) -> Vec<Candidate> {
    let mut candidates = catalog
        .records(&event.dependency.package)
        .iter()
        .filter(|candidate| source_matches(&candidate.source, &event.dependency.source))
        .filter(|record| event.dependency.requirement.matches(&record.version))
        .filter(|candidate| !registry_candidate_is_patched(catalog, event, candidate))
        .filter(|record| {
            !record.yanked
                || locked.iter().any(|locked| {
                    locked.name == record.name
                        && locked.checksum.is_some()
                        && same_semver_identity(&locked.version, &record.version)
                        && matches!(
                            record.source,
                            ResolvedSource::CratesIo { checksum }
                                if locked.checksum == Some(checksum)
                        )
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    let rust_policy = options.rust_policy();
    candidates.sort_unstable_by(|left, right| {
        let left_locked = lock_rank(left, locked);
        let right_locked = lock_rank(right, locked);
        right_locked.cmp(&left_locked).then_with(|| {
            if rust_policy == IncompatibleRustVersions::Fallback
                && left_locked == 0
                && right_locked == 0
            {
                let left_compatible = rust_compatibility_count(left, &options.rust_versions);
                let right_compatible = rust_compatibility_count(right, &options.rust_versions);
                right_compatible
                    .cmp(&left_compatible)
                    .then_with(|| right.version.cmp(&left.version))
            } else {
                right.version.cmp(&left.version)
            }
        })
    });
    candidates
}

fn registry_candidate_is_patched(catalog: &Catalog, event: &Event, candidate: &Candidate) -> bool {
    if event.dependency.source != RequirementSource::CratesIo
        || !matches!(candidate.source, ResolvedSource::CratesIo { .. })
    {
        return false;
    }
    catalog.records(&candidate.name).iter().any(|replacement| {
        same_semver_identity(&replacement.version, &candidate.version)
            && matches!(
                replacement.source,
                ResolvedSource::Path {
                    patched_crates_io: true,
                    ..
                } | ResolvedSource::Git {
                    patched_crates_io: true,
                    ..
                }
            )
    })
}

fn lock_rank(record: &Candidate, locked: &[LockedPreference]) -> u8 {
    locked
        .iter()
        .any(|locked| {
            locked.name == record.name
                && same_semver_identity(&locked.version, &record.version)
                && matches!(
                    record.source,
                    ResolvedSource::CratesIo { checksum }
                        if locked.checksum.is_none_or(|expected| expected == checksum)
                )
        })
        .into()
}

fn rust_compatibility_count(record: &Candidate, rust_versions: &[Version]) -> usize {
    let Some(required) = &record.rust_version else {
        return rust_versions.len();
    };
    let requirement = VersionReq::parse(&format!("^{}", required.original));
    rust_versions
        .iter()
        .filter(|version| {
            let stable = Version::new(version.major, version.minor, version.patch);
            requirement
                .as_ref()
                .is_ok_and(|required| required.matches(&stable))
        })
        .count()
}

fn validate_locked_checksums(catalog: &Catalog, locked: &[LockedPreference]) -> Result<()> {
    for locked in locked {
        let Some(expected) = locked.checksum else {
            continue;
        };
        if let Some(record) = catalog.records(&locked.name).iter().find(|record| {
            matches!(record.source, ResolvedSource::CratesIo { .. })
                && same_semver_identity(&record.version, &locked.version)
        }) && !matches!(
            record.source,
            ResolvedSource::CratesIo { checksum } if checksum == expected
        ) {
            return Err(Error::failure(format!(
                "Cargo.lock checksum for `{} {}` conflicts with the sparse index",
                locked.name, locked.version
            )));
        }
    }
    Ok(())
}

fn source_matches(source: &ResolvedSource, requirement: &RequirementSource) -> bool {
    match (source, requirement) {
        (ResolvedSource::CratesIo { .. }, RequirementSource::CratesIo) => true,
        (
            ResolvedSource::Path {
                logical_root,
                patched_crates_io,
                ..
            },
            RequirementSource::CratesIo,
        ) => *patched_crates_io && !logical_root.as_os_str().is_empty(),
        (
            ResolvedSource::Git {
                logical_root,
                patched_crates_io,
                ..
            },
            RequirementSource::CratesIo,
        ) => *patched_crates_io && !logical_root.as_os_str().is_empty(),
        (ResolvedSource::Path { logical_root, .. }, RequirementSource::Path(required)) => {
            logical_root == required
        }
        (ResolvedSource::Git { cargo_source, .. }, RequirementSource::Git(required)) => {
            crate::git::parse_locked_source(cargo_source)
                .is_ok_and(|locked| locked.matches(required))
        }
        (
            ResolvedSource::CratesIo { .. },
            RequirementSource::Path(_) | RequirementSource::Git(_),
        )
        | (ResolvedSource::Path { .. }, RequirementSource::Git(_))
        | (ResolvedSource::Git { .. }, RequirementSource::Path(_)) => false,
    }
}

fn normalize_context(resolver: ResolverVersion, context: FeatureContext) -> FeatureContext {
    match resolver {
        ResolverVersion::V1 => FeatureContext::Unified,
        ResolverVersion::V2 | ResolverVersion::V3 => context,
    }
}

fn target_dependency_context(parent: FeatureContext, selector: Option<&str>) -> FeatureContext {
    match parent {
        FeatureContext::Unified => FeatureContext::Unified,
        FeatureContext::Host => FeatureContext::Host,
        FeatureContext::Target(parent) => match (parent.is_empty(), selector) {
            (_, None) => FeatureContext::Target(parent),
            (true, Some(selector)) => FeatureContext::Target(selector.to_owned()),
            (false, Some(selector)) => FeatureContext::Target(format!("all({parent};{selector})")),
        },
    }
}

fn root_context(
    resolver: ResolverVersion,
    scope: Scope<'_>,
    dependency: &CandidateDependency,
) -> FeatureContext {
    let context = match scope {
        Scope::WorkspaceMetadata { .. } => FeatureContext::Unified,
        Scope::Complete | Scope::WorkspaceComplete => {
            FeatureContext::Target(dependency.target.clone().unwrap_or_default())
        }
        Scope::Selected(_) | Scope::WorkspaceSelected { .. } => {
            FeatureContext::Target(String::new())
        }
    };
    normalize_scope_context(resolver, scope, context)
}

fn child_target_context(
    scope: Scope<'_>,
    parent: FeatureContext,
    selector: Option<&str>,
) -> FeatureContext {
    match scope {
        Scope::Complete | Scope::WorkspaceComplete => target_dependency_context(parent, selector),
        Scope::Selected(_) | Scope::WorkspaceSelected { .. } | Scope::WorkspaceMetadata { .. } => {
            parent
        }
    }
}

// Metadata reports resolver requests across platforms and dependency kinds;
// those node lists differ from the per-unit host/target feature sets.
fn normalize_scope_context(
    resolver: ResolverVersion,
    scope: Scope<'_>,
    context: FeatureContext,
) -> FeatureContext {
    if matches!(scope, Scope::WorkspaceMetadata { .. }) {
        FeatureContext::Unified
    } else {
        normalize_context(resolver, context)
    }
}

fn semver_compatible(left: &Version, right: &Version) -> bool {
    if left.major != right.major {
        return false;
    }
    if left.major != 0 {
        return true;
    }
    if left.minor != right.minor {
        return false;
    }
    left.minor != 0 || left.patch == right.patch
}

fn same_semver_identity(left: &Version, right: &Version) -> bool {
    left.major == right.major
        && left.minor == right.minor
        && left.patch == right.patch
        && left.pre == right.pre
}

pub(crate) fn parse_local_rust_version(package: &str, value: &str) -> Result<RustVersion> {
    if value.is_empty() || value.starts_with('v') || value.contains(['-', '+']) {
        return Err(Error::failure(format!(
            "local package `{package}` has invalid `rust-version` `{value}`"
        )));
    }
    let normalized = match value.split('.').count() {
        1 => format!("{value}.0.0"),
        2 => format!("{value}.0"),
        3 => value.to_owned(),
        _ => {
            return Err(Error::failure(format!(
                "local package `{package}` has invalid `rust-version` `{value}`"
            )));
        }
    };
    let version = Version::parse(&normalized).map_err(|error| {
        Error::failure(format!(
            "local package `{package}` has invalid `rust-version` `{value}`: {error}"
        ))
    })?;
    Ok(RustVersion {
        original: value.to_owned(),
        version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;
    use semver::VersionReq;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    const SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
    static NEXT_LOCAL_FIXTURE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn snapshots_share_candidates_but_keep_selection_state_independent() {
        let manifest = manifest("child = \"1\"", "extra = []", "2");
        let candidate = local_candidate(
            manifest.clone(),
            PathBuf::from("/fixture"),
            PathBuf::from("/fixture"),
            [0; 32],
            false,
        )
        .unwrap();
        let key = PackageKey {
            name: candidate.name.clone(),
            version: candidate.version.clone(),
            source: candidate.source.key(),
        };
        let mut state = State::default();
        state.nodes.insert(
            key.clone(),
            Node {
                record: Arc::new(candidate),
                activations: BTreeMap::from([(FeatureContext::Unified, Activation::default())]),
                compile_kinds: BTreeSet::from([CompileKind::Target]),
                edges: BTreeMap::new(),
            },
        );
        let mut branch = state.clone();
        let original = &state.nodes[&key];
        let changed = branch.nodes.get_mut(&key).unwrap();
        assert!(Arc::ptr_eq(&original.record, &changed.record));
        assert!(original.record.local_manifest.is_some());
        let activation = changed
            .activations
            .get_mut(&FeatureContext::Unified)
            .unwrap();
        activation.active.insert("extra".into());
        activation.enabled_optional.insert("optional".into());
        activation
            .dependency_features
            .insert("optional".into(), BTreeSet::from(["extra".into()]));
        activation.weak_dependencies.insert(0);
        activation.sent.insert(
            (CompileKind::Target, 0),
            Sent {
                features: BTreeSet::from(["extra".into()]),
                default_features: true,
            },
        );
        changed.compile_kinds.insert(CompileKind::Host);
        changed.edges.insert(
            (
                CompileKind::Target,
                CompileKind::Host,
                FeatureContext::Unified,
                0,
            ),
            key.clone(),
        );
        branch.links.insert("native".into(), key.clone());
        branch.root_edges.insert(
            (CompileKind::Target, FeatureContext::Unified, 0),
            key.clone(),
        );
        branch
            .root_declarations
            .insert(0, changed.record.dependencies[0].clone());
        let activation = &original.activations[&FeatureContext::Unified];
        assert!(activation.active.is_empty());
        assert!(activation.enabled_optional.is_empty());
        assert!(activation.dependency_features.is_empty());
        assert!(activation.weak_dependencies.is_empty());
        assert!(activation.sent.is_empty());
        assert_eq!(
            original.compile_kinds,
            BTreeSet::from([CompileKind::Target])
        );
        assert!(original.edges.is_empty());
        assert!(state.links.is_empty());
        assert!(state.root_edges.is_empty());
        assert!(state.root_declarations.is_empty());

        // Resolution must retain local source data with or without surviving snapshots.
        let shared = state.clone().into_resolution();
        drop(branch);
        assert_eq!(Arc::strong_count(&state.nodes[&key].record), 1);
        let owned = state.into_resolution();
        for resolution in [shared, owned] {
            let package = &resolution.packages[0];
            assert_eq!(package.key, key);
            assert_eq!(package.source.key(), key.source);
            assert!(package.local_manifest.is_some());
            assert!(package.target_features.is_empty());
            assert!(package.edges.is_empty());
            assert!(resolution.root_edges.is_empty());
        }
    }

    struct LocalFixture(PathBuf);

    impl LocalFixture {
        fn new() -> Self {
            let id = NEXT_LOCAL_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("lorry-resolver-local-{}-{id}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn package(&self, relative: &str, manifest: &str) {
            let root = self.0.join(relative);
            fs::create_dir_all(root.join("src")).unwrap();
            fs::write(root.join("Cargo.toml"), manifest).unwrap();
            fs::write(root.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
        }
    }

    impl Drop for LocalFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn complete_workspace_resolves_unselected_constraints_and_optional_members_once() {
        let fixture = LocalFixture::new();
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[workspace]\nmembers = [\"a\", \"b\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        fixture.package("a", "[package]\nname = \"a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nshared = \"1\"\noptional = { version = \"1\", optional = true }\n[features]\nextra = [\"dep:optional\"]\n");
        fixture.package("b", "[package]\nname = \"b\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nshared = \"=1.0.0\"\n");
        let workspace = crate::manifest::SourceWorkspace::load(&fixture.0, None).unwrap();
        let mut catalog = Catalog::default();
        for (name, version) in [
            ("shared", "1.0.0"),
            ("shared", "1.1.0"),
            ("optional", "1.0.0"),
        ] {
            catalog
                .insert(record(name, version, "[]", "{}", ""))
                .unwrap();
        }
        let mut limits = options(ResolverVersion::V2);
        limits.package_limit = PackageLimit::with_max(2);
        let complete =
            resolve_complete_workspace(&workspace, &mut catalog, &limits, &[], &mut |_, _, _| {
                Ok(())
            })
            .unwrap();
        assert_eq!(complete.root_edges.len(), 2);
        assert_eq!(complete.packages.len(), 4);
        let shared = complete
            .packages
            .iter()
            .filter(|package| package.key.name == "shared")
            .collect::<Vec<_>>();
        assert_eq!(shared.len(), 1);
        assert_eq!(shared[0].key.version, Version::parse("1.0.0").unwrap());
        let a = complete
            .packages
            .iter()
            .find(|package| package.key.name == "a")
            .unwrap();
        assert!(a.target_features.contains("extra"));
        assert!(a.edges.iter().any(|edge| edge.package.name == "optional"));
        let cfg = CfgSet::parse("unix\ntarget_os=\"linux\"\n").unwrap();
        let selection = TargetSelection {
            host_triple: "x86_64-unknown-linux-gnu",
            host_cfg: &cfg,
            target_triple: "x86_64-unknown-linux-gnu",
            target_cfg: &cfg,
        };
        let mut member = workspace::MemberRequest {
            root: fixture.0.join("a"),
            features: BTreeSet::new(),
            default_features: false,
            dev: false,
            selected: true,
        };
        // A completed locked identity remains usable if the index marks it yanked.
        catalog
            .records
            .get_mut("shared")
            .unwrap()
            .iter_mut()
            .find(|candidate| candidate.version == Version::new(1, 0, 0))
            .unwrap()
            .record
            .yanked = true;
        let selected_graph = workspace::resolve_selected_workspace(
            &complete,
            &catalog,
            &limits,
            std::slice::from_ref(&member),
            selection,
        )
        .unwrap();
        assert_eq!(selected(&selected_graph, "shared")[0].to_string(), "1.0.0");
        assert_eq!(selected_graph.packages.len(), 2);
        assert!(
            selected_graph
                .packages
                .iter()
                .all(|package| !matches!(package.key.name.as_str(), "b" | "optional"))
        );
        member.features.insert("extra".to_owned());
        let selected_graph = workspace::resolve_selected_workspace(
            &complete,
            &catalog,
            &limits,
            &[member],
            selection,
        )
        .unwrap();
        assert_eq!(selected_graph.packages.len(), 3);
        assert_eq!(selected(&selected_graph, "shared")[0].to_string(), "1.0.0");
        assert!(
            selected_graph
                .packages
                .iter()
                .any(|package| package.key.name == "optional")
        );
        limits.package_limit = PackageLimit::with_max(1);
        assert!(
            resolve_complete_workspace(&workspace, &mut catalog, &limits, &[], &mut |_, _, _| Ok(
                ()
            ))
            .unwrap_err()
            .to_string()
            .contains("limit of 1")
        );
    }

    #[test]
    fn complete_workspace_includes_development_edges_but_rejects_normal_cycles() {
        let fixture = LocalFixture::new();
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[workspace]\nmembers = [\"a\", \"b\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        let a = "[package]\nname = \"a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dev-dependencies]\nb = { path = \"../b\" }\n";
        fixture.package("a", a);
        fixture.package("b", "[package]\nname = \"b\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\na = { path = \"../a\" }\n");
        let workspace = crate::manifest::SourceWorkspace::load(&fixture.0, None).unwrap();
        let limits = options(ResolverVersion::V2);
        let complete = resolve_complete_workspace(
            &workspace,
            &mut Catalog::default(),
            &limits,
            &[],
            &mut |_, _, _| Ok(()),
        )
        .unwrap();
        let a_node = complete
            .packages
            .iter()
            .find(|package| package.key.name == "a")
            .unwrap();
        assert_eq!(a_node.edges[0].kind, DependencyKind::Dev);
        let cfg = CfgSet::parse("unix\ntarget_os=\"linux\"\n").unwrap();
        let selection = TargetSelection {
            host_triple: "x86_64-unknown-linux-gnu",
            host_cfg: &cfg,
            target_triple: "x86_64-unknown-linux-gnu",
            target_cfg: &cfg,
        };
        let mut catalog = Catalog::default();
        let complete =
            resolve_complete_workspace(&workspace, &mut catalog, &limits, &[], &mut |_, _, _| {
                Ok(())
            })
            .unwrap();
        let member = workspace::MemberRequest {
            root: fixture.0.join("a"),
            features: BTreeSet::new(),
            default_features: true,
            dev: true,
            selected: true,
        };
        let selected_graph = workspace::resolve_selected_workspace(
            &complete,
            &catalog,
            &limits,
            &[member],
            selection,
        )
        .unwrap();
        assert_eq!(selected_graph.packages.len(), 2);
        assert_eq!(
            selected_graph
                .packages
                .iter()
                .find(|package| package.key.name == "a")
                .unwrap()
                .edges[0]
                .kind,
            DependencyKind::Dev
        );
        fs::write(
            fixture.0.join("a/Cargo.toml"),
            a.replace("dev-dependencies", "dependencies"),
        )
        .unwrap();
        let workspace = crate::manifest::SourceWorkspace::load(&fixture.0, None).unwrap();
        assert!(
            resolve_complete_workspace(
                &workspace,
                &mut Catalog::default(),
                &limits,
                &[],
                &mut |_, _, _| Ok(())
            )
            .unwrap_err()
            .to_string()
            .contains("dependency cycle")
        );
    }

    fn cargo_unit_features(output: &[u8]) -> BTreeMap<String, BTreeSet<String>> {
        let graph: serde_json::Value = serde_json::from_slice(output).unwrap();
        graph["units"]
            .as_array()
            .unwrap()
            .iter()
            .map(|unit| {
                let id = unit["pkg_id"].as_str().unwrap();
                let (source, fragment) = id.rsplit_once('#').unwrap();
                let name = fragment
                    .split_once('@')
                    .map_or_else(|| source.rsplit('/').next().unwrap(), |(name, _)| name)
                    .to_owned();
                let features = unit["features"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|feature| feature.as_str().unwrap().to_owned())
                    .collect::<BTreeSet<_>>();
                (name, features)
            })
            .collect::<BTreeMap<_, _>>()
    }

    #[test]
    fn qualified_and_weak_member_features_match_cargo_unit_features() {
        let fixture = LocalFixture::new();
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[workspace]\nmembers = [\"a\", \"b\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        let source = "[package]\nname = \"a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nrenamed = { package = \"b\", path = \"../b\", optional = true, default-features = false }\n[features]\nenable = [\"dep:renamed\"]\n";
        fixture.package("a", source);
        fixture.package("b", "[package]\nname = \"b\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[features]\nextra = []\n");
        let cfg = CfgSet::parse("unix\ntarget_os=\"linux\"\n").unwrap();
        let selection = TargetSelection {
            host_triple: "x86_64-unknown-linux-gnu",
            host_cfg: &cfg,
            target_triple: "x86_64-unknown-linux-gnu",
            target_cfg: &cfg,
        };
        let limits = options(ResolverVersion::V2);
        for (source, features, succeeds) in [
            (source.to_owned(), "renamed?/extra", true),
            (source.to_owned(), "renamed/extra", true),
            (source.to_owned(), "enable,renamed?/extra", true),
            (source.to_owned(), "renamed", false),
            (
                source.replace("[features]\nenable = [\"dep:renamed\"]\n", ""),
                "renamed/extra",
                true,
            ),
            (
                source
                    .replace(", optional = true", "")
                    .replace("[features]\nenable = [\"dep:renamed\"]\n", ""),
                "renamed?/extra",
                true,
            ),
        ] {
            fs::write(fixture.0.join("a/Cargo.toml"), source).unwrap();
            let workspace = crate::manifest::SourceWorkspace::load(&fixture.0, None).unwrap();
            let mut catalog = Catalog::default();
            let complete = resolve_complete_workspace(
                &workspace,
                &mut catalog,
                &limits,
                &[],
                &mut |_, _, _| Ok(()),
            )
            .unwrap();
            let roots = BTreeSet::from([fixture.0.join("a")]);
            let requests = workspace::features::member_requests(
                &workspace,
                &roots,
                &crate::cli::FeatureSelection {
                    features: features.split(',').map(str::to_owned).collect(),
                    all: false,
                    no_default: true,
                },
                false,
            );
            let resolved = requests.and_then(|requests| {
                workspace::resolve_selected_workspace(
                    &complete, &catalog, &limits, &requests, selection,
                )
            });
            let output = std::process::Command::new(env!("CARGO"))
                .env(
                    "RUSTC",
                    Path::new(env!("CARGO")).parent().unwrap().join("rustc"),
                )
                .args([
                    "build",
                    "--offline",
                    "-p",
                    "a",
                    "--no-default-features",
                    "--features",
                    features,
                    "-Z",
                    "unstable-options",
                    "--unit-graph",
                    "--manifest-path",
                ])
                .arg(fixture.0.join("Cargo.toml"))
                .output()
                .unwrap();
            assert_eq!(
                output.status.success(),
                succeeds,
                "{features}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(resolved.is_ok(), succeeds, "{features}: {resolved:?}");
            if !succeeds {
                continue;
            }
            let cargo_features = cargo_unit_features(&output.stdout);
            let lorry_features = resolved
                .unwrap()
                .packages
                .into_iter()
                .map(|package| (package.key.name, package.target_features))
                .collect::<BTreeMap<_, _>>();
            assert_eq!(lorry_features, cargo_features, "{features}");
        }
    }

    #[test]
    fn resolver_one_current_package_features_do_not_compile_an_unselected_root() {
        let fixture = LocalFixture::new();
        fixture.package("", "[package]\nname = \"a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[workspace]\nmembers = [\"b\", \"shared\"]\nresolver = \"1\"\n[dependencies]\nshared = { path = \"shared\", default-features = false }\n[features]\nextra = [\"shared/extra\"]\n");
        fixture.package("b", "[package]\nname = \"b\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nshared = { path = \"../shared\", default-features = false }\n");
        fixture.package("shared", "[package]\nname = \"shared\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[features]\nextra = []\n");
        let workspace = crate::manifest::SourceWorkspace::load(&fixture.0, None).unwrap();
        let mut catalog = Catalog::default();
        let limits = options(ResolverVersion::V1);
        let complete =
            resolve_complete_workspace(&workspace, &mut catalog, &limits, &[], &mut |_, _, _| {
                Ok(())
            })
            .unwrap();
        let cfg = CfgSet::parse("unix\ntarget_os=\"linux\"\n").unwrap();
        let selection = TargetSelection {
            host_triple: "x86_64-unknown-linux-gnu",
            host_cfg: &cfg,
            target_triple: "x86_64-unknown-linux-gnu",
            target_cfg: &cfg,
        };
        let requests = workspace::features::member_requests(
            &workspace,
            &BTreeSet::from([fixture.0.join("b")]),
            &crate::cli::FeatureSelection {
                features: BTreeSet::from(["extra".to_owned()]),
                all: false,
                no_default: false,
            },
            false,
        )
        .unwrap();
        let selected = workspace::resolve_selected_workspace(
            &complete, &catalog, &limits, &requests, selection,
        )
        .unwrap();
        assert_eq!(selected.root_edges.len(), 1);
        assert_eq!(selected.root_edges[0].package.name, "b");
        let features = selected
            .packages
            .into_iter()
            .map(|package| (package.key.name, package.target_features))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            features.keys().map(String::as_str).collect::<Vec<_>>(),
            ["b", "shared"]
        );
        assert_eq!(features["shared"], BTreeSet::from(["extra".to_owned()]));
        let output = std::process::Command::new(env!("CARGO"))
            .env(
                "RUSTC",
                Path::new(env!("CARGO")).parent().unwrap().join("rustc"),
            )
            .args([
                "build",
                "--offline",
                "-p",
                "b",
                "--features",
                "extra",
                "-Z",
                "unstable-options",
                "--unit-graph",
                "--manifest-path",
            ])
            .arg(fixture.0.join("Cargo.toml"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(features, cargo_unit_features(&output.stdout));

        let root_source = fs::read_to_string(fixture.0.join("Cargo.toml")).unwrap();
        fixture.package(
            "a",
            &root_source
                .replace(
                    "[workspace]\nmembers = [\"b\", \"shared\"]\nresolver = \"1\"\n",
                    "",
                )
                .replace("path = \"shared\"", "path = \"../shared\""),
        );
        let b_source = fs::read_to_string(fixture.0.join("b/Cargo.toml")).unwrap();
        fs::write(
            fixture.0.join("b/Cargo.toml"),
            format!("{b_source}[features]\ndefault = [\"extra\"]\nextra = [\"shared/other\"]\n"),
        )
        .unwrap();
        let shared = fs::read_to_string(fixture.0.join("shared/Cargo.toml")).unwrap();
        fs::write(
            fixture.0.join("shared/Cargo.toml"),
            format!("{shared}other = []\n"),
        )
        .unwrap();
        for (version, resolver) in [
            ("1", ResolverVersion::V1),
            ("2", ResolverVersion::V2),
            ("3", ResolverVersion::V3),
        ] {
            for virtual_root in [false, true] {
                let source = if virtual_root {
                    format!(
                        "[workspace]\nmembers = [\"a\", \"b\", \"shared\"]\nresolver = \"{version}\"\n"
                    )
                } else {
                    root_source.replace("resolver = \"1\"", &format!("resolver = \"{version}\""))
                };
                fs::write(fixture.0.join("Cargo.toml"), source).unwrap();
                let workspace = crate::manifest::SourceWorkspace::load(&fixture.0, None).unwrap();
                let mut catalog = Catalog::default();
                let limits = options(resolver);
                let complete = resolve_complete_workspace(
                    &workspace,
                    &mut catalog,
                    &limits,
                    &[],
                    &mut |_, _, _| Ok(()),
                )
                .unwrap();
                for (named, no_default, all) in [
                    ("extra", false, false),
                    ("extra", true, false),
                    ("b/extra", true, false),
                    ("b?/extra", true, false),
                    ("", true, false),
                    ("", false, true),
                    ("", true, true),
                    ("absent", false, false),
                ] {
                    let flags = crate::cli::FeatureSelection {
                        features: if named.is_empty() {
                            BTreeSet::new()
                        } else {
                            BTreeSet::from([named.to_owned()])
                        },
                        all,
                        no_default,
                    };
                    let requests = workspace::features::member_requests(
                        &workspace,
                        &BTreeSet::from([fixture.0.join("b")]),
                        &flags,
                        false,
                    );
                    let lorry = requests.and_then(|requests| {
                        workspace::resolve_selected_workspace(
                            &complete, &catalog, &limits, &requests, selection,
                        )
                    });
                    let mut command = std::process::Command::new(env!("CARGO"));
                    command
                        .env(
                            "RUSTC",
                            Path::new(env!("CARGO")).parent().unwrap().join("rustc"),
                        )
                        .args([
                            "build",
                            "--offline",
                            "-p",
                            "b",
                            "-Z",
                            "unstable-options",
                            "--unit-graph",
                            "--manifest-path",
                        ])
                        .arg(fixture.0.join("Cargo.toml"));
                    if !named.is_empty() {
                        command.args(["--features", named]);
                    }
                    if no_default {
                        command.arg("--no-default-features");
                    }
                    if all {
                        command.arg("--all-features");
                    }
                    let output = command.output().unwrap();
                    assert_eq!(
                        lorry.is_ok(),
                        output.status.success(),
                        "resolver {version}, virtual {virtual_root}, {flags:?}: {lorry:?}; {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                    if let Ok(lorry) = lorry {
                        let features = lorry
                            .packages
                            .into_iter()
                            .map(|package| (package.key.name, package.target_features))
                            .collect::<BTreeMap<_, _>>();
                        assert_eq!(
                            features,
                            cargo_unit_features(&output.stdout),
                            "resolver {version}, virtual {virtual_root}, {flags:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn metadata_features_match_cargo_across_platforms_and_dependency_kinds() {
        let fixture = LocalFixture::new();
        fs::write(fixture.0.join("Cargo.toml"), "[workspace]\nmembers = [\"app\", \"shared\"]\nexclude = [\"leaf\", \"win-only\", \"host-only\"]\nresolver = \"2\"\n").unwrap();
        fixture.package("app", "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nshared = { path = \"../shared\", default-features = false }\n[target.'cfg(windows)'.dependencies]\nwin-only = { path = \"../win-only\", features = [\"win\"] }\nshared = { path = \"../shared\", features = [\"windows\"] }\n[build-dependencies]\nshared = { path = \"../shared\", features = [\"host\"] }\n[dev-dependencies]\nshared = { path = \"../shared\", features = [\"dev\"] }\n");
        fixture.package("shared", "[package]\nname = \"shared\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nleaf = { path = \"../leaf\", optional = true }\nhost-only = { path = \"../host-only\", optional = true }\n[features]\nwindows = [\"dep:leaf\"]\nhost = [\"dep:host-only\"]\ndev = [\"dep:leaf\"]\n");
        for name in ["leaf", "win-only", "host-only"] {
            fixture.package(name, &format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[features]\nwin = []\n"));
        }
        let workspace = crate::manifest::SourceWorkspace::load(&fixture.0, None).unwrap();
        let mut catalog = Catalog::default();
        let limits = options(ResolverVersion::V2);
        let complete =
            resolve_complete_workspace(&workspace, &mut catalog, &limits, &[], &mut |_, _, _| {
                Ok(())
            })
            .unwrap();
        let roots = workspace
            .packages
            .iter()
            .map(|member| member.root.clone())
            .collect();
        let requests = workspace::features::member_requests(
            &workspace,
            &roots,
            &crate::cli::FeatureSelection::default(),
            true,
        )
        .unwrap();
        let metadata =
            workspace::resolve_metadata_workspace(&complete, &catalog, &limits, &requests).unwrap();
        let features = metadata
            .packages
            .iter()
            .map(|package| {
                (
                    package.key.name.clone(),
                    package
                        .feature_sets
                        .values()
                        .flatten()
                        .cloned()
                        .collect::<BTreeSet<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            features["shared"],
            BTreeSet::from(["dev".to_owned(), "host".to_owned(), "windows".to_owned()])
        );
        assert!(features.contains_key("leaf") && features.contains_key("host-only"));
        for platform in [
            None,
            Some("x86_64-unknown-linux-gnu"),
            Some("x86_64-pc-windows-msvc"),
        ] {
            let mut command = std::process::Command::new(env!("CARGO"));
            command
                .env(
                    "RUSTC",
                    Path::new(env!("CARGO")).parent().unwrap().join("rustc"),
                )
                .args([
                    "metadata",
                    "--offline",
                    "--format-version=1",
                    "--manifest-path",
                ])
                .arg(fixture.0.join("Cargo.toml"));
            if let Some(platform) = platform {
                command.args(["--filter-platform", platform]);
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let cargo: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            let names = cargo["packages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|package| {
                    (
                        package["id"].as_str().unwrap(),
                        package["name"].as_str().unwrap(),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let nodes = cargo["resolve"]["nodes"].as_array().unwrap();
            for node in nodes {
                let name = names[node["id"].as_str().unwrap()];
                let cargo_features = node["features"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|feature| feature.as_str().unwrap().to_owned())
                    .collect::<BTreeSet<_>>();
                assert_eq!(features[name], cargo_features, "{name}, {platform:?}");
            }
            if platform.is_none() {
                assert_eq!(features.len(), nodes.len());
            }
            if platform == Some("x86_64-unknown-linux-gnu") {
                assert!(!names.values().any(|name| *name == "win-only"));
            }
        }
    }

    fn checksum(version: &str) -> String {
        let digit = version
            .bytes()
            .filter(u8::is_ascii_digit)
            .fold(0_u8, |sum, byte| sum.wrapping_add(byte - b'0'));
        format!("{digit:02x}").repeat(32)
    }

    fn record(
        name: &str,
        version: &str,
        dependencies: &str,
        features: &str,
        extra: &str,
    ) -> Record {
        let source = format!(
            "{{\"name\":\"{name}\",\"vers\":\"{version}\",\
             \"deps\":{dependencies},\"cksum\":\"{}\",\
             \"features\":{features},\"yanked\":false{extra}}}\n",
            checksum(version)
        );
        Record::parse(Path::new("/fixture/index-record.json"), source.as_bytes()).unwrap()
    }

    fn dependency(name: &str, requirement: &str) -> String {
        format!(
            "{{\"name\":\"{name}\",\"req\":\"{requirement}\",\
             \"features\":[],\"optional\":false,\"default_features\":true,\
             \"target\":null,\"kind\":\"normal\"}}"
        )
    }

    fn dependency_with(
        alias: &str,
        package: &str,
        requirement: &str,
        features: &[&str],
        optional: bool,
        kind: &str,
    ) -> String {
        let features = features
            .iter()
            .map(|feature| format!("\"{feature}\""))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"name\":\"{alias}\",\"package\":\"{package}\",\
             \"req\":\"{requirement}\",\"features\":[{features}],\
             \"optional\":{optional},\"default_features\":true,\
             \"target\":null,\"kind\":\"{kind}\"}}"
        )
    }

    fn dependency_for_target(name: &str, requirement: &str, target: &str, kind: &str) -> String {
        format!(
            "{{\"name\":\"{name}\",\"req\":\"{requirement}\",\
             \"features\":[],\"optional\":false,\"default_features\":true,\
             \"target\":\"{target}\",\"kind\":\"{kind}\"}}"
        )
    }

    fn manifest(dependencies: &str, features: &str, resolver: &str) -> Manifest {
        Manifest::parse(
            Path::new("/fixture"),
            Path::new("/fixture/Cargo.toml"),
            &format!(
                "[package]\nname = \"root\"\nversion = \"0.1.0\"\n\
                 edition = \"2021\"\nresolver = \"{resolver}\"\n\
                 [dependencies]\n{dependencies}\n\
                 [features]\n{features}\n"
            ),
        )
        .unwrap()
    }

    fn target_manifest(resolver: &str) -> Manifest {
        Manifest::parse(
            Path::new("/fixture"),
            Path::new("/fixture/Cargo.toml"),
            &format!(
                "[package]\nname = \"root\"\nversion = \"0.1.0\"\n\
                 edition = \"2021\"\nresolver = \"{resolver}\"\n\
                 [target.'cfg(unix)'.dependencies]\n\
                 unix-shared = {{ package = \"shared\", version = \"1\", features = [\"unix\"] }}\n\
                 [target.'cfg(windows)'.dependencies]\n\
                 windows-shared = {{ package = \"shared\", version = \"1\", features = [\"windows\"] }}\n"
            ),
        )
        .unwrap()
    }

    fn options(resolver: ResolverVersion) -> Options {
        Options {
            resolver,
            incompatible_rust_versions: None,
            rust_versions: vec![Version::parse("1.70.0").unwrap()],
            package_limit: PackageLimit::with_max(64),
            max_depth: 16,
        }
    }

    fn selected<'a>(resolution: &'a Resolution, name: &str) -> Vec<&'a Version> {
        resolution
            .packages
            .iter()
            .filter(|package| package.key.name == name)
            .map(|package| &package.key.version)
            .collect()
    }

    #[test]
    fn backtracks_to_unify_semver_compatible_requirements() {
        let mut catalog = Catalog::default();
        catalog
            .insert(record(
                "a",
                "1.1.0",
                &format!("[{}]", dependency("shared", "^1.1")),
                "{}",
                "",
            ))
            .unwrap();
        catalog
            .insert(record(
                "a",
                "1.0.0",
                &format!("[{}]", dependency("shared", "=1.0.0")),
                "{}",
                "",
            ))
            .unwrap();
        catalog
            .insert(record(
                "b",
                "1.0.0",
                &format!("[{}]", dependency("shared", "=1.0.0")),
                "{}",
                "",
            ))
            .unwrap();
        catalog
            .insert(record("shared", "1.1.0", "[]", "{}", ""))
            .unwrap();
        catalog
            .insert(record("shared", "1.0.0", "[]", "{}", ""))
            .unwrap();
        let root = manifest("a = \"1\"\nb = \"1\"", "", "2");
        let resolution = resolve(&root, &catalog, &options(ResolverVersion::V2), &[]).unwrap();
        assert_eq!(
            selected(&resolution, "a"),
            [&Version::parse("1.0.0").unwrap()]
        );
        assert_eq!(
            selected(&resolution, "shared"),
            [&Version::parse("1.0.0").unwrap()]
        );
    }

    #[test]
    fn dynamically_loads_only_names_reached_by_resolution() {
        let root = manifest("a = \"1\"", "", "2");
        let mut catalog = Catalog::default();
        let mut loaded = Vec::new();
        let mut loader = |name: &str, _requirement: &VersionReq, catalog: &mut Catalog| {
            loaded.push(name.to_owned());
            match name {
                "a" => catalog.insert(record(
                    "a",
                    "1.0.0",
                    &format!("[{}]", dependency("b", "1")),
                    "{}",
                    "",
                )),
                "b" => catalog.insert(record("b", "1.0.0", "[]", "{}", "")),
                _ => panic!("resolver requested unexpected sparse record `{name}`"),
            }
        };

        let resolution = resolve_dynamic(
            &root,
            &mut catalog,
            &options(ResolverVersion::V2),
            &[],
            &mut loader,
        )
        .unwrap();

        assert_eq!(loaded, ["a", "b"]);
        assert_eq!(resolution.packages.len(), 2);
        assert_eq!(selected(&resolution, "a").len(), 1);
        assert_eq!(selected(&resolution, "b").len(), 1);
    }

    #[test]
    fn git_patch_satisfies_crates_io_without_losing_git_identity() {
        let root = manifest("demo = \"=1.2.3\"", "", "2");
        let patched = Manifest::parse(
            Path::new("/git/demo"),
            Path::new("/git/demo/Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"1.2.3\"\nedition = \"2021\"\n",
        )
        .unwrap();
        let cargo_source = "git+https://example.com/demo.git?branch=motor#0123456789abcdef0123456789abcdef01234567";
        let mut catalog = Catalog::default();
        catalog
            .insert(record("demo", "1.2.3", "[]", "{}", ""))
            .unwrap();
        catalog
            .insert_git_patch(
                patched,
                ResolvedSource::Git {
                    cargo_source: cargo_source.to_owned(),
                    git_url: "https://example.com/demo.git".to_owned(),
                    requested_revision: "motor".to_owned(),
                    resolved_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                    git_tree: "1".repeat(40),
                    repository_tree_sha256: [2; 32],
                    package_path: String::new(),
                    logical_root: PathBuf::from("/git/demo"),
                    physical_root: PathBuf::from("/git/demo"),
                    source_tree_sha256: [3; 32],
                    patched_crates_io: false,
                },
            )
            .unwrap();
        catalog.locked_repository = Some(LockedRepository {
            source: LockedRegistrySource::Lorry(
                RepositorySet::open(
                    &crate::config::Repositories::default(),
                    DEFAULT_TREE_LIMITS,
                    16 * 1024 * 1024,
                )
                .unwrap(),
            ),
            packages: BTreeMap::new(),
        });

        let resolution = resolve(&root, &catalog, &options(ResolverVersion::V2), &[]).unwrap();
        let [package] = resolution.packages.as_slice() else {
            panic!("expected one patched package");
        };
        assert_eq!(
            package.key.source,
            PackageSourceKey::Git(cargo_source.to_owned())
        );
        assert!(matches!(
            package.source,
            ResolvedSource::Git {
                patched_crates_io: true,
                ..
            }
        ));
    }

    #[test]
    fn loader_failures_are_not_retried_during_backtracking() {
        let root = manifest("a = \"1\"", "", "2");
        let mut catalog = Catalog::default();
        let mut loaded = Vec::new();
        let mut loader = |name: &str, _requirement: &VersionReq, catalog: &mut Catalog| {
            loaded.push(name.to_owned());
            match name {
                "a" => {
                    let dependencies = format!("[{}]", dependency("broken", "1"));
                    catalog.insert(record("a", "1.1.0", &dependencies, "{}", ""))?;
                    catalog.insert(record("a", "1.0.0", &dependencies, "{}", ""))
                }
                "broken" => Err(Error::failure("sparse acquisition failed")),
                _ => panic!("resolver requested unexpected sparse record `{name}`"),
            }
        };

        let error = resolve_dynamic(
            &root,
            &mut catalog,
            &options(ResolverVersion::V2),
            &[],
            &mut loader,
        )
        .unwrap_err();

        assert!(error.to_string().contains("sparse acquisition failed"));
        assert_eq!(loaded, ["a", "broken"]);
    }

    #[test]
    fn merges_target_resolutions_and_derives_lock_preferences() {
        let mut catalog = Catalog::default();
        catalog
            .insert(record(
                "shared",
                "1.0.0",
                "[]",
                "{\"unix\":[],\"windows\":[]}",
                "",
            ))
            .unwrap();
        let root = target_manifest("2");
        let host_cfg = CfgSet::parse("unix\n").unwrap();
        let unix = CfgSet::parse("unix\n").unwrap();
        let windows = CfgSet::parse("windows\n").unwrap();
        let resolve_for = |triple, cfg| {
            resolve_selected(
                &root,
                &catalog,
                &options(ResolverVersion::V2),
                &[],
                TargetSelection {
                    target_triple: triple,
                    target_cfg: cfg,
                    host_triple: "x86_64-unknown-linux-gnu",
                    host_cfg: &host_cfg,
                },
            )
            .unwrap()
        };

        let merged = merge_resolutions([
            resolve_for("x86_64-unknown-linux-musl", &unix),
            resolve_for("x86_64-pc-windows-msvc", &windows),
        ])
        .unwrap();

        let shared = merged
            .packages
            .iter()
            .find(|package| package.key.name == "shared")
            .unwrap();
        assert_eq!(
            shared.target_features,
            BTreeSet::from(["unix".into(), "windows".into()])
        );
        let locked = LockedPreference::from_resolution(&merged);
        assert_eq!(locked.len(), 1);
        assert_eq!(locked[0].name, "shared");
        let ResolvedSource::CratesIo { checksum } = &shared.source else {
            panic!("shared fixture unexpectedly resolved to a path");
        };
        assert_eq!(locked[0].checksum, Some(*checksum));
    }

    #[test]
    fn permits_distinct_semver_incompatible_versions() {
        let mut catalog = Catalog::default();
        catalog
            .insert(record("demo", "0.2.1", "[]", "{}", ""))
            .unwrap();
        catalog
            .insert(record("demo", "0.1.9", "[]", "{}", ""))
            .unwrap();
        let root = manifest(
            "old = { package = \"demo\", version = \"0.1\" }\n\
             new = { package = \"demo\", version = \"0.2\" }",
            "",
            "2",
        );
        let resolution = resolve(&root, &catalog, &options(ResolverVersion::V2), &[]).unwrap();
        assert_eq!(selected(&resolution, "demo").len(), 2);
    }

    #[test]
    fn retains_locked_and_yanked_versions_but_checks_their_checksum() {
        let mut catalog = Catalog::default();
        let mut yanked = record("demo", "1.2.0", "[]", "{}", "");
        yanked.yanked = true;
        let yanked_checksum = yanked.checksum;
        catalog.insert(yanked).unwrap();
        catalog
            .insert(record("demo", "1.1.0", "[]", "{}", ""))
            .unwrap();
        let root = manifest("demo = \"1\"", "", "2");

        let unlocked = resolve(&root, &catalog, &options(ResolverVersion::V2), &[]).unwrap();
        assert_eq!(
            selected(&unlocked, "demo"),
            [&Version::parse("1.1.0").unwrap()]
        );
        let locked = [LockedPreference {
            name: "demo".to_owned(),
            version: Version::parse("1.2.0").unwrap(),
            checksum: Some(yanked_checksum),
        }];
        let resolution = resolve(&root, &catalog, &options(ResolverVersion::V2), &locked).unwrap();
        assert_eq!(
            selected(&resolution, "demo"),
            [&Version::parse("1.2.0").unwrap()]
        );

        let corrupt = [LockedPreference {
            checksum: Some([0_u8; 32]),
            ..locked[0].clone()
        }];
        assert!(
            resolve(&root, &catalog, &options(ResolverVersion::V2), &corrupt)
                .unwrap_err()
                .to_string()
                .contains("checksum")
        );
    }

    #[test]
    fn exact_upgrade_replaces_only_the_selected_lock_preference() {
        let mut catalog = Catalog::default();
        let demo_old = record("demo", "1.1.0", "[]", "{}", "");
        let demo_checksum = demo_old.checksum;
        let other_old = record("other", "1.1.0", "[]", "{}", "");
        let other_checksum = other_old.checksum;
        for candidate in [
            demo_old,
            record("demo", "1.2.0", "[]", "{}", ""),
            other_old,
            record("other", "1.2.0", "[]", "{}", ""),
        ] {
            catalog.insert(candidate).unwrap();
        }
        let root = manifest("demo = \"1\"\nother = \"1\"", "", "2");
        let demo_version = Version::parse("1.1.0").unwrap();
        let mut preferences = vec![
            LockedPreference {
                name: "demo".to_owned(),
                version: demo_version.clone(),
                checksum: Some(demo_checksum),
            },
            LockedPreference {
                name: "other".to_owned(),
                version: Version::parse("1.1.0").unwrap(),
                checksum: Some(other_checksum),
            },
        ];
        LockedPreference::force_version(
            &mut preferences,
            "demo",
            Some(&demo_version),
            Version::parse("1.2.0").unwrap(),
        );
        let resolution =
            resolve(&root, &catalog, &options(ResolverVersion::V2), &preferences).unwrap();
        assert_eq!(selected(&resolution, "demo")[0].to_string(), "1.2.0");
        assert_eq!(selected(&resolution, "other")[0].to_string(), "1.1.0");
    }

    #[test]
    fn resolver_three_falls_back_to_rust_compatible_versions() {
        let mut catalog = Catalog::default();
        catalog
            .insert(record(
                "demo",
                "1.2.0",
                "[]",
                "{}",
                ",\"rust_version\":\"1.80\"",
            ))
            .unwrap();
        catalog
            .insert(record(
                "demo",
                "1.1.0",
                "[]",
                "{}",
                ",\"rust_version\":\"1.60\"",
            ))
            .unwrap();
        let root = manifest("demo = \"1\"", "", "3");
        let fallback = resolve(&root, &catalog, &options(ResolverVersion::V3), &[]).unwrap();
        assert_eq!(
            selected(&fallback, "demo"),
            [&Version::parse("1.1.0").unwrap()]
        );

        let mut allow = options(ResolverVersion::V3);
        allow.incompatible_rust_versions = Some(IncompatibleRustVersions::Allow);
        let allow = resolve(&root, &catalog, &allow, &[]).unwrap();
        assert_eq!(
            selected(&allow, "demo"),
            [&Version::parse("1.2.0").unwrap()]
        );
    }

    #[test]
    fn workspace_rust_versions_rank_compatibility_counts_before_versions() {
        let fixture = LocalFixture::new();
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[workspace]\nmembers = [\"a\", \"b\"]\nresolver = \"3\"\n",
        )
        .unwrap();
        for (name, rust) in [("a", "1.70"), ("b", "1.80")] {
            fixture.package(name, &format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\nrust-version = \"{rust}\"\n[dependencies]\ndemo = \"1\"\n"));
        }
        let workspace = crate::manifest::SourceWorkspace::load(&fixture.0, None).unwrap();
        let mut catalog = Catalog::default();
        for (version, rust) in [("1.1.0", "1.75"), ("1.2.0", "1.85")] {
            catalog
                .insert(record(
                    "demo",
                    version,
                    "[]",
                    "{}",
                    &format!(",\"rust_version\":\"{rust}\""),
                ))
                .unwrap();
        }
        let mut limits = options(ResolverVersion::V3);
        // A declared workspace MSRV replaces the newer compiler fallback.
        limits.rust_versions = vec![Version::parse("1.99.0-dev").unwrap()];
        let solve = |catalog: &mut Catalog, locked: &[LockedPreference]| {
            resolve_complete_workspace(&workspace, catalog, &limits, locked, &mut |_, _, _| Ok(()))
                .unwrap()
        };
        assert_eq!(
            selected(&solve(&mut catalog, &[]), "demo")[0].to_string(),
            "1.1.0"
        );
        catalog
            .insert(record(
                "demo",
                "1.0.0",
                "[]",
                "{}",
                ",\"rust_version\":\"1.65\"",
            ))
            .unwrap();
        assert_eq!(
            selected(&solve(&mut catalog, &[]), "demo")[0].to_string(),
            "1.0.0"
        );
        let preferred = record("demo", "1.2.0", "[]", "{}", ",\"rust_version\":\"1.85\"");
        let locked = [LockedPreference {
            name: preferred.name,
            version: preferred.version,
            checksum: Some(preferred.checksum),
        }];
        assert_eq!(
            selected(&solve(&mut catalog, &locked), "demo")[0].to_string(),
            "1.2.0"
        );
    }

    #[test]
    fn workspace_without_msrv_uses_the_stable_compiler_release_as_fallback() {
        let fixture = LocalFixture::new();
        fixture.package("", "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[workspace]\nresolver = \"3\"\n[dependencies]\ndemo = \"1\"\n");
        let workspace = crate::manifest::SourceWorkspace::load(&fixture.0, None).unwrap();
        let mut catalog = Catalog::default();
        for (version, rust) in [("1.1.0", "1.69"), ("1.2.0", "1.70")] {
            catalog
                .insert(record(
                    "demo",
                    version,
                    "[]",
                    "{}",
                    &format!(",\"rust_version\":\"{rust}\""),
                ))
                .unwrap();
        }
        let mut limits = options(ResolverVersion::V3);
        limits.rust_versions = vec![Version::parse("1.70.0-dev").unwrap()];
        let resolution =
            resolve_complete_workspace(&workspace, &mut catalog, &limits, &[], &mut |_, _, _| {
                Ok(())
            })
            .unwrap();
        assert_eq!(selected(&resolution, "demo")[0].to_string(), "1.2.0");
    }

    #[test]
    fn backtracks_when_a_candidate_lacks_a_requested_feature() {
        let mut catalog = Catalog::default();
        catalog
            .insert(record("demo", "1.2.0", "[]", "{}", ""))
            .unwrap();
        catalog
            .insert(record("demo", "1.1.0", "[]", "{\"needed\":[]}", ""))
            .unwrap();
        let root = manifest(
            "demo = { version = \"1\", features = [\"needed\"] }",
            "",
            "2",
        );
        let resolution = resolve(&root, &catalog, &options(ResolverVersion::V2), &[]).unwrap();
        assert_eq!(
            selected(&resolution, "demo"),
            [&Version::parse("1.1.0").unwrap()]
        );
    }

    #[test]
    fn resolves_optional_default_and_separate_host_features() {
        let dependencies = [
            dependency_with("shared", "shared", "1", &["target"], false, "normal"),
            dependency_with("shared-build", "shared", "1", &["host"], false, "build"),
            dependency_with("optional", "optional", "1", &[], true, "normal"),
            dependency_with("weak", "weak", "1", &[], true, "normal"),
            dependency_with("defaultdep", "defaultdep", "1", &[], true, "normal"),
        ]
        .join(",");
        let mut catalog = Catalog::default();
        catalog
            .insert(record(
                "a",
                "1.0.0",
                &format!("[{dependencies}]"),
                "{\"default\":[\"dep:defaultdep\"],\
                 \"full\":[\"dep:optional\",\"weak?/feature\"]}",
                "",
            ))
            .unwrap();
        catalog
            .insert(record(
                "shared",
                "1.0.0",
                "[]",
                "{\"target\":[],\"host\":[]}",
                "",
            ))
            .unwrap();
        for name in ["optional", "weak", "defaultdep"] {
            catalog
                .insert(record(name, "1.0.0", "[]", "{\"feature\":[]}", ""))
                .unwrap();
        }
        let root = manifest("a = { version = \"1\", features = [\"full\"] }", "", "2");
        let resolution = resolve(&root, &catalog, &options(ResolverVersion::V2), &[]).unwrap();
        assert_eq!(selected(&resolution, "optional").len(), 1);
        assert_eq!(selected(&resolution, "defaultdep").len(), 1);
        assert!(selected(&resolution, "weak").is_empty());
        let shared = resolution
            .packages
            .iter()
            .find(|package| package.key.name == "shared")
            .unwrap();
        assert_eq!(shared.target_features, ["target".to_owned()].into());
        assert_eq!(shared.host_features, ["host".to_owned()].into());

        let root = manifest("a = { version = \"1\", features = [\"full\"] }", "", "1");
        let resolution = resolve(&root, &catalog, &options(ResolverVersion::V1), &[]).unwrap();
        let shared = resolution
            .packages
            .iter()
            .find(|package| package.key.name == "shared")
            .unwrap();
        assert_eq!(
            shared.compile_kinds,
            [CompileKind::Target, CompileKind::Host].into()
        );
        assert_eq!(
            shared.feature_sets[&FeatureContext::Unified],
            ["host".to_owned(), "target".to_owned()].into()
        );
        let a = resolution
            .packages
            .iter()
            .find(|package| package.key.name == "a")
            .unwrap();
        assert_eq!(
            a.edges
                .iter()
                .map(|edge| edge.compile_kind)
                .collect::<BTreeSet<_>>(),
            [CompileKind::Target, CompileKind::Host].into()
        );
    }

    #[test]
    fn optional_dependency_features_are_implicit_unless_namespaced() {
        let dependencies = [
            dependency_with("implicit", "implicit", "1", &[], true, "normal"),
            dependency_with("namespaced", "namespaced", "1", &[], true, "normal"),
        ]
        .join(",");
        let mut catalog = Catalog::default();
        catalog
            .insert(record(
                "a",
                "1.0.0",
                &format!("[{dependencies}]"),
                "{\"default\":[\"implicit\",\"dep:namespaced\"]}",
                "",
            ))
            .unwrap();
        for name in ["implicit", "namespaced"] {
            catalog
                .insert(record(name, "1.0.0", "[]", "{}", ""))
                .unwrap();
        }

        let root = manifest("a = \"1\"", "", "2");
        let resolution = resolve(&root, &catalog, &options(ResolverVersion::V2), &[]).unwrap();
        assert_eq!(selected(&resolution, "implicit").len(), 1);
        assert_eq!(selected(&resolution, "namespaced").len(), 1);
        let a = resolution
            .packages
            .iter()
            .find(|package| package.key.name == "a")
            .unwrap();
        assert_eq!(
            a.target_features,
            BTreeSet::from(["default".to_owned(), "implicit".to_owned()])
        );
    }

    #[test]
    fn resolver_two_separates_target_feature_sets_while_one_unifies_them() {
        let mut catalog = Catalog::default();
        catalog
            .insert(record(
                "shared",
                "1.0.0",
                "[]",
                "{\"unix\":[],\"windows\":[]}",
                "",
            ))
            .unwrap();

        let root = target_manifest("2");
        let resolution = resolve(&root, &catalog, &options(ResolverVersion::V2), &[]).unwrap();
        let shared = resolution
            .packages
            .iter()
            .find(|package| package.key.name == "shared")
            .unwrap();
        assert_eq!(
            shared
                .feature_sets
                .get(&FeatureContext::Target("cfg(unix)".to_owned())),
            Some(&["unix".to_owned()].into())
        );
        assert_eq!(
            shared
                .feature_sets
                .get(&FeatureContext::Target("cfg(windows)".to_owned())),
            Some(&["windows".to_owned()].into())
        );

        let root = target_manifest("1");
        let resolution = resolve(&root, &catalog, &options(ResolverVersion::V1), &[]).unwrap();
        let shared = resolution
            .packages
            .iter()
            .find(|package| package.key.name == "shared")
            .unwrap();
        assert_eq!(
            shared.feature_sets.get(&FeatureContext::Unified),
            Some(&["unix".to_owned(), "windows".to_owned()].into())
        );
        assert_eq!(shared.feature_sets.len(), 1);
    }

    #[test]
    fn selected_resolution_uses_only_default_features_and_matching_target_dependencies() {
        let mut catalog = Catalog::default();
        catalog
            .insert(record(
                "shared",
                "1.0.0",
                "[]",
                "{\"unix\":[],\"windows\":[]}",
                "",
            ))
            .unwrap();
        for name in ["default-dep", "extra-dep", "exact-target", "other-target"] {
            catalog
                .insert(record(name, "1.0.0", "[]", "{}", ""))
                .unwrap();
        }
        let root = Manifest::parse(
            Path::new("/fixture"),
            Path::new("/fixture/Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\n\
             default-dep = { version = \"1\", optional = true }\n\
             extra-dep = { version = \"1\", optional = true }\n\
             [target.'cfg(unix)'.dependencies]\n\
             unix-shared = { package = \"shared\", version = \"1\", features = [\"unix\"] }\n\
             [target.'cfg(windows)'.dependencies]\n\
             windows-shared = { package = \"shared\", version = \"1\", features = [\"windows\"] }\n\
             [target.'x86_64-unknown-linux-musl'.dependencies]\n\
             exact-target = \"1\"\n\
             [target.'aarch64-unknown-linux-gnu'.dependencies]\n\
             other-target = \"1\"\n\
             [features]\ndefault = [\"dep:default-dep\"]\nextra = [\"dep:extra-dep\"]\n",
        )
        .unwrap();
        let target_cfg = CfgSet::parse("unix\n").unwrap();
        let host_cfg = CfgSet::parse("windows\n").unwrap();
        let resolution = resolve_selected(
            &root,
            &catalog,
            &options(ResolverVersion::V2),
            &[],
            TargetSelection {
                target_triple: "x86_64-unknown-linux-musl",
                target_cfg: &target_cfg,
                host_triple: "x86_64-pc-windows-msvc",
                host_cfg: &host_cfg,
            },
        )
        .unwrap();

        assert_eq!(selected(&resolution, "default-dep").len(), 1);
        assert!(selected(&resolution, "extra-dep").is_empty());
        assert_eq!(selected(&resolution, "exact-target").len(), 1);
        assert!(selected(&resolution, "other-target").is_empty());
        let shared = resolution
            .packages
            .iter()
            .find(|package| package.key.name == "shared")
            .unwrap();
        assert_eq!(
            shared.target_features,
            ["unix".to_owned()].into_iter().collect()
        );
        assert_eq!(resolution.root_edges.len(), 3);
    }

    #[test]
    fn selected_resolution_evaluates_dependencies_of_host_units_against_the_host() {
        let mut catalog = Catalog::default();
        catalog
            .insert(record(
                "target-package",
                "1.0.0",
                &format!(
                    "[{},{}]",
                    dependency_for_target("host-build", "1", "cfg(unix)", "build"),
                    dependency_for_target("inactive-build", "1", "cfg(windows)", "build"),
                ),
                "{}",
                "",
            ))
            .unwrap();
        catalog
            .insert(record(
                "host-build",
                "1.0.0",
                &format!(
                    "[{},{}]",
                    dependency_for_target("host-selected", "1", "cfg(windows)", "normal"),
                    dependency_for_target("host-inactive", "1", "cfg(unix)", "normal"),
                ),
                "{}",
                "",
            ))
            .unwrap();
        for name in ["inactive-build", "host-selected", "host-inactive"] {
            catalog
                .insert(record(name, "1.0.0", "[]", "{}", ""))
                .unwrap();
        }
        let root = manifest("target-package = \"1\"", "", "2");
        let target_cfg = CfgSet::parse("unix\n").unwrap();
        let host_cfg = CfgSet::parse("windows\n").unwrap();
        let resolution = resolve_selected(
            &root,
            &catalog,
            &options(ResolverVersion::V2),
            &[],
            TargetSelection {
                target_triple: "x86_64-unknown-linux-musl",
                target_cfg: &target_cfg,
                host_triple: "x86_64-pc-windows-msvc",
                host_cfg: &host_cfg,
            },
        )
        .unwrap();

        assert_eq!(selected(&resolution, "host-build").len(), 1);
        assert_eq!(selected(&resolution, "host-selected").len(), 1);
        assert!(selected(&resolution, "inactive-build").is_empty());
        assert!(selected(&resolution, "host-inactive").is_empty());
        assert_eq!(resolution.root_edges[0].alias, "target-package");
        assert_eq!(resolution.root_edges[0].kind, DependencyKind::Normal);
        let target = resolution
            .packages
            .iter()
            .find(|package| package.key.name == "target-package")
            .unwrap();
        assert_eq!(target.edges[0].alias, "host-build");
        assert_eq!(target.edges[0].kind, DependencyKind::Build);
        assert_eq!(target.edges[0].target.as_deref(), Some("cfg(unix)"));
        let host = resolution
            .packages
            .iter()
            .find(|package| package.key.name == "host-build")
            .unwrap();
        assert_eq!(host.edges[0].alias, "host-selected");
        assert_eq!(host.edges[0].kind, DependencyKind::Normal);
        assert_eq!(host.edges[0].target.as_deref(), Some("cfg(windows)"));
        assert!(host.feature_sets.contains_key(&FeatureContext::Host));
    }

    #[test]
    fn annotated_proc_macro_uses_host_context_and_separate_features() {
        let mut catalog = Catalog::default();
        catalog
            .insert(record(
                "derive-example",
                "1.0.0",
                &format!(
                    "[{}]",
                    dependency_with("helper", "helper", "1", &["macro-context"], false, "normal")
                ),
                "{}",
                "",
            ))
            .unwrap();
        catalog
            .insert(record(
                "helper",
                "1.0.0",
                "[]",
                "{\"macro-context\":[],\"target-context\":[]}",
                "",
            ))
            .unwrap();
        let key = PackageKey {
            name: "derive-example".to_owned(),
            version: Version::parse("1.0.0").unwrap(),
            source: PackageSourceKey::CratesIo,
        };
        assert!(catalog.annotate_proc_macro(&key, true).unwrap());
        assert!(!catalog.annotate_proc_macro(&key, true).unwrap());
        let root = manifest(
            "derive-example = \"1\"\nhelper = { version = \"1\", features = [\"target-context\"] }",
            "",
            "2",
        );
        let cfg = CfgSet::parse("unix\n").unwrap();
        let resolution = resolve_selected(
            &root,
            &catalog,
            &options(ResolverVersion::V2),
            &[],
            TargetSelection {
                target_triple: "x86_64-unknown-motor",
                target_cfg: &cfg,
                host_triple: "x86_64-unknown-linux-gnu",
                host_cfg: &cfg,
            },
        )
        .unwrap();
        let derive = resolution
            .packages
            .iter()
            .find(|package| package.key.name == "derive-example")
            .unwrap();
        assert_eq!(derive.compile_kinds, [CompileKind::Host].into());
        let helper = resolution
            .packages
            .iter()
            .find(|package| package.key.name == "helper")
            .unwrap();
        assert_eq!(
            helper.compile_kinds,
            [CompileKind::Host, CompileKind::Target].into()
        );
        assert_eq!(helper.host_features, ["macro-context".to_owned()].into());
        assert_eq!(helper.target_features, ["target-context".to_owned()].into());
    }

    #[test]
    fn records_weak_lock_edges_only_when_the_package_is_selected_elsewhere() {
        let mut catalog = Catalog::default();
        catalog
            .insert(record(
                "a",
                "1.0.0",
                &format!(
                    "[{}]",
                    dependency_with("weak", "weak", "1", &[], true, "normal")
                ),
                "{\"full\":[\"weak?/feature\"]}",
                "",
            ))
            .unwrap();
        catalog
            .insert(record(
                "other",
                "1.0.0",
                &format!("[{}]", dependency("weak", "1")),
                "{}",
                "",
            ))
            .unwrap();
        catalog
            .insert(record("weak", "1.0.0", "[]", "{\"feature\":[]}", ""))
            .unwrap();
        let root = manifest(
            "a = { version = \"1\", features = [\"full\"] }\nother = \"1\"",
            "",
            "2",
        );
        let resolution = resolve(&root, &catalog, &options(ResolverVersion::V2), &[]).unwrap();
        let a = resolution
            .packages
            .iter()
            .find(|package| package.key.name == "a")
            .unwrap();
        assert!(a.edges.is_empty());
        assert_eq!(a.lock_edges.len(), 1);
        assert_eq!(a.lock_edges[0].package.name, "weak");
    }

    #[test]
    fn lazily_resolves_and_hashes_unversioned_local_path_packages() {
        let fixture = LocalFixture::new();
        fixture.package(
            "a",
            "[package]\nname = \"a\"\nversion = \"1.2.3\"\nedition = \"2021\"\n\
             [dependencies]\nb = { path = \"../b\", optional = true }\n\
             [features]\ndefault = [\"dep:b\"]\n",
        );
        fixture.package(
            "b",
            "[package]\nname = \"b\"\nversion = \"2.0.0\"\nedition = \"2021\"\n",
        );
        let root = Manifest::parse(
            &fixture.0,
            &fixture.0.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\na = { path = \"a\" }\n",
        )
        .unwrap();
        let resolution = resolve(
            &root,
            &Catalog::default(),
            &options(ResolverVersion::V2),
            &[],
        )
        .unwrap();
        assert_eq!(selected(&resolution, "a").len(), 1);
        assert_eq!(selected(&resolution, "b").len(), 1);
        for package in &resolution.packages {
            let ResolvedSource::Path {
                logical_root,
                physical_root,
                source_tree_sha256,
                patched_crates_io,
            } = &package.source
            else {
                panic!("local fixture resolved as a registry package");
            };
            assert!(logical_root.is_absolute());
            assert_eq!(logical_root, physical_root);
            assert_ne!(*source_tree_sha256, [0_u8; 32]);
            assert!(!patched_crates_io);
            assert_eq!(
                package.local_manifest.as_ref().unwrap().name,
                package.key.name
            );
        }

        let constrained = Manifest::parse(
            &fixture.0,
            &fixture.0.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\na = { path = \"a\", version = \"=9.0.0\" }\n",
        )
        .unwrap();
        assert!(
            resolve(
                &constrained,
                &Catalog::default(),
                &options(ResolverVersion::V2),
                &[],
            )
            .unwrap_err()
            .to_string()
            .contains("no version")
        );

        let mixed = Manifest::parse(
            &fixture.0,
            &fixture.0.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\nlocal-a = { package = \"a\", path = \"a\" }\n\
             registry-a = { package = \"a\", version = \"=1.2.3\" }\n",
        )
        .unwrap();
        let mut catalog = Catalog::default();
        catalog
            .insert(record("a", "1.2.3", "[]", "{}", ""))
            .unwrap();
        let resolution = resolve(&mixed, &catalog, &options(ResolverVersion::V2), &[]).unwrap();
        assert_eq!(selected(&resolution, "a").len(), 2);
        assert!(
            resolution
                .packages
                .iter()
                .any(|package| package.key.source == PackageSourceKey::CratesIo)
        );
        assert!(
            resolution
                .packages
                .iter()
                .any(|package| matches!(&package.key.source, PackageSourceKey::Path(_)))
        );
    }

    #[test]
    fn locked_repository_loading_skips_inactive_objects_and_reports_selected_missing_objects() {
        let fixture = LocalFixture::new();
        fixture.package(
            "local",
            "[package]\nname = \"local\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
        );
        fs::create_dir(fixture.0.join("src")).unwrap();
        fs::write(fixture.0.join("src/lib.rs"), "pub fn root() {}\n").unwrap();
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\nlocal = { path = \"local\" }\n\
             [target.'cfg(windows)'.dependencies]\nmissing = \"=2.0.0\"\n",
        )
        .unwrap();
        fs::write(
            fixture.0.join("Cargo.lock"),
            format!(
                "version = 4\n\
                 [[package]]\nname = \"local\"\nversion = \"1.0.0\"\n\
                 [[package]]\nname = \"missing\"\nversion = \"2.0.0\"\nsource = \"{SOURCE}\"\n\
                 checksum = \"{}\"\n\
                 [[package]]\nname = \"root\"\nversion = \"0.1.0\"\n\
                 dependencies = [\"local\", \"missing\"]\n",
                checksum("2.0.0"),
            ),
        )
        .unwrap();
        let manifest = Manifest::load(&fixture.0).unwrap();
        let repositories = RepositorySet::open(
            &crate::config::Repositories::default(),
            DEFAULT_TREE_LIMITS,
            16 * 1024 * 1024,
        )
        .unwrap();
        let catalog = Catalog::from_locked_repository(&manifest, &repositories).unwrap();
        let locked = LockedPreference::from_lockfile(manifest.lock.as_ref()).unwrap();
        let unix = CfgSet::parse("unix\n").unwrap();
        let selected = resolve_selected(
            &manifest,
            &catalog,
            &options(ResolverVersion::V2),
            &locked,
            TargetSelection {
                target_triple: "x86_64-unknown-linux-musl",
                target_cfg: &unix,
                host_triple: "x86_64-unknown-linux-gnu",
                host_cfg: &unix,
            },
        )
        .unwrap();
        crate::offline::validate_selected_resolution(&manifest, &selected).unwrap();
        assert_eq!(selected.packages.len(), 1);
        assert_eq!(selected.packages[0].key.name, "local");

        let error =
            resolve(&manifest, &catalog, &options(ResolverVersion::V2), &locked).unwrap_err();
        assert!(error.to_string().contains("missing 2.0.0"));
        assert!(error.render().contains("lorry vendor"));
    }

    #[test]
    fn resolves_and_lock_checks_a_frozen_mixed_source_graph() {
        let fixture = LocalFixture::new();
        fixture.package(
            "moto-rt",
            "[package]\nname = \"moto-rt\"\nversion = \"0.16.4\"\nedition = \"2024\"\n",
        );
        fixture.package(
            "moto-sys",
            "[package]\nname = \"moto-sys\"\nversion = \"0.2.4\"\nedition = \"2024\"\n\
             [dependencies]\nmoto-rt = { path = \"../moto-rt\" }\n\
             [features]\ndefault = [\"userspace\"]\nmoto-rt = []\nuserspace = [\"moto-rt\"]\n",
        );
        fs::create_dir(fixture.0.join("src")).unwrap();
        fs::write(fixture.0.join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[package]\nname = \"mixed-root\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\
             [target.'cfg(unix)'.dependencies]\nlibc = \"=0.2.139\"\n\
             [target.'cfg(not(unix))'.dependencies]\n\
             moto-sys = { path = \"moto-sys\" }\n\
             moto-rt = { path = \"moto-rt\" }\n",
        )
        .unwrap();
        fs::write(
            fixture.0.join("Cargo.lock"),
            format!(
                "version = 4\n\n\
                 [[package]]\nname = \"libc\"\nversion = \"0.2.139\"\nsource = \"{SOURCE}\"\n\
                 checksum = \"201de327520df007757c1f0adce6e827fe8562fbc28bfd9c15571c66ca1f5f79\"\n\n\
                 [[package]]\nname = \"mixed-root\"\nversion = \"0.1.0\"\n\
                 dependencies = [\"libc\", \"moto-rt\", \"moto-sys\"]\n\n\
                 [[package]]\nname = \"moto-rt\"\nversion = \"0.16.4\"\n\n\
                 [[package]]\nname = \"moto-sys\"\nversion = \"0.2.4\"\n\
                 dependencies = [\"moto-rt\"]\n"
            ),
        )
        .unwrap();
        let manifest = Manifest::load(&fixture.0).unwrap();
        let libc = Record::parse(
            Path::new("/fixture/libc-index-record.json"),
            b"{\"name\":\"libc\",\"vers\":\"0.2.139\",\"deps\":[],\
              \"cksum\":\"201de327520df007757c1f0adce6e827fe8562fbc28bfd9c15571c66ca1f5f79\",\
              \"features\":{\"default\":[\"std\"],\"std\":[]},\"yanked\":false}\n",
        )
        .unwrap();
        let mut catalog = Catalog::default();
        catalog.insert(libc).unwrap();
        let locked = LockedPreference::from_lockfile(manifest.lock.as_ref()).unwrap();
        let resolution = resolve(
            &manifest,
            &catalog,
            &Options {
                resolver: manifest.resolver,
                incompatible_rust_versions: None,
                rust_versions: vec![Version::parse("1.98.0").unwrap()],
                package_limit: PackageLimit::with_max(16),
                max_depth: 8,
            },
            &locked,
        )
        .unwrap();
        crate::offline::validate_resolution(&manifest, &resolution).unwrap();
        assert_eq!(selected(&resolution, "libc").len(), 1);
        assert_eq!(selected(&resolution, "moto-sys").len(), 1);
        assert_eq!(selected(&resolution, "moto-rt").len(), 1);
        let moto_sys = resolution
            .packages
            .iter()
            .find(|package| package.key.name == "moto-sys")
            .unwrap();
        assert_eq!(
            moto_sys.target_features,
            ["default", "moto-rt", "userspace"]
                .map(str::to_owned)
                .into()
        );
        assert_eq!(moto_sys.lock_edges.len(), 1);
        assert_eq!(moto_sys.lock_edges[0].package.name, "moto-rt");
    }

    #[test]
    fn reaching_the_package_limit_fails_instead_of_choosing_older_versions() {
        let mut catalog = Catalog::default();
        let dependencies = format!("[{},{}]", dependency("x", "1"), dependency("y", "1"));
        catalog
            .insert(record("a", "1.1.0", &dependencies, "{}", ""))
            .unwrap();
        catalog
            .insert(record("a", "1.0.0", "[]", "{}", ""))
            .unwrap();
        catalog
            .insert(record("x", "1.0.0", "[]", "{}", ""))
            .unwrap();
        catalog
            .insert(record("y", "1.0.0", "[]", "{}", ""))
            .unwrap();
        let root = manifest("a = \"1\"", "", "2");
        // `a 1.0.0` would fit in two packages, but Cargo selects `a 1.1.0`.
        let mut limited = options(ResolverVersion::V2);
        limited.package_limit = PackageLimit::with_max(2);
        let error = resolve(&root, &catalog, &limited, &[])
            .unwrap_err()
            .render();
        assert!(error.contains("limit of 2"), "{error}");
        assert!(error.contains("`max-packages`"), "{error}");

        limited.package_limit = PackageLimit::with_max(3);
        let resolution = resolve(&root, &catalog, &limited, &[]).unwrap();
        assert!(
            resolution
                .packages
                .iter()
                .any(|package| package.key.name == "a"
                    && package.key.version == Version::new(1, 1, 0))
        );
    }

    #[test]
    fn rejects_links_conflicts_and_graph_limits() {
        let mut catalog = Catalog::default();
        catalog
            .insert(record("a", "1.0.0", "[]", "{}", ",\"links\":\"native\""))
            .unwrap();
        catalog
            .insert(record("b", "1.0.0", "[]", "{}", ",\"links\":\"native\""))
            .unwrap();
        let root = manifest("a = \"1\"\nb = \"1\"", "", "2");
        assert!(
            resolve(&root, &catalog, &options(ResolverVersion::V2), &[])
                .unwrap_err()
                .to_string()
                .contains("link")
        );

        let mut limits = options(ResolverVersion::V2);
        limits.package_limit = PackageLimit::with_max(1);
        assert!(
            resolve(&root, &catalog, &limits, &[])
                .unwrap_err()
                .to_string()
                .contains("limit of 1")
        );
    }

    #[test]
    fn rejects_dependency_cycles_and_deep_paths_to_selected_packages() {
        let mut catalog = Catalog::default();
        catalog
            .insert(record(
                "a",
                "1.0.0",
                &format!("[{}]", dependency("b", "1")),
                "{}",
                "",
            ))
            .unwrap();
        catalog
            .insert(record(
                "b",
                "1.0.0",
                &format!("[{}]", dependency("a", "1")),
                "{}",
                "",
            ))
            .unwrap();
        let root = manifest("a = \"1\"", "", "2");
        assert!(
            resolve(&root, &catalog, &options(ResolverVersion::V2), &[])
                .unwrap_err()
                .to_string()
                .contains("cycle")
        );

        let mut catalog = Catalog::default();
        catalog
            .insert(record(
                "a",
                "1.0.0",
                &format!("[{}]", dependency("b", "1")),
                "{}",
                "",
            ))
            .unwrap();
        catalog
            .insert(record(
                "b",
                "1.0.0",
                &format!("[{}]", dependency("shared", "1")),
                "{}",
                "",
            ))
            .unwrap();
        catalog
            .insert(record("shared", "1.0.0", "[]", "{}", ""))
            .unwrap();
        let root = manifest("shared = \"1\"\na = \"1\"", "", "2");
        let mut limits = options(ResolverVersion::V2);
        limits.max_depth = 2;
        assert!(
            resolve(&root, &catalog, &limits, &[])
                .unwrap_err()
                .to_string()
                .contains("dependency depth")
        );
    }

    #[test]
    fn matches_the_frozen_stage_two_cargo_resolution_oracle() {
        let root = Path::new("tests/oracles/stage2-resolution/root");
        let manifest = Manifest::load(root).unwrap();
        let mut catalog = Catalog::default();
        for entry in fs::read_dir("tests/oracles/stage2-resolution/index-records").unwrap() {
            let path = entry.unwrap().path();
            catalog
                .insert(Record::parse(&path, &fs::read(&path).unwrap()).unwrap())
                .unwrap();
        }
        let locked = LockedPreference::from_lockfile(manifest.lock.as_ref()).unwrap();
        let options = Options {
            resolver: manifest.resolver,
            incompatible_rust_versions: Some(IncompatibleRustVersions::Allow),
            rust_versions: vec![Version::parse("1.98.0").unwrap()],
            package_limit: PackageLimit::with_max(64),
            max_depth: 16,
        };
        let complete = resolve(&manifest, &catalog, &options, &locked).unwrap();
        crate::offline::validate_resolution(&manifest, &complete).unwrap();
        assert_eq!(
            crate::lockfile::render(&manifest, &complete).unwrap(),
            fs::read(root.join("Cargo.lock")).unwrap()
        );

        let linux = CfgSet::parse("unix\ntarget_os=\"linux\"\n").unwrap();
        let selected = resolve_selected(
            &manifest,
            &catalog,
            &options,
            &locked,
            TargetSelection {
                target_triple: "x86_64-unknown-linux-gnu",
                target_cfg: &linux,
                host_triple: "x86_64-unknown-linux-gnu",
                host_cfg: &linux,
            },
        )
        .unwrap();
        crate::offline::validate_selected_resolution(&manifest, &selected).unwrap();
        assert_eq!(
            selected
                .packages
                .iter()
                .map(|package| package.key.name.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["a", "defaultdep", "optional", "platform", "shared"])
        );
    }

    #[test]
    fn resolves_the_seeded_lorry_lock_graph_when_requested() {
        let Some(repository) = std::env::var_os("LORRY_TEST_SEEDED_REPOSITORY") else {
            return;
        };
        let mut catalog = Catalog::default();
        let objects = PathBuf::from(repository).join("objects/crates-io/sha256");
        for prefix in fs::read_dir(objects).unwrap() {
            for object in fs::read_dir(prefix.unwrap().path()).unwrap() {
                let path = object.unwrap().path().join("index-record.json");
                catalog
                    .insert(Record::parse(&path, &fs::read(&path).unwrap()).unwrap())
                    .unwrap();
            }
        }

        let manifest = Manifest::load(Path::new(".")).unwrap();
        let locked = LockedPreference::from_lockfile(manifest.lock.as_ref()).unwrap();
        let lock = manifest.lock.as_ref().unwrap();
        for package in &lock.packages {
            if package.source.as_deref() != Some(SOURCE)
                || catalog.contains_registry(
                    &package.name,
                    &Version::parse(&package.version.original).unwrap(),
                )
            {
                continue;
            }
            let dependencies = package
                .dependencies
                .iter()
                .map(|dependency| {
                    let name = dependency.split_whitespace().next().unwrap();
                    let matches = lock
                        .packages
                        .iter()
                        .filter(|package| package.name == name)
                        .collect::<Vec<_>>();
                    assert_eq!(
                        matches.len(),
                        1,
                        "test supplement needs an unambiguous lock dependency"
                    );
                    Dependency {
                        alias: name.to_owned(),
                        package: name.to_owned(),
                        requirement: VersionReq::parse(&format!(
                            "={}",
                            matches[0].version.original
                        ))
                        .unwrap(),
                        features: Vec::new(),
                        optional: false,
                        default_features: true,
                        target: None,
                        kind: DependencyKind::Normal,
                    }
                })
                .collect();
            catalog
                .insert(Record {
                    name: package.name.clone(),
                    version: Version::parse(&package.version.original).unwrap(),
                    dependencies,
                    checksum: decode_hex(package.checksum.as_deref().unwrap()).unwrap(),
                    features: BTreeMap::new(),
                    features2: BTreeMap::new(),
                    yanked: false,
                    links: None,
                    schema: 1,
                    rust_version: None,
                    published: None,
                    exact_bytes: Vec::new(),
                })
                .unwrap();
        }
        let resolution = resolve(
            &manifest,
            &catalog,
            &Options {
                resolver: manifest.resolver,
                incompatible_rust_versions: None,
                rust_versions: vec![Version::parse("1.98.0").unwrap()],
                package_limit: PackageLimit::with_max(64),
                max_depth: 16,
            },
            &locked,
        )
        .unwrap();
        crate::offline::validate_resolution(&manifest, &resolution).unwrap();
        assert_eq!(
            crate::lockfile::render(&manifest, &resolution).unwrap(),
            fs::read("Cargo.lock").unwrap()
        );
        let expected = lock
            .packages
            .iter()
            .filter(|package| package.source.as_deref() == Some(SOURCE))
            .map(|package| {
                (
                    package.name.clone(),
                    Version::parse(&package.version.original).unwrap(),
                )
            })
            .collect::<BTreeSet<_>>();
        let actual = resolution
            .packages
            .iter()
            .filter(|package| matches!(&package.source, ResolvedSource::CratesIo { .. }))
            .map(|package| (package.key.name.clone(), package.key.version.clone()))
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected);
    }

    #[test]
    fn selected_lorry_graph_loads_objects_directly_from_the_seeded_repository() {
        let Some(repository) = std::env::var_os("LORRY_TEST_SEEDED_REPOSITORY") else {
            return;
        };
        let manifest = Manifest::load(Path::new(".")).unwrap();
        let repositories = RepositorySet::open(
            &crate::config::Repositories {
                system: Some(PathBuf::from(repository)),
                ..crate::config::Repositories::default()
            },
            DEFAULT_TREE_LIMITS,
            16 * 1024 * 1024,
        )
        .unwrap();
        let catalog = Catalog::from_locked_repository(&manifest, &repositories).unwrap();
        let locked = LockedPreference::from_lockfile(manifest.lock.as_ref()).unwrap();
        let linux = CfgSet::parse(
            "debug_assertions\npanic=\"unwind\"\ntarget_arch=\"x86_64\"\n\
             target_endian=\"little\"\ntarget_env=\"gnu\"\ntarget_family=\"unix\"\n\
             target_os=\"linux\"\ntarget_pointer_width=\"64\"\ntarget_vendor=\"unknown\"\nunix\n",
        )
        .unwrap();
        let resolution = resolve_selected(
            &manifest,
            &catalog,
            &Options {
                resolver: manifest.resolver,
                incompatible_rust_versions: None,
                rust_versions: vec![Version::parse("1.98.0").unwrap()],
                package_limit: PackageLimit::with_max(64),
                max_depth: 16,
            },
            &locked,
            TargetSelection {
                target_triple: "x86_64-unknown-linux-gnu",
                target_cfg: &linux,
                host_triple: "x86_64-unknown-linux-gnu",
                host_cfg: &linux,
            },
        )
        .unwrap();
        crate::offline::validate_selected_resolution(&manifest, &resolution).unwrap();
        assert!(
            resolution
                .packages
                .iter()
                .all(|package| package.key.name != "moto-rt")
        );
    }
}
