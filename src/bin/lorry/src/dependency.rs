use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::thread;

use crate::admission_state::{Capability, CompactState, Context, Review};
use crate::archive::{ExtractedArchive, Limits as ArchiveLimits, extract_crate};
use crate::cargo_registry::CargoRegistry;
use crate::config::Config;
use crate::diagnostic::{Error, Result};
use crate::hash::hex;
use crate::manifest::Manifest;
use crate::offline;
use crate::patch;
use crate::policy::{self, Admission, PackageEvidence};
use crate::repository::RepositorySet;
use crate::resolver::{
    Catalog, Options, PackageKey, PackageSourceKey, Resolution, ResolvedPackage, ResolvedSource,
    TargetSelection,
};
use crate::source_tree::{Exclusions, Limits as TreeLimits, Tree};
use crate::toolchain::Toolchain;
use crate::validation::ValidationMode;
pub(crate) mod workspace;

use crate::unit::{
    CompilationPlan, PlanOptions, SourceRemap, UnitGraph, plan_dependency_units_with_remaps,
};

#[derive(Debug)]
pub struct PreparedGraph {
    pub resolution: Resolution,
    pub admission: Admission,
    pub packages: BTreeMap<PackageKey, PreparedPackage>,
    cargo_registry_mode: bool,
}

#[derive(Debug)]
pub struct PreparedPackage {
    pub manifest: Manifest,
    pub evidence: PackageEvidence,
    _extracted: Option<ExtractedArchive>,
    cargo_registry: bool,
}

/// The units a plan compiles for the selected workspace members.
pub(crate) enum UnitSelection<'a> {
    /// Libraries and binaries, all or one named binary, as a plain build or
    /// check selects them.
    Default {
        check: bool,
        binary: Option<&'a str>,
    },
    /// Explicit target selectors such as `--lib`, `--bins`, or `--test NAME`.
    Targets(&'a crate::cli::TargetSelection, crate::unit::UnitMode),
    /// Every test harness, as a plain `lorry test` selects them.
    Tests,
}

impl PreparedGraph {
    pub(crate) fn plan(
        &self,
        options: &PlanOptions<'_>,
        selected: &[PackageKey],
        selection: UnitSelection<'_>,
    ) -> Result<CompilationPlan> {
        let manifests = self
            .packages
            .iter()
            .map(|(key, package)| (key.clone(), package.manifest.clone()))
            .collect();
        let graph = match selection {
            UnitSelection::Default { check, binary } => crate::unit::workspace_units(
                &self.resolution,
                &manifests,
                selected,
                check,
                true,
                binary,
                options.release || options.profile.opt_level != "0",
            )?,
            UnitSelection::Targets(targets, mode) => crate::unit::workspace_compiler_targets(
                &self.resolution,
                &manifests,
                selected,
                targets,
                options,
                mode,
            )?,
            UnitSelection::Tests => {
                crate::unit::workspace_test_units(&self.resolution, &manifests, selected, options)?
            }
        };
        self.finish_plan(options, manifests, graph)
    }

    fn finish_plan(
        &self,
        options: &PlanOptions<'_>,
        manifests: BTreeMap<PackageKey, Manifest>,
        graph: UnitGraph,
    ) -> Result<CompilationPlan> {
        let mut source_remaps = BTreeMap::<PackageKey, SourceRemap>::new();
        let mut complete_source_trees = BTreeSet::<PackageKey>::new();
        let mut logical_roots = BTreeMap::<PathBuf, PathBuf>::new();
        let mut physical_roots = BTreeMap::<PathBuf, PathBuf>::new();
        for package in &self.resolution.packages {
            let remap = match &package.source {
                ResolvedSource::CratesIo { checksum } => {
                    let prepared = self.packages.get(&package.key).ok_or_else(|| {
                        Error::failure(format!(
                            "prepared graph has no source for `{} {}`",
                            package.key.name, package.key.version
                        ))
                    })?;
                    if self.cargo_registry_mode {
                        None
                    } else {
                        Some(SourceRemap::registry(
                            options.workspace_root,
                            checksum,
                            &prepared.manifest.root,
                        )?)
                    }
                }
                ResolvedSource::Path {
                    logical_root,
                    physical_root,
                    source_tree_sha256,
                    ..
                } => {
                    if self.cargo_registry_mode {
                        None
                    } else if logical_root != physical_root {
                        return Err(Error::failure(format!(
                            "path package `{} {}` has distinct logical and physical roots",
                            package.key.name, package.key.version
                        )));
                    } else if physical_root.starts_with(options.workspace_root) {
                        None
                    } else {
                        Some(SourceRemap::path(
                            options.workspace_root,
                            source_tree_sha256,
                            physical_root,
                        )?)
                    }
                }
                ResolvedSource::Git {
                    physical_root,
                    cargo_source,
                    package_path,
                    ..
                } => {
                    complete_source_trees.insert(package.key.clone());
                    if self.cargo_registry_mode {
                        None
                    } else {
                        Some(SourceRemap::git(
                            options.workspace_root,
                            cargo_source,
                            package_path,
                            physical_root,
                        )?)
                    }
                }
            };
            let Some(remap) = remap else {
                continue;
            };
            if let Some(previous) =
                logical_roots.insert(remap.logical_root.clone(), remap.physical_root.clone())
                && previous != remap.physical_root
            {
                return Err(Error::failure(format!(
                    "logical source root `{}` maps to multiple physical roots",
                    remap.logical_root.display()
                )));
            }
            if let Some(previous) =
                physical_roots.insert(remap.physical_root.clone(), remap.logical_root.clone())
                && previous != remap.logical_root
            {
                return Err(Error::failure(format!(
                    "physical source root `{}` maps to multiple logical roots",
                    remap.physical_root.display()
                )));
            }
            if source_remaps.insert(package.key.clone(), remap).is_some() {
                return Err(Error::failure(format!(
                    "package `{} {}` has multiple source mappings",
                    package.key.name, package.key.version
                )));
            }
        }
        let source_exclusions = complete_source_trees
            .into_iter()
            .map(|key| (key, Exclusions::None))
            .collect();
        plan_dependency_units_with_remaps(
            &graph,
            &manifests,
            options,
            &source_remaps,
            &source_exclusions,
        )
    }

    pub fn revalidate_cargo_registry_sources(&self, limits: TreeLimits) -> Result<()> {
        for (key, package) in &self.packages {
            if !package.cargo_registry {
                continue;
            }
            let tree = Tree::scan(
                &package.manifest.root,
                limits,
                Exclusions::CargoRegistryMarker,
            )?;
            if tree.sha256 != package.evidence.source_tree_sha256 {
                return Err(Error::failure(format!(
                    "Cargo registry source for `{} {}` changed while it was being built",
                    key.name, key.version
                )));
            }
        }
        Ok(())
    }
}

impl PreparedPackage {
    pub fn source_root(&self) -> &Path {
        &self.manifest.root
    }
}

#[derive(Clone, Copy)]
pub enum RegistrySource<'a> {
    Lorry(&'a RepositorySet),
    Cargo(&'a CargoRegistry),
}

/// How a command opens its one verified registry source.
pub(crate) struct RegistryAccess<'a> {
    pub use_cargo_registry: bool,
    pub validation: ValidationMode,
    pub staging_parent: &'a Path,
    pub evidence_root: &'a Path,
}

/// Locked inputs that workspace commands read before resolution: the registry
/// source, the locked Git sources, and resolver options.
pub(crate) struct LockedContext {
    registry: OpenRegistry,
    pub direct: crate::git::DirectCatalog,
    pub options: Options,
}

enum OpenRegistry {
    Lorry(RepositorySet),
    Cargo(CargoRegistry),
}

impl LockedContext {
    pub(crate) fn open(
        manifest: &Manifest,
        config: &Config,
        toolchain: &Toolchain,
        access: RegistryAccess<'_>,
    ) -> Result<Self> {
        let registry = if access.use_cargo_registry {
            OpenRegistry::Cargo(CargoRegistry::discover_with_validation(
                access.staging_parent,
                &config.policy.limits,
                access.validation,
                Some(access.evidence_root),
            )?)
        } else {
            OpenRegistry::Lorry(RepositorySet::open_with_validation(
                &config.repositories,
                crate::engine::repository_tree_limits(&config.policy.limits)?,
                config.policy.limits.max_package_bytes,
                access.validation,
            )?)
        };
        Ok(Self {
            registry,
            direct: crate::git::load_locked_sources(manifest, &config.policy.limits)?,
            options: resolver_options(manifest, config, toolchain)?,
        })
    }

    pub(crate) fn source(&self) -> RegistrySource<'_> {
        match &self.registry {
            OpenRegistry::Lorry(repositories) => RegistrySource::Lorry(repositories),
            OpenRegistry::Cargo(registry) => RegistrySource::Cargo(registry),
        }
    }
}

/// Resolver options shared by build, vendor, and admission reconstruction.
pub fn resolver_options(
    manifest: &Manifest,
    config: &Config,
    toolchain: &Toolchain,
) -> Result<Options> {
    let rust_version = semver::Version::parse(&toolchain.release).map_err(|error| {
        Error::failure(format!(
            "selected rustc release `{}` is not a semantic version: {error}",
            toolchain.release
        ))
    })?;
    Ok(Options {
        resolver: manifest.resolver,
        incompatible_rust_versions: config.incompatible_rust_versions,
        rust_versions: vec![rust_version],
        package_limit: crate::policy::PackageLimit::new(&config.policy.limits, manifest),
        max_depth: config.policy.limits.max_depth,
    })
}

fn git_package_evidence(
    direct: &crate::git::DirectCatalog,
    packages: &[&ResolvedPackage],
) -> Result<BTreeMap<PackageKey, PackageEvidence>> {
    packages
        .iter()
        .map(|package| Ok((package.key.clone(), direct.evidence(package)?)))
        .collect()
}

fn registry_package_evidence_set(
    source: RegistrySource<'_>,
    config: &Config,
    staging_parent: &Path,
    packages: &[(&ResolvedPackage, [u8; 32])],
    describe: bool,
) -> Result<BTreeMap<PackageKey, PreparedPackage>> {
    if packages.is_empty() {
        return Ok(BTreeMap::new());
    }
    let workers = thread::available_parallelism()
        .map_or(1, usize::from)
        .min(packages.len());
    let chunk_size = packages.len().div_ceil(workers);
    let batches = thread::scope(|scope| {
        let handles = packages
            .chunks(chunk_size)
            .map(|chunk| {
                scope.spawn(|| {
                    chunk
                        .iter()
                        .map(|(package, checksum)| {
                            (
                                package.key.clone(),
                                registry_package_evidence(
                                    source,
                                    config,
                                    staging_parent,
                                    package,
                                    checksum,
                                    describe,
                                ),
                            )
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .map_err(|_| Error::failure("registry evidence worker terminated unexpectedly"))
            })
            .collect::<Result<Vec<_>>>()
    })?;
    let mut prepared = BTreeMap::new();
    for (key, package) in batches.into_iter().flatten() {
        prepared.insert(key, package?);
    }
    Ok(prepared)
}

/// Inspection reads every locked registry object locally, so it verifies them
/// in parallel before resolution.
fn locked_catalog(
    manifest: &Manifest,
    source: RegistrySource<'_>,
    direct: &crate::git::DirectCatalog,
    describe: bool,
) -> Result<Catalog> {
    if let RegistrySource::Lorry(repositories) = source {
        let checksums = manifest
            .lock
            .iter()
            .flat_map(|lock| &lock.packages)
            .filter_map(|package| package.checksum.clone())
            .collect::<Vec<_>>();
        repositories.prefetch_registries(&checksums)?;
    }
    source_catalog(manifest, Some(source), direct, describe)
}

/// Starts a resolver catalog from the locked crates.io candidates in `source`
/// (none for an unlocked resolution), then adds patches and direct Git sources.
pub(crate) fn source_catalog(
    manifest: &Manifest,
    source: Option<RegistrySource<'_>>,
    direct: &crate::git::DirectCatalog,
    describe: bool,
) -> Result<Catalog> {
    let mut catalog = match source {
        Some(RegistrySource::Lorry(repositories)) => {
            Catalog::from_locked_repository(manifest, repositories)?
        }
        Some(RegistrySource::Cargo(registry)) => {
            Catalog::from_locked_cargo_registry(manifest, registry)?
        }
        None => Catalog::default(),
    };
    if describe {
        patch::configure_sources(manifest, &mut catalog)?;
    } else {
        patch::configure(manifest, &mut catalog)?;
    }
    direct.configure(&mut catalog)?;
    Ok(catalog)
}

/// Shared inputs for canonical review reconstruction.
pub struct ReviewInputs<'a> {
    pub manifest: &'a Manifest,
    pub config: &'a Config,
    pub source: RegistrySource<'a>,
    pub toolchain: &'a Toolchain,
    pub options: &'a Options,
    pub staging_parent: &'a Path,
    pub direct: Option<&'a crate::git::DirectCatalog>,
    pub prepare_context: Option<Context>,
}

fn prepare_resolution_packages(
    resolution: &Resolution,
    config: &Config,
    source: RegistrySource<'_>,
    staging_parent: &Path,
    direct: &crate::git::DirectCatalog,
    describe: bool,
) -> Result<BTreeMap<PackageKey, PreparedPackage>> {
    let git = resolution
        .packages
        .iter()
        .filter(|package| matches!(package.source, ResolvedSource::Git { .. }))
        .collect::<Vec<_>>();
    let mut git_evidence = git_package_evidence(direct, &git)?;
    let registry = resolution
        .packages
        .iter()
        .filter_map(|package| match package.source {
            ResolvedSource::CratesIo { checksum } => Some((package, checksum)),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut packages =
        registry_package_evidence_set(source, config, staging_parent, &registry, describe)?;
    for package in &resolution.packages {
        if packages.contains_key(&package.key) {
            continue;
        }
        let (manifest, evidence) = match &package.source {
            ResolvedSource::Git { .. } => (
                package.local_manifest.clone().ok_or_else(|| {
                    Error::failure(format!(
                        "resolved Git package `{} {}` has no inspected manifest",
                        package.key.name, package.key.version
                    ))
                })?,
                git_evidence
                    .remove(&package.key)
                    .expect("every verified Git package has evidence"),
            ),
            ResolvedSource::Path { .. } => (
                package.local_manifest.clone().ok_or_else(|| {
                    Error::failure(format!(
                        "resolved path package `{} {}` has no inspected manifest",
                        package.key.name, package.key.version
                    ))
                })?,
                PackageEvidence::from_path(package)?,
            ),
            ResolvedSource::CratesIo { .. } => unreachable!(),
        };
        packages.insert(
            package.key.clone(),
            PreparedPackage {
                manifest,
                evidence,
                _extracted: None,
                cargo_registry: false,
            },
        );
    }
    Ok(packages)
}

fn registry_package_evidence(
    source: RegistrySource<'_>,
    config: &Config,
    staging_parent: &Path,
    package: &ResolvedPackage,
    checksum: &[u8; 32],
    describe: bool,
) -> Result<PreparedPackage> {
    match source {
        RegistrySource::Lorry(repositories) => {
            let checksum = hex(checksum);
            let object = repositories.lookup_registry(&checksum)?.ok_or_else(|| {
                Error::failure(format!(
                    "locked crates.io package `{} {}` has no verified source object in the configured repositories",
                    package.key.name, package.key.version
                ))
                .with_help("run `lorry fetch` to acquire the missing locked sources")
            })?;
            let (source_root, extracted) = if object.retained_source {
                (object.root.join("source"), None)
            } else {
                let extracted = extract_crate(
                    &object.root.join("package.crate"),
                    object.checksum,
                    staging_parent,
                    &object.name,
                    &object.version,
                    ArchiveLimits::from_policy(&config.policy.limits),
                )?;
                (extracted.path().to_owned(), Some(extracted))
            };
            let inspected_manifest = if !describe && object.retained_source {
                repositories.load_registry_manifest(&object)?
            } else {
                Manifest::load_registry_dependency(&source_root, describe)?
            };
            let package_evidence = match (&extracted, object.source_tree.as_ref()) {
                (Some(extracted), _) => PackageEvidence::from_registry(
                    package,
                    &object,
                    &inspected_manifest,
                    extracted.tree(),
                    false,
                )?,
                (None, Some(tree)) => PackageEvidence::from_registry(
                    package,
                    &object,
                    &inspected_manifest,
                    tree,
                    false,
                )?,
                (None, None) => PackageEvidence::from_trusted_registry(
                    package,
                    &object,
                    &inspected_manifest,
                    false,
                )?,
            };
            Ok(PreparedPackage {
                manifest: inspected_manifest,
                evidence: package_evidence,
                _extracted: extracted,
                cargo_registry: false,
            })
        }
        RegistrySource::Cargo(registry) => {
            let locked_checksum = hex(checksum);
            let cached = if describe {
                registry.load_description(
                    &package.key.name,
                    &package.key.version,
                    &locked_checksum,
                )?
            } else {
                registry.load(&package.key.name, &package.key.version, &locked_checksum)?
            };
            if cached.checksum != *checksum {
                return Err(Error::failure(format!(
                    "Cargo registry source checksum does not match resolved package `{} {}`",
                    package.key.name, package.key.version
                )));
            }
            let (manifest, evidence) = cached.into_parts();
            Ok(PreparedPackage {
                manifest,
                evidence,
                _extracted: None,
                cargo_registry: true,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::{CommandOptions, dependency_rustc_invocation};
    use crate::config::{CargoCompat, IncompatibleRustVersions, Repositories};
    use crate::resolver::PackageSourceKey;
    use crate::source_tree::DEFAULT_LIMITS;
    use crate::toolchain::{CfgSet, Toolchain};
    use crate::unit::{ProfileContext, UnitKind, UnitMode, selected_library_key};
    use semver::Version;
    use serde_json::Value;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    pub(super) struct Fixture(pub(super) PathBuf);

    impl Fixture {
        pub(super) fn new() -> Self {
            let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("lorry-dependency-{}-{id}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(path.join("src")).unwrap();
            fs::write(path.join("src/lib.rs"), "pub fn root() {}\n").unwrap();
            Self(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    pub(super) fn options(manifest: &Manifest) -> Options {
        Options {
            resolver: manifest.resolver,
            incompatible_rust_versions: Some(IncompatibleRustVersions::Allow),
            rust_versions: vec![Version::parse("1.98.0").unwrap()],
            package_limit: crate::policy::PackageLimit::with_max(64),
            max_depth: Some(16),
        }
    }

    fn toolchain() -> Toolchain {
        Toolchain {
            rustc: "/rustc".into(),
            clippy: None,
            verbose_version: "rustc 1.98.0-nightly (bc2112ed5 2026-06-18)\n\
                              binary: rustc\n\
                              commit-hash: bc2112ed56c99fa649e09ab3ab286afab3d9059a\n\
                              commit-date: 2026-06-18\n\
                              host: x86_64-unknown-linux-gnu\n\
                              release: 1.98.0-nightly\n\
                              LLVM version: 22.1.7\n"
                .to_owned(),
            release: "1.98.0-nightly".to_owned(),
            host: "x86_64-unknown-linux-gnu".to_owned(),
            compatibility: CargoCompat::V1_99,
            query_cache: None,
        }
    }

    fn assert_check_graph_matches_cargo(
        fixture: &Path,
        plan: &CompilationPlan,
        cargo_selection: &[&str],
    ) {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let output = Command::new(cargo)
            .args(["-Z", "unstable-options", "check", "--release"])
            .args(cargo_selection)
            .args(["--unit-graph", "--offline"])
            .arg("--manifest-path")
            .arg(fixture.join("Cargo.toml"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let cargo: Value = serde_json::from_slice(&output.stdout).unwrap();
        let units = cargo["units"].as_array().unwrap();
        let cargo_nodes = units
            .iter()
            .map(|unit| {
                assert_eq!(unit["mode"], "check");
                let package = if unit["pkg_id"]
                    .as_str()
                    .unwrap()
                    .starts_with(&format!("path+file://{}#", fixture.display()))
                {
                    "root"
                } else {
                    "local"
                };
                (
                    package.to_owned(),
                    unit["target"]["kind"][0].as_str().unwrap().to_owned(),
                    unit["target"]["name"].as_str().unwrap().to_owned(),
                    unit["profile"]["panic"].as_str().unwrap().to_owned(),
                )
            })
            .collect::<Vec<_>>();
        let lorry_node = |key: &crate::unit::UnitKey| {
            let unit = &plan.units[key];
            if key.package.name == "root" {
                assert!(matches!(key.mode, UnitMode::Check | UnitMode::CheckTest));
            } else {
                // Lorry intentionally builds dependency code while checking roots.
                assert_eq!(key.mode, UnitMode::Build);
            }
            let kind = match key.kind {
                UnitKind::Library | UnitKind::LibraryHarness => "lib",
                UnitKind::Binary | UnitKind::BinaryHarness => "bin",
                UnitKind::IntegrationHarness => "test",
                _ => panic!("unexpected unit in check oracle: {:?}", key.kind),
            };
            (
                key.package.name.clone(),
                kind.to_owned(),
                key.target
                    .clone()
                    .unwrap_or_else(|| key.package.name.clone()),
                match unit.settings.profile.panic {
                    crate::identity::CargoPanicStrategy::Abort => "abort",
                    crate::identity::CargoPanicStrategy::Unwind => "unwind",
                }
                .to_owned(),
            )
        };
        let mut expected_nodes = cargo_nodes.clone();
        expected_nodes.sort();
        let mut actual_nodes = plan.units.keys().map(lorry_node).collect::<Vec<_>>();
        actual_nodes.sort();
        assert_eq!(actual_nodes, expected_nodes);

        let mut cargo_edges = Vec::new();
        for (parent, unit) in units.iter().enumerate() {
            for edge in unit["dependencies"].as_array().unwrap() {
                cargo_edges.push((
                    cargo_nodes[parent].clone(),
                    cargo_nodes[edge["index"].as_u64().unwrap() as usize].clone(),
                    edge["extern_crate_name"].as_str().unwrap().to_owned(),
                ));
            }
        }
        cargo_edges.sort();
        let mut lorry_edges = plan
            .units
            .values()
            .flat_map(|unit| {
                unit.unit.dependencies.iter().map(|edge| {
                    (
                        lorry_node(&unit.unit.key),
                        lorry_node(&edge.unit),
                        edge.alias.clone().unwrap_or_default(),
                    )
                })
            })
            .collect::<Vec<_>>();
        lorry_edges.sort();
        assert_eq!(lorry_edges, cargo_edges);

        let mut cargo_roots = cargo["roots"]
            .as_array()
            .unwrap()
            .iter()
            .map(|index| cargo_nodes[index.as_u64().unwrap() as usize].clone())
            .collect::<Vec<_>>();
        cargo_roots.sort();
        let mut lorry_roots = plan
            .units
            .keys()
            .filter(|key| {
                key.package.name == "root"
                    && (matches!(
                        key.kind,
                        UnitKind::LibraryHarness
                            | UnitKind::BinaryHarness
                            | UnitKind::IntegrationHarness
                    ) || (key.profile == ProfileContext::Normal
                        && matches!(key.kind, UnitKind::Library | UnitKind::Binary)))
            })
            .map(lorry_node)
            .collect::<Vec<_>>();
        lorry_roots.sort();
        assert_eq!(lorry_roots, cargo_roots);
    }

    #[test]
    fn prepares_a_path_only_graph_without_a_repository_or_staging() {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.0.join("src")).unwrap();
        fs::write(fixture.0.join("src/lib.rs"), "pub fn root() {}\n").unwrap();
        fs::write(fixture.0.join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::create_dir_all(fixture.0.join("tests")).unwrap();
        fs::write(
            fixture.0.join("tests/integration.rs"),
            "#[test] fn test() {}\n",
        )
        .unwrap();
        fs::create_dir_all(fixture.0.join("local/src")).unwrap();
        fs::write(
            fixture.0.join("local/Cargo.toml"),
            "[package]\nname = \"local\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\
             license = \"MIT\"\n",
        )
        .unwrap();
        fs::write(fixture.0.join("local/src/lib.rs"), "pub fn local() {}\n").unwrap();
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\nlocal = { path = \"local\" }\n\
             [profile.release]\npanic = \"abort\"\n",
        )
        .unwrap();
        fs::write(
            fixture.0.join("Cargo.lock"),
            "version = 4\n\
             [[package]]\nname = \"local\"\nversion = \"1.0.0\"\n\
             [[package]]\nname = \"root\"\nversion = \"0.1.0\"\ndependencies = [\"local\"]\n",
        )
        .unwrap();
        let manifest = Manifest::load_for_build(&fixture.0).unwrap();
        let config = Config::default();
        let repositories =
            RepositorySet::open(&Repositories::default(), DEFAULT_LIMITS, 16 * 1024 * 1024)
                .unwrap();
        let cfg = CfgSet::parse("unix\n").unwrap();
        let staging = fixture.0.join("unused-staging");
        let selection = TargetSelection {
            target_triple: "x86_64-unknown-linux-musl",
            target_cfg: &cfg,
            host_triple: "x86_64-unknown-linux-gnu",
            host_cfg: &cfg,
        };
        let source = RegistrySource::Lorry(&repositories);
        let direct = crate::git::DirectCatalog::default();
        let resolver_options = options(&manifest);
        let prepare = |dev| {
            workspace::prepare_member(
                &fixture.0,
                &config,
                source,
                &direct,
                &resolver_options,
                selection,
                &staging,
                dev,
            )
            .unwrap()
        };
        let graph = prepare(false);
        let library = selected_library_key(&manifest).unwrap();
        let selected = std::slice::from_ref(&library.package);

        assert!(!staging.exists());
        assert_eq!(graph.packages.len(), 2);
        let local = graph
            .packages
            .keys()
            .find(|key| key.name == "local")
            .unwrap();
        assert!(matches!(local.source, PackageSourceKey::Path(_)));
        assert_eq!(graph.packages[local].source_root(), fixture.0.join("local"));
        assert!(graph.admission.packages.contains_key(local));
        let options = PlanOptions {
            workspace_root: &manifest.root,
            release: true,
            panic_abort: true,
            profile: &crate::manifest::Profile {
                panic_abort: true,
                ..crate::manifest::Profile::release()
            },
            rustc: &toolchain(),
            logical_target: None,
            rustflags: &[],
        };
        let plan = graph
            .plan(
                &options,
                selected,
                UnitSelection::Default {
                    check: false,
                    binary: None,
                },
            )
            .unwrap();
        assert!(plan.units.values().all(|unit| unit.source_remap.is_none()));
        let check_plan = graph
            .plan(
                &options,
                selected,
                UnitSelection::Default {
                    check: true,
                    binary: None,
                },
            )
            .unwrap();
        assert_check_graph_matches_cargo(&fixture.0, &check_plan, &[]);

        // Integration harness environments come from the test plan.
        let shared = prepare(true);
        let focused = shared
            .plan(&options, selected, UnitSelection::Tests)
            .unwrap();
        let integration = focused
            .units
            .keys()
            .find(|key| {
                key.kind == UnitKind::IntegrationHarness
                    && key.target.as_deref() == Some("integration")
            })
            .unwrap();
        let manifests = shared
            .packages
            .iter()
            .map(|(key, package)| (key.clone(), package.manifest.clone()))
            .collect::<BTreeMap<_, _>>();
        let binary_path = fixture.0.join("output/root");
        let other_package = shared
            .packages
            .keys()
            .find(|key| key.name == "local")
            .unwrap()
            .clone();
        let binary_paths = BTreeMap::from([
            (
                library.package.clone(),
                BTreeMap::from([("root".to_owned(), binary_path.clone())]),
            ),
            (
                other_package.clone(),
                BTreeMap::from([
                    ("root".to_owned(), fixture.0.join("other/root")),
                    ("foreign".to_owned(), fixture.0.join("other/foreign")),
                ]),
            ),
        ]);
        let temp_dir = fixture.0.join("output/tmp");
        let temp_dirs = BTreeMap::from([
            (library.package.clone(), temp_dir.clone()),
            (other_package.clone(), fixture.0.join("other/tmp")),
        ]);
        let command_options = CommandOptions {
            cargo: Path::new("/cargo"),
            workspace_root: &fixture.0,
            selected_packages: std::slice::from_ref(&library.package),
            host_profile: Path::new("/target/release"),
            target_profile: Path::new("/target/release"),
            host_incremental: Path::new("/incremental/host"),
            target_incremental: Path::new("/incremental/target"),
            physical_target: None,
            host_linker: None,
            target_linker: None,
            integration_binaries: Some(&binary_paths),
            integration_temp_dirs: Some(&temp_dirs),
            verbose: false,
        };
        let invocation =
            dependency_rustc_invocation(&focused, &manifests, integration, &command_options)
                .unwrap()
                .unwrap();
        assert!(
            invocation
                .arguments
                .iter()
                .any(|argument| argument == "--test")
        );
        assert!(
            !invocation
                .arguments
                .iter()
                .any(|argument| argument == "--crate-type")
        );
        assert_eq!(invocation.environment["CARGO_BIN_EXE_root"], binary_path);
        assert!(!invocation.environment.contains_key("CARGO_BIN_EXE_foreign"));
        assert_eq!(invocation.environment["CARGO_TARGET_TMPDIR"], temp_dir);
        let missing_package =
            BTreeMap::from([(other_package.clone(), binary_paths[&other_package].clone())]);
        let missing_options = CommandOptions {
            integration_binaries: Some(&missing_package),
            ..command_options
        };
        let error =
            dependency_rustc_invocation(&focused, &manifests, integration, &missing_options)
                .unwrap_err();
        assert!(error.to_string().contains("no program environment"));
    }
}
