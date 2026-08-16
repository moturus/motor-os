#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

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
    Catalog, LockedPreference, Options, PackageKey, Resolution, ResolvedPackage, ResolvedSource,
    TargetSelection, resolve_selected,
};
use crate::source_tree::{Exclusions, Limits as TreeLimits, Tree};
use crate::toolchain::Toolchain;
use crate::unit::{
    CompilationPlan, PlanOptions, SourceRemap, UnitGraph, dependency_units,
    plan_dependency_units_with_remaps,
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
    extracted: Option<ExtractedArchive>,
    cargo_registry: bool,
}

impl PreparedGraph {
    pub fn dependency_units(&self) -> Result<UnitGraph> {
        let manifests = self
            .packages
            .iter()
            .map(|(key, package)| (key.clone(), package.manifest.clone()))
            .collect();
        dependency_units(&self.resolution, &manifests)
    }

    pub fn dependency_plan(&self, options: &PlanOptions<'_>) -> Result<CompilationPlan> {
        let manifests = self
            .packages
            .iter()
            .map(|(key, package)| (key.clone(), package.manifest.clone()))
            .collect();
        let graph = dependency_units(&self.resolution, &manifests)?;
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
                    required_patch,
                    ..
                } => {
                    if required_patch.is_some() {
                        complete_source_trees.insert(package.key.clone());
                    }
                    if self.cargo_registry_mode {
                        None
                    } else if logical_root != physical_root {
                        let id = required_patch.as_deref().ok_or_else(|| {
                            Error::failure(format!(
                                "path package `{} {}` has distinct logical and physical roots without a required-patch identity",
                                package.key.name, package.key.version
                            ))
                        })?;
                        Some(
                            SourceRemap::required_patch(
                                options.workspace_root,
                                logical_root,
                                physical_root,
                            )
                            .map_err(|error| {
                                Error::failure(format!("required patch `{id}`: {error}"))
                            })?,
                        )
                    } else {
                        Some(SourceRemap::path(
                            options.workspace_root,
                            source_tree_sha256,
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

    pub fn is_ephemeral(&self) -> bool {
        self.extracted.is_some()
    }
}

pub fn prepare_locked(
    manifest: &Manifest,
    config: &Config,
    repositories: &RepositorySet,
    options: &Options,
    selection: TargetSelection<'_>,
    staging_parent: &Path,
) -> Result<PreparedGraph> {
    prepare_locked_with(
        manifest,
        config,
        RegistrySource::Lorry(repositories),
        options,
        selection,
        staging_parent,
    )
}

pub fn prepare_locked_cargo_registry(
    manifest: &Manifest,
    config: &Config,
    registry: &CargoRegistry,
    options: &Options,
    selection: TargetSelection<'_>,
    staging_parent: &Path,
) -> Result<PreparedGraph> {
    prepare_locked_with(
        manifest,
        config,
        RegistrySource::Cargo(registry),
        options,
        selection,
        staging_parent,
    )
}

pub fn prepare_locked_source(
    manifest: &Manifest,
    config: &Config,
    source: RegistrySource<'_>,
    options: &Options,
    selection: TargetSelection<'_>,
    staging_parent: &Path,
) -> Result<PreparedGraph> {
    prepare_locked_with(manifest, config, source, options, selection, staging_parent)
}

#[derive(Clone, Copy)]
pub enum RegistrySource<'a> {
    Lorry(&'a RepositorySet),
    Cargo(&'a CargoRegistry),
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
        rust_version,
        max_packages: config.policy.limits.max_packages,
        max_depth: config.policy.limits.max_depth,
    })
}

fn locked_catalog(
    manifest: &Manifest,
    config: &Config,
    source: RegistrySource<'_>,
) -> Result<Catalog> {
    let mut catalog = match source {
        RegistrySource::Lorry(repositories) => {
            Catalog::from_locked_repository(manifest, repositories)?
        }
        RegistrySource::Cargo(registry) => Catalog::from_locked_cargo_registry(manifest, registry)?,
    };
    match source {
        RegistrySource::Lorry(repositories) => {
            patch::configure(manifest, config, repositories, &mut catalog)?
        }
        RegistrySource::Cargo(_) => {
            patch::configure_cargo_registry(manifest, config, &mut catalog)?
        }
    }
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
}

/// Reconstructs the canonical review document for the recorded contexts from
/// Cargo.toml, Cargo.lock, and verified repository evidence. Lookup and
/// extraction here are inspection: nothing is admitted, compiled, or cached
/// until the commitment and policy both pass.
pub fn reconstruct_review(
    inputs: &ReviewInputs<'_>,
    contexts: &[Context],
    capabilities: Vec<Capability>,
) -> Result<Review> {
    let manifest = inputs.manifest;
    let lock = manifest
        .lock
        .as_ref()
        .ok_or_else(|| Error::failure("compact dependency admission requires Cargo.lock"))?;
    let mut review = Review::from_graph(manifest, lock, contexts.to_vec())?;
    let mut catalog = locked_catalog(manifest, inputs.config, inputs.source)?;
    let locked = LockedPreference::from_lockfile(manifest.lock.as_ref())?;
    let mut infos = BTreeMap::new();
    for context in contexts {
        for triple in [&context.host, &context.target] {
            if !infos.contains_key(triple.as_str()) {
                infos.insert(triple.as_str(), inputs.toolchain.target_info(Some(triple))?);
            }
        }
    }
    let mut evidence = BTreeMap::new();
    for context in contexts {
        let host = &infos[context.host.as_str()];
        let target = &infos[context.target.as_str()];
        let selection = TargetSelection {
            target_triple: &target.triple,
            target_cfg: &target.cfg,
            host_triple: &host.triple,
            host_cfg: &host.cfg,
        };
        let resolution = loop {
            let resolution =
                resolve_selected(manifest, &catalog, inputs.options, &locked, selection)?;
            offline::validate_selected_resolution(manifest, &resolution)?;
            for package in &resolution.packages {
                let ResolvedSource::CratesIo { checksum } = &package.source else {
                    continue;
                };
                if !evidence.contains_key(&package.key) {
                    let prepared = registry_package_evidence(
                        inputs.source,
                        inputs.config,
                        inputs.staging_parent,
                        package,
                        checksum,
                    )?;
                    evidence.insert(package.key.clone(), prepared.evidence.clone());
                }
                catalog.annotate_proc_macro(&package.key, evidence[&package.key].proc_macro)?;
            }
            let refined = resolve_selected(manifest, &catalog, inputs.options, &locked, selection)?;
            if refined == resolution {
                break resolution;
            }
        };
        review.add_context_resolution(context, &resolution, &evidence)?;
    }
    review.complete(capabilities)?;
    Ok(review)
}

/// Reconstructs the committed review and verifies the compact commitment.
pub fn verify_compact_admission(
    inputs: &ReviewInputs<'_>,
    compact: &CompactState,
) -> Result<Review> {
    let review = reconstruct_review(inputs, &compact.contexts, compact.capabilities.clone())?;
    if review.commitment()? != compact.review_sha256 {
        return Err(Error::failure(
            "Lorry dependency state commitment does not match the reconstructed review document",
        )
        .with_help("run `lorry vendor` to review and re-admit the current dependency graph"));
    }
    Ok(review)
}

fn registry_package_evidence(
    source: RegistrySource<'_>,
    config: &Config,
    staging_parent: &Path,
    package: &ResolvedPackage,
    checksum: &[u8; 32],
) -> Result<PreparedPackage> {
    match source {
        RegistrySource::Lorry(repositories) => {
            let checksum = hex(checksum);
            let object = repositories.lookup_registry(&checksum)?.ok_or_else(|| {
                Error::failure(format!(
                    "locked crates.io package `{} {}` became unavailable while preparing its source",
                    package.key.name, package.key.version
                ))
                .with_help("run `lorry vendor` to acquire the missing package")
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
            let inspected_manifest = Manifest::load_path_dependency(&source_root)?;
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
                extracted,
                cargo_registry: false,
            })
        }
        RegistrySource::Cargo(registry) => {
            let locked_checksum = hex(checksum);
            let cached =
                registry.load(&package.key.name, &package.key.version, &locked_checksum)?;
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
                extracted: None,
                cargo_registry: true,
            })
        }
    }
}

fn prepare_locked_with(
    manifest: &Manifest,
    config: &Config,
    source: RegistrySource<'_>,
    options: &Options,
    selection: TargetSelection<'_>,
    staging_parent: &Path,
) -> Result<PreparedGraph> {
    let mut catalog = locked_catalog(manifest, config, source)?;
    let locked = LockedPreference::from_lockfile(manifest.lock.as_ref())?;
    let mut packages = BTreeMap::new();
    let (resolution, preflight) = loop {
        let resolution = resolve_selected(manifest, &catalog, options, &locked, selection)?;
        offline::validate_selected_resolution(manifest, &resolution)?;
        let preflight = policy::preflight(&config.policy, &resolution)?;
        for package in &resolution.packages {
            if !packages.contains_key(&package.key) {
                let prepared = match &package.source {
                    ResolvedSource::CratesIo { checksum } => registry_package_evidence(
                        source,
                        config,
                        staging_parent,
                        package,
                        checksum,
                    )?,
                    ResolvedSource::Path { .. } => {
                        let inspected_manifest =
                            package.local_manifest.clone().ok_or_else(|| {
                                Error::failure(format!(
                                    "resolved path package `{} {}` has no inspected manifest",
                                    package.key.name, package.key.version
                                ))
                            })?;
                        let package_evidence = PackageEvidence::from_path(package)?;
                        PreparedPackage {
                            manifest: inspected_manifest,
                            evidence: package_evidence,
                            extracted: None,
                            cargo_registry: false,
                        }
                    }
                };
                packages.insert(package.key.clone(), prepared);
            }
            catalog
                .annotate_proc_macro(&package.key, packages[&package.key].evidence.proc_macro)?;
        }
        let refined = resolve_selected(manifest, &catalog, options, &locked, selection)?;
        if refined == resolution {
            break (resolution, preflight);
        }
    };
    let selected = resolution
        .packages
        .iter()
        .map(|package| package.key.clone())
        .collect::<std::collections::BTreeSet<_>>();
    packages.retain(|key, _| selected.contains(key));
    let evidence = packages
        .iter()
        .map(|(key, package)| (key.clone(), package.evidence.clone()))
        .collect();
    let admission = policy::inspect(&preflight, &resolution, &evidence)?;
    Ok(PreparedGraph {
        resolution,
        admission,
        packages,
        cargo_registry_mode: matches!(source, RegistrySource::Cargo(_)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CargoCompat, IncompatibleRustVersions, Repositories};
    use crate::resolver::PackageSourceKey;
    use crate::source_tree::DEFAULT_LIMITS;
    use crate::toolchain::{CfgSet, Toolchain};
    use semver::Version;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
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

    fn options(manifest: &Manifest) -> Options {
        Options {
            resolver: manifest.resolver,
            incompatible_rust_versions: Some(IncompatibleRustVersions::Allow),
            rust_version: Version::parse("1.98.0").unwrap(),
            max_packages: 64,
            max_depth: 16,
        }
    }

    fn toolchain() -> Toolchain {
        Toolchain {
            rustc: "/rustc".into(),
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
            compatibility: CargoCompat::V1_98,
        }
    }

    fn copy_tree(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let file_type = entry.file_type().unwrap();
            let output = destination.join(entry.file_name());
            if file_type.is_dir() {
                copy_tree(&entry.path(), &output);
            } else {
                assert!(file_type.is_file());
                fs::copy(entry.path(), output).unwrap();
            }
        }
    }

    #[test]
    fn prepares_a_path_only_graph_without_a_repository_or_staging() {
        let fixture = Fixture::new();
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
             [dependencies]\nlocal = { path = \"local\" }\n",
        )
        .unwrap();
        fs::write(
            fixture.0.join("Cargo.lock"),
            "version = 4\n\
             [[package]]\nname = \"local\"\nversion = \"1.0.0\"\n\
             [[package]]\nname = \"root\"\nversion = \"0.1.0\"\ndependencies = [\"local\"]\n",
        )
        .unwrap();
        let manifest = Manifest::load(&fixture.0).unwrap();
        let config = Config::default();
        let repositories =
            RepositorySet::open(&Repositories::default(), DEFAULT_LIMITS, 16 * 1024 * 1024)
                .unwrap();
        let cfg = CfgSet::parse("unix\n").unwrap();
        let staging = fixture.0.join("unused-staging");
        let graph = prepare_locked(
            &manifest,
            &config,
            &repositories,
            &options(&manifest),
            TargetSelection {
                target_triple: "x86_64-unknown-linux-musl",
                target_cfg: &cfg,
                host_triple: "x86_64-unknown-linux-gnu",
                host_cfg: &cfg,
            },
            &staging,
        )
        .unwrap();

        assert!(!staging.exists());
        assert_eq!(graph.packages.len(), 1);
        let (key, package) = graph.packages.first_key_value().unwrap();
        assert!(matches!(key.source, PackageSourceKey::Path(_)));
        assert_eq!(package.source_root(), fixture.0.join("local"));
        assert!(!package.is_ephemeral());
        assert!(graph.admission.packages.contains_key(key));
        let plan = graph
            .dependency_plan(&PlanOptions {
                workspace_root: &manifest.root,
                release: true,
                test_profile: false,
                release_profile: &manifest.release,
                rustc: &toolchain(),
                logical_target: None,
                rustflags: &[],
            })
            .unwrap();
        let remap = plan
            .units
            .values()
            .next()
            .unwrap()
            .source_remap
            .as_ref()
            .unwrap();
        let ResolvedSource::Path {
            source_tree_sha256, ..
        } = &graph.resolution.packages[0].source
        else {
            unreachable!()
        };
        assert_eq!(
            remap.presented_root,
            PathBuf::from(format!(
                ".lorry/path/sha256/{}/source",
                hex(source_tree_sha256)
            ))
        );
    }

    #[test]
    fn prepares_and_admits_the_selected_seeded_lorry_graph_when_requested() {
        let Some(repository) = std::env::var_os("LORRY_TEST_SEEDED_REPOSITORY") else {
            return;
        };
        let repository = PathBuf::from(repository);
        let generated = repository.parent().unwrap().join("lorry.toml");
        let fixture = Fixture::new();
        let home_config = fixture.0.join("home/.config/lorry");
        fs::create_dir_all(&home_config).unwrap();
        fs::copy(generated, home_config.join("lorry.toml")).unwrap();
        let config = Config::load_for_test(
            Path::new("."),
            &BTreeMap::from([(
                "HOME".to_owned(),
                fixture.0.join("home").display().to_string(),
            )]),
        )
        .unwrap();
        let repositories = RepositorySet::open(
            &config.repositories,
            DEFAULT_LIMITS,
            config.policy.limits.max_package_bytes,
        )
        .unwrap();
        let manifest = Manifest::load(Path::new(".")).unwrap();
        let linux = CfgSet::parse(
            "debug_assertions\npanic=\"unwind\"\ntarget_arch=\"x86_64\"\n\
             target_endian=\"little\"\ntarget_env=\"gnu\"\ntarget_family=\"unix\"\n\
             target_os=\"linux\"\ntarget_pointer_width=\"64\"\ntarget_vendor=\"unknown\"\nunix\n",
        )
        .unwrap();
        let graph = prepare_locked(
            &manifest,
            &config,
            &repositories,
            &options(&manifest),
            TargetSelection {
                target_triple: "x86_64-unknown-linux-gnu",
                target_cfg: &linux,
                host_triple: "x86_64-unknown-linux-gnu",
                host_cfg: &linux,
            },
            &fixture.0.join("staging"),
        )
        .unwrap();

        assert_eq!(graph.packages.len(), graph.resolution.packages.len());
        assert_eq!(graph.packages.len(), graph.admission.packages.len());
        assert!(
            graph
                .packages
                .values()
                .all(|package| package.source_root().is_dir() && !package.is_ephemeral())
        );
        let units = graph.dependency_units().unwrap();
        assert_eq!(units.units.len(), units.order.len());
        assert!(units.units.keys().any(|unit| {
            unit.package.name == "crc32fast" && unit.kind == crate::unit::UnitKind::BuildScriptRun
        }));
        assert!(units.units.keys().any(|unit| {
            unit.package.name == "generic-array"
                && unit.kind == crate::unit::UnitKind::BuildScriptRun
        }));
        let plan = graph
            .dependency_plan(&PlanOptions {
                workspace_root: &manifest.root,
                release: true,
                test_profile: false,
                release_profile: &manifest.release,
                rustc: &toolchain(),
                logical_target: None,
                rustflags: &[],
            })
            .unwrap();
        assert_eq!(plan.units.len(), units.units.len());
        assert_eq!(plan.order, units.order);
        let mut registry_remaps = 0;
        let mut patch_remaps = 0;
        for unit in plan.units.values() {
            let package = graph
                .resolution
                .packages
                .iter()
                .find(|package| package.key == unit.unit.key.package)
                .unwrap();
            match &package.source {
                ResolvedSource::CratesIo { checksum } => {
                    let remap = unit.source_remap.as_ref().unwrap();
                    assert_eq!(
                        remap.presented_root,
                        PathBuf::from(format!(".lorry/registry/sha256/{}/source", hex(checksum)))
                    );
                    registry_remaps += 1;
                }
                ResolvedSource::Path {
                    logical_root,
                    physical_root,
                    ..
                } if logical_root != physical_root => {
                    assert_eq!(
                        unit.source_remap.as_ref().unwrap().logical_root,
                        *logical_root
                    );
                    patch_remaps += 1;
                }
                ResolvedSource::Path {
                    source_tree_sha256, ..
                } => {
                    assert_eq!(
                        unit.source_remap.as_ref().unwrap().presented_root,
                        PathBuf::from(format!(
                            ".lorry/path/sha256/{}/source",
                            hex(source_tree_sha256)
                        ))
                    );
                }
            }
        }
        assert!(registry_remaps > 0);
        assert!(patch_remaps > 0);
    }

    #[test]
    fn privately_extracts_an_archive_only_selected_object_when_requested() {
        let Some(repository) = std::env::var_os("LORRY_TEST_SEEDED_REPOSITORY") else {
            return;
        };
        const CHECKSUM: &str = "320119579fcad9c21884f5c4861d16174d0e06250625266f50fe6898340abefa";
        let repository = PathBuf::from(repository);
        let generated = repository.parent().unwrap().join("lorry.toml");
        let fixture = Fixture::new();
        let copied_repository = fixture.0.join("archive-repository");
        fs::create_dir_all(&copied_repository).unwrap();
        fs::copy(
            repository.join("repository.toml"),
            copied_repository.join("repository.toml"),
        )
        .unwrap();
        let source_object = repository
            .join("objects/crates-io/sha256")
            .join(&CHECKSUM[..2])
            .join(CHECKSUM);
        let copied_object = copied_repository
            .join("objects/crates-io/sha256")
            .join(&CHECKSUM[..2])
            .join(CHECKSUM);
        copy_tree(&source_object, &copied_object);
        fs::remove_dir_all(copied_object.join("source")).unwrap();
        fs::remove_file(copied_object.join("source-manifest.json")).unwrap();
        let metadata = fs::read_to_string(copied_object.join("package.toml"))
            .unwrap()
            .replace("retained-source = true", "retained-source = false");
        fs::write(copied_object.join("package.toml"), metadata).unwrap();

        fs::write(
            fixture.0.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\nadler2 = \"=2.0.1\"\n",
        )
        .unwrap();
        fs::write(
            fixture.0.join("Cargo.lock"),
            format!(
                "version = 4\n\
                 [[package]]\nname = \"adler2\"\nversion = \"2.0.1\"\n\
                 source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
                 checksum = \"{CHECKSUM}\"\n\
                 [[package]]\nname = \"root\"\nversion = \"0.1.0\"\n\
                 dependencies = [\"adler2\"]\n"
            ),
        )
        .unwrap();
        let home_config = fixture.0.join("home/.config/lorry");
        fs::create_dir_all(&home_config).unwrap();
        fs::copy(generated, home_config.join("lorry.toml")).unwrap();
        let mut config = Config::load_for_test(
            &fixture.0,
            &BTreeMap::from([(
                "HOME".to_owned(),
                fixture.0.join("home").display().to_string(),
            )]),
        )
        .unwrap();
        config.repositories.system = Some(copied_repository);
        config.repositories.user = None;
        let repositories = RepositorySet::open(
            &config.repositories,
            DEFAULT_LIMITS,
            config.policy.limits.max_package_bytes,
        )
        .unwrap();
        let manifest = Manifest::load(&fixture.0).unwrap();
        let linux = CfgSet::parse("unix\ntarget_os=\"linux\"\n").unwrap();
        let staging = fixture.0.join("staging");
        let graph = prepare_locked(
            &manifest,
            &config,
            &repositories,
            &options(&manifest),
            TargetSelection {
                target_triple: "x86_64-unknown-linux-gnu",
                target_cfg: &linux,
                host_triple: "x86_64-unknown-linux-gnu",
                host_cfg: &linux,
            },
            &staging,
        )
        .unwrap();

        let package = graph.packages.values().next().unwrap();
        assert!(package.is_ephemeral());
        assert!(package.source_root().join("src/lib.rs").is_file());
        let extracted = package.source_root().to_owned();
        drop(graph);
        assert!(!extracted.exists());
    }
}
