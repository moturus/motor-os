#![allow(dead_code)]

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
    Catalog, LockedPreference, Options, PackageKey, PackageSourceKey, Resolution, ResolvedPackage,
    ResolvedSource, TargetSelection, resolve_selected,
};
use crate::source_tree::{Exclusions, Limits as TreeLimits, Tree};
use crate::toolchain::Toolchain;
pub(crate) mod workspace;

use crate::unit::{
    CheckTargetSelection, CompilationPlan, PlanOptions, ProfileContext, SourceRemap, UnitGraph,
    add_selected_binaries, add_selected_harnesses, add_selected_integration_harnesses,
    add_selected_library, dependency_units, plan_dependency_units_with_remaps,
    selected_check_units, selected_library_key,
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
        self.plan(options, None, false, None)
    }

    pub fn selected_targets_plan(
        &self,
        options: &PlanOptions<'_>,
        selected: &Manifest,
        binary_name: Option<&str>,
        include_binaries: bool,
        include_harnesses: bool,
    ) -> Result<CompilationPlan> {
        self.plan(
            options,
            Some((selected, binary_name, include_binaries, include_harnesses)),
            false,
            None,
        )
    }

    pub fn selected_mixed_test_plan(
        &self,
        options: &PlanOptions<'_>,
        selected: &Manifest,
        include_harnesses: bool,
        integration_name: Option<&str>,
    ) -> Result<CompilationPlan> {
        if options.test_profile {
            return Err(Error::failure(
                "mixed test plan requires normal profile options",
            ));
        }
        self.plan(
            options,
            Some((selected, None, true, include_harnesses)),
            true,
            integration_name,
        )
    }

    pub fn selected_check_plan(
        &self,
        options: &PlanOptions<'_>,
        selected: &Manifest,
        selection: &CheckTargetSelection<'_>,
    ) -> Result<CompilationPlan> {
        let mut manifests = self
            .packages
            .iter()
            .map(|(key, package)| (key.clone(), package.manifest.clone()))
            .collect();
        let graph = selected_check_units(
            &self.resolution,
            &manifests,
            selected,
            selection,
            options.panic_abort,
        )?;
        let key = selected_library_key(selected)?;
        if manifests.insert(key.package, selected.clone()).is_some() {
            return Err(Error::failure(
                "selected package duplicates a dependency package",
            ));
        }
        self.finish_plan(options, manifests, graph)
    }

    fn plan(
        &self,
        options: &PlanOptions<'_>,
        selected: Option<(&Manifest, Option<&str>, bool, bool)>,
        mixed_profile: bool,
        integration_name: Option<&str>,
    ) -> Result<CompilationPlan> {
        let mut manifests = self
            .packages
            .iter()
            .map(|(key, package)| (key.clone(), package.manifest.clone()))
            .collect();
        let normal_needed = !mixed_profile
            || selected.is_some_and(|(manifest, _, _, _)| !manifest.binaries.is_empty());
        let base_graph = dependency_units(&self.resolution, &manifests)?;
        let mut test_graph = mixed_profile.then(|| base_graph.clone());
        let mut graph = if normal_needed {
            base_graph
        } else {
            UnitGraph {
                units: BTreeMap::new(),
                order: Vec::new(),
            }
        };
        if let Some((selected, binary_name, include_binaries, include_harnesses)) = selected {
            let key = if normal_needed && selected.library.is_some() {
                add_selected_library(&mut graph, &self.resolution, &manifests, selected)?
            } else {
                selected_library_key(selected)?
            };
            if include_binaries && normal_needed {
                add_selected_binaries(
                    &mut graph,
                    &self.resolution,
                    &manifests,
                    selected,
                    binary_name,
                )?;
            }
            if include_harnesses && !mixed_profile {
                add_selected_harnesses(&mut graph, &self.resolution, &manifests, selected)?;
            }
            if let Some(test_graph) = test_graph.as_mut() {
                if selected.library.is_some() {
                    add_selected_library(test_graph, &self.resolution, &manifests, selected)?;
                }
                if include_harnesses {
                    add_selected_harnesses(test_graph, &self.resolution, &manifests, selected)?;
                }
            }
            if manifests.insert(key.package, selected.clone()).is_some() {
                return Err(Error::failure(
                    "selected package duplicates a dependency package",
                ));
            }
        }
        if let Some(test_graph) = test_graph {
            graph.merge(test_graph.with_profile(ProfileContext::Test, options.panic_abort))?;
            let selected = selected.unwrap().0;
            add_selected_integration_harnesses(
                &mut graph,
                &self.resolution,
                &manifests,
                selected,
                integration_name,
                options.panic_abort,
                true,
            )?;
        } else if options.test_profile {
            graph = graph.with_profile(ProfileContext::Test, options.panic_abort);
        }
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
        None,
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
        None,
    )
}

pub fn prepare_locked_source(
    manifest: &Manifest,
    config: &Config,
    source: LockedSource<'_>,
    options: &Options,
    selection: TargetSelection<'_>,
    staging_parent: &Path,
) -> Result<PreparedGraph> {
    if let Some(resolution) = source.verified_resolution {
        return prepare_verified_resolution(
            manifest,
            config,
            source.registry,
            staging_parent,
            source.direct,
            resolution,
        );
    }
    prepare_locked_with(
        manifest,
        config,
        source.registry,
        options,
        selection,
        staging_parent,
        Some(source.direct),
    )
}

pub struct LockedSource<'a> {
    pub registry: RegistrySource<'a>,
    pub direct: &'a crate::git::DirectCatalog,
    pub verified_resolution: Option<Resolution>,
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
        rust_versions: vec![rust_version],
        package_limit: crate::policy::PackageLimit::new(&config.policy.limits, manifest),
        max_depth: config.policy.limits.max_depth,
    })
}

/// Inspects independent Git package trees concurrently while preserving
/// deterministic package and error order.
pub fn inspect_git_package_evidence(
    packages: &[&ResolvedPackage],
) -> Result<BTreeMap<PackageKey, PackageEvidence>> {
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
                        .map(|package| (package.key.clone(), PackageEvidence::from_git(package)))
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| {
                handle.join().map_err(|_| {
                    Error::failure("Git package evidence worker terminated unexpectedly")
                })
            })
            .collect::<Result<Vec<_>>>()
    })?;
    let mut inspected = BTreeMap::new();
    for (key, evidence) in batches.into_iter().flatten() {
        inspected.insert(key, evidence?);
    }
    Ok(inspected)
}

fn git_package_evidence(
    direct: Option<&crate::git::DirectCatalog>,
    packages: &[&ResolvedPackage],
) -> Result<BTreeMap<PackageKey, PackageEvidence>> {
    let Some(direct) = direct else {
        return inspect_git_package_evidence(packages);
    };
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

fn locked_catalog(
    manifest: &Manifest,
    config: &Config,
    source: RegistrySource<'_>,
    direct: Option<&crate::git::DirectCatalog>,
) -> Result<Catalog> {
    let mut catalog = match source {
        RegistrySource::Lorry(repositories) => {
            let checksums = manifest
                .lock
                .iter()
                .flat_map(|lock| &lock.packages)
                .filter_map(|package| package.checksum.clone())
                .collect::<Vec<_>>();
            repositories.prefetch_registries(&checksums)?;
            Catalog::from_locked_repository(manifest, repositories)?
        }
        RegistrySource::Cargo(registry) => Catalog::from_locked_cargo_registry(manifest, registry)?,
    };
    patch::configure(manifest, &mut catalog)?;
    if let Some(direct) = direct {
        direct.configure(&mut catalog)?;
    } else {
        crate::git::configure_direct(manifest, &config.policy.limits, &mut catalog)?;
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
    pub direct: Option<&'a crate::git::DirectCatalog>,
    pub prepare_context: Option<Context>,
}

pub struct VerifiedAdmission {
    review: Review,
    resolution: Option<Resolution>,
}

/// Returns the registry proc-macro identities recorded in a compact state
/// that still identify packages in the current lockfile. These are resolver
/// hints only: source evidence is inspected again before admission succeeds.
pub fn capability_registry_proc_macros(
    manifest: &Manifest,
    capabilities: &[Capability],
) -> Result<BTreeSet<PackageKey>> {
    Ok(LockedPreference::from_lockfile(manifest.lock.as_ref())?
        .into_iter()
        .filter_map(|package| {
            let checksum = package.checksum?;
            capabilities
                .iter()
                .any(|capability| {
                    capability.proc_macro
                        && capability.package == package.name
                        && capability.version == package.version.to_string()
                        && capability.checksum == hex(&checksum)
                })
                .then_some(PackageKey {
                    name: package.name,
                    version: package.version,
                    source: PackageSourceKey::CratesIo,
                })
        })
        .collect())
}

impl VerifiedAdmission {
    pub fn into_parts(self) -> (Review, Option<Resolution>) {
        (self.review, self.resolution)
    }

    pub fn into_review(self) -> Review {
        self.review
    }
}

/// Reconstructs the canonical review document for the recorded contexts from
/// Cargo.toml, Cargo.lock, and verified repository evidence. Lookup and
/// extraction here are inspection: nothing is admitted, compiled, or cached
/// until the commitment and policy both pass.
pub fn reconstruct_review(
    inputs: &ReviewInputs<'_>,
    contexts: &[Context],
    capabilities: Vec<Capability>,
) -> Result<VerifiedAdmission> {
    let manifest = inputs.manifest;
    let lock = manifest
        .lock
        .as_ref()
        .ok_or_else(|| Error::failure("compact dependency admission requires Cargo.lock"))?;
    let mut review = Review::from_graph(manifest, lock, contexts.to_vec())?;
    let mut catalog = locked_catalog(manifest, inputs.config, inputs.source, inputs.direct)?;
    for key in capability_registry_proc_macros(manifest, &capabilities)? {
        catalog.annotate_proc_macro(&key, true)?;
    }
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
    let mut prepared_resolution = None;
    let mut resolved = Vec::new();
    if let Some((first, remaining)) = contexts.split_first() {
        let (resolution, refined, discovered) =
            resolve_review_context(inputs, first, &infos, catalog, &locked, evidence)?;
        catalog = refined;
        evidence = discovered;
        resolved.push((first, resolution));
        let parallel = thread::scope(|scope| {
            let infos = &infos;
            let locked = &locked;
            let handles = remaining
                .iter()
                .map(|context| {
                    let catalog = catalog.clone();
                    let evidence = evidence.clone();
                    thread::Builder::new()
                        .stack_size(8 * 1024 * 1024)
                        .spawn_scoped(scope, move || {
                            resolve_review_context(
                                inputs, context, infos, catalog, locked, evidence,
                            )
                        })
                        .map_err(|error| {
                            Error::failure(format!(
                                "failed to start review context worker: {error}"
                            ))
                        })
                })
                .collect::<Result<Vec<_>>>()?;
            handles
                .into_iter()
                .map(|handle| {
                    handle.join().map_err(|_| {
                        Error::failure("review context worker terminated unexpectedly")
                    })?
                })
                .collect::<Result<Vec<_>>>()
        })?;
        for (context, (resolution, _, discovered)) in remaining.iter().zip(parallel) {
            for (key, package_evidence) in discovered {
                if let Some(existing) = evidence.insert(key.clone(), package_evidence.clone())
                    && existing != package_evidence
                {
                    return Err(Error::failure(format!(
                        "review contexts disagree about evidence for `{} {}`",
                        key.name, key.version
                    )));
                }
            }
            resolved.push((context, resolution));
        }
    }
    for (context, resolution) in resolved {
        review.add_context_resolution(context, &resolution, &evidence)?;
        if inputs.prepare_context.as_ref() == Some(context) {
            prepared_resolution = Some(resolution);
        }
    }
    review.complete(capabilities)?;
    Ok(VerifiedAdmission {
        review,
        resolution: prepared_resolution,
    })
}

fn resolve_review_context(
    inputs: &ReviewInputs<'_>,
    context: &Context,
    infos: &BTreeMap<&str, crate::toolchain::TargetInfo>,
    mut catalog: Catalog,
    locked: &[LockedPreference],
    mut evidence: BTreeMap<PackageKey, PackageEvidence>,
) -> Result<(Resolution, Catalog, BTreeMap<PackageKey, PackageEvidence>)> {
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
            resolve_selected(inputs.manifest, &catalog, inputs.options, locked, selection)?;
        offline::validate_selected_resolution(inputs.manifest, &resolution)?;
        let pending_git = resolution
            .packages
            .iter()
            .filter(|package| {
                matches!(package.source, ResolvedSource::Git { .. })
                    && !evidence.contains_key(&package.key)
            })
            .collect::<Vec<_>>();
        evidence.extend(git_package_evidence(inputs.direct, &pending_git)?);
        let pending_registry = resolution
            .packages
            .iter()
            .filter_map(|package| match package.source {
                ResolvedSource::CratesIo { checksum } if !evidence.contains_key(&package.key) => {
                    Some((package, checksum))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        evidence.extend(
            registry_package_evidence_set(
                inputs.source,
                inputs.config,
                inputs.staging_parent,
                &pending_registry,
                false,
            )?
            .into_iter()
            .map(|(key, package)| (key, package.evidence)),
        );
        let mut proc_macro_changed = false;
        for package in &resolution.packages {
            if !matches!(
                package.source,
                ResolvedSource::Git { .. } | ResolvedSource::CratesIo { .. }
            ) {
                continue;
            }
            proc_macro_changed |=
                catalog.annotate_proc_macro(&package.key, evidence[&package.key].proc_macro)?;
        }
        if !proc_macro_changed {
            break resolution;
        }
        let refined =
            resolve_selected(inputs.manifest, &catalog, inputs.options, locked, selection)?;
        if refined == resolution {
            break resolution;
        }
    };
    Ok((resolution, catalog, evidence))
}

/// Reconstructs the committed review and verifies the compact commitment.
pub fn verify_compact_admission(
    inputs: &ReviewInputs<'_>,
    compact: &CompactState,
) -> Result<VerifiedAdmission> {
    let verified = reconstruct_review(inputs, &compact.contexts, compact.capabilities.clone())?;
    if verified.review.commitment()? != compact.review_sha256 {
        return Err(Error::failure(
            "Lorry dependency state commitment does not match the reconstructed review document",
        )
        .with_help(
            "run `lorry vendor [--accept-all]` to review and re-admit the current dependency graph",
        ));
    }
    Ok(verified)
}

fn prepare_verified_resolution(
    manifest: &Manifest,
    config: &Config,
    source: RegistrySource<'_>,
    staging_parent: &Path,
    direct: &crate::git::DirectCatalog,
    resolution: Resolution,
) -> Result<PreparedGraph> {
    offline::validate_selected_resolution(manifest, &resolution)?;
    let preflight = policy::preflight(&config.policy, &resolution)?;
    let packages =
        prepare_resolution_packages(&resolution, config, source, staging_parent, direct, false)?;
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
    let mut git_evidence = git_package_evidence(Some(direct), &git)?;
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
                extracted: None,
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
                    "locked crates.io package `{} {}` became unavailable while preparing its source",
                    package.key.name, package.key.version
                ))
                .with_help("run `lorry vendor [--accept-all]` to acquire the missing package")
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
            let inspected_manifest = if describe {
                Manifest::load_source_dependency(&source_root)?
            } else if object.retained_source {
                repositories.load_registry_manifest(&object)?
            } else {
                Manifest::load_path_dependency(&source_root)?
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
                extracted,
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
    direct: Option<&crate::git::DirectCatalog>,
) -> Result<PreparedGraph> {
    let mut catalog = locked_catalog(manifest, config, source, direct)?;
    let locked = LockedPreference::from_lockfile(manifest.lock.as_ref())?;
    let mut packages = BTreeMap::new();
    let (resolution, preflight) = loop {
        let resolution = resolve_selected(manifest, &catalog, options, &locked, selection)?;
        offline::validate_selected_resolution(manifest, &resolution)?;
        let preflight = policy::preflight(&config.policy, &resolution)?;
        let pending_git = resolution
            .packages
            .iter()
            .filter(|package| {
                matches!(package.source, ResolvedSource::Git { .. })
                    && !packages.contains_key(&package.key)
            })
            .collect::<Vec<_>>();
        let mut git_evidence = git_package_evidence(direct, &pending_git)?;
        for package in pending_git {
            let manifest = package.local_manifest.clone().ok_or_else(|| {
                Error::failure(format!(
                    "resolved Git package `{} {}` has no inspected manifest",
                    package.key.name, package.key.version
                ))
            })?;
            let evidence = git_evidence
                .remove(&package.key)
                .expect("every inspected Git package has evidence");
            packages.insert(
                package.key.clone(),
                PreparedPackage {
                    manifest,
                    evidence,
                    extracted: None,
                    cargo_registry: false,
                },
            );
        }
        let pending_registry = resolution
            .packages
            .iter()
            .filter_map(|package| match package.source {
                ResolvedSource::CratesIo { checksum } if !packages.contains_key(&package.key) => {
                    Some((package, checksum))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        packages.extend(registry_package_evidence_set(
            source,
            config,
            staging_parent,
            &pending_registry,
            false,
        )?);
        for package in &resolution.packages {
            if !packages.contains_key(&package.key) {
                let prepared = match &package.source {
                    ResolvedSource::CratesIo { .. } => {
                        unreachable!("registry evidence was prepared above")
                    }
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
                    ResolvedSource::Git { .. } => unreachable!("Git evidence was prepared above"),
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
    use crate::compile::{CommandOptions, dependency_rustc_invocation};
    use crate::config::{CargoCompat, IncompatibleRustVersions, Repositories};
    use crate::resolver::PackageSourceKey;
    use crate::source_tree::DEFAULT_LIMITS;
    use crate::toolchain::{CfgSet, Toolchain};
    use crate::unit::{CheckTargetSelection, ProfileContext, UnitEdgeKind, UnitKind, UnitMode};
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
            max_depth: 16,
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
        }
    }

    fn git_package(root: &Path, name: &str) -> ResolvedPackage {
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            format!(
                "[package]\nname = \"{name}\"\nversion = \"1.0.0\"\nedition = \"2021\"\nlicense = \"MIT\"\nbuild = false\n"
            ),
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn demo() {}\n").unwrap();
        let manifest = Manifest::load_path_dependency(root).unwrap();
        let tree = Tree::scan(root, DEFAULT_LIMITS, Exclusions::None).unwrap();
        let cargo_source =
            format!("git+https://example.com/{name}.git#0123456789abcdef0123456789abcdef01234567");
        ResolvedPackage {
            key: PackageKey {
                name: name.to_owned(),
                version: Version::parse("1.0.0").unwrap(),
                source: PackageSourceKey::Git(cargo_source.clone()),
            },
            source: ResolvedSource::Git {
                cargo_source,
                git_url: format!("https://example.com/{name}.git"),
                requested_revision: "HEAD".to_owned(),
                resolved_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                git_tree: "0".repeat(40),
                repository_tree_sha256: tree.sha256,
                package_path: String::new(),
                logical_root: root.to_owned(),
                physical_root: root.to_owned(),
                source_tree_sha256: tree.sha256,
                patched_crates_io: false,
            },
            local_manifest: Some(manifest),
            feature_sets: BTreeMap::new(),
            compile_kinds: [crate::resolver::CompileKind::Target].into(),
            target_features: BTreeSet::new(),
            host_features: BTreeSet::new(),
            edges: Vec::new(),
            lock_edges: Vec::new(),
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
    fn inspects_independent_git_packages_together() {
        let fixture = Fixture::new();
        let first = git_package(&fixture.0.join("first"), "first");
        let second = git_package(&fixture.0.join("second"), "second");

        let evidence = inspect_git_package_evidence(&[&first, &second]).unwrap();
        let ResolvedSource::Git {
            source_tree_sha256, ..
        } = second.source
        else {
            unreachable!()
        };

        assert_eq!(evidence.len(), 2);
        assert_eq!(evidence[&first.key].license, "MIT");
        assert_eq!(evidence[&second.key].source_tree_sha256, source_tree_sha256);
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
                    _ => unreachable!(),
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
        let options = PlanOptions {
            workspace_root: &manifest.root,
            release: true,
            test_profile: false,
            panic_abort: manifest.release.panic_abort,
            release_profile: &manifest.release,
            rustc: &toolchain(),
            logical_target: None,
            rustflags: &[],
        };
        let plan = graph.dependency_plan(&options).unwrap();
        assert!(plan.units.values().all(|unit| unit.source_remap.is_none()));
        let mixed = graph
            .selected_mixed_test_plan(&options, &manifest, true, None)
            .unwrap();
        let library = selected_library_key(&manifest).unwrap();
        let test_library = library
            .clone()
            .with_profile(ProfileContext::Test, options.panic_abort);
        assert!(mixed.units.contains_key(&library));
        assert!(mixed.units.contains_key(&test_library));
        assert_eq!(
            mixed
                .units
                .keys()
                .filter(|key| key.package == library.package && key.kind == UnitKind::Binary)
                .count(),
            1
        );
        assert!(mixed.units.keys().any(|key| {
            key.package == library.package
                && key.kind == UnitKind::BinaryHarness
                && key.profile == ProfileContext::Test
        }));
        assert_ne!(
            mixed.units[&library].identity,
            mixed.units[&test_library].identity
        );
        let integration = mixed
            .units
            .keys()
            .find(|key| key.kind == UnitKind::IntegrationHarness)
            .unwrap();
        assert_eq!(integration.profile, ProfileContext::Test);
        let edges = &mixed.units[integration].unit.dependencies;
        assert!(edges.iter().any(|edge| {
            edge.kind == UnitEdgeKind::RustDependency && edge.unit == test_library
        }));
        assert!(edges.iter().any(|edge| {
            edge.kind == UnitEdgeKind::ArtifactDependency
                && edge.unit.kind == UnitKind::Binary
                && edge.unit.profile == ProfileContext::Normal
        }));

        let focused = graph
            .selected_mixed_test_plan(&options, &manifest, false, Some("integration"))
            .unwrap();
        let integration = focused
            .units
            .keys()
            .find(|key| key.kind == UnitKind::IntegrationHarness)
            .unwrap();
        let mut manifests = graph
            .packages
            .iter()
            .map(|(key, package)| (key.clone(), package.manifest.clone()))
            .collect::<BTreeMap<_, _>>();
        manifests.insert(library.package.clone(), manifest.clone());
        let binary_path = fixture.0.join("output/root");
        let binary_paths = BTreeMap::from([("root".to_owned(), binary_path.clone())]);
        let temp_dir = fixture.0.join("output/tmp");
        let command_options = CommandOptions {
            cargo: Path::new("/cargo"),
            workspace_root: &fixture.0,
            selected_package: Some(&library.package),
            host_profile: Path::new("/target/release"),
            target_profile: Path::new("/target/release"),
            host_incremental: Path::new("/incremental/host"),
            target_incremental: Path::new("/incremental/target"),
            physical_target: None,
            host_linker: None,
            target_linker: None,
            integration_binaries: Some(&binary_paths),
            integration_temp_dir: Some(&temp_dir),
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
        assert_eq!(invocation.environment["CARGO_BIN_EXE_root"], binary_path);
        assert_eq!(invocation.environment["CARGO_TARGET_TMPDIR"], temp_dir);
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let output = Command::new(cargo)
            .args([
                "-Z",
                "unstable-options",
                "test",
                "--release",
                "--test",
                "integration",
                "--unit-graph",
                "--offline",
            ])
            .arg("--manifest-path")
            .arg(fixture.0.join("Cargo.toml"))
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
                let package_id = unit["pkg_id"].as_str().unwrap();
                let package =
                    if package_id.starts_with(&format!("path+file://{}#", fixture.0.display())) {
                        manifest.name.as_str()
                    } else {
                        package_id
                            .rsplit('/')
                            .next()
                            .unwrap()
                            .split('#')
                            .next()
                            .unwrap()
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
            let unit = &focused.units[key];
            let kind = match key.kind {
                UnitKind::Library => "lib",
                UnitKind::Binary => "bin",
                UnitKind::IntegrationHarness => "test",
                _ => panic!("unexpected unit in integration oracle: {:?}", key.kind),
            };
            let name = key.target.as_deref().unwrap_or_else(|| {
                if key.package == library.package {
                    manifest.library.as_ref().unwrap().name.as_str()
                } else {
                    graph.packages[&key.package]
                        .manifest
                        .library
                        .as_ref()
                        .unwrap()
                        .name
                        .as_str()
                }
            });
            (
                key.package.name.clone(),
                kind.to_owned(),
                name.to_owned(),
                match unit.settings.profile.panic {
                    crate::identity::CargoPanicStrategy::Abort => "abort",
                    crate::identity::CargoPanicStrategy::Unwind => "unwind",
                    _ => unreachable!(),
                }
                .to_owned(),
            )
        };
        let lorry_nodes = focused
            .units
            .keys()
            .map(lorry_node)
            .collect::<BTreeSet<_>>();
        assert_eq!(lorry_nodes, cargo_nodes.iter().cloned().collect());
        let mut cargo_edges = BTreeSet::new();
        for (parent, unit) in units.iter().enumerate() {
            for edge in unit["dependencies"].as_array().unwrap() {
                cargo_edges.insert((
                    cargo_nodes[parent].clone(),
                    cargo_nodes[edge["index"].as_u64().unwrap() as usize].clone(),
                    edge["extern_crate_name"].as_str().unwrap().to_owned(),
                ));
            }
        }
        let lorry_edges = focused
            .units
            .values()
            .flat_map(|unit| {
                unit.unit.dependencies.iter().map(|edge| {
                    (
                        lorry_node(&unit.unit.key),
                        lorry_node(&edge.unit),
                        edge.alias.clone().unwrap(),
                    )
                })
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(lorry_edges, cargo_edges);
        let cargo_roots = cargo["roots"]
            .as_array()
            .unwrap()
            .iter()
            .map(|index| cargo_nodes[index.as_u64().unwrap() as usize].clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            cargo_roots,
            focused
                .units
                .keys()
                .filter(|key| key.kind == UnitKind::IntegrationHarness)
                .map(lorry_node)
                .collect()
        );

        let check_plan = graph
            .selected_check_plan(
                &options,
                &manifest,
                &CheckTargetSelection {
                    normal: false,
                    binaries: false,
                    binary_name: None,
                    harnesses: false,
                    integrations: true,
                    integration_name: Some("integration"),
                },
            )
            .unwrap();
        assert!(
            check_plan.units.keys().all(|key| {
                key.package != library.package || key.profile == ProfileContext::Test
            })
        );
        assert!(check_plan.units.keys().any(|key| {
            key.kind == UnitKind::IntegrationHarness && key.mode == UnitMode::CheckTest
        }));
        assert!(check_plan.units.keys().any(|key| {
            key.kind == UnitKind::Library
                && key.package == library.package
                && key.mode == UnitMode::Check
        }));
        assert!(
            !check_plan
                .units
                .keys()
                .any(|key| key.kind == UnitKind::Binary)
        );
        assert!(check_plan.units.values().any(|unit| {
            unit.unit.key.kind == UnitKind::IntegrationHarness
                && unit.settings.mode == crate::identity::CargoCompileMode::Check { test: true }
        }));
        let check_key = check_plan
            .units
            .keys()
            .find(|key| key.kind == UnitKind::IntegrationHarness)
            .unwrap();
        let check_invocation =
            dependency_rustc_invocation(&check_plan, &manifests, check_key, &command_options)
                .unwrap()
                .unwrap();
        assert!(matches!(
            check_invocation.output,
            crate::compile::RustcOutput::Metadata { .. }
        ));
        assert!(
            check_invocation
                .arguments
                .iter()
                .any(|argument| argument == "--emit=dep-info,metadata")
        );
        assert_check_graph_matches_cargo(&fixture.0, &check_plan, &["--test", "integration"]);
        let all_check = graph
            .selected_check_plan(
                &options,
                &manifest,
                &CheckTargetSelection {
                    normal: true,
                    binaries: true,
                    binary_name: None,
                    harnesses: true,
                    integrations: true,
                    integration_name: None,
                },
            )
            .unwrap();
        assert_check_graph_matches_cargo(&fixture.0, &all_check, &["--all-targets"]);

        fs::remove_file(fixture.0.join("src/main.rs")).unwrap();
        let library_only = Manifest::load(&fixture.0).unwrap();
        let library_only_plan = graph
            .selected_mixed_test_plan(&options, &library_only, false, Some("integration"))
            .unwrap();
        assert!(
            library_only_plan.units.keys().all(|key| {
                key.package != library.package || key.profile == ProfileContext::Test
            })
        );
        assert!(
            library_only_plan
                .units
                .keys()
                .any(|key| { key.kind == UnitKind::IntegrationHarness })
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
                panic_abort: manifest.release.panic_abort,
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
                ResolvedSource::Git { .. } => panic!("fixture has no Git dependencies"),
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
