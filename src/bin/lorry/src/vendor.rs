use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::Path;

use semver::Version;

use crate::admission_state::{self, CompactState, Context, Review};
use crate::archive::{ExtractedArchive, Limits as ArchiveLimits, extract_crate};
use crate::atomic::{AtomicDirectory, AtomicFile};
use crate::change_review;
use crate::cli::{Cli, VendorMode, VendorOptions, Verbosity};
use crate::config::{Config, PolicyAction, PolicyLimits, PolicyRule};
use crate::curl::{Client, archive_url, sparse_url};
use crate::dependency;
use crate::diagnostic::{Error, Result};
use crate::engine;
use crate::hash::hex;
use crate::lockfile;
use crate::manifest::Manifest;
use crate::patch;
use crate::policy::{self, PackageEvidence};
use crate::progress::Progress;
use crate::redirect::TrustPolicy;
use crate::repository::{RepositorySet, RepositoryTransaction, RepositoryWriter};
use crate::resolver::{
    self, Catalog, LockedPreference, PackageKey, PackageSourceKey, Resolution, ResolvedPackage,
    ResolvedSource, TargetSelection,
};
use crate::source_tree::Limits as TreeLimits;
use crate::sparse;
use crate::toolchain::{TargetInfo, Toolchain};
use crate::upgrade;
use crate::vendor_lock::ProjectVendorLock;

pub fn execute(cli: &Cli, options: &VendorOptions) -> Result<i32> {
    if cli.use_cargo_registry {
        return Err(Error::usage(
            "`--use-cargo-registry` cannot be combined with `vendor`",
            "remove `--use-cargo-registry`; vendoring uses only Lorry repositories",
        ));
    }
    let current = env::current_dir()
        .map_err(|error| Error::failure(format!("failed to read current directory: {error}")))?;
    match &options.mode {
        VendorMode::Sync => execute_reconcile(
            cli,
            &current,
            cli.package.as_deref(),
            options.accept_all,
            None,
        ),
        VendorMode::Upgrade(upgrade) => {
            let (package, version) = (&upgrade.package, &upgrade.version);
            execute_reconcile(
                cli,
                &current,
                cli.package.as_deref(),
                options.accept_all,
                Some((package, version)),
            )
        }
    }
}

fn execute_reconcile(
    cli: &Cli,
    current: &Path,
    selected_package: Option<&str>,
    accept_all: bool,
    requested: Option<(&str, &str)>,
) -> Result<i32> {
    if requested.is_some() && accept_all {
        return Err(Error::usage(
            "`--accept-all` cannot approve a dependency upgrade",
            "rerun interactively without `--accept-all` to review package and capability changes",
        ));
    }
    let initial_manifest = Manifest::load_for_vendor_selected(current, selected_package)?;
    let config = Config::load(&initial_manifest.root)?;
    let progress = Progress::new(cli.verbosity != Verbosity::Quiet);
    let lock = ProjectVendorLock::acquire(&initial_manifest.workspace_root)?;
    if cli.verbosity == Verbosity::Verbose {
        eprintln!("Locked {}", lock.path().display());
    }
    crate::git::materialize_manifest_patches(
        &initial_manifest.workspace_root,
        &config.network,
        &config.policy.limits,
        accept_all,
        cli.verbosity == Verbosity::Verbose,
        progress,
    )?;
    let initial_manifest = Manifest::load_for_vendor_selected(current, selected_package)?;
    let direct = crate::git::materialize_locked_dependencies(
        &initial_manifest,
        &config.network,
        &config.policy.limits,
        accept_all,
        cli.verbosity == Verbosity::Verbose,
        progress,
    )?;
    let previous = CompactState::load(&initial_manifest.root)?;
    let config = Config::load(&initial_manifest.root)?;
    let toolchain = Toolchain::discover(cli.toolchain.as_deref(), &config)?;
    engine::check_rust_version(&initial_manifest, &toolchain)?;
    let host = toolchain.target_info(None)?;
    let contexts = vendor_contexts(&toolchain, &config, &host, previous.as_ref())?;

    let manifest = Manifest::load_for_vendor_selected(current, selected_package)?;
    let forced = requested
        .map(|(package, version)| upgrade::transitive_selection(&manifest, package, version))
        .transpose()?;
    if forced.is_some() && previous.is_none() {
        return Err(
            Error::failure("dependency upgrade requires generated Lorry dependency state")
                .with_help(
                    "run `lorry vendor [--accept-all]` once to create `.lorry/dependencies-v2.toml`",
                ),
        );
    }
    let changed = prepare_networked(
        &manifest,
        &config,
        &toolchain,
        &contexts,
        forced.as_ref(),
        previous.as_ref(),
        Some(&direct),
        accept_all,
        progress,
    )?;

    if cli.verbosity != Verbosity::Quiet {
        eprintln!(
            "{} Cargo.lock",
            if changed { "Updated" } else { "Verified" }
        );
    }
    Ok(0)
}

fn vendor_contexts(
    toolchain: &Toolchain,
    config: &Config,
    host: &TargetInfo,
    previous: Option<&CompactState>,
) -> Result<Vec<VendorContext>> {
    let mut triples = config
        .vendor
        .targets
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if config.vendor.include_host {
        triples.insert(host.triple.clone());
    }
    if triples.is_empty() {
        return Err(
            Error::failure("the candidate vendor context set for this host is empty")
                .with_help("configure `[vendor].targets` or set `include-host = true`"),
        );
    }
    // The current host's context set is replaced by the configured set;
    // contexts reviewed on every other host are preserved exactly. Contexts
    // dropped from the current host's set are still resolved once so the
    // committed baseline stays reconstructible during this run.
    let mut recorded = BTreeMap::new();
    for triple in triples {
        recorded.insert((host.triple.clone(), triple), true);
    }
    if let Some(previous) = previous {
        for context in &previous.contexts {
            let key = (context.host.clone(), context.target.clone());
            if context.host != host.triple {
                recorded.insert(key, true);
            } else {
                recorded.entry(key).or_insert(false);
            }
        }
    }
    let mut infos: BTreeMap<String, TargetInfo> = BTreeMap::new();
    infos.insert(host.triple.clone(), host.clone());
    for (context_host, context_target) in recorded.keys() {
        for triple in [context_host, context_target] {
            if !infos.contains_key(triple) {
                infos.insert(triple.clone(), toolchain.target_info(Some(triple))?);
            }
        }
    }
    Ok(recorded
        .into_iter()
        .map(|((context_host, context_target), recorded)| VendorContext {
            context: Context {
                host: context_host.clone(),
                target: context_target.clone(),
            },
            host: infos[&context_host].clone(),
            target: infos[&context_target].clone(),
            recorded,
        })
        .collect())
}

struct VendorContext {
    context: Context,
    host: TargetInfo,
    target: TargetInfo,
    recorded: bool,
}

#[cfg(test)]
fn prepare_path_only(
    manifest: &Manifest,
    config: &Config,
    toolchain: &Toolchain,
    host: &TargetInfo,
    targets: &[TargetInfo],
) -> Result<Vec<u8>> {
    let locked_registry_names = manifest
        .lock
        .iter()
        .flat_map(|lock| &lock.packages)
        .filter(|package| package.source.is_some())
        .map(|package| package.name.clone())
        .collect::<BTreeSet<_>>();
    let mut loader = |name: &str, _requirement: &semver::VersionReq, _catalog: &mut Catalog| {
        if locked_registry_names.contains(name) {
            Ok(())
        } else {
            Err(fetch_pending(name))
        }
    };
    let contexts = test_contexts(host, targets);
    let repositories = RepositorySet::open(
        &config.repositories,
        repository_tree_limits(&config.policy.limits)?,
        config.policy.limits.max_package_bytes,
    )?;
    let (lock, _, selected) = prepare_with_loader(
        manifest,
        config,
        toolchain,
        &contexts,
        None,
        &repositories,
        &BTreeSet::new(),
        &mut loader,
        &reject_registry_packages,
    )?;
    inspect_path_policy(config, &selected)?;
    Ok(lock)
}

#[cfg(test)]
fn test_contexts(host: &TargetInfo, targets: &[TargetInfo]) -> Vec<VendorContext> {
    targets
        .iter()
        .map(|target| VendorContext {
            context: Context {
                host: host.triple.clone(),
                target: target.triple.clone(),
            },
            host: host.clone(),
            target: target.clone(),
            recorded: true,
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn prepare_networked(
    manifest: &Manifest,
    config: &Config,
    toolchain: &Toolchain,
    contexts: &[VendorContext],
    forced: Option<&upgrade::Selection>,
    previous: Option<&CompactState>,
    direct: Option<&crate::git::DirectCatalog>,
    accept_all: bool,
    progress: Progress,
) -> Result<bool> {
    let stdin = io::stdin();
    prepare_networked_with_approval(
        manifest,
        config,
        toolchain,
        contexts,
        forced,
        previous,
        direct,
        accept_all,
        stdin.is_terminal(),
        &mut stdin.lock(),
        &mut io::stderr().lock(),
        progress,
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_networked_with_approval(
    manifest: &Manifest,
    config: &Config,
    toolchain: &Toolchain,
    contexts: &[VendorContext],
    forced: Option<&upgrade::Selection>,
    previous: Option<&CompactState>,
    direct: Option<&crate::git::DirectCatalog>,
    accept_all: bool,
    terminal: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
    progress: Progress,
) -> Result<bool> {
    progress.report("Checking dependency repository state")?;
    let mut acquisition = Acquisition::new(config, manifest, progress)?;
    let repositories = acquisition.repositories().clone();
    // The committed document is needed only to display an interactive diff.
    // Reconstructing it verifies and inventories every dependency source, so
    // avoid that work when --accept-all would reject a changed graph anyway.
    let committed = if accept_all {
        None
    } else {
        previous
            .map(|previous| {
                try_reconstruct_committed_review(
                    manifest,
                    config,
                    toolchain,
                    &repositories,
                    previous,
                    direct,
                )
            })
            .transpose()?
            .flatten()
    };
    let forced = forced.map(upgrade::Selection::as_resolver_input);
    let base_catalog = prepare_catalog(manifest, config, &repositories, forced.is_some(), direct)?;
    let mut known_proc_macros = previous
        .map(|previous| {
            dependency::capability_registry_proc_macros(manifest, &previous.capabilities)
        })
        .transpose()?
        .unwrap_or_default();
    struct CachedEvidence {
        identity: Vec<(PackageKey, ResolvedSource)>,
        packages: BTreeMap<PackageKey, PackageEvidence>,
    }
    let mut evidence_cache: Option<CachedEvidence> = None;
    progress.report("Resolving dependency graph")?;
    let (lock, per_context, selected, evidence, admission) = loop {
        let (lock, per_context, selected) = {
            let mut loader =
                |name: &str, requirement: &semver::VersionReq, catalog: &mut Catalog| {
                    acquisition.load_sparse(name, requirement, catalog)
                };
            prepare_with_catalog(
                manifest,
                config,
                toolchain,
                contexts,
                forced,
                base_catalog.clone(),
                &known_proc_macros,
                &mut loader,
                &|_| Ok(()),
            )?
        };
        let mut review_policy = config.policy.clone();
        if let Some(previous) = previous {
            add_change_review_rules(&mut review_policy, previous, &selected)?;
        }
        let preflight = policy::preflight(&review_policy, &selected)?;
        let missing = acquisition.missing_selected(&selected)?;
        require_approval_mode(missing, accept_all, terminal)?;
        acquisition.stage_selected(&selected)?;
        let identity = selected
            .packages
            .iter()
            .map(|package| (package.key.clone(), package.source.clone()))
            .collect::<Vec<_>>();
        let evidence = match &evidence_cache {
            Some(cached) if cached.identity == identity => cached.packages.clone(),
            _ => {
                progress.report("Verifying selected dependency sources")?;
                let evidence = acquisition.evidence(&selected, direct)?;
                evidence_cache = Some(CachedEvidence {
                    identity,
                    packages: evidence.clone(),
                });
                evidence
            }
        };
        let discovered = evidence
            .iter()
            .filter(|(key, evidence)| {
                evidence.proc_macro && key.source == PackageSourceKey::CratesIo
            })
            .map(|(key, _)| key.clone())
            .collect::<BTreeSet<_>>();
        if known_proc_macros != discovered {
            known_proc_macros = discovered;
            continue;
        }
        let admission = policy::inspect(&preflight, &selected, &evidence)?;
        break (lock, per_context, selected, evidence, admission);
    };

    let (candidate, capabilities) = candidate_review(
        manifest,
        &lock,
        contexts,
        &per_context,
        &evidence,
        &admission,
    )?;
    let commitment = candidate.commitment()?;
    let recorded = recorded_contexts(contexts);
    let unchanged = previous.is_some_and(|previous| {
        previous.review_sha256 == commitment
            && previous.contexts == recorded
            && previous.capabilities == capabilities
    });
    if let Some(previous) = previous {
        if !unchanged {
            if accept_all {
                return Err(Error::usage(
                    "`--accept-all` cannot approve a dependency change",
                    "rerun interactively without `--accept-all` to review the complete candidate",
                ));
            }
            change_review::approve(
                committed.as_ref(),
                &previous.review_sha256,
                &candidate,
                terminal,
                input,
                output,
            )?;
        }
    } else {
        let report = candidate.render()?;
        writeln!(output, "Complete candidate review document:")
            .and_then(|()| output.write_all(&report))
            .map_err(|error| Error::failure(format!("failed to write vendor review: {error}")))?;
        approve_new_packages(&selected, &evidence, accept_all, input, output)?;
    }
    let staged_lock = stage_lockfile(&manifest.workspace_root.join("Cargo.lock"), &lock)?;
    acquisition.publish()?;
    let changed = staged_lock.is_some();
    if let Some(staged_lock) = staged_lock {
        staged_lock.commit()?;
    }
    CompactState {
        review_sha256: commitment,
        contexts: recorded,
        capabilities,
    }
    .write(&manifest.root)?;
    Ok(changed)
}

fn try_reconstruct_committed_review(
    manifest: &Manifest,
    config: &Config,
    toolchain: &Toolchain,
    repositories: &RepositorySet,
    previous: &CompactState,
    direct: Option<&crate::git::DirectCatalog>,
) -> Result<Option<Review>> {
    if manifest.lock.is_none() {
        return Ok(None);
    }
    let options = dependency::resolver_options(manifest, config, toolchain)?;
    let staging = AtomicDirectory::new(&env::temp_dir(), "lorry-vendor-baseline")?;
    Ok(dependency::verify_compact_admission(
        &dependency::ReviewInputs {
            manifest,
            config,
            source: dependency::RegistrySource::Lorry(repositories),
            toolchain,
            options: &options,
            staging_parent: staging.path(),
            direct,
            prepare_context: None,
        },
        previous,
    )
    .map(dependency::VerifiedAdmission::into_review)
    .ok())
}

fn recorded_contexts(contexts: &[VendorContext]) -> Vec<Context> {
    contexts
        .iter()
        .filter(|entry| entry.recorded)
        .map(|entry| entry.context.clone())
        .collect()
}

fn context_resolution<'a>(
    per_context: &'a [(Context, Resolution)],
    context: &Context,
) -> Result<&'a Resolution> {
    per_context
        .iter()
        .find(|(candidate, _)| candidate == context)
        .map(|(_, resolution)| resolution)
        .ok_or_else(|| {
            Error::failure(format!(
                "no resolution was computed for reviewed context `{} -> {}`",
                context.host, context.target
            ))
        })
}

/// Builds the candidate canonical review from the staged lockfile, the
/// recorded per-context resolutions, and staged/verified evidence.
fn candidate_review(
    manifest: &Manifest,
    lock: &[u8],
    contexts: &[VendorContext],
    per_context: &[(Context, Resolution)],
    evidence: &BTreeMap<PackageKey, PackageEvidence>,
    admission: &policy::Admission,
) -> Result<(Review, Vec<admission_state::Capability>)> {
    let lock_source = String::from_utf8(lock.to_vec()).map_err(|error| {
        Error::failure(format!("generated Cargo.lock is not valid UTF-8: {error}"))
    })?;
    let locked_manifest = manifest.clone().with_lock_source(lock_source)?;
    let locked_lock = locked_manifest
        .lock
        .clone()
        .expect("candidate manifest was loaded with a lock source");
    let recorded = recorded_contexts(contexts);
    let mut candidate = Review::from_graph(&locked_manifest, &locked_lock, recorded.clone())?;
    let mut merged = Vec::new();
    for context in &recorded {
        merged.push(context_resolution(per_context, context)?.clone());
    }
    let merged = resolver::merge_resolutions(merged)?;
    let capabilities = admission_state::capabilities_from(&merged, evidence, admission)?;
    for context in &recorded {
        let resolution = context_resolution(per_context, context)?;
        candidate.add_context_resolution(context, resolution, evidence)?;
    }
    candidate.complete(capabilities.clone())?;
    Ok((candidate, capabilities))
}

fn add_change_review_rules(
    policy: &mut crate::config::Policy,
    previous: &CompactState,
    selected: &Resolution,
) -> Result<()> {
    for (index, package) in selected.packages.iter().enumerate() {
        let ResolvedSource::CratesIo { checksum } = package.source else {
            continue;
        };
        let native_tools = previous
            .capabilities
            .iter()
            .filter(|capability| capability.package == package.key.name)
            .flat_map(|capability| capability.native_tools.iter().copied())
            .collect();
        let id = format!("lorry-change-review-{index:05}");
        if policy.rules.contains_key(&id) {
            return Err(Error::failure(format!(
                "configured policy rule `{id}` conflicts with dependency change review"
            )));
        }
        policy.rules.insert(
            id,
            PolicyRule {
                action: PolicyAction::Allow,
                name: Some(package.key.name.clone()),
                version: Some(
                    semver::VersionReq::parse(&format!("={}", package.key.version)).map_err(
                        |error| {
                            Error::failure(format!(
                                "failed to create exact dependency change rule for `{} {}`: {error}",
                                package.key.name, package.key.version
                            ))
                        },
                    )?,
                ),
                source: Some("crates.io".to_owned()),
                checksum: Some(hex(&checksum)),
                source_tree_sha256: None,
                license: None,
                allow_build_script: true,
                allow_proc_macro: true,
                native_tools,
                provenance: Path::new(crate::admission_state::RELATIVE_PATH).to_path_buf(),
            },
        );
    }
    Ok(())
}

/// The rendered candidate lockfile, the per-context resolutions, and their
/// merged selection.
type PreparedContexts = (Vec<u8>, Vec<(Context, Resolution)>, Resolution);

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn prepare_with_loader(
    manifest: &Manifest,
    config: &Config,
    toolchain: &Toolchain,
    contexts: &[VendorContext],
    forced: Option<(&str, Option<&Version>, &Version)>,
    repositories: &RepositorySet,
    proc_macros: &BTreeSet<PackageKey>,
    loader: &mut dyn FnMut(&str, &semver::VersionReq, &mut Catalog) -> Result<()>,
    after_complete: &dyn Fn(&Resolution) -> Result<()>,
) -> Result<PreparedContexts> {
    let catalog = prepare_catalog(manifest, config, repositories, forced.is_some(), None)?;
    prepare_with_catalog(
        manifest,
        config,
        toolchain,
        contexts,
        forced,
        catalog,
        proc_macros,
        loader,
        after_complete,
    )
}

fn prepare_catalog(
    manifest: &Manifest,
    config: &Config,
    repositories: &RepositorySet,
    allow_unlocked: bool,
    direct: Option<&crate::git::DirectCatalog>,
) -> Result<Catalog> {
    let mut catalog = if manifest.lock.is_some() {
        Catalog::from_locked_repository(manifest, repositories)?
    } else {
        Catalog::default()
    };
    if allow_unlocked {
        catalog.allow_unlocked_registry_candidates();
    }
    patch::configure(manifest, config, repositories, &mut catalog)?;
    if let Some(direct) = direct {
        direct.configure(&mut catalog)?;
    } else {
        crate::git::configure_direct(manifest, &config.policy.limits, &mut catalog)?;
    }
    Ok(catalog)
}

#[allow(clippy::too_many_arguments)]
fn prepare_with_catalog(
    manifest: &Manifest,
    config: &Config,
    toolchain: &Toolchain,
    contexts: &[VendorContext],
    forced: Option<(&str, Option<&Version>, &Version)>,
    mut catalog: Catalog,
    proc_macros: &BTreeSet<PackageKey>,
    loader: &mut dyn FnMut(&str, &semver::VersionReq, &mut Catalog) -> Result<()>,
    after_complete: &dyn Fn(&Resolution) -> Result<()>,
) -> Result<PreparedContexts> {
    for key in proc_macros {
        catalog.annotate_proc_macro(key, true)?;
    }
    let mut locked = LockedPreference::from_lockfile(manifest.lock.as_ref())?;
    if let Some((name, old, version)) = forced {
        LockedPreference::force_version(&mut locked, name, old, version.clone());
    }
    let options = dependency::resolver_options(manifest, config, toolchain)?;
    let complete = resolver::resolve_dynamic(manifest, &mut catalog, &options, &locked, loader)?;
    if let Some((name, _, version)) = forced
        && !complete
            .packages
            .iter()
            .any(|package| package.key.name == name && package.key.version == *version)
    {
        return Err(Error::failure(format!(
            "requested upgrade `{name} {version}` is not present in the resolved graph"
        ))
        .with_help("the requested version must satisfy every active dependency requirement"));
    }
    after_complete(&complete)?;

    let selected_locked = LockedPreference::from_resolution(&complete);
    let mut per_context = Vec::new();
    for entry in contexts {
        let resolution = resolver::resolve_selected_dynamic(
            manifest,
            &mut catalog,
            &options,
            &selected_locked,
            TargetSelection {
                target_triple: &entry.target.triple,
                target_cfg: &entry.target.cfg,
                host_triple: &entry.host.triple,
                host_cfg: &entry.host.cfg,
            },
            loader,
        )?;
        per_context.push((entry.context.clone(), resolution));
    }
    let selected =
        resolver::merge_resolutions(per_context.iter().map(|(_, resolution)| resolution.clone()))?;
    Ok((
        lockfile::render(manifest, &complete)?,
        per_context,
        selected,
    ))
}

struct Acquisition<'a> {
    config: &'a Config,
    /// Shared across the whole vendor run so each repository object is
    /// verified once, not re-hashed by every inventory, resolution, and
    /// evidence pass.
    repositories: RepositorySet,
    records: BTreeMap<(String, Version), sparse::Record>,
    fetched: BTreeSet<String>,
    inspections: Vec<ExtractedArchive>,
    state: Option<AcquisitionState>,
    progress: Progress,
}

struct AcquisitionState {
    client: Client,
    trust: TrustPolicy,
    transaction: RepositoryTransaction,
}

impl<'a> Acquisition<'a> {
    fn new(config: &'a Config, manifest: &Manifest, progress: Progress) -> Result<Self> {
        let repositories = RepositorySet::open(
            &config.repositories,
            repository_tree_limits(&config.policy.limits)?,
            config.policy.limits.max_package_bytes,
        )?;
        let mut locked = Vec::new();
        for package in manifest.lock.iter().flat_map(|lock| &lock.packages) {
            let (Some(_source), Some(checksum)) = (&package.source, &package.checksum) else {
                continue;
            };
            let version = Version::parse(&package.version.original).map_err(|error| {
                Error::failure(format!(
                    "locked package has invalid version `{} {}`: {error}",
                    package.name, package.version.original
                ))
            })?;
            locked.push((package.name.clone(), version, checksum.clone()));
        }
        let objects = repositories.lookup_registries(
            &locked
                .iter()
                .map(|(_, _, checksum)| checksum.clone())
                .collect::<Vec<_>>(),
        )?;
        let mut records = BTreeMap::new();
        for (name, version, checksum) in locked {
            let Some(object) = objects[&checksum].clone() else {
                continue;
            };
            if object.name != name || object.version != version {
                return Err(Error::failure(format!(
                    "repository object `{checksum}` does not match locked package `{} {}`",
                    name, version
                )));
            }
            let key = (object.name.clone(), object.version.clone());
            if let Some(existing) = records.insert(key, object.index.clone())
                && existing != object.index
            {
                return Err(Error::failure(format!(
                    "repositories disagree about locked package `{} {}`",
                    name, version
                )));
            }
        }
        Ok(Self {
            config,
            repositories,
            records,
            fetched: BTreeSet::new(),
            inspections: Vec::new(),
            state: None,
            progress,
        })
    }

    fn repositories(&self) -> &RepositorySet {
        &self.repositories
    }

    fn load_sparse(
        &mut self,
        name: &str,
        requirement: &semver::VersionReq,
        catalog: &mut Catalog,
    ) -> Result<()> {
        let expected = name.to_ascii_lowercase();
        for record in self
            .records
            .iter()
            .filter(|((name, _), _)| name == &expected)
            .map(|(_, record)| record.clone())
            .collect::<Vec<_>>()
        {
            if !catalog.contains_registry(&record.name, &record.version) {
                catalog.insert(record)?;
            }
        }
        if self.fetched.contains(&expected)
            || catalog.contains_crates_io_candidate(&expected, requirement)
        {
            return Ok(());
        }
        let url = sparse_url(&expected)?;
        self.progress
            .report(format_args!("Updating crates.io index for `{expected}`"))?;
        let state = self.state()?;
        let download = state.client.download(
            &url,
            &mut state.trust,
            state.transaction.path(),
            sparse::MAX_RESPONSE_BYTES,
        )?;
        for record in sparse::load_response(download.path(), &expected)? {
            let key = (record.name.clone(), record.version.clone());
            if let Some(existing) = self.records.get(&key) {
                if existing != &record {
                    return Err(Error::failure(format!(
                        "sparse acquisition changed package version `{} {}`",
                        record.name, record.version
                    )));
                }
            } else {
                catalog.insert(record.clone())?;
                self.records.insert(key, record);
            }
        }
        self.fetched.insert(expected);
        Ok(())
    }

    fn stage_selected(&mut self, resolution: &Resolution) -> Result<usize> {
        let max_package_bytes = self.config.policy.limits.max_package_bytes;
        self.stage_selected_with(resolution, |state, package, record| {
            let url = archive_url(&package.key.name, &package.key.version)?;
            let download = state.client.download(
                &url,
                &mut state.trust,
                state.transaction.path(),
                max_package_bytes,
            )?;
            state.transaction.stage_registry(record, download.path())?;
            Ok(())
        })
    }

    fn missing_selected(&self, resolution: &Resolution) -> Result<usize> {
        let repositories = &self.repositories;
        let mut missing = 0;
        for package in &resolution.packages {
            let ResolvedSource::CratesIo { checksum } = package.source else {
                continue;
            };
            if repositories.lookup_registry(&hex(&checksum))?.is_none()
                && !self.has_staged_registry(checksum)
            {
                missing += 1;
            }
        }
        Ok(missing)
    }

    fn evidence(
        &mut self,
        resolution: &Resolution,
        direct: Option<&crate::git::DirectCatalog>,
    ) -> Result<BTreeMap<PackageKey, PackageEvidence>> {
        let repositories = self.repositories.clone();
        let mut retained = Vec::new();
        for package in &resolution.packages {
            let ResolvedSource::CratesIo { checksum } = package.source else {
                continue;
            };
            if self.has_staged_registry(checksum) {
                continue;
            }
            let object = repositories
                .lookup_registry(&hex(&checksum))?
                .ok_or_else(|| {
                    Error::failure(format!(
                        "selected crates.io package `{} {}` is absent",
                        package.key.name, package.key.version
                    ))
                })?;
            if object.retained_source {
                retained.push(object);
            }
        }
        repositories.load_registry_manifests(&retained)?;
        let git_packages = resolution
            .packages
            .iter()
            .filter(|package| matches!(package.source, ResolvedSource::Git { .. }))
            .collect::<Vec<_>>();
        let mut evidence = match direct {
            Some(direct) => git_packages
                .iter()
                .map(|package| Ok((package.key.clone(), direct.evidence(package)?)))
                .collect::<Result<BTreeMap<_, _>>>()?,
            None => dependency::inspect_git_package_evidence(&git_packages)?,
        };
        for package in &resolution.packages {
            let package_evidence = match &package.source {
                ResolvedSource::Path { .. } => PackageEvidence::from_path(package)?,
                ResolvedSource::Git { .. } => continue,
                ResolvedSource::CratesIo { checksum } => {
                    let staged = self.state.as_ref().and_then(|state| {
                        state
                            .transaction
                            .objects()
                            .iter()
                            .find(|object| object.object().checksum == *checksum)
                    });
                    if let Some(staged) = staged {
                        PackageEvidence::from_registry(
                            package,
                            staged.object(),
                            staged.manifest(),
                            staged.source_tree()?,
                            true,
                        )?
                    } else {
                        let object = repositories.lookup_registry(&hex(checksum))?.ok_or_else(
                            || {
                                Error::failure(format!(
                                    "selected crates.io package `{} {}` was not staged or present",
                                    package.key.name, package.key.version
                                ))
                            },
                        )?;
                        let (source, tree) = if object.retained_source {
                            let tree = object.source_tree.clone().ok_or_else(|| {
                                Error::failure(format!(
                                    "verified object for `{} {}` retains no source tree",
                                    package.key.name, package.key.version
                                ))
                            })?;
                            (object.root.join("source"), tree)
                        } else {
                            let extracted = extract_crate(
                                &object.root.join("package.crate"),
                                object.checksum,
                                &env::temp_dir(),
                                &object.name,
                                &object.version,
                                ArchiveLimits::from_policy(&self.config.policy.limits),
                            )?;
                            let source = extracted.path().to_owned();
                            let tree = extracted.tree().clone();
                            self.inspections.push(extracted);
                            (source, tree)
                        };
                        let manifest = if object.retained_source {
                            repositories.load_registry_manifest(&object)?
                        } else {
                            Manifest::load_path_dependency(&source)?
                        };
                        PackageEvidence::from_registry(package, &object, &manifest, &tree, false)?
                    }
                }
            };
            evidence.insert(package.key.clone(), package_evidence);
        }
        Ok(evidence)
    }

    fn publish(self) -> Result<()> {
        if let Some(state) = self.state {
            state.transaction.publish()?;
        }
        Ok(())
    }

    fn stage_selected_with(
        &mut self,
        resolution: &Resolution,
        mut stage: impl FnMut(&mut AcquisitionState, &ResolvedPackage, &sparse::Record) -> Result<()>,
    ) -> Result<usize> {
        let repositories = RepositorySet::open(
            &self.config.repositories,
            repository_tree_limits(&self.config.policy.limits)?,
            self.config.policy.limits.max_package_bytes,
        )?;
        let mut staged = 0;
        for package in &resolution.packages {
            let ResolvedSource::CratesIo { checksum } = package.source else {
                continue;
            };
            if repositories.lookup_registry(&hex(&checksum))?.is_some()
                || self.has_staged_registry(checksum)
            {
                continue;
            }
            let key = (package.key.name.clone(), package.key.version.clone());
            let record = self.records.get(&key).cloned().ok_or_else(|| {
                Error::failure(format!(
                    "resolved crates.io package `{} {}` has no acquired sparse index record",
                    package.key.name, package.key.version
                ))
            })?;
            if record.checksum != checksum {
                return Err(Error::failure(format!(
                    "acquired sparse index checksum changed for resolved package `{} {}`",
                    package.key.name, package.key.version
                )));
            }
            self.progress.report(format_args!(
                "Downloading {} v{}",
                package.key.name, package.key.version
            ))?;
            stage(self.state()?, package, &record)?;
            staged += 1;
        }
        Ok(staged)
    }

    fn has_staged_registry(&self, checksum: [u8; 32]) -> bool {
        self.state.as_ref().is_some_and(|state| {
            state
                .transaction
                .objects()
                .iter()
                .any(|object| object.object().checksum == checksum)
        })
    }

    fn state(&mut self) -> Result<&mut AcquisitionState> {
        if self.state.is_none() {
            let client = Client::discover(&self.config.network)?;
            let trust = TrustPolicy::load_default()?;
            let tree = repository_tree_limits(&self.config.policy.limits)?;
            let writer = RepositoryWriter::open(
                &self.config.repositories,
                tree,
                ArchiveLimits::from_policy(&self.config.policy.limits),
            )?;
            self.state = Some(AcquisitionState {
                client,
                trust,
                transaction: writer.begin()?,
            });
        }
        Ok(self.state.as_mut().unwrap())
    }
}

fn require_approval_mode(missing: usize, accept_all: bool, terminal: bool) -> Result<()> {
    if missing == 0 || accept_all || terminal {
        return Ok(());
    }
    Err(Error::failure(format!(
        "{missing} new package{} require approval, but no interactive terminal is available",
        if missing == 1 { "" } else { "s" }
    ))
    .with_help("rerun `lorry vendor --accept-all` to approve every policy-compliant package"))
}

fn approve_new_packages(
    resolution: &Resolution,
    evidence: &BTreeMap<PackageKey, PackageEvidence>,
    accept_all: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<()> {
    let mut packages = Vec::new();
    for package in &resolution.packages {
        let package_evidence = evidence.get(&package.key).ok_or_else(|| {
            Error::failure(format!(
                "package approval has no evidence for `{} {}`",
                package.key.name, package.key.version
            ))
        })?;
        if package_evidence.newly_acquired {
            packages.push(package);
        }
    }
    packages.sort_unstable_by(|left, right| left.key.cmp(&right.key));
    if packages.is_empty() {
        return Ok(());
    }
    writeln!(output, "New crates.io packages ({}):", packages.len())
        .map_err(|error| Error::failure(format!("failed to write vendor summary: {error}")))?;
    for package in &packages {
        let package_evidence = &evidence[&package.key];
        let ResolvedSource::CratesIo { checksum } = package.source else {
            return Err(Error::failure(
                "new package approval contains a non-registry package",
            ));
        };
        let archive_bytes = package_evidence.archive_bytes.ok_or_else(|| {
            Error::failure(format!(
                "new package `{} {}` has no archive size",
                package.key.name, package.key.version
            ))
        })?;
        let dependencies = package
            .edges
            .iter()
            .filter(|edge| {
                evidence
                    .get(&edge.package)
                    .is_some_and(|value| value.newly_acquired)
            })
            .map(|edge| format!("{} {}", edge.package.name, edge.package.version))
            .collect::<BTreeSet<_>>();
        writeln!(
            output,
            "  {} {}: source=crates.io checksum={} license={} build-script={} \
             archive-bytes={} extracted-bytes={} new-dependencies={}",
            package.key.name,
            package.key.version,
            hex(&checksum),
            package_evidence.license,
            if package_evidence.build_script {
                "yes"
            } else {
                "no"
            },
            archive_bytes,
            package_evidence.extracted_bytes,
            if dependencies.is_empty() {
                "none".to_owned()
            } else {
                dependencies.into_iter().collect::<Vec<_>>().join(", ")
            }
        )
        .map_err(|error| Error::failure(format!("failed to write vendor summary: {error}")))?;
    }
    if accept_all {
        return Ok(());
    }
    for package in packages {
        write!(
            output,
            "Approve {} {}? [y/N]: ",
            package.key.name, package.key.version
        )
        .and_then(|()| output.flush())
        .map_err(|error| Error::failure(format!("failed to write vendor prompt: {error}")))?;
        let mut response = String::new();
        std::io::Read::take(&mut *input, 65)
            .read_line(&mut response)
            .map_err(|error| Error::failure(format!("failed to read package approval: {error}")))?;
        if !matches!(response.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            return Err(Error::failure(format!(
                "approval declined for package `{} {}`",
                package.key.name, package.key.version
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
fn inspect_path_policy(config: &Config, resolution: &Resolution) -> Result<()> {
    let preflight = policy::preflight(&config.policy, resolution)?;
    let evidence = resolution
        .packages
        .iter()
        .map(|package| Ok((package.key.clone(), PackageEvidence::from_path(package)?)))
        .collect::<Result<BTreeMap<PackageKey, PackageEvidence>>>()?;
    policy::inspect(&preflight, resolution, &evidence)?;
    Ok(())
}

#[cfg(test)]
fn reject_registry_packages(resolution: &Resolution) -> Result<()> {
    let packages = resolution
        .packages
        .iter()
        .filter(|package| package.key.source == crate::resolver::PackageSourceKey::CratesIo)
        .map(|package| format!("{} {}", package.key.name, package.key.version))
        .collect::<Vec<_>>();
    if packages.is_empty() {
        return Ok(());
    }
    Err(Error::failure(format!(
        "crates.io archive acquisition is not enabled yet; the resolved graph requires {}",
        packages.join(", ")
    ))
    .with_help("sparse metadata was acquired; the next Stage-2 increment stages crate archives"))
}

#[cfg(test)]
fn fetch_pending(name: &str) -> Error {
    Error::failure(format!(
        "sparse-index metadata for crates.io package `{name}` is unavailable because the \
         direct curl acquisition path is not implemented yet"
    ))
}

fn stage_lockfile(path: &Path, bytes: &[u8]) -> Result<Option<AtomicFile>> {
    match fs::read(path) {
        Ok(existing)
            if existing == bytes || lock_versions_are_the_only_difference(&existing, bytes) =>
        {
            return Ok(None);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(Error::failure(format!(
                "failed to read lockfile `{}`: {error}",
                path.display()
            )));
        }
    }
    let mut staged = AtomicFile::new(path)?;
    staged.write_all(bytes)?;
    staged.persist()?;
    Ok(Some(staged))
}

fn lock_versions_are_the_only_difference(existing: &[u8], candidate: &[u8]) -> bool {
    const HEADER: &[u8] = b"# This file is automatically @generated by Cargo.\n\
                             # It is not intended for manual editing.\n";
    let Some(existing) = existing.strip_prefix(HEADER) else {
        return false;
    };
    let Some(candidate) = candidate.strip_prefix(HEADER) else {
        return false;
    };
    existing.strip_prefix(b"version = 3\n") == candidate.strip_prefix(b"version = 4\n")
}

fn repository_tree_limits(policy: &PolicyLimits) -> Result<TreeLimits> {
    let entries = usize::try_from(policy.max_package_files).map_err(|_| {
        Error::failure("policy max-package-files does not fit this platform's address space")
    })?;
    Ok(TreeLimits {
        max_tree_bytes: policy.max_extracted_package_bytes,
        max_entries: entries,
        max_path_bytes: 4096,
        max_file_bytes: policy.max_extracted_package_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CargoCompat, PolicyDefault};
    use crate::hash::Sha256;
    use crate::resolver::{CompileKind, FeatureContext, PackageSourceKey, ResolvedEdge};
    use crate::toolchain::CfgSet;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(label: &str) -> Self {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let root =
                env::temp_dir().join(format!("lorry-vendor-{label}-{}-{id}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join("src")).unwrap();
            fs::write(root.join("src/lib.rs"), "pub fn root() {}\n").unwrap();
            Self(root)
        }

        fn manifest(&self) -> Manifest {
            Manifest::load_for_vendor(&self.0).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn toolchain() -> Toolchain {
        Toolchain {
            rustc: "/rustc".into(),
            verbose_version: String::new(),
            release: "1.98.0-nightly".to_owned(),
            host: "x86_64-unknown-linux-gnu".to_owned(),
            compatibility: CargoCompat::V1_98,
        }
    }

    fn target() -> TargetInfo {
        TargetInfo {
            triple: "x86_64-unknown-linux-gnu".to_owned(),
            cfg: CfgSet::parse(
                "target_arch=\"x86_64\"\ntarget_os=\"linux\"\ntarget_family=\"unix\"\nunix\n",
            )
            .unwrap(),
        }
    }

    fn crate_archive(name: &str, version: &str) -> Vec<u8> {
        fn octal(field: &mut [u8], value: u64) {
            let text = format!("{value:0width$o}", width = field.len() - 1);
            field[..text.len()].copy_from_slice(text.as_bytes());
        }
        fn append(tar: &mut Vec<u8>, path: &str, contents: &[u8]) {
            let mut header = [0_u8; 512];
            header[..path.len()].copy_from_slice(path.as_bytes());
            octal(&mut header[100..108], 0o644);
            octal(&mut header[124..136], contents.len() as u64);
            header[148..156].fill(b' ');
            header[156] = b'0';
            header[257..263].copy_from_slice(b"ustar\0");
            header[263..265].copy_from_slice(b"00");
            let checksum = header.iter().map(|byte| *byte as u64).sum::<u64>();
            header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
            tar.extend_from_slice(&header);
            tar.extend_from_slice(contents);
            tar.resize(tar.len().div_ceil(512) * 512, 0);
        }

        let root = format!("{name}-{version}");
        let mut tar = Vec::new();
        append(
            &mut tar,
            &format!("{root}/Cargo.toml"),
            format!(
                "[package]\nname = \"{name}\"\nversion = \"{version}\"\n\
                 edition = \"2021\"\nlicense = \"MIT\"\n"
            )
            .as_bytes(),
        );
        append(
            &mut tar,
            &format!("{root}/src/lib.rs"),
            b"pub fn fixture() {}\n",
        );
        tar.resize(tar.len() + 1024, 0);
        let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
        gzip.write_all(&tar).unwrap();
        gzip.finish().unwrap()
    }

    fn registry_package(name: &str, version: &Version, checksum: [u8; 32]) -> ResolvedPackage {
        ResolvedPackage {
            key: PackageKey {
                name: name.to_owned(),
                version: version.clone(),
                source: PackageSourceKey::CratesIo,
            },
            source: ResolvedSource::CratesIo { checksum },
            local_manifest: None,
            feature_sets: BTreeMap::new(),
            compile_kinds: BTreeSet::from([CompileKind::Target]),
            target_features: BTreeSet::new(),
            host_features: BTreeSet::new(),
            edges: Vec::new(),
            lock_edges: Vec::new(),
        }
    }

    #[test]
    fn dependency_free_vendor_persists_before_atomic_lock_commit() {
        let fixture = Fixture::new("empty");
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        let manifest = fixture.manifest();
        let config = Config::default();
        let target = target();
        let bytes = prepare_path_only(
            &manifest,
            &config,
            &toolchain(),
            &target,
            std::slice::from_ref(&target),
        )
        .unwrap();
        let lock_path = fixture.0.join("Cargo.lock");
        assert!(!lock_path.exists());
        let contexts = test_contexts(&target, std::slice::from_ref(&target));
        assert!(
            prepare_networked(
                &manifest,
                &config,
                &toolchain(),
                &contexts,
                None,
                None,
                None,
                true,
                Progress::new(false),
            )
            .unwrap()
        );
        assert_eq!(fs::read(&lock_path).unwrap(), bytes);
        let state_path = CompactState::path(&fixture.0);
        let written = CompactState::load(&fixture.0).unwrap().unwrap();
        assert_eq!(written.contexts, recorded_contexts(&contexts));
        assert!(written.capabilities.is_empty());
        let locked = fixture.manifest();
        assert!(
            !prepare_networked(
                &locked,
                &config,
                &toolchain(),
                &contexts,
                None,
                Some(&written),
                None,
                true,
                Progress::new(false),
            )
            .unwrap()
        );
        assert_eq!(
            CompactState::load(&fixture.0).unwrap().unwrap(),
            written,
            "an unchanged graph rewrites identical state at `{}`",
            state_path.display()
        );
    }

    #[test]
    fn unchanged_v3_vendor_preserves_the_existing_lock() {
        let fixture = Fixture::new("unchanged-v3");
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        let lock = b"# This file is automatically @generated by Cargo.\n\
                     # It is not intended for manual editing.\n\
                     version = 3\n\n\
                     [[package]]\n\
                     name = \"root\"\n\
                     version = \"0.1.0\"\n";
        fs::write(fixture.0.join("Cargo.lock"), lock).unwrap();
        let manifest = fixture.manifest();
        let config = Config::default();
        let target = target();
        let contexts = test_contexts(&target, std::slice::from_ref(&target));

        assert!(
            !prepare_networked(
                &manifest,
                &config,
                &toolchain(),
                &contexts,
                None,
                None,
                None,
                true,
                Progress::new(false),
            )
            .unwrap()
        );
        assert_eq!(fs::read(fixture.0.join("Cargo.lock")).unwrap(), lock);
    }

    #[test]
    fn ordinary_vendor_reconciles_an_edited_manifest_after_review() {
        let fixture = Fixture::new("manifest-reconciliation");
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        let config = Config::default();
        let target = target();
        let contexts = test_contexts(&target, std::slice::from_ref(&target));
        let mut initial_output = Vec::new();
        prepare_networked_with_approval(
            &fixture.manifest(),
            &config,
            &toolchain(),
            &contexts,
            None,
            None,
            None,
            true,
            false,
            &mut "".as_bytes(),
            &mut initial_output,
            Progress::new(false),
        )
        .unwrap();
        let previous = CompactState::load(&fixture.0).unwrap().unwrap();
        let previous_state = fs::read(CompactState::path(&fixture.0)).unwrap();
        let previous_lock = fs::read(fixture.0.join("Cargo.lock")).unwrap();

        fs::write(
            fixture.0.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [features]\nreviewed-change = []\n",
        )
        .unwrap();
        let edited = fixture.manifest();
        let error = prepare_networked_with_approval(
            &edited,
            &config,
            &toolchain(),
            &contexts,
            None,
            Some(&previous),
            None,
            true,
            false,
            &mut "".as_bytes(),
            &mut Vec::new(),
            Progress::new(false),
        )
        .unwrap_err();
        assert!(
            error
                .render()
                .contains("cannot approve a dependency change")
        );
        assert_eq!(
            fs::read(CompactState::path(&fixture.0)).unwrap(),
            previous_state
        );
        assert_eq!(
            fs::read(fixture.0.join("Cargo.lock")).unwrap(),
            previous_lock
        );

        let mut output = Vec::new();
        assert!(
            !prepare_networked_with_approval(
                &edited,
                &config,
                &toolchain(),
                &contexts,
                None,
                Some(&previous),
                None,
                false,
                true,
                &mut "yes\n".as_bytes(),
                &mut output,
                Progress::new(false),
            )
            .unwrap()
        );
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains(&previous.review_sha256));
        assert!(output.contains("no semantic diff is available"));
        assert!(output.contains("reviewed-change"));
        let current = CompactState::load(&fixture.0).unwrap().unwrap();
        assert_ne!(current.review_sha256, previous.review_sha256);
        assert_eq!(
            fs::read(fixture.0.join("Cargo.lock")).unwrap(),
            previous_lock
        );
    }

    #[test]
    fn path_only_vendor_upgrades_a_stale_v3_lock_and_enforces_policy_first() {
        let fixture = Fixture::new("path");
        fs::create_dir_all(fixture.0.join("local/src")).unwrap();
        fs::write(
            fixture.0.join("local/Cargo.toml"),
            "[package]\nname = \"local\"\nversion = \"1.2.3\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(fixture.0.join("local/src/lib.rs"), "pub fn local() {}\n").unwrap();
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\nlocal = { path = \"local\" }\n",
        )
        .unwrap();
        let stale = b"# This file is automatically @generated by Cargo.\n\
                      # It is not intended for manual editing.\n\
                      version = 3\n\n\
                      [[package]]\n\
                      name = \"root\"\n\
                      version = \"0.0.1\"\n";
        fs::write(fixture.0.join("Cargo.lock"), stale).unwrap();
        let manifest = fixture.manifest();
        let target = target();
        let mut denied = Config::default();
        denied.policy.path_roots = vec![fixture.0.join("elsewhere")];
        let error = prepare_path_only(
            &manifest,
            &denied,
            &toolchain(),
            &target,
            std::slice::from_ref(&target),
        )
        .unwrap_err();
        assert!(error.to_string().contains("policy.path-roots"));
        assert_eq!(fs::read(fixture.0.join("Cargo.lock")).unwrap(), stale);

        let bytes = prepare_path_only(
            &manifest,
            &Config::default(),
            &toolchain(),
            &target,
            std::slice::from_ref(&target),
        )
        .unwrap();
        assert!(String::from_utf8_lossy(&bytes).contains("\nversion = 4\n"));
        stage_lockfile(&fixture.0.join("Cargo.lock"), &bytes)
            .unwrap()
            .unwrap()
            .commit()
            .unwrap();
        let repaired = Manifest::load(&fixture.0).unwrap();
        assert_eq!(repaired.lock.unwrap().packages.len(), 2);
    }

    #[test]
    fn registry_graph_waits_for_curl_acquisition_without_writing_a_lock() {
        let fixture = Fixture::new("registry");
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\nserde = \"1\"\n",
        )
        .unwrap();
        let manifest = fixture.manifest();
        let target = target();
        let error = prepare_path_only(
            &manifest,
            &Config::default(),
            &toolchain(),
            &target,
            std::slice::from_ref(&target),
        )
        .unwrap_err();
        assert!(error.render().contains("curl acquisition"));
        assert!(!fixture.0.join("Cargo.lock").exists());
    }

    #[test]
    fn stages_only_missing_selected_registry_archives() {
        let fixture = Fixture::new("acquire");
        let repository = fixture.0.join("repository");
        let mut config = Config::default();
        config.repositories.local = Some(repository);
        config.repositories.keep_sources = false;
        config.policy.default = PolicyDefault::Allow;
        let bytes = crate_archive("demo", "1.2.3");
        let archive = fixture.0.join("demo.crate");
        fs::write(&archive, &bytes).unwrap();
        let mut digest = Sha256::new();
        digest.update(&bytes);
        let checksum = digest.finish();
        let version = Version::parse("1.2.3").unwrap();
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\ndemo = \"1\"\n",
        )
        .unwrap();
        fs::write(
            fixture.0.join("Cargo.lock"),
            format!(
                "version = 4\n\
                 [[package]]\nname = \"demo\"\nversion = \"{version}\"\n\
                 source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
                 checksum = \"{}\"\n\
                 [[package]]\nname = \"root\"\nversion = \"0.1.0\"\n\
                 dependencies = [\"demo\"]\n",
                hex(&checksum)
            ),
        )
        .unwrap();
        let manifest = fixture.manifest();
        let record = sparse::Record::parse(
            Path::new("/demo-index"),
            format!(
                "{{\"name\":\"demo\",\"vers\":\"{version}\",\"deps\":[],\
                 \"cksum\":\"{}\",\"features\":{{}},\"yanked\":false}}\n",
                hex(&checksum)
            )
            .as_bytes(),
        )
        .unwrap();
        let package = registry_package("demo", &version, checksum);
        let resolution = Resolution {
            root_edges: vec![ResolvedEdge {
                dependency_index: 0,
                alias: "demo".to_owned(),
                kind: sparse::DependencyKind::Normal,
                parent_compile_kind: None,
                compile_kind: CompileKind::Target,
                context: FeatureContext::Unified,
                package: package.key.clone(),
            }],
            packages: vec![package],
        };
        let mut acquisition = Acquisition::new(&config, &manifest, Progress::new(false)).unwrap();
        acquisition
            .records
            .insert(("demo".to_owned(), version.clone()), record.clone());
        acquisition.fetched.insert("demo".to_owned());
        let requirement = semver::VersionReq::parse("^1").unwrap();
        let mut catalog = Catalog::default();
        acquisition
            .load_sparse("demo", &requirement, &mut catalog)
            .unwrap();
        acquisition
            .load_sparse("demo", &requirement, &mut catalog)
            .unwrap();
        assert!(catalog.contains_registry("demo", &version));
        assert!(acquisition.state.is_none());
        assert!(require_approval_mode(1, false, false).is_err());

        let staged = acquisition
            .stage_selected_with(&resolution, |state, _, record| {
                state.transaction.stage_registry(record, &archive)?;
                Ok(())
            })
            .unwrap();
        assert_eq!(staged, 1);
        assert_eq!(acquisition.missing_selected(&resolution).unwrap(), 0);
        assert_eq!(
            acquisition
                .stage_selected_with(&resolution, |_, _, _| {
                    panic!("an object staged by an earlier resolution pass must not be downloaded")
                })
                .unwrap(),
            0
        );
        assert_eq!(
            acquisition.state.as_ref().unwrap().transaction.objects()[0]
                .object()
                .name,
            "demo"
        );
        let evidence = acquisition.evidence(&resolution, None).unwrap();
        let preflight = policy::preflight(&config.policy, &resolution).unwrap();
        policy::inspect(&preflight, &resolution, &evidence).unwrap();
        assert!(evidence[&resolution.packages[0].key].newly_acquired);
        let mut output = Vec::new();
        approve_new_packages(
            &resolution,
            &evidence,
            false,
            &mut std::io::Cursor::new(b"yes\n"),
            &mut output,
        )
        .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("source=crates.io"));
        assert!(output.contains("license=MIT"));
        assert!(output.contains("Approve demo 1.2.3?"));
        acquisition.publish().unwrap();

        let mut warm = Acquisition::new(&config, &manifest, Progress::new(false)).unwrap();
        assert_eq!(
            warm.records.get(&("demo".to_owned(), version)),
            Some(&record)
        );
        let mut catalog = Catalog::default();
        warm.load_sparse("demo", &requirement, &mut catalog)
            .unwrap();
        assert!(warm.state.is_none());
        assert_eq!(
            warm.stage_selected_with(&resolution, |_, _, _| {
                panic!("an existing verified object must not be downloaded")
            })
            .unwrap(),
            0
        );
        assert!(warm.state.is_none());
        let evidence = warm.evidence(&resolution, None).unwrap();
        assert!(!evidence[&resolution.packages[0].key].newly_acquired);
        assert_eq!(warm.inspections.len(), 1);
        assert!(warm.inspections[0].path().is_dir());
        let mut output = Vec::new();
        approve_new_packages(
            &resolution,
            &evidence,
            false,
            &mut std::io::Cursor::new(b""),
            &mut output,
        )
        .unwrap();
        assert!(output.is_empty());
    }
}
