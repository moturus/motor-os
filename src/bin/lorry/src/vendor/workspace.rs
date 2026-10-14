use super::*;
use crate::admission_state::ReviewScope;
use crate::cli::{FeatureSelection, FetchOptions};
use crate::manifest::SourceWorkspace;
use crate::resolver::workspace::{
    features::member_requests, resolve_complete_workspace, resolve_selected_workspace,
};
use crate::workspace_trust;

pub(crate) fn fetch(cli: &Cli, options: &FetchOptions) -> Result<i32> {
    if cli.use_cargo_registry == Some(true) {
        return Err(Error::usage(
            "`--use-cargo-registry` cannot be combined with `fetch`",
            "remove `--use-cargo-registry`; fetch populates verified Lorry repositories",
        ));
    }
    let current = env::current_dir()
        .map_err(|error| Error::failure(format!("failed to read current directory: {error}")))?;
    let mut workspace =
        SourceWorkspace::load(&current, cli.manifest_path.as_deref().map(Path::new))?;
    Manifest::report_warnings(&workspace.packages, cli.verbosity);
    let config = Config::load_source_workspace(&current, &workspace, cli.max_packages)?;
    workspace.load_locked_context().map_err(|error| {
        error.with_help("provide a usable Cargo.lock with `lorry vendor`, then run `lorry fetch`")
    })?;
    if workspace.packages.is_empty() {
        return Ok(0);
    }
    policy::preflight_locked_sources(&config.policy, workspace.packages[0].lock.as_ref().unwrap())?;
    let _lock = ProjectVendorLock::acquire(&workspace.root)?;
    let progress = Progress::new(cli.verbosity != Verbosity::Quiet);
    let manifest = &workspace.packages[0];
    let toolchain = Toolchain::discover(cli.toolchain.as_deref(), &config, false)?;
    // Resolve target information before acquisition, so an invalid target has
    // no network or repository side effects.
    let targets = options
        .targets
        .iter()
        .map(|target| toolchain.target_info(Some(target)))
        .collect::<Result<Vec<_>>>()?;
    let host = if targets.is_empty() {
        None
    } else {
        Some(toolchain.target_info(None)?)
    };
    let direct = if options.offline {
        crate::git::load_locked_sources(
            manifest,
            &config.policy.limits,
            crate::validation::ValidationMode::Strict,
        )?
    } else {
        crate::git::materialize_locked_sources(
            manifest,
            &config.network,
            &config.policy.limits,
            cli.verbosity == Verbosity::Verbose,
            progress,
        )?
    };
    let mut acquisition = Acquisition::new(
        &config,
        manifest,
        progress,
        cli.verbosity == Verbosity::Verbose,
    )?;
    let resolver_options = dependency::resolver_options(manifest, &config, &toolchain)?;
    let (complete, mut catalog) = resolve_locked(
        &workspace,
        &config,
        &direct,
        &resolver_options,
        &mut acquisition,
        options.offline,
    )?;
    if !options.offline {
        acquisition.stage_resolution_inputs(&complete)?;
    }
    let mut inspected = BTreeSet::new();
    let selected =
        loop {
            let selected = acquisition_resolution(
                &workspace,
                &complete,
                &catalog,
                &resolver_options,
                host.as_ref(),
                &targets,
            )?;
            if targets.is_empty() {
                break selected;
            }
            let refined =
                discover_proc_macros(&selected, &mut catalog, &mut inspected, &mut |package| {
                    let mut package = package.clone();
                    package.edges.clear();
                    let context =
                        package.feature_sets.keys().next().cloned().ok_or_else(|| {
                            Error::failure("selected source has no feature context")
                        })?;
                    let compile_kind = *package
                        .compile_kinds
                        .first()
                        .ok_or_else(|| Error::failure("selected source has no compilation kind"))?;
                    let single = Resolution {
                        root_edges: vec![resolver::ResolvedEdge {
                            dependency_index: 0,
                            alias: package.key.name.clone(),
                            kind: crate::sparse::DependencyKind::Normal,
                            target: None,
                            parent_compile_kind: None,
                            compile_kind,
                            context,
                            package: package.key.clone(),
                        }],
                        packages: vec![package.clone()],
                    };
                    if !options.offline {
                        acquisition.stage_selected(&single)?;
                    }
                    let evidence = acquisition.evidence(&single, &direct)?;
                    policy::inspect_sources(&config.policy, &single, &evidence)?;
                    Ok(evidence[&package.key].proc_macro)
                })?;
            if !refined {
                break selected;
            }
        };
    if !options.offline {
        acquisition.stage_selected(&selected)?;
    }
    let evidence = acquisition.evidence(&selected, &direct)?;
    policy::inspect_sources(&config.policy, &selected, &evidence)?;
    acquisition.publish()?;
    progress.report("Verified locked workspace sources")?;
    Ok(0)
}

pub(crate) fn vendor_workspace(cli: &Cli, options: &VendorOptions) -> Result<i32> {
    if cli.use_cargo_registry == Some(true) {
        return Err(Error::usage(
            "vendor uses only verified Lorry repositories",
            "remove --use-cargo-registry",
        ));
    }
    let current = env::current_dir()
        .map_err(|error| Error::failure(format!("failed to read current directory: {error}")))?;
    let mut workspace =
        SourceWorkspace::load(&current, cli.manifest_path.as_deref().map(Path::new))?;
    workspace.load_context(options.locked)?;
    let mut config = Config::load_source_workspace(&current, &workspace, cli.max_packages)?;
    if workspace.packages.is_empty() {
        return Ok(0);
    }
    let accept_all = options.accept_all || config.policy.accept_all;
    config.policy.accept_all = accept_all;
    // With a terminal, missing build-time grants join the review below.
    config.policy.propose_missing = !accept_all && crate::prompt::interactive();
    if options.locked {
        policy::preflight_locked_sources(
            &config.policy,
            workspace.packages[0].lock.as_ref().unwrap(),
        )?;
    }
    let lock = ProjectVendorLock::acquire(&workspace.root)?;
    if cli.verbosity == Verbosity::Verbose {
        eprintln!("Locked {}", lock.path().display());
    }
    let previous = CompactState::load_replaceable(&workspace.root)?;
    let forced = match &options.mode {
        VendorMode::Sync => None,
        VendorMode::Upgrade(upgrade) => Some(upgrade::workspace_selection(
            &workspace.packages,
            &upgrade.package,
            &upgrade.version,
        )?),
    };
    if forced.is_some() && previous.is_none() {
        return Err(
            Error::failure("dependency upgrade requires generated Lorry dependency state")
                .with_help("run `lorry vendor [--accept-all]` to create workspace admission"),
        );
    }
    let scope = review_scope(cli, &workspace, previous.as_ref())?;
    let migration = migration::Records::collect(&workspace, &scope)?;
    let progress = Progress::new(cli.verbosity != Verbosity::Quiet);
    progress.report(scope.description())?;
    let mut manifest = workspace.packages[0].clone();
    let refreshes = if options.locked {
        vec![]
    } else {
        crate::git::resolve_patch_refreshes(
            &manifest,
            &config.network,
            &config.policy.limits,
            cli.verbosity == Verbosity::Verbose,
        )?
    };
    manifest = apply_patch_refreshes(&manifest, &refreshes)?;
    let toolchain = Toolchain::discover(cli.toolchain.as_deref(), &config, false)?;
    let host = toolchain.target_info(None)?;
    let contexts = vendor_contexts(&toolchain, &config, &host, previous.as_ref())?
        .into_iter()
        .filter(|context| context.recorded)
        .collect::<Vec<_>>();
    let direct = if options.offline {
        crate::git::load_locked_sources(
            &manifest,
            &config.policy.limits,
            crate::validation::ValidationMode::Strict,
        )?
    } else {
        crate::git::materialize_locked_sources(
            &manifest,
            &config.network,
            &config.policy.limits,
            cli.verbosity == Verbosity::Verbose,
            progress,
        )?
    };
    progress.report("Checking dependency repository state")?;
    let mut acquisition = Acquisition::new(
        &config,
        &manifest,
        progress,
        cli.verbosity == Verbosity::Verbose,
    )?;
    let resolver_options = dependency::resolver_options(&manifest, &config, &toolchain)?;
    progress.report("Resolving dependency graph")?;
    let (complete, mut catalog, staged_lock) = if options.locked {
        let (complete, catalog) = resolve_locked(
            &workspace,
            &config,
            &direct,
            &resolver_options,
            &mut acquisition,
            options.offline,
        )?;
        (complete, catalog, None)
    } else {
        let mut catalog = dependency::source_catalog(&manifest, None, &direct, true)?;
        let mut locked = LockedPreference::from_lockfile(manifest.lock.as_ref())?;
        if let Some(forced) = &forced {
            let (name, old, version) = forced.as_resolver_input();
            let requirement = semver::VersionReq::parse(&format!("={version}"))
                .map_err(|error| Error::failure(format!("invalid upgrade requirement: {error}")))?;
            // A compatible cached version otherwise keeps the lazy loader
            // from discovering the explicitly requested replacement.
            acquisition.load_sparse(name, &requirement, &mut catalog)?;
            LockedPreference::force_version(&mut locked, name, old, version.clone());
        }
        let complete = resolve_complete_workspace(
            &workspace,
            &mut catalog,
            &resolver_options,
            &locked,
            &mut |name, requirement, catalog| acquisition.load_sparse(name, requirement, catalog),
        )?;
        if let Some(forced) = &forced {
            let (name, _, version) = forced.as_resolver_input();
            if !complete.packages.iter().any(|package| {
                package.key.source == PackageSourceKey::CratesIo
                    && package.key.name == name
                    && package.key.version == *version
            }) {
                return Err(Error::failure(format!(
                    "requested upgrade `{name} {version}` is not present in the resolved graph"
                ))
                .with_help("the requested version must satisfy every dependency requirement"));
            }
        }
        policy::preflight_sources(&config.policy, &complete)?;
        let default_format = lockfile::Format::for_workspace(&workspace)?;
        let format = manifest
            .lock
            .as_ref()
            .map_or(default_format, |lock| lock.format);
        let lock = lockfile::render_workspace(&complete, format)?;
        let source = String::from_utf8(lock.clone()).map_err(|error| {
            Error::failure(format!("generated Cargo.lock is not UTF-8: {error}"))
        })?;
        let candidate = manifest.clone().with_lock_source(source)?;
        for member in &mut workspace.packages {
            member.lock = candidate.lock.clone();
        }
        let staged_lock = stage_lockfile(&workspace.root.join("Cargo.lock"), &lock)?;
        (complete, catalog, staged_lock)
    };
    if !options.offline {
        acquisition.stage_resolution_inputs(&complete)?;
    }
    let requests = dependency::workspace::admission::requests(&workspace, &scope)?;
    let (resolutions, selected, evidence) = loop {
        let resolutions = contexts
            .iter()
            .map(|context| {
                resolve_selected_workspace(
                    &complete,
                    &catalog,
                    &resolver_options,
                    &requests,
                    TargetSelection {
                        host_triple: &context.host.triple,
                        host_cfg: &context.host.cfg,
                        target_triple: &context.target.triple,
                        target_cfg: &context.target.cfg,
                    },
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let selected = resolver::merge_resolutions(resolutions.clone())?;
        policy::preflight_sources(&config.policy, &selected)?;
        if !options.offline {
            acquisition.stage_selected(&selected)?;
        }
        progress.report("Verifying selected dependency sources")?;
        let evidence = acquisition.evidence(&selected, &direct)?;
        policy::inspect_sources(&config.policy, &selected, &evidence)?;
        if !dependency::workspace::annotate_proc_macros(&mut catalog, &evidence)? {
            break (resolutions, selected, evidence);
        }
    };
    let recorded = contexts
        .iter()
        .map(|context| context.context.clone())
        .collect::<Vec<_>>();
    let mut candidate = dependency::workspace::admission::review(
        &workspace,
        scope.clone(),
        &recorded,
        &resolutions,
        &evidence,
        vec![],
    )?;
    // Reviewing ordinary compilation creates exact source rules; executing
    // build-time code still needs the caller's explicit package grants.
    let mut review_policy = config.policy.clone();
    candidate.apply_to_policy(&mut review_policy, &workspace.root)?;
    let preflight = policy::preflight_workspace(&review_policy, &selected)?;
    let admission = policy::inspect(&preflight, &selected, &evidence)?;
    let capabilities = admission_state::capabilities_from(&selected, &evidence, &admission)?;
    candidate.complete(capabilities.clone())?;
    let commitment = candidate.commitment()?;
    // A record the user never approved, such as one committed to a cloned
    // repository, is reviewed in full like a new one.
    let approved = previous
        .as_ref()
        .is_some_and(|previous| config.policy.approves(&previous.review_sha256));
    // Repository Cargo settings that can run a program also need approval.
    let cargo_configs = config
        .unapproved_cargo_configs()
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    let unchanged = approved
        && admission.proposed.is_empty()
        && cargo_configs.is_empty()
        && previous.as_ref().is_some_and(|previous| {
            previous.scope == scope
                && previous.review_sha256 == commitment
                && previous.contexts == recorded
                && previous.capabilities == capabilities
        });
    if !unchanged || !migration.is_empty() || direct.materialized_sources().next().is_some() {
        migration.report(cli.lorry_messages, false)?;
        let stdin = io::stdin();
        let mut output = io::stderr().lock();
        if !cli.lorry_messages {
            write_git_review(&refreshes, &direct, previous.is_none(), &mut output)?;
            let added = selected
                .packages
                .iter()
                .filter(|package| {
                    matches!(package.source, ResolvedSource::CratesIo { .. })
                        && evidence[&package.key].newly_acquired
                })
                .count();
            if added != 0 {
                writeln!(output, "New crates.io packages ({added}):").map_err(|error| {
                    Error::failure(format!("failed to write workspace review summary: {error}"))
                })?;
            }
        }
        // Corrupt records already fail in `load_replaceable`. A record that
        // parses but does not rebuild cannot be told apart from changed inputs,
        // so the report shows the complete candidate without a warning.
        let baseline = previous
            .as_ref()
            .filter(|_| approved)
            .and_then(|previous| {
                dependency::workspace::admission::reconstruct(
                    &dependency::ReviewInputs {
                        manifest: &manifest,
                        config: &config,
                        source: dependency::RegistrySource::Lorry(acquisition.repositories()),
                        toolchain: &toolchain,
                        options: &resolver_options,
                        staging_parent: &env::temp_dir(),
                        direct: Some(&direct),
                        prepare_context: None,
                        validation: crate::validation::ValidationMode::Strict,
                    },
                    previous,
                )
                .ok()
            })
            .map(|reconstructed| reconstructed.review);
        let proposals = proposed_grants(&selected, &evidence, &admission)?;
        write_proposals(&proposals, &config, cli.lorry_messages, &mut output)?;
        write_cargo_configs(&cargo_configs, cli.lorry_messages, &mut output)?;
        let mode = if accept_all {
            change_review::Mode::AcceptAll
        } else if options.locked
            || !migration.is_empty()
            || direct.materialized_sources().next().is_some()
            // Proposed grants and Cargo files need a "yes" even when the
            // dependency review itself is unchanged.
            || !proposals.is_empty()
            || !cargo_configs.is_empty()
        {
            change_review::Mode::Forced
        } else {
            change_review::Mode::Change
        };
        if cli.lorry_messages {
            change_review::approve_json(
                baseline.as_ref(),
                previous.as_ref().map(|state| state.review_sha256.as_str()),
                &candidate,
                mode,
                crate::prompt::interactive(),
                &mut stdin.lock(),
                &mut output,
            )?;
        } else {
            let report = change_review::workspace::render(
                baseline.as_ref(),
                previous.as_ref().map(|state| state.review_sha256.as_str()),
                &candidate,
                &selected,
            )?;
            change_review::workspace::approve(
                baseline.as_ref(),
                &candidate,
                &report,
                mode,
                crate::prompt::interactive(),
                &mut stdin.lock(),
                &mut output,
            )?;
        }
    }
    acquisition.publish()?;
    if let Some(lock) = staged_lock {
        lock.commit()?;
    }
    CompactState {
        scope,
        review_sha256: commitment.clone(),
        contexts: recorded,
        capabilities,
    }
    .write(&workspace.root)?;
    record_decisions(
        &config,
        options.accept_all,
        &commitment,
        proposed_grants(&selected, &evidence, &admission)?,
        &cargo_configs,
        &selected,
    )?;
    migration.remove()?;
    migration.report(cli.lorry_messages, true)?;
    progress.report("Verified Cargo.lock and workspace admission")?;
    Ok(0)
}

/// The build-time code that the user approves in this review.
fn proposed_grants(
    selected: &Resolution,
    evidence: &BTreeMap<PackageKey, policy::PackageEvidence>,
    admission: &policy::Admission,
) -> Result<Vec<workspace_trust::Grant>> {
    let mut grants = Vec::new();
    for package in &selected.packages {
        if !admission.proposed.contains(&package.key) {
            continue;
        }
        let evidence = &evidence[&package.key];
        let source = match &package.source {
            ResolvedSource::CratesIo { checksum } => workspace_trust::GrantSource::CratesIo {
                version: package.key.version.clone(),
                checksum: crate::hash::hex(checksum),
            },
            ResolvedSource::Git { .. } => workspace_trust::GrantSource::Git {
                version: package.key.version.clone(),
                source_tree_sha256: crate::hash::hex(&evidence.source_tree_sha256),
            },
            ResolvedSource::Path { .. } => workspace_trust::GrantSource::Path {
                source_tree_sha256: (!package
                    .local_manifest
                    .as_ref()
                    .is_some_and(|manifest| manifest.editable))
                .then(|| crate::hash::hex(&evidence.source_tree_sha256)),
            },
        };
        grants.push(workspace_trust::Grant {
            name: package.key.name.clone(),
            source,
            build_script: evidence.build_script,
            proc_macro: evidence.proc_macro,
        });
    }
    Ok(grants)
}

/// Lists the proposed build-time code and the native tools each build
/// script will receive, so one approval covers what it names.
fn write_proposals(
    grants: &[workspace_trust::Grant],
    config: &Config,
    json: bool,
    output: &mut impl Write,
) -> Result<()> {
    if grants.is_empty() {
        return Ok(());
    }
    let tools = config
        .native_tools
        .keys()
        .map(|(_, role)| *role)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(crate::admission_state::native_tool_name)
        .collect::<Vec<_>>();
    let write_error =
        |error: io::Error| Error::failure(format!("failed to write build-time grants: {error}"));
    if json {
        let message = serde_json::json!({
            "reason": "lorry-vendor-grants",
            "native_tools": tools,
            "grants": grants.iter().map(|grant| serde_json::json!({
                "name": grant.name,
                "source": match &grant.source {
                    workspace_trust::GrantSource::CratesIo { .. } => "crates.io",
                    workspace_trust::GrantSource::Git { .. } => "git",
                    workspace_trust::GrantSource::Path { .. } => "path",
                },
                "build_script": grant.build_script,
                "proc_macro": grant.proc_macro,
            })).collect::<Vec<_>>(),
        });
        return writeln!(output, "{message}").map_err(write_error);
    }
    let tools = if tools.is_empty() {
        "none configured".to_owned()
    } else {
        tools.join(", ")
    };
    writeln!(output, "Build-time code to approve ({}):", grants.len()).map_err(write_error)?;
    for grant in grants {
        let version = match &grant.source {
            workspace_trust::GrantSource::CratesIo { version, .. }
            | workspace_trust::GrantSource::Git { version, .. } => format!(" {version}"),
            workspace_trust::GrantSource::Path { .. } => " (path)".to_owned(),
        };
        let mut kinds = Vec::new();
        if grant.build_script {
            kinds.push(format!("build script (native tools: {tools})"));
        }
        if grant.proc_macro {
            kinds.push("procedural macro".to_owned());
        }
        writeln!(output, "  + {}{version}: {}", grant.name, kinds.join("; "))
            .map_err(write_error)?;
    }
    Ok(())
}

/// Lists the repository Cargo configuration files that this review approves,
/// with the settings that need it.
fn write_cargo_configs(
    configs: &[crate::config::CargoTrust],
    json: bool,
    output: &mut impl Write,
) -> Result<()> {
    if configs.is_empty() {
        return Ok(());
    }
    let write_error = |error: io::Error| {
        Error::failure(format!(
            "failed to write Cargo configuration review: {error}"
        ))
    };
    if json {
        let message = serde_json::json!({
            "reason": "lorry-vendor-cargo-config",
            "files": configs.iter().map(|trust| serde_json::json!({
                "file": trust.file,
                "sha256": trust.sha256,
                "settings": trust.settings,
            })).collect::<Vec<_>>(),
        });
        return writeln!(output, "{message}").map_err(write_error);
    }
    writeln!(
        output,
        "Repository Cargo configuration to approve ({}):",
        configs.len()
    )
    .map_err(write_error)?;
    for trust in configs {
        writeln!(output, "  + {}", trust.file.display()).map_err(write_error)?;
        for setting in &trust.settings {
            writeln!(output, "      {setting}").map_err(write_error)?;
        }
    }
    Ok(())
}

/// Records `--accept-all`, the approved review, the approved grants, and the
/// approved Cargo configuration in the user's configuration. Grants for
/// packages no longer selected go.
fn record_decisions(
    config: &Config,
    accept_all: bool,
    commitment: &str,
    proposed: Vec<workspace_trust::Grant>,
    cargo_configs: &[crate::config::CargoTrust],
    selected: &Resolution,
) -> Result<()> {
    let unchanged = (!accept_all || config.policy.accept_all)
        && config.policy.approved_review.as_deref() == Some(commitment)
        && proposed.is_empty()
        && cargo_configs.is_empty();
    if unchanged {
        return Ok(());
    }
    let workspace = config
        .policy
        .workspace
        .as_deref()
        .ok_or_else(|| Error::failure("workspace decisions need the workspace root"))?;
    let store = workspace_trust::Store::for_process(workspace).ok_or_else(|| {
        Error::failure("cannot record workspace decisions without an absolute HOME")
            .with_help("set HOME to the absolute path of the current user's home directory")
    })?;
    store.update(|decisions| {
        decisions.accept_all |= accept_all;
        decisions.approved_review = Some(commitment.to_owned());
        decisions.grants.retain(|grant| match &grant.source {
            workspace_trust::GrantSource::Path { .. } => true,
            workspace_trust::GrantSource::CratesIo { version, .. }
            | workspace_trust::GrantSource::Git { version, .. } => selected
                .packages
                .iter()
                .any(|package| package.key.name == grant.name && package.key.version == *version),
        });
        decisions.grants.extend(proposed);
        decisions.cargo_configs.extend(
            cargo_configs
                .iter()
                .map(|trust| (trust.file.clone(), trust.sha256.clone())),
        );
    })
}

fn review_scope(
    cli: &Cli,
    workspace: &SourceWorkspace,
    previous: Option<&CompactState>,
) -> Result<ReviewScope> {
    let explicit = cli.selection != crate::manifest::PackageSelection::default()
        || cli.features != FeatureSelection::default();
    if !explicit {
        return Ok(previous
            .map(|state| state.scope.clone())
            .unwrap_or_default());
    }
    let whole = cli.selection.packages.is_empty() && cli.selection.exclude.is_empty();
    let packages = if whole {
        vec![]
    } else {
        let (roots, _) = cli.selection.select(
            workspace
                .packages
                .iter()
                .map(|member| (member.name.as_str(), &member.version, member.root.as_path())),
            workspace
                .packages
                .iter()
                .map(|member| member.root.as_path()),
        )?;
        let mut packages = workspace
            .packages
            .iter()
            .filter(|member| roots.contains(&member.root))
            .map(|member| member.name.clone())
            .collect::<Vec<_>>();
        packages.sort();
        if packages.is_empty() {
            return Err(Error::failure("workspace review selects no packages"));
        }
        packages
    };
    Ok(ReviewScope {
        packages,
        features: cli.features.features.iter().cloned().collect(),
        all_features: cli.features.all,
        no_default_features: cli.features.no_default,
    })
}

/// Fetch and locked vendor resolve the lock with acquisition of the index
/// records that verified local state lacks.
fn resolve_locked(
    workspace: &SourceWorkspace,
    config: &Config,
    direct: &crate::git::DirectCatalog,
    options: &resolver::Options,
    acquisition: &mut Acquisition<'_>,
    offline: bool,
) -> Result<(Resolution, Catalog)> {
    let manifest = &workspace.packages[0];
    let repositories = acquisition.repositories().clone();
    dependency::workspace::resolve_locked(
        workspace,
        config,
        dependency::RegistrySource::Lorry(&repositories),
        direct,
        options,
        Some(&mut |name, _, catalog| {
            acquisition.load_locked_sparse(manifest, name, catalog, offline)
        }),
    )
}

fn discover_proc_macros(
    selected: &Resolution,
    catalog: &mut Catalog,
    inspected: &mut BTreeSet<PackageKey>,
    inspect: &mut dyn FnMut(&ResolvedPackage) -> Result<bool>,
) -> Result<bool> {
    let packages = selected
        .packages
        .iter()
        .map(|package| (&package.key, package))
        .collect::<BTreeMap<_, _>>();
    let mut pending = selected
        .root_edges
        .iter()
        .map(|edge| edge.package.clone())
        .collect::<std::collections::VecDeque<_>>();
    let mut visited = BTreeSet::new();
    while let Some(key) = pending.pop_front() {
        if !visited.insert(key.clone()) {
            continue;
        }
        let package = packages
            .get(&key)
            .ok_or_else(|| Error::failure("fetch traversal references an unresolved package"))?;
        if key.source == PackageSourceKey::CratesIo
            && inspected.insert(key.clone())
            && catalog.annotate_proc_macro(&key, inspect(package)?)?
        {
            // Re-project before visiting children: a newly discovered macro's
            // target dependencies must not be downloaded in the wrong context.
            return Ok(true);
        }
        pending.extend(package.edges.iter().map(|edge| edge.package.clone()));
    }
    Ok(false)
}

fn acquisition_resolution(
    workspace: &SourceWorkspace,
    complete: &Resolution,
    catalog: &Catalog,
    options: &resolver::Options,
    host: Option<&TargetInfo>,
    targets: &[TargetInfo],
) -> Result<Resolution> {
    if targets.is_empty() {
        return Ok(complete.clone());
    }
    let roots = workspace
        .packages
        .iter()
        .map(|member| member.root.clone())
        .collect();
    let requests = member_requests(
        workspace,
        &roots,
        &FeatureSelection {
            all: true,
            ..FeatureSelection::default()
        },
        true,
    )?;
    resolver::merge_resolutions(
        targets
            .iter()
            .map(|target| {
                resolve_selected_workspace(
                    complete,
                    catalog,
                    options,
                    &requests,
                    TargetSelection {
                        host_triple: &host.unwrap().triple,
                        host_cfg: &host.unwrap().cfg,
                        target_triple: &target.triple,
                        target_cfg: &target.cfg,
                    },
                )
            })
            .collect::<Result<Vec<_>>>()?,
    )
}
