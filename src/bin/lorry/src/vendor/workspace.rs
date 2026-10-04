use super::*;
use crate::cli::{FeatureSelection, FetchOptions};
use crate::manifest::SourceWorkspace;
use crate::resolver::workspace::{
    features::member_requests, resolve_complete_workspace, resolve_selected_workspace,
};

pub(crate) fn fetch(cli: &Cli, options: &FetchOptions) -> Result<i32> {
    if cli.use_cargo_registry {
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
    workspace.load_locked_context().map_err(|error| {
        error.with_help("provide a usable Cargo.lock with `lorry vendor`, then run `lorry fetch`")
    })?;
    let mut config = Config::load_workspace(
        &current,
        &workspace.root,
        workspace
            .packages
            .iter()
            .map(|package| package.root.as_path()),
    )?;
    config.apply_max_packages(cli.max_packages)?;
    if workspace.packages.is_empty() {
        return Ok(0);
    }
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
        crate::git::load_locked_sources(manifest, &config.policy.limits)?
    } else {
        crate::git::materialize_locked_sources(
            manifest,
            &config.network,
            &config.policy.limits,
            cli.verbosity == Verbosity::Verbose,
            progress,
        )?
    };
    let mut acquisition = Acquisition::for_sources(&config, manifest, progress)?;
    let resolver_options = dependency::resolver_options(manifest, &config, &toolchain)?;
    let (complete, catalog) = resolve_locked(
        &workspace,
        &config,
        &direct,
        &resolver_options,
        &mut acquisition,
        options.offline,
    )?;
    let selected = acquisition_resolution(
        &workspace,
        &complete,
        &catalog,
        &resolver_options,
        host.as_ref(),
        &targets,
    )?;
    if !options.offline {
        acquisition.stage_selected(&selected)?;
    }
    let evidence = acquisition.evidence(&selected, Some(&direct))?;
    policy::inspect_sources(&config.policy, &selected, &evidence)?;
    acquisition.publish()?;
    progress.report("Verified locked workspace sources")?;
    Ok(0)
}

fn resolve_locked(
    workspace: &SourceWorkspace,
    config: &Config,
    direct: &crate::git::DirectCatalog,
    options: &resolver::Options,
    acquisition: &mut Acquisition<'_>,
    offline: bool,
) -> Result<(Resolution, Catalog)> {
    let manifest = &workspace.packages[0];
    let lock = manifest.lock.as_ref().ok_or_else(|| {
        Error::failure("workspace source acquisition requires Cargo.lock")
            .with_help("run `lorry vendor` to create the workspace lock")
    })?;
    let mut catalog = prepare_catalog(
        manifest,
        config,
        acquisition.repositories(),
        false,
        Some(direct),
    )?;
    catalog.use_fetch_hint();
    let complete = resolve_complete_workspace(
        workspace,
        &mut catalog,
        options,
        &LockedPreference::from_lockfile(Some(lock))?,
        &mut |name, _, catalog| acquisition.load_locked_sparse(manifest, name, catalog, offline),
    )?;
    crate::offline::validate_workspace_resolution(lock, &complete)?;
    policy::preflight_sources(&config.policy, &complete)?;
    Ok((complete, catalog))
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
