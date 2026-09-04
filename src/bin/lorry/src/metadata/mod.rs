mod graph;
mod package;
pub mod wire;

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::admission_state::{CompactState, Context};
use crate::atomic::AtomicDirectory;
use crate::cargo_registry::CargoRegistry;
use crate::cli::{Cli, MetadataOptions, Verbosity};
use crate::config::{Config, effective_rustflags};
use crate::dependency::{self, PreparedGraph};
use crate::diagnostic::{Error, Result};
use crate::manifest::Manifest;
use crate::progress::Progress;
use crate::repository::RepositorySet;
use crate::resolver::{PackageKey, ResolvedSource, TargetSelection};
use crate::source_tree::Exclusions;
use crate::toolchain::Toolchain;
use crate::unit::PlanOptions;
use crate::validation::ValidationMode;

const MOTOR_TARGET: &str = "x86_64-unknown-motor";

pub fn execute(cli: &Cli, options: &MetadataOptions) -> Result<i32> {
    let current = env::current_dir()
        .map_err(|error| Error::failure(format!("failed to read current directory: {error}")))?;
    let manifest = Manifest::load_selected_or_manifest_path(
        &current,
        options.manifest_path.as_deref().map(std::path::Path::new),
        cli.package.as_deref(),
        true,
    )?;
    let mut config = Config::load(&manifest.root)?;
    let toolchain = Toolchain::discover(cli.toolchain.as_deref(), &config)?;
    crate::engine::check_rust_version(&manifest, &toolchain)?;
    let physical_target = config.selected_target(options.filter_platform.as_deref())?;
    let target = toolchain.target_info(physical_target.as_deref())?;
    manifest.require_supported_target(&target)?;
    let host = if physical_target.is_some() {
        toolchain.target_info(None)?
    } else {
        target.clone()
    };
    if cli.verbosity == Verbosity::Verbose {
        eprintln!(
            "Using {} (rustc {}, Cargo {:?} compatibility)",
            toolchain.rustc.display(),
            toolchain.release,
            toolchain.compatibility
        );
    }

    if options.no_deps {
        return write_document(&graph::no_dependencies(&manifest)?);
    }
    let compact_state = CompactState::load(&manifest.root)?;
    if let Some(compact) = &compact_state {
        compact.require_context(&host.triple, &target.triple)?;
    }

    let staging = AtomicDirectory::new(&env::temp_dir(), "lorry-metadata")?;
    let progress = Progress::new(cli.verbosity != Verbosity::Quiet);
    progress.report("Verifying dependency state")?;
    let repositories = if cli.use_cargo_registry {
        None
    } else {
        Some(RepositorySet::open_with_validation(
            &config.repositories,
            crate::engine::repository_tree_limits(&config.policy.limits)?,
            config.policy.limits.max_package_bytes,
            ValidationMode::Trusted,
        )?)
    };
    let cargo_registry = if cli.use_cargo_registry {
        Some(CargoRegistry::discover_with_validation(
            staging.path(),
            &config.policy.limits,
            ValidationMode::Trusted,
            Some(&crate::engine::artifact_root(&manifest).join(".cargo-evidence")),
        )?)
    } else {
        None
    };
    let source = match (&repositories, &cargo_registry) {
        (Some(repositories), None) => dependency::RegistrySource::Lorry(repositories),
        (None, Some(registry)) => dependency::RegistrySource::Cargo(registry),
        _ => unreachable!("exactly one registry source is constructed"),
    };
    let direct = crate::git::load_locked_dependencies(&manifest, &config.policy.limits)?;
    let resolver_options = dependency::resolver_options(&manifest, &config, &toolchain)?;
    let selection = TargetSelection {
        target_triple: &target.triple,
        target_cfg: &target.cfg,
        host_triple: &host.triple,
        host_cfg: &host.cfg,
    };
    let verified_resolution = if let Some(compact) = &compact_state {
        let verified = dependency::verify_compact_admission(
            &dependency::ReviewInputs {
                manifest: &manifest,
                config: &config,
                source,
                toolchain: &toolchain,
                options: &resolver_options,
                staging_parent: staging.path(),
                direct: Some(&direct),
                prepare_context: Some(Context {
                    host: host.triple.clone(),
                    target: target.triple.clone(),
                }),
            },
            compact,
        )?;
        let (review, resolution) = verified.into_parts();
        review.apply_to_policy(&mut config.policy, &manifest.root)?;
        resolution
    } else {
        None
    };
    progress.report("Preparing dependency graph")?;
    let prepared = dependency::prepare_locked_source(
        &manifest,
        &config,
        dependency::LockedSource {
            registry: source,
            direct: &direct,
            verified_resolution,
        },
        &resolver_options,
        selection,
        staging.path(),
    )?;
    let target_cfgs = crate::engine::matching_cfgs(&config, &target)?;
    let target_options = config.target_options(&target.triple, &target_cfgs)?;
    let rustflags = effective_rustflags(&config, &target_options)?;
    let logical_target = if physical_target.is_some() {
        physical_target.as_deref()
    } else if cfg!(target_os = "motor") {
        Some(MOTOR_TARGET)
    } else {
        None
    };
    let plan = prepared.dependency_plan(&PlanOptions {
        workspace_root: &manifest.workspace_root,
        release: false,
        test_profile: false,
        panic_abort: manifest.panic_abort(false),
        release_profile: &manifest.release,
        rustc: &toolchain,
        logical_target,
        rustflags: &rustflags,
    })?;
    let cache_root = config.cache_directory()?;
    let roots = publish_sources(&cache_root, &config, &prepared)?;
    write_document(&graph::resolved(
        &manifest,
        &prepared,
        &plan,
        &roots,
        config.policy.limits.max_packages,
    )?)
}

fn publish_sources(
    cache_root: &std::path::Path,
    config: &Config,
    prepared: &PreparedGraph,
) -> Result<BTreeMap<PackageKey, PathBuf>> {
    let limits = crate::engine::repository_tree_limits(&config.policy.limits)?;
    prepared
        .resolution
        .packages
        .iter()
        .map(|package| {
            let prepared_package = &prepared.packages[&package.key];
            let root = match &package.source {
                ResolvedSource::Path { physical_root, .. } => fs::canonicalize(physical_root)
                    .map_err(|error| {
                        Error::failure(format!(
                            "failed to canonicalize path package `{}`: {error}",
                            physical_root.display()
                        ))
                    })?,
                ResolvedSource::CratesIo { .. } | ResolvedSource::Git { .. } => {
                    crate::source_view::publish_package(
                        cache_root,
                        &package.key.name,
                        &package.key.version,
                        prepared_package.source_root(),
                        prepared_package.evidence.source_tree_sha256,
                        limits,
                        if matches!(package.source, ResolvedSource::CratesIo { .. }) {
                            Exclusions::CargoRegistryMarker
                        } else {
                            Exclusions::None
                        },
                    )?
                }
            };
            Ok((package.key.clone(), root))
        })
        .collect()
}

fn write_document(document: &wire::Metadata) -> Result<i32> {
    let bytes = wire::render(document)
        .map_err(|error| Error::failure(format!("failed to serialize metadata: {error}")))?;
    io::stdout()
        .write_all(&bytes)
        .map_err(|error| Error::failure(format!("failed to write metadata: {error}")))?;
    Ok(0)
}
