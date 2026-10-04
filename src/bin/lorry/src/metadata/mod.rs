pub(crate) mod graph;
pub(crate) mod package;
pub mod wire;

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::atomic::AtomicDirectory;
use crate::cargo_registry::CargoRegistry;
use crate::cli::{Cli, MetadataOptions, Verbosity};
use crate::config::Config;
use crate::dependency::{self, PreparedGraph, PreparedPackage};
use crate::diagnostic::{Error, Result};
use crate::manifest::{Manifest, SourceWorkspace};
use crate::progress::Progress;
use crate::repository::RepositorySet;
use crate::resolver::{PackageKey, Resolution, ResolvedSource};
use crate::source_tree::Exclusions;
use crate::toolchain::Toolchain;
use crate::validation::ValidationMode;

pub fn execute(cli: &Cli, options: &MetadataOptions) -> Result<i32> {
    let current = env::current_dir()
        .map_err(|error| Error::failure(format!("failed to read current directory: {error}")))?;
    let mut workspace = SourceWorkspace::load(
        &current,
        options.manifest_path.as_deref().map(std::path::Path::new),
    )?;
    warn_default_format(cli, options);
    Manifest::report_warnings(&workspace.packages, cli.verbosity);
    if options.no_deps {
        return write_document(&graph::no_dependencies(&workspace)?);
    }
    let config = Config::load_workspace(
        &current,
        &workspace.root,
        workspace
            .packages
            .iter()
            .map(|member| member.root.as_path()),
    )?;
    if workspace.packages.is_empty() {
        let prepared = dependency::workspace::PreparedSources {
            resolution: Resolution {
                root_edges: Vec::new(),
                packages: Vec::new(),
            },
            packages: BTreeMap::new(),
        };
        return write_document(&graph::workspace::resolved(
            &workspace,
            &prepared,
            &BTreeMap::new(),
            None,
        )?);
    }
    workspace.load_locked_context().map_err(|error| {
        error.with_help(
        "provide a current Cargo.lock, then run `lorry fetch` to acquire missing locked sources")
    })?;
    let manifest = &workspace.packages[0];
    let toolchain = Toolchain::discover(cli.toolchain.as_deref(), &config, false)?;
    // Cargo's build.target does not filter metadata; only --filter-platform
    // limits its nodes. Feature requests are still resolved across platforms.
    let platform = options
        .filter_platform
        .as_deref()
        .map(|triple| toolchain.target_info(Some(triple)))
        .transpose()?;
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
            Some(&crate::engine::artifact_root(manifest).join(".cargo-evidence")),
        )?)
    } else {
        None
    };
    let source = match (&repositories, &cargo_registry) {
        (Some(repositories), None) => dependency::RegistrySource::Lorry(repositories),
        (None, Some(registry)) => dependency::RegistrySource::Cargo(registry),
        _ => unreachable!("exactly one registry source is constructed"),
    };
    let direct = crate::git::load_locked_sources(manifest, &config.policy.limits)?;
    let resolver_options = dependency::resolver_options(manifest, &config, &toolchain)?;
    let (complete, catalog) = dependency::workspace::resolve_locked(
        &workspace,
        &config,
        source,
        &direct,
        &resolver_options,
    )?;
    let members = crate::resolver::workspace::features::member_requests(
        &workspace,
        &workspace
            .packages
            .iter()
            .map(|member| member.root.clone())
            .collect(),
        &cli.features,
        true,
    )?;
    let resolution = crate::resolver::workspace::resolve_metadata_workspace(
        &complete,
        &catalog,
        &resolver_options,
        &members,
    )?;
    let prepared = dependency::workspace::prepare_sources(
        resolution,
        &config,
        source,
        staging.path(),
        &direct,
    )?;
    let cache_root = config.cache_directory()?;
    let roots = publish_source_parts(
        &cache_root,
        &config,
        &prepared.resolution,
        &prepared.packages,
    )?;
    let mut document =
        graph::workspace::resolved(&workspace, &prepared, &roots, platform.as_ref())?;
    let target_directory = config.target_directory(&current, &workspace.root, None);
    document.target_directory = package::path_utf8(&target_directory, "metadata target directory")?;
    document
        .build_directory
        .clone_from(&document.target_directory);
    write_document(&document)
}

fn warn_default_format(cli: &Cli, options: &MetadataOptions) {
    if !options.format_version_explicit && cli.verbosity != Verbosity::Quiet {
        eprintln!(
            "warning: please specify `--format-version` flag explicitly to avoid compatibility problems"
        );
    }
}

pub(crate) fn publish_sources(
    cache_root: &std::path::Path,
    config: &Config,
    prepared: &PreparedGraph,
) -> Result<BTreeMap<PackageKey, PathBuf>> {
    publish_source_parts(cache_root, config, &prepared.resolution, &prepared.packages)
}

fn publish_source_parts(
    cache_root: &std::path::Path,
    config: &Config,
    resolution: &Resolution,
    packages: &BTreeMap<PackageKey, PreparedPackage>,
) -> Result<BTreeMap<PackageKey, PathBuf>> {
    let limits = crate::engine::repository_tree_limits(&config.policy.limits)?;
    resolution
        .packages
        .iter()
        .map(|package| {
            let prepared_package = &packages[&package.key];
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
