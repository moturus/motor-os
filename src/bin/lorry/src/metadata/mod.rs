pub(crate) mod graph;
pub(crate) mod package;
pub mod wire;

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::cli::{Cli, MetadataOptions, Verbosity};
use crate::config::Config;
use crate::dependency::{self, PreparedGraph, PreparedPackage};
use crate::diagnostic::{Error, Result};
use crate::manifest::{Manifest, SourceWorkspace};
use crate::progress::Progress;
use crate::resolver::{PackageKey, Resolution, ResolvedSource};
use crate::source_tree::Exclusions;
use crate::toolchain::Toolchain;
use crate::validation::ValidationMode;

pub fn execute(cli: &Cli, options: &MetadataOptions) -> Result<i32> {
    crate::cargo_registry::with_fallback(cli, |cli, notes| execute_with(cli, notes, options))
}

fn execute_with(cli: &Cli, notes: Verbosity, options: &MetadataOptions) -> Result<i32> {
    let current = env::current_dir()
        .map_err(|error| Error::failure(format!("failed to read current directory: {error}")))?;
    let mut workspace = SourceWorkspace::load(
        &current,
        cli.manifest_path.as_deref().map(std::path::Path::new),
    )?;
    warn_default_format(notes, options);
    Manifest::report_warnings(&workspace.packages, notes);
    let mut config = Config::load_source_workspace(&current, &workspace, cli.max_packages)?;
    config.report_ignored(notes);
    let use_cargo_registry = crate::cargo_registry::selected(cli, &config);
    if use_cargo_registry {
        config.trust_cargo_cache();
    }
    let target_directory = package::path_utf8(
        &config.target_directory(&current, &workspace.root, None),
        "metadata target directory",
    )?;
    let set_target_directory = |document: &mut wire::Metadata| {
        document.target_directory.clone_from(&target_directory);
        document
            .build_directory
            .clone_from(&document.target_directory);
    };
    if options.no_deps {
        let mut document = graph::no_dependencies(&workspace)?;
        set_target_directory(&mut document);
        return write_document(&document);
    }
    if workspace.packages.is_empty() {
        return Err(Error::failure(
            "the manifest is virtual, and the workspace contains no package",
        ));
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
    // Extraction for inspection creates its own private directories here.
    let scratch = env::temp_dir();
    Progress::new(notes != Verbosity::Quiet).report("Verifying dependency state")?;
    let locked = dependency::LockedContext::open(
        manifest,
        &config,
        &toolchain,
        dependency::RegistryAccess {
            use_cargo_registry,
            validation: ValidationMode::Trusted,
            staging_parent: &scratch,
            evidence_root: &crate::engine::artifact_root(manifest).join(".cargo-evidence"),
        },
    )?;
    let (complete, catalog) = dependency::workspace::resolve_locked(
        &workspace,
        &config,
        locked.source(),
        &locked.direct,
        &locked.options,
        None,
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
        &locked.options,
        &members,
    )?;
    let prepared = dependency::workspace::prepare_sources(
        resolution,
        &config,
        locked.source(),
        &scratch,
        &locked.direct,
    )?;
    let cache_root = config.cache_directory()?;
    let roots = publish_source_parts(
        &cache_root,
        &config,
        &prepared.resolution,
        &prepared.packages,
        ValidationMode::Trusted,
    )?;
    let mut document =
        graph::workspace::resolved(&workspace, &prepared, &roots, platform.as_ref())?;
    set_target_directory(&mut document);
    write_document(&document)
}

fn warn_default_format(notes: Verbosity, options: &MetadataOptions) {
    if !options.format_version_explicit && notes != Verbosity::Quiet {
        eprintln!(
            "warning: please specify `--format-version` flag explicitly to avoid compatibility problems"
        );
    }
}

pub(crate) fn publish_sources(
    cache_root: &std::path::Path,
    config: &Config,
    prepared: &PreparedGraph,
    validation: ValidationMode,
) -> Result<BTreeMap<PackageKey, PathBuf>> {
    publish_source_parts(
        cache_root,
        config,
        &prepared.resolution,
        &prepared.packages,
        validation,
    )
}

fn publish_source_parts(
    cache_root: &std::path::Path,
    config: &Config,
    resolution: &Resolution,
    packages: &BTreeMap<PackageKey, PreparedPackage>,
    validation: ValidationMode,
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
                // Builds compile Cargo's own extraction, so messages and
                // metadata name it, as Cargo does, instead of a copy.
                ResolvedSource::CratesIo { .. } if prepared_package.in_cargo_registry() => {
                    prepared_package.source_root().to_owned()
                }
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
                        validation,
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
