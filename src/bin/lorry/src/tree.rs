use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{self, Write};

use crate::admission_state::{CompactState, Context};
use crate::atomic::AtomicDirectory;
use crate::cargo_registry::CargoRegistry;
use crate::cli::{Cli, TreeOptions, Verbosity};
use crate::config::Config;
use crate::dependency::{self, PreparedGraph};
use crate::diagnostic::{Error, Result};
use crate::manifest::Manifest;
use crate::progress::Progress;
use crate::repository::RepositorySet;
use crate::resolver::{
    CompileKind, FeatureContext, PackageKey, ResolvedEdge, ResolvedSource, TargetSelection,
};
use crate::sparse::DependencyKind;
use crate::toolchain::Toolchain;
use crate::validation::ValidationMode;

pub fn execute(cli: &Cli, options: &TreeOptions) -> Result<i32> {
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
    let physical_target = config.selected_target(options.target.as_deref())?;
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

    let compact_state = CompactState::load(&manifest.root)?;
    if let Some(compact) = &compact_state {
        compact.require_context(&host.triple, &target.triple)?;
    }
    let staging = AtomicDirectory::new(&env::temp_dir(), "lorry-tree")?;
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
    let rendered = render(&manifest, &prepared)?;
    io::stdout()
        .write_all(rendered.as_bytes())
        .map_err(|error| Error::failure(format!("failed to write dependency tree: {error}")))?;
    Ok(0)
}

fn render(root: &Manifest, prepared: &PreparedGraph) -> Result<String> {
    let packages = prepared
        .resolution
        .packages
        .iter()
        .map(|package| (package.key.clone(), package))
        .collect::<BTreeMap<_, _>>();
    let mut output = format!(
        "{} v{} ({})\n",
        root.name,
        root.version.original,
        utf8(&fs::canonicalize(&root.root).map_err(path_error)?)?
    );
    let mut expanded = BTreeSet::new();
    render_children(
        &mut output,
        "",
        &prepared.resolution.root_edges,
        None,
        prepared,
        &packages,
        &mut expanded,
    )?;
    Ok(output)
}

fn render_children(
    output: &mut String,
    prefix: &str,
    edges: &[ResolvedEdge],
    parent_compile_kind: Option<CompileKind>,
    prepared: &PreparedGraph,
    packages: &BTreeMap<PackageKey, &crate::resolver::ResolvedPackage>,
    expanded: &mut BTreeSet<(PackageKey, CompileKind, FeatureContext)>,
) -> Result<()> {
    let mut groups = BTreeMap::<u8, BTreeSet<(PackageKey, CompileKind, FeatureContext)>>::new();
    for edge in edges {
        if edge.parent_compile_kind != parent_compile_kind {
            continue;
        }
        let group = match edge.kind {
            DependencyKind::Normal => 0,
            DependencyKind::Build => 1,
            DependencyKind::Dev => {
                return Err(Error::failure(
                    "selected dependency tree contains a dev-dependency edge",
                ));
            }
        };
        groups.entry(group).or_default().insert((
            edge.package.clone(),
            edge.compile_kind,
            edge.context.clone(),
        ));
    }
    for group in [0, 1] {
        let Some(children) = groups.get(&group) else {
            continue;
        };
        if group == 1 {
            output.push_str(prefix);
            output.push_str("[build-dependencies]\n");
        }
        for (index, child) in children.iter().enumerate() {
            let (key, compile_kind, context) = child;
            let last = index + 1 == children.len();
            let package = packages.get(key).ok_or_else(|| {
                Error::failure(format!(
                    "dependency tree references unresolved package `{} {}`",
                    key.name, key.version
                ))
            })?;
            let prepared_package = prepared.packages.get(key).ok_or_else(|| {
                Error::failure(format!(
                    "prepared graph omits tree package `{} {}`",
                    key.name, key.version
                ))
            })?;
            output.push_str(prefix);
            output.push_str(if last { "└── " } else { "├── " });
            output.push_str(&package_line(package, &prepared_package.manifest)?);
            let has_children = package
                .edges
                .iter()
                .any(|edge| edge.parent_compile_kind == Some(*compile_kind));
            if has_children && !expanded.insert((key.clone(), *compile_kind, context.clone())) {
                output.push_str(" (*)\n");
                continue;
            }
            output.push('\n');
            if has_children {
                let mut child_prefix = prefix.to_owned();
                child_prefix.push_str(if last { "    " } else { "│   " });
                render_children(
                    output,
                    &child_prefix,
                    &package.edges,
                    Some(*compile_kind),
                    prepared,
                    packages,
                    expanded,
                )?;
            }
        }
    }
    Ok(())
}

fn package_line(package: &crate::resolver::ResolvedPackage, manifest: &Manifest) -> Result<String> {
    let mut line = format!("{} v{}", package.key.name, package.key.version);
    if manifest
        .library
        .as_ref()
        .is_some_and(|library| library.proc_macro)
    {
        line.push_str(" (proc-macro)");
    }
    match &package.source {
        ResolvedSource::CratesIo { .. } => {}
        ResolvedSource::Path { logical_root, .. } => {
            line.push_str(&format!(" ({})", utf8(logical_root)?));
        }
        ResolvedSource::Git { cargo_source, .. } => {
            let locked = crate::git::parse_locked_source(cargo_source)?;
            let source = cargo_source
                .strip_prefix("git+")
                .and_then(|value| value.rsplit_once('#').map(|(remote, _)| remote))
                .ok_or_else(|| Error::failure("invalid resolved Git source identity"))?;
            line.push_str(&format!(" ({source}#{})", &locked.commit[..8]));
        }
    }
    Ok(line)
}

fn utf8(path: &std::path::Path) -> Result<&str> {
    path.to_str().ok_or_else(|| {
        Error::failure(format!(
            "dependency tree path is not valid UTF-8: {}",
            path.display()
        ))
    })
}

fn path_error(error: std::io::Error) -> Error {
    Error::failure(format!(
        "failed to canonicalize dependency tree path: {error}"
    ))
}
