use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::io::{self, Write};

use crate::cli::{Cli, TreeOptions, Verbosity};
use crate::config::Config;
use crate::dependency::{self, LockedContext, RegistryAccess, workspace::PreparedSources};
use crate::diagnostic::{Error, Result};
use crate::manifest::{Manifest, SourceWorkspace};
use crate::progress::Progress;
use crate::resolver::workspace::{features::member_requests, resolve_selected_workspace};
use crate::resolver::{
    CompileKind, FeatureContext, PackageKey, ResolvedEdge, ResolvedSource, TargetSelection,
};
use crate::sparse::DependencyKind;
use crate::toolchain::Toolchain;
use crate::validation::ValidationMode;

pub fn execute(cli: &Cli, options: &TreeOptions) -> Result<i32> {
    crate::cargo_registry::with_fallback(cli, |cli, notes| execute_with(cli, notes, options))
}

fn execute_with(cli: &Cli, notes: Verbosity, options: &TreeOptions) -> Result<i32> {
    let current = env::current_dir()
        .map_err(|error| Error::failure(format!("failed to read current directory: {error}")))?;
    let mut workspace = SourceWorkspace::load(
        &current,
        cli.manifest_path.as_deref().map(std::path::Path::new),
    )?;
    let (roots, warnings) = cli.selection.select(
        workspace
            .packages
            .iter()
            .map(|member| (member.name.as_str(), &member.version, member.root.as_path())),
        workspace.default_members.iter().map(|root| root.as_path()),
    )?;
    if notes != Verbosity::Quiet {
        for warning in warnings {
            eprintln!("warning: {warning}");
        }
    }
    workspace.load_locked_context()?;
    let manifest = &workspace.packages[0];
    let mut config = Config::load_source_workspace(&current, &workspace, cli.max_packages)?;
    let use_cargo_registry = crate::cargo_registry::selected(cli, &config);
    if use_cargo_registry {
        config.trust_cargo_cache();
    }
    Manifest::report_warnings(&workspace.packages, notes);
    let toolchain = Toolchain::discover(cli.toolchain.as_deref(), &config, false)?;
    let physical_target = config.selected_target(options.target.as_deref())?;
    let target = toolchain.target_info(physical_target.as_deref())?;
    let host = if physical_target.is_some() {
        toolchain.target_info(None)?
    } else {
        target.clone()
    };
    if notes == Verbosity::Verbose {
        eprintln!(
            "Using {} (rustc {}, Cargo {:?} compatibility)",
            toolchain.rustc.display(),
            toolchain.release,
            toolchain.compatibility
        );
    }

    // Extraction for inspection creates its own private directories here.
    let scratch = env::temp_dir();
    Progress::new(notes != Verbosity::Quiet).report("Verifying dependency state")?;
    let locked = LockedContext::open(
        manifest,
        &config,
        &toolchain,
        RegistryAccess {
            use_cargo_registry,
            validation: ValidationMode::Trusted,
            staging_parent: &scratch,
            evidence_root: &crate::engine::artifact_root(manifest).join(".cargo-evidence"),
        },
    )?;
    let selection = TargetSelection {
        target_triple: &target.triple,
        target_cfg: &target.cfg,
        host_triple: &host.triple,
        host_cfg: &host.cfg,
    };
    let (complete, mut catalog) = dependency::workspace::resolve_locked(
        &workspace,
        &config,
        locked.source(),
        &locked.direct,
        &locked.options,
        None,
    )?;
    let requests = member_requests(
        &workspace,
        &roots.iter().cloned().collect(),
        &cli.features,
        false,
    )?;
    Progress::new(cli.verbosity != Verbosity::Quiet).report("Preparing dependency graph")?;
    let prepared = dependency::workspace::inspect_selected(
        &mut catalog,
        &config,
        locked.source(),
        &scratch,
        &locked.direct,
        |catalog| {
            resolve_selected_workspace(&complete, catalog, &locked.options, &requests, selection)
        },
    )?;
    // Like Cargo, print the roots in package-id order.
    let mut roots = prepared.resolution.root_edges.iter().collect::<Vec<_>>();
    roots.sort_by(|left, right| left.package.cmp(&right.package));
    let rendered = roots
        .into_iter()
        .map(|edge| {
            let root = prepared
                .resolution
                .packages
                .iter()
                .find(|package| package.key == edge.package)
                .ok_or_else(|| Error::failure("dependency tree omits a selected workspace root"))?;
            render(root, edge.compile_kind, &prepared)
        })
        .collect::<Result<Vec<_>>>()?
        .join("\n");
    io::stdout()
        .write_all(rendered.as_bytes())
        .map_err(|error| Error::failure(format!("failed to write dependency tree: {error}")))?;
    Ok(0)
}

fn render(
    root: &crate::resolver::ResolvedPackage,
    kind: CompileKind,
    prepared: &PreparedSources,
) -> Result<String> {
    let packages = prepared
        .resolution
        .packages
        .iter()
        .map(|package| (package.key.clone(), package))
        .collect::<BTreeMap<_, _>>();
    let mut output = format!(
        "{}\n",
        package_line(root, &prepared.packages[&root.key].manifest)?
    );
    let mut expanded = BTreeSet::new();
    render_children(
        &mut output,
        "",
        &root.edges,
        Some(kind),
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
    prepared: &PreparedSources,
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
