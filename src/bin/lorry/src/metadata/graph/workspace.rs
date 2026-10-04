use super::*;
use crate::dependency::workspace::PreparedSources;
use crate::resolver::Resolution;
use crate::toolchain::TargetInfo;

pub(crate) fn resolved(
    workspace: &SourceWorkspace,
    prepared: &PreparedSources,
    presented_roots: &BTreeMap<PackageKey, PathBuf>,
    platform: Option<&TargetInfo>,
) -> Result<wire::Metadata> {
    let edges = platform_edges(&prepared.resolution, platform)?;
    let mut ids = BTreeMap::new();
    let mut dependency_roots = BTreeMap::new();
    for package in &prepared.resolution.packages {
        let manifest = &prepared.packages[&package.key].manifest;
        ids.insert(
            package.key.clone(),
            package::package_id(manifest, Identity::Resolved(package))?,
        );
        dependency_roots.insert(
            fs::canonicalize(&manifest.root).map_err(path_error)?,
            fs::canonicalize(&presented_roots[&package.key]).map_err(path_error)?,
        );
    }
    let mut pending = prepared
        .resolution
        .root_edges
        .iter()
        .map(|edge| edge.package.clone())
        .collect::<Vec<_>>();
    let mut reachable = BTreeSet::new();
    while let Some(key) = pending.pop() {
        if reachable.insert(key.clone()) {
            pending.extend(edges[&key].iter().map(|edge| edge.package.clone()));
        }
    }
    let mut packages = Vec::new();
    let mut nodes = Vec::new();
    for resolved in &prepared.resolution.packages {
        if !reachable.contains(&resolved.key) {
            continue;
        }
        let manifest = &prepared.packages[&resolved.key].manifest;
        packages.push(package::map(
            manifest,
            Identity::Resolved(resolved),
            &presented_roots[&resolved.key],
            &dependency_roots,
        )?);
        nodes.push(map_node(
            &ids[&resolved.key],
            &edges[&resolved.key],
            manifest,
            resolved
                .target_features
                .union(&resolved.host_features)
                .cloned()
                .collect(),
            &ids,
        )?);
    }
    let order = ids
        .iter()
        .map(|(key, id)| Ok((id.clone(), package_order(key)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    packages.sort_by(|left, right| order[&left.id].cmp(&order[&right.id]));
    nodes.sort_by(|left, right| order[&left.id].cmp(&order[&right.id]));
    let members = workspace
        .packages
        .iter()
        .map(|member| package::package_id(member, Identity::Root))
        .collect::<Result<BTreeSet<_>>>()?;
    let defaults = workspace
        .packages
        .iter()
        .filter(|member| workspace.default_members.contains(&member.root))
        .map(|member| package::package_id(member, Identity::Root))
        .collect::<Result<BTreeSet<_>>>()?;
    let current = workspace
        .packages
        .iter()
        .find(|member| Some(member.root.as_path()) == workspace.manifest_path.parent())
        .map(|member| package::package_id(member, Identity::Root))
        .transpose()?;
    finish(
        &workspace.root,
        members.into_iter().collect(),
        defaults.into_iter().collect(),
        packages,
        Some(wire::Resolve {
            nodes,
            root: current,
        }),
        workspace.metadata.clone(),
    )
}

fn platform_edges(
    resolution: &Resolution,
    platform: Option<&TargetInfo>,
) -> Result<BTreeMap<PackageKey, Vec<ResolvedEdge>>> {
    resolution
        .packages
        .iter()
        .map(|package| {
            let mut retained = BTreeSet::new();
            for edge in &package.edges {
                let active = match (platform, edge.target.as_deref()) {
                    (None, _) | (_, None) => true,
                    (Some(platform), Some(selector)) if selector.starts_with("cfg(") => {
                        platform.cfg.matches_selector(selector)?
                    }
                    (Some(platform), Some(selector)) => platform.triple == selector,
                };
                if active {
                    retained.insert(edge.package.clone());
                }
            }
            // Cargo filters package pairs, then reports every declaration of a
            // retained pair, including declarations on another platform.
            Ok((
                package.key.clone(),
                package
                    .edges
                    .iter()
                    .filter(|edge| retained.contains(&edge.package))
                    .cloned()
                    .collect(),
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::dependency::{RegistrySource, workspace as sources};
    use crate::resolver::{Options, workspace as solver};
    use std::process::Command;

    #[test]
    fn resolved_workspace_document_matches_cargo_with_platform_and_development_edges() {
        let fixture =
            crate::atomic::AtomicDirectory::new(&std::env::temp_dir(), "lorry-workspace-metadata")
                .unwrap();
        let root = fixture.path();
        fs::write(root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"app\", \"shared\"]\nexclude = [\"windows-only\"]\nresolver = \"2\"\ndefault-members = [\"app\"]\n").unwrap();
        for name in ["app", "shared", "windows-only"] {
            fs::create_dir_all(root.join(name).join("src")).unwrap();
            fs::write(root.join(name).join("src/lib.rs"), "pub fn package() {}\n").unwrap();
            let declarations = if name == "app" {
                "[dependencies]\nshared = { path = \"../shared\" }\n\
                 [dev-dependencies]\nshared = { path = \"../shared\", features = [\"dev\"] }\n\
                 [target.'cfg(windows)'.dependencies]\nshared = { path = \"../shared\", features = [\"windows\"] }\n\
                 windows-only = { path = \"../windows-only\" }\n\
                 [[bin]]\nname = \"app\"\nrequired-features = []\n"
            } else {
                "[features]\ndev = []\nwindows = []\n"
            };
            fs::write(root.join(name).join("Cargo.toml"), format!(
                "[package]\nname = {name:?}\nversion = \"1.0.0\"\nedition = \"2021\"\n{declarations}")).unwrap();
        }
        fs::write(root.join("app/src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(root.join("windows-only/src/main.rs"), "fn main() {}\n").unwrap();
        fs::create_dir_all(root.join("windows-only/examples")).unwrap();
        fs::create_dir_all(root.join("windows-only/benches")).unwrap();
        fs::write(root.join("windows-only/benches/speed.rs"), "fn main() {}\n").unwrap();
        fs::write(root.join("windows-only/build.rs"), "fn main() {}\n").unwrap();
        fs::write(root.join("windows-only/examples/demo.rs"), "fn main() {}\n").unwrap();
        fs::write(
            root.join("windows-only/src/integration.rs"),
            "#[test] fn test() {}\n",
        )
        .unwrap();
        fs::write(
            root.join("windows-only/Cargo.toml"),
            "[package]\nname = \"windows-only\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\
             [lib]\ncrate-type = [\"staticlib\"]\n\
             [dev-dependencies]\nshared = { path = \"../shared\", features = [\"dev\"] }\n\
             unprepared-registry = \"987654321\"\n\
             [[test]]\nname = \"integration\"\npath = \"src/integration.rs\"\n",
        )
        .unwrap();
        let cargo = |platform: Option<&str>| {
            let mut command = Command::new(env!("CARGO"));
            command
                .current_dir(root)
                .env(
                    "RUSTC",
                    Path::new(env!("CARGO")).parent().unwrap().join("rustc"),
                )
                .args(["metadata", "--offline", "--format-version=1"]);
            if let Some(platform) = platform {
                command.args(["--filter-platform", platform]);
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
        };
        let expected = cargo(None);
        let mut workspace = SourceWorkspace::load(root, None).unwrap();
        workspace.load_locked_context().unwrap();
        let config = Config::default();
        let repositories = crate::repository::RepositorySet::open(
            &config.repositories,
            crate::source_tree::DEFAULT_LIMITS,
            config.policy.limits.max_package_bytes,
        )
        .unwrap();
        let registry = RegistrySource::Lorry(&repositories);
        let direct = crate::git::DirectCatalog::default();
        let options = Options {
            resolver: workspace.packages[0].resolver,
            incompatible_rust_versions: config.incompatible_rust_versions,
            rust_versions: vec![semver::Version::new(1, 99, 0)],
            package_limit: crate::policy::PackageLimit::new(
                &config.policy.limits,
                &workspace.packages[0],
            ),
            max_depth: config.policy.limits.max_depth,
        };
        let (complete, catalog) =
            sources::resolve_locked(&workspace, &config, registry, &direct, &options).unwrap();
        let members = solver::features::member_requests(
            &workspace,
            &workspace
                .packages
                .iter()
                .map(|member| member.root.clone())
                .collect(),
            &crate::cli::FeatureSelection::default(),
            true,
        )
        .unwrap();
        let resolution =
            solver::resolve_metadata_workspace(&complete, &catalog, &options, &members).unwrap();
        let prepared = sources::prepare_sources(
            resolution,
            &config,
            registry,
            &root.join("staging"),
            &direct,
        )
        .unwrap();
        let roots = prepared
            .packages
            .iter()
            .map(|(key, package)| (key.clone(), package.source_root().to_owned()))
            .collect();
        let actual =
            serde_json::to_value(resolved(&workspace, &prepared, &roots, None).unwrap()).unwrap();
        assert_eq!(actual, expected);
        let platform = TargetInfo {
            triple: "x86_64-unknown-linux-gnu".to_owned(),
            cfg: crate::toolchain::CfgSet::parse("unix\ntarget_os=\"linux\"\n").unwrap(),
        };
        assert_eq!(
            serde_json::to_value(resolved(&workspace, &prepared, &roots, Some(&platform)).unwrap())
                .unwrap(),
            cargo(Some(&platform.triple))
        );
        workspace.manifest_path = root.join("app/Cargo.toml");
        let document = resolved(&workspace, &prepared, &roots, None).unwrap();
        assert!(
            document
                .resolve
                .unwrap()
                .root
                .unwrap()
                .ends_with("/app#1.0.0")
        );
        assert!(!root.join(".lorry").exists());
    }
}
