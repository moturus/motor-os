use super::*;
use crate::manifest::SourceWorkspace;
use crate::resolver::workspace::resolve_locked_workspace;

pub(crate) mod admission;

/// Inspected sources carry no execution admission. Metadata and fetch can use
/// them even when build scripts and procedural macros have no allow rules.
#[derive(Debug)]
pub(crate) struct PreparedSources {
    pub resolution: Resolution,
    pub packages: BTreeMap<PackageKey, PreparedPackage>,
}

pub(crate) fn resolve_locked(
    workspace: &SourceWorkspace,
    config: &Config,
    source: RegistrySource<'_>,
    direct: &crate::git::DirectCatalog,
    options: &Options,
) -> Result<(Resolution, Catalog)> {
    let context = workspace
        .packages
        .first()
        .ok_or_else(|| Error::failure("an empty workspace has no dependency graph to prepare"))?;
    let lock = context
        .lock
        .as_ref()
        .ok_or_else(|| Error::failure("workspace dependency preparation requires Cargo.lock"))?;
    let mut catalog = locked_catalog(context, source, direct, true)?;
    catalog.use_fetch_hint();
    let complete = resolve_locked_workspace(
        workspace,
        &mut catalog,
        options,
        lock,
        &mut |_, _, _| Ok(()),
    )?;
    offline::validate_workspace_resolution(lock, &complete)?;
    policy::preflight_sources(&config.policy, &complete)?;
    Ok((complete, catalog))
}

/// Resolve ordinary compilation without admission only for path packages or the
/// explicit Cargo-registry mode. Source inspection refines host macro contexts;
/// it never executes package code or grants capabilities.
pub(crate) fn resolve_compilation(
    inputs: &ReviewInputs<'_>,
    workspace: &SourceWorkspace,
    members: &[crate::resolver::workspace::MemberRequest],
    selection: TargetSelection<'_>,
) -> Result<Resolution> {
    let direct = inputs
        .direct
        .ok_or_else(|| Error::failure("workspace compilation requires locked Git sources"))?;
    let (complete, mut catalog) = resolve_locked(
        workspace,
        inputs.config,
        inputs.source,
        direct,
        inputs.options,
    )?;
    loop {
        let resolution = crate::resolver::workspace::resolve_selected_workspace(
            &complete,
            &catalog,
            inputs.options,
            members,
            selection,
        )?;
        if matches!(inputs.source, RegistrySource::Lorry(_))
            && resolution.packages.iter().any(|package| {
                matches!(
                    package.source,
                    ResolvedSource::CratesIo { .. } | ResolvedSource::Git { .. }
                )
            })
        {
            return Err(Error::failure(
                "compilation using crates.io or Git packages requires workspace admission",
            ).with_help("run workspace-root `lorry vendor --locked [--offline]` to review and approve these sources"));
        }
        let inspected = prepare_sources(
            resolution.clone(),
            inputs.config,
            inputs.source,
            inputs.staging_parent,
            direct,
        )?;
        let mut refined = false;
        for (key, package) in inspected.packages {
            if key.source == PackageSourceKey::CratesIo {
                refined |= catalog.annotate_proc_macro(&key, package.evidence.proc_macro)?;
            }
        }
        if !refined {
            return Ok(resolution);
        }
    }
}

pub(crate) fn prepare_sources(
    resolution: Resolution,
    config: &Config,
    source: RegistrySource<'_>,
    staging_parent: &Path,
    direct: &crate::git::DirectCatalog,
) -> Result<PreparedSources> {
    policy::preflight_sources(&config.policy, &resolution)?;
    let packages =
        prepare_resolution_packages(&resolution, config, source, staging_parent, direct, true)?;
    let evidence = packages
        .iter()
        .map(|(key, package)| (key.clone(), package.evidence.clone()))
        .collect();
    policy::inspect_sources(&config.policy, &resolution, &evidence)?;
    Ok(PreparedSources {
        resolution,
        packages,
    })
}

pub(crate) fn prepare_compilation(
    mut resolution: Resolution,
    config: &Config,
    source: RegistrySource<'_>,
    staging_parent: &Path,
    direct: &crate::git::DirectCatalog,
) -> Result<PreparedGraph> {
    let selected = resolution
        .root_edges
        .iter()
        .map(|edge| edge.package.clone())
        .collect::<Vec<_>>();
    compilation_manifests(&mut resolution, &selected)?;
    policy::preflight_sources(&config.policy, &resolution)?;
    let preflight = policy::preflight_workspace(&config.policy, &resolution)?;
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

// Compiler loading validates executable target descriptions. Preserve the
// workspace ownership that also defines member source identity and freshness.
pub(super) fn compilation_manifests(
    resolution: &mut Resolution,
    selected: &[PackageKey],
) -> Result<()> {
    for package in &mut resolution.packages {
        if let Some(manifest) = &package.local_manifest {
            let mut compilation = if manifest.editable
                && (selected.contains(&package.key) || manifest.library.is_none())
            {
                Manifest::load_compilation_member(manifest)?
            } else {
                Manifest::load_path_dependency(&manifest.root)?
            };
            compilation.editable = manifest.editable;
            compilation
                .workspace_root
                .clone_from(&manifest.workspace_root);
            compilation
                .workspace_members
                .clone_from(&manifest.workspace_members);
            package.local_manifest = Some(compilation);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn selected_library_members_retain_binary_targets_during_preparation() {
        let fixture = super::super::tests::Fixture::new();
        fs::write(fixture.0.join("Cargo.toml"), "[package]\nname = \"root\"\nversion = \"1.0.0\"\nedition = \"2024\"\n[workspace]\nmembers = [\"other\"]\ndefault-members = [\"other\"]\nresolver = \"2\"\n").unwrap();
        fs::write(fixture.0.join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::create_dir_all(fixture.0.join("other/src")).unwrap();
        fs::write(fixture.0.join("other/src/lib.rs"), "").unwrap();
        fs::write(
            fixture.0.join("other/Cargo.toml"),
            "[package]\nname = \"other\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        fs::write(fixture.0.join("Cargo.lock"), "version = 4\n[[package]]\nname = \"root\"\nversion = \"1.0.0\"\n[[package]]\nname = \"other\"\nversion = \"1.0.0\"\n").unwrap();
        for library in [true, false] {
            if !library {
                fs::remove_file(fixture.0.join("src/lib.rs")).unwrap();
            }
            let mut workspace = SourceWorkspace::load(&fixture.0, None).unwrap();
            workspace.load_locked_context().unwrap();
            let config = Config::default();
            let repositories = RepositorySet::open(
                &config.repositories,
                crate::source_tree::DEFAULT_LIMITS,
                config.policy.limits.max_package_bytes,
            )
            .unwrap();
            let source = RegistrySource::Lorry(&repositories);
            let direct = crate::git::DirectCatalog::default();
            let options = super::super::tests::options(&workspace.packages[0]);
            let (complete, catalog) =
                resolve_locked(&workspace, &config, source, &direct, &options).unwrap();
            let members = crate::resolver::workspace::features::member_requests(
                &workspace,
                &[fixture.0.clone()].into(),
                &crate::cli::FeatureSelection::default(),
                false,
            )
            .unwrap();
            let cfg = crate::toolchain::CfgSet::parse("unix\n").unwrap();
            let selected = crate::resolver::workspace::resolve_selected_workspace(
                &complete,
                &catalog,
                &options,
                &members,
                TargetSelection {
                    host_triple: "x86_64-unknown-linux-gnu",
                    host_cfg: &cfg,
                    target_triple: "x86_64-unknown-linux-gnu",
                    target_cfg: &cfg,
                },
            )
            .unwrap();
            let prepared =
                prepare_compilation(selected, &config, source, &fixture.0, &direct).unwrap();
            assert_eq!(prepared.packages.len(), 1);
            let root = &prepared.packages.values().next().unwrap().manifest;
            assert_eq!(root.name, "root");
            assert_eq!(root.root, fixture.0);
            assert_eq!(root.library.is_some(), library);
            assert_eq!(
                root.targets_of(crate::manifest::TargetKind::Bin)
                    .map(|target| target.name.as_str())
                    .collect::<Vec<_>>(),
                ["root"]
            );
        }
    }

    #[test]
    fn compilation_preparation_retains_member_roots_and_requires_execution_grants() {
        let fixture = super::super::tests::Fixture::new();
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[workspace]\nmembers = [\"app\", \"shared\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        for member in ["app", "shared"] {
            let root = fixture.0.join(member);
            fs::create_dir_all(root.join("src")).unwrap();
            fs::write(
                root.join("Cargo.toml"),
                format!(
                    "[package]\nname = \"{member}\"\nversion = \"1.0.0\"\nedition = \"2024\"\n"
                ),
            )
            .unwrap();
        }
        fs::write(fixture.0.join("app/Cargo.toml"), "[package]\nname = \"app\"\nversion = \"1.0.0\"\nedition = \"2024\"\n[dependencies]\nshared = { path = \"../shared\" }\n").unwrap();
        fs::write(fixture.0.join("app/src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(fixture.0.join("shared/src/lib.rs"), "pub fn shared() {}\n").unwrap();
        fs::write(
            fixture.0.join("shared/build.rs"),
            format!(
                "fn main() {{ std::fs::write({:?}, \"executed\").unwrap(); }}\n",
                fixture.0.join("executed")
            ),
        )
        .unwrap();
        fs::write(fixture.0.join("Cargo.lock"), "version = 4\n[[package]]\nname = \"app\"\nversion = \"1.0.0\"\ndependencies = [\"shared\"]\n[[package]]\nname = \"shared\"\nversion = \"1.0.0\"\n").unwrap();
        let mut workspace = SourceWorkspace::load(&fixture.0, None).unwrap();
        workspace.load_locked_context().unwrap();
        let mut config = Config::default();
        let repositories = RepositorySet::open(
            &config.repositories,
            crate::source_tree::DEFAULT_LIMITS,
            config.policy.limits.max_package_bytes,
        )
        .unwrap();
        let source = RegistrySource::Lorry(&repositories);
        let direct = crate::git::DirectCatalog::default();
        let options = super::super::tests::options(&workspace.packages[0]);
        let (complete, catalog) =
            resolve_locked(&workspace, &config, source, &direct, &options).unwrap();
        let cfg = crate::toolchain::CfgSet::parse("unix\n").unwrap();
        let members = crate::resolver::workspace::features::member_requests(
            &workspace,
            &[fixture.0.join("app")].into(),
            &crate::cli::FeatureSelection::default(),
            false,
        )
        .unwrap();
        let selected = crate::resolver::workspace::resolve_selected_workspace(
            &complete,
            &catalog,
            &options,
            &members,
            TargetSelection {
                host_triple: "x86_64-unknown-linux-gnu",
                host_cfg: &cfg,
                target_triple: "x86_64-unknown-linux-gnu",
                target_cfg: &cfg,
            },
        )
        .unwrap();
        let before = selected
            .packages
            .iter()
            .map(|package| {
                (
                    package.key.clone(),
                    PackageEvidence::from_path(package).unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let error = prepare_compilation(selected.clone(), &config, source, &fixture.0, &direct)
            .unwrap_err();
        assert!(
            error
                .render()
                .contains("contains a build script without an explicit matching policy grant"),
            "{}",
            error.render()
        );
        let shared = selected
            .packages
            .iter()
            .find(|package| package.key.name == "shared")
            .unwrap();
        config.policy.rules.insert(
            "shared-script".into(),
            crate::config::PolicyRule {
                action: crate::config::PolicyAction::Allow,
                name: Some("shared".into()),
                version: Some(semver::VersionReq::parse("=1.0.0").unwrap()),
                source: Some("path".into()),
                checksum: None,
                source_tree_sha256: Some(hex(&before[&shared.key].source_tree_sha256)),
                license: None,
                allow_build_script: true,
                allow_proc_macro: false,
                native_tools: BTreeSet::new(),
                caller_env: Default::default(),
                provenance: fixture.0.join("lorry.toml"),
            },
        );
        let prepared = prepare_compilation(selected, &config, source, &fixture.0, &direct).unwrap();
        assert_eq!(prepared.resolution.root_edges.len(), 1);
        assert_eq!(prepared.packages.len(), 2);
        for (key, package) in &prepared.packages {
            assert_eq!(package.evidence, before[key]);
            assert_eq!(package.manifest.workspace_root, workspace.root);
            assert!(package.manifest.editable);
        }
        let app = prepared
            .packages
            .keys()
            .find(|key| key.name == "app")
            .unwrap()
            .clone();
        assert!(prepared.packages[&app].manifest.library.is_none());
        assert_eq!(
            prepared.packages[&app]
                .manifest
                .targets_of(crate::manifest::TargetKind::Bin)
                .count(),
            1
        );
        let toolchain = Toolchain::discover(None, &config, false).unwrap();
        let plan = prepared
            .workspace_plan(
                &PlanOptions {
                    workspace_root: &workspace.root,
                    release: false,
                    panic_abort: false,
                    dev_profile: &workspace.packages[0].dev,
                    release_profile: &workspace.packages[0].release,
                    rustc: &toolchain,
                    logical_target: None,
                    rustflags: &[],
                },
                &[app],
                false,
                true,
                None,
            )
            .unwrap();
        assert_eq!(plan.units.len(), 4);
        assert!(!fixture.0.join("executed").exists());
        assert!(!fixture.0.join("target").exists());
        assert!(!fixture.0.join(".lorry").exists());
    }

    #[test]
    fn complete_workspace_sources_do_not_execute_or_create_admission() {
        let fixture = super::super::tests::Fixture::new();
        for member in ["app", "shared"] {
            fs::create_dir_all(fixture.0.join(member).join("src")).unwrap();
            fs::write(
                fixture.0.join(member).join("src/lib.rs"),
                "pub fn member() {}\n",
            )
            .unwrap();
        }
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[workspace]\nmembers = [\"app\", \"shared\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        fs::write(
            fixture.0.join("app/Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"1.0.0\"\n\
             [dependencies]\nshared = { path = \"../shared\" }\n",
        )
        .unwrap();
        fs::write(
            fixture.0.join("shared/Cargo.toml"),
            "[package]\nname = \"shared\"\nversion = \"1.0.0\"\n\
             [lib]\nproc-macro = true\n",
        )
        .unwrap();
        fs::write(
            fixture.0.join("shared/build.rs"),
            "compile_error!(\"source preparation must not compile this\");\n",
        )
        .unwrap();
        let lock = "version = 4\n\
            [[package]]\nname = \"app\"\nversion = \"1.0.0\"\ndependencies = [\"shared\"]\n\
            [[package]]\nname = \"shared\"\nversion = \"1.0.0\"\n";
        fs::write(fixture.0.join("Cargo.lock"), lock).unwrap();
        let mut workspace = SourceWorkspace::load(&fixture.0, None).unwrap();
        workspace.load_locked_context().unwrap();
        let config = Config::default();
        let repositories = RepositorySet::open(
            &crate::config::Repositories::default(),
            crate::source_tree::DEFAULT_LIMITS,
            config.policy.limits.max_package_bytes,
        )
        .unwrap();
        let direct = crate::git::DirectCatalog::default();
        let source = RegistrySource::Lorry(&repositories);
        let (complete, _) = resolve_locked(
            &workspace,
            &config,
            source,
            &direct,
            &super::super::tests::options(&workspace.packages[0]),
        )
        .unwrap();
        let staging = fixture.0.join("unused-staging");
        let prepared = prepare_sources(complete, &config, source, &staging, &direct).unwrap();
        assert_eq!(prepared.packages.len(), 2);
        assert!(
            prepared
                .packages
                .values()
                .any(|package| package.evidence.proc_macro && package.evidence.build_script)
        );
        assert!(!staging.exists());
        assert!(!fixture.0.join("target").exists());
        assert!(!fixture.0.join(".lorry").exists());
        assert_eq!(
            fs::read_to_string(fixture.0.join("Cargo.lock")).unwrap(),
            lock
        );
    }
}
