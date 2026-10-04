use super::*;
use crate::manifest::SourceWorkspace;
use crate::resolver::workspace::resolve_complete_workspace;

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
    let mut catalog = locked_catalog(context, config, source, Some(direct))?;
    catalog.use_fetch_hint();
    let complete = resolve_complete_workspace(
        workspace,
        &mut catalog,
        options,
        &LockedPreference::from_lockfile(Some(lock))?,
        &mut |_, _, _| Ok(()),
    )?;
    offline::validate_workspace_resolution(lock, &complete)?;
    policy::preflight_sources(&config.policy, &complete)?;
    Ok((complete, catalog))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
