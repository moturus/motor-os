use super::*;
use crate::manifest::SourceWorkspace;

/// Seed ordinary member packages into one solver, including every optional
/// member feature. The returned root edges name the members themselves.
pub(crate) fn resolve_complete_workspace(
    workspace: &SourceWorkspace,
    catalog: &mut Catalog,
    options: &Options,
    locked: &[LockedPreference],
    loader: &mut dyn FnMut(&str, &VersionReq, &mut Catalog) -> Result<()>,
) -> Result<Resolution> {
    catalog.workspace_root.clone_from(&workspace.root);
    catalog.workspace_members = workspace
        .packages
        .iter()
        .map(|member| (member.name.clone(), member.root.clone()))
        .collect();
    let mut options = options.clone();
    let declared_rust_versions = workspace
        .packages
        .iter()
        .filter(|member| !member.metadata.rust_version.is_empty())
        .map(|member| {
            parse_local_rust_version(&member.name, &member.metadata.rust_version)
                .map(|version| version.version)
        })
        .collect::<Result<Vec<_>>>()?;
    if !declared_rust_versions.is_empty() {
        options.rust_versions = declared_rust_versions;
    }
    options.package_limit = options
        .package_limit
        .with_members(catalog.workspace_members.values().cloned());
    validate_locked_checksums(catalog, locked)?;
    let mut queue = VecDeque::new();
    for (index, member) in workspace.packages.iter().enumerate() {
        let mut member = member.clone();
        member
            .workspace_members
            .clone_from(&catalog.workspace_members);
        member.workspace_root.clone_from(&workspace.root);
        let checksum = crate::member_source::snapshot(&member, true)?.sha256;
        let records = catalog.records.entry(member.name.clone()).or_default();
        let patched = records.iter().any(|candidate| {
            matches!(
                &candidate.source,
                ResolvedSource::Path { logical_root, patched_crates_io: true, .. }
                    if logical_root == &member.root
            )
        });
        let candidate = local_candidate(
            member.clone(),
            member.root.clone(),
            member.root.clone(),
            checksum,
            patched,
        )?;
        let version = candidate.version.clone();
        let namespaced = member
            .features
            .values()
            .flatten()
            .filter_map(|reference| reference.strip_prefix("dep:"))
            .collect::<BTreeSet<_>>();
        let mut features = member.features.keys().cloned().collect::<BTreeSet<_>>();
        features.extend(
            member
                .dependencies
                .iter()
                .filter(|dependency| {
                    dependency.optional && !namespaced.contains(dependency.alias.as_str())
                })
                .map(|dependency| dependency.alias.clone()),
        );
        records.retain(|existing| {
            existing.source.key() != PackageSourceKey::Path(member.root.clone())
        });
        records.push(candidate);
        records.sort_unstable_by(|left, right| right.version.cmp(&left.version));
        catalog.paths.insert(
            member.root.clone(),
            PackageKey {
                name: member.name.clone(),
                version,
                source: PackageSourceKey::Path(member.root.clone()),
            },
        );
        let dependency = CandidateDependency {
            dependency: Dependency {
                alias: member.name.clone(),
                package: member.name.clone(),
                requirement: VersionReq::parse(&format!("={}", member.version.original))
                    .map_err(|error| Error::failure(format!("invalid member version: {error}")))?,
                features: features.into_iter().collect(),
                optional: false,
                default_features: true,
                target: None,
                kind: DependencyKind::Normal,
            },
            source: RequirementSource::Path(member.root),
        };
        queue.push_back(Event {
            parent: None,
            parent_compile_kind: None,
            dependency_index: index,
            context: root_context(options.resolver, Scope::WorkspaceComplete, &dependency),
            compile_kind: CompileKind::Target,
            dependency,
            depth: 0,
            ancestors: BTreeSet::new(),
        });
    }
    let resolution = solve_request(
        queue,
        catalog,
        &options,
        locked,
        Scope::WorkspaceComplete,
        loader,
    )?;
    let packages = resolution
        .packages
        .iter()
        .map(|package| (&package.key, package))
        .collect();
    let mut done = BTreeSet::new();
    let mut visiting = BTreeSet::new();
    for package in &resolution.packages {
        validate_cycles(&package.key, &packages, &mut done, &mut visiting)?;
    }
    Ok(resolution)
}

// Independently seeded roots may have sent their edges before another root
// reaches them, so event ancestry alone cannot prove workspace acyclicity.
fn validate_cycles<'a>(
    key: &'a PackageKey,
    packages: &BTreeMap<&'a PackageKey, &'a ResolvedPackage>,
    done: &mut BTreeSet<&'a PackageKey>,
    visiting: &mut BTreeSet<&'a PackageKey>,
) -> Result<()> {
    if done.contains(key) {
        return Ok(());
    }
    if !visiting.insert(key) {
        return Err(Error::failure(format!(
            "dependency cycle reaches `{} {}` again",
            key.name, key.version
        )));
    }
    for edge in &packages[key].edges {
        if edge.kind != DependencyKind::Dev {
            validate_cycles(&edge.package, packages, done, visiting)?;
        }
    }
    visiting.remove(key);
    done.insert(key);
    Ok(())
}
