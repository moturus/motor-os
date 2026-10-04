use super::*;
use crate::manifest::SourceWorkspace;

pub(crate) mod features;

pub(crate) struct MemberRequest {
    pub root: PathBuf,
    pub features: BTreeSet<String>,
    pub default_features: bool,
    pub dev: bool,
    pub selected: bool,
}

/// Recompute features and reachability while retaining every complete-graph
/// dependency identity, including versions constrained by unselected members.
pub(crate) fn resolve_selected_workspace(
    complete: &Resolution,
    catalog: &Catalog,
    options: &Options,
    members: &[MemberRequest],
    selection: TargetSelection<'_>,
) -> Result<Resolution> {
    let dev_members = members
        .iter()
        .filter(|member| member.dev)
        .map(|member| member.root.clone())
        .collect();
    let scope = Scope::WorkspaceSelected {
        selection,
        complete,
        dev_members: &dev_members,
    };
    // Cargo's resolver 1 activates features from inactive platforms and
    // member dev-dependencies, then builds only reachable active units.
    let features = if options.resolver == ResolverVersion::V1 {
        Scope::WorkspaceMetadata { complete }
    } else {
        scope
    };
    let mut resolution = resolve_workspace_request(complete, catalog, options, members, features)?;
    if options.resolver == ResolverVersion::V1 {
        for package in &mut resolution.packages {
            let dev = matches!(&package.key.source, PackageSourceKey::Path(root) if dev_members.contains(root));
            let active = |edge: &ResolvedEdge| -> Result<bool> {
                let platform = if edge.kind == DependencyKind::Build {
                    CompileKind::Host
                } else {
                    edge.parent_compile_kind.unwrap()
                };
                Ok((edge.kind != DependencyKind::Dev || dev)
                    && scope.matches(platform, edge.target.as_deref())?)
            };
            for edges in [&mut package.edges, &mut package.lock_edges] {
                let keep = edges.iter().map(active).collect::<Result<Vec<_>>>()?;
                let mut keep = keep.into_iter();
                edges.retain(|_| keep.next().unwrap());
            }
        }
        retain_selected_roots(&mut resolution, members);
    }
    Ok(resolution)
}

pub(crate) fn resolve_metadata_workspace(
    complete: &Resolution,
    catalog: &Catalog,
    options: &Options,
    members: &[MemberRequest],
) -> Result<Resolution> {
    resolve_workspace_request(
        complete,
        catalog,
        options,
        members,
        Scope::WorkspaceMetadata { complete },
    )
}

fn resolve_workspace_request(
    complete: &Resolution,
    catalog: &Catalog,
    options: &Options,
    members: &[MemberRequest],
    scope: Scope<'_>,
) -> Result<Resolution> {
    let mut queue = VecDeque::new();
    for (index, member) in members.iter().enumerate() {
        let package = complete
            .packages
            .iter()
            .find(|package| {
                package.key.source == PackageSourceKey::Path(member.root.clone())
                    && package
                        .local_manifest
                        .as_ref()
                        .is_some_and(|manifest| manifest.editable)
            })
            .ok_or_else(|| {
                Error::failure(format!(
                    "selected member `{}` is absent from the complete resolution",
                    member.root.display(),
                ))
            })?;
        let dependency = CandidateDependency {
            dependency: Dependency {
                alias: package.key.name.clone(),
                package: package.key.name.clone(),
                requirement: VersionReq::parse(&format!("={}", package.key.version))
                    .map_err(|error| Error::failure(format!("invalid member version: {error}")))?,
                features: member.features.iter().cloned().collect(),
                optional: false,
                default_features: member.default_features,
                target: None,
                kind: DependencyKind::Normal,
            },
            source: RequirementSource::Path(member.root.clone()),
        };
        queue.push_back(Event {
            parent: None,
            parent_compile_kind: None,
            dependency_index: index,
            context: root_context(options.resolver, scope, &dependency),
            compile_kind: CompileKind::Target,
            dependency,
            depth: 0,
            ancestors: BTreeSet::new(),
        });
    }
    let mut catalog = catalog.clone();
    let mut options = options.clone();
    options.package_limit = options
        .package_limit
        .with_members(catalog.workspace_members.values().cloned());
    let locked = LockedPreference::from_resolution(complete);
    let mut resolution = solve_request(
        queue,
        &mut catalog,
        &options,
        &locked,
        scope,
        &mut |_, _, _| Ok(()),
    )?;
    retain_selected_roots(&mut resolution, members);
    Ok(resolution)
}

// Resolver 1 may activate the current package's features even when only another
// member is selected. Keep that unification without compiling the extra root.
fn retain_selected_roots(resolution: &mut Resolution, members: &[MemberRequest]) {
    resolution.root_edges.retain(|edge| {
        members.iter().any(|member| {
            member.selected && edge.package.source == PackageSourceKey::Path(member.root.clone())
        })
    });
    let packages = resolution
        .packages
        .iter()
        .map(|package| (&package.key, package))
        .collect::<BTreeMap<_, _>>();
    let mut pending = resolution
        .root_edges
        .iter()
        .map(|edge| (edge.package.clone(), edge.compile_kind))
        .collect::<Vec<_>>();
    let mut reachable = BTreeMap::<PackageKey, BTreeSet<CompileKind>>::new();
    while let Some((key, kind)) = pending.pop() {
        if !reachable.entry(key.clone()).or_default().insert(kind) {
            continue;
        }
        for edge in &packages[&key].edges {
            if edge.parent_compile_kind == Some(kind) {
                pending.push((edge.package.clone(), edge.compile_kind));
            }
        }
    }
    resolution
        .packages
        .retain(|package| reachable.contains_key(&package.key));
    for package in &mut resolution.packages {
        package.compile_kinds.clone_from(&reachable[&package.key]);
        package.feature_sets.retain(|context, _| match context {
            FeatureContext::Unified => true,
            FeatureContext::Target(_) => package.compile_kinds.contains(&CompileKind::Target),
            FeatureContext::Host => package.compile_kinds.contains(&CompileKind::Host),
        });
        if !package.compile_kinds.contains(&CompileKind::Target) {
            package.target_features.clear();
        }
        if !package.compile_kinds.contains(&CompileKind::Host) {
            package.host_features.clear();
        }
        for edges in [&mut package.edges, &mut package.lock_edges] {
            edges.retain(|edge| {
                edge.parent_compile_kind
                    .is_some_and(|kind| package.compile_kinds.contains(&kind))
                    && reachable.contains_key(&edge.package)
            });
        }
    }
}

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
    catalog.descriptive_sources = true;
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
        let features = features::all_features(&member);
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
