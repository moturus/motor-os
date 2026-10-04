use super::*;
use crate::admission_state::ReviewScope;
use crate::cli::FeatureSelection;
use crate::resolver::CompileKind;
use crate::resolver::workspace::{
    MemberRequest, features::member_requests, resolve_selected_workspace,
};

pub(crate) struct Reconstructed {
    pub review: Review,
    pub workspace: SourceWorkspace,
    pub complete: Resolution,
    pub catalog: Catalog,
    pub scopes: Vec<Resolution>,
}

pub(crate) fn reconstruct(
    inputs: &ReviewInputs<'_>,
    compact: &CompactState,
) -> Result<Reconstructed> {
    let scope = compact
        .scope
        .as_ref()
        .ok_or_else(|| Error::failure("workspace admission has no recorded scope"))?;
    let mut workspace = SourceWorkspace::load(&inputs.manifest.root, Some(&inputs.manifest.path))?;
    workspace.load_locked_context()?;
    let direct =
        crate::git::load_locked_sources(&workspace.packages[0], &inputs.config.policy.limits)?;
    let (complete, mut catalog) = resolve_locked(
        &workspace,
        inputs.config,
        inputs.source,
        &direct,
        inputs.options,
    )?;
    let members = requests(&workspace, scope)?;
    let mut resolutions = Vec::new();
    let mut evidence = BTreeMap::new();
    for context in &compact.contexts {
        let host = inputs.toolchain.target_info(Some(&context.host))?;
        let target = inputs.toolchain.target_info(Some(&context.target))?;
        let selection = TargetSelection {
            host_triple: &host.triple,
            host_cfg: &host.cfg,
            target_triple: &target.triple,
            target_cfg: &target.cfg,
        };
        let resolution = loop {
            let resolution = resolve_selected_workspace(
                &complete,
                &catalog,
                inputs.options,
                &members,
                selection,
            )?;
            let inspected = prepare_sources(
                resolution.clone(),
                inputs.config,
                inputs.source,
                inputs.staging_parent,
                &direct,
            )?;
            let mut refined = false;
            for (key, package) in inspected.packages {
                if key.source == PackageSourceKey::CratesIo {
                    refined |= catalog.annotate_proc_macro(&key, package.evidence.proc_macro)?;
                }
                if let Some(previous) = evidence.insert(key, package.evidence.clone())
                    && previous != package.evidence
                {
                    return Err(Error::failure(
                        "workspace review contexts disagree about source evidence",
                    ));
                }
            }
            if !refined {
                break resolution;
            }
        };
        resolutions.push(resolution);
    }
    let selected = crate::resolver::merge_resolutions(resolutions.clone())?;
    evidence.retain(|key, _| selected.packages.iter().any(|package| package.key == *key));
    let review = review(
        &workspace,
        scope.clone(),
        &compact.contexts,
        &resolutions,
        &evidence,
        compact.capabilities.clone(),
    )?;
    if review.commitment()? != compact.review_sha256 {
        return Err(Error::failure("workspace admission commitment does not match the recorded review scope")
            .with_help("run workspace-root `lorry vendor --locked` to review and re-admit the current dependencies"));
    }
    let mut policy = inputs.config.policy.clone();
    review.apply_to_policy(&mut policy, &workspace.root)?;
    let preflight = crate::policy::preflight_workspace(&policy, &selected)?;
    let admission = crate::policy::inspect(&preflight, &selected, &evidence)?;
    if crate::admission_state::capabilities_from(&selected, &evidence, &admission)?
        != compact.capabilities
    {
        return Err(
            Error::failure("workspace capability policy differs from the recorded grants")
                .with_help(
                    "run workspace-root `lorry vendor --locked` to review the capability changes",
                ),
        );
    }
    Ok(Reconstructed {
        review,
        workspace,
        complete,
        catalog,
        scopes: resolutions,
    })
}

pub(crate) fn verify(
    inputs: &ReviewInputs<'_>,
    compact: &CompactState,
) -> Result<VerifiedAdmission> {
    let reconstructed = reconstruct(inputs, compact)?;
    let resolution = if inputs.prepare_context.is_some() {
        let members = member_requests(
            &reconstructed.workspace,
            &[inputs.manifest.root.clone()].into(),
            &FeatureSelection::default(),
            false,
        )?;
        let selected = select_requested(&reconstructed, inputs, compact, &members)?;
        Some(legacy_dependency_graph(selected, &inputs.manifest.root)?)
    } else {
        None
    };
    Ok(VerifiedAdmission {
        review: reconstructed.review,
        resolution,
    })
}

/// Verify every requested root and feature before exposing the shared member
/// resolution to compilation or a completed-profile shortcut.
pub(crate) fn verify_requested(
    inputs: &ReviewInputs<'_>,
    compact: &CompactState,
    members: &[MemberRequest],
) -> Result<VerifiedAdmission> {
    let reconstructed = reconstruct(inputs, compact)?;
    let selected = select_requested(&reconstructed, inputs, compact, members)?;
    Ok(VerifiedAdmission {
        review: reconstructed.review,
        resolution: Some(selected),
    })
}

fn select_requested(
    reconstructed: &Reconstructed,
    inputs: &ReviewInputs<'_>,
    compact: &CompactState,
    members: &[MemberRequest],
) -> Result<Resolution> {
    let context = inputs.prepare_context.as_ref().ok_or_else(|| {
        Error::failure("workspace compilation admission requires a host/target context")
    })?;
    compact.require_context(&context.host, &context.target)?;
    if !members.iter().any(|member| member.selected) {
        return Err(Error::failure(
            "workspace compilation admission has no selected members",
        ));
    }
    let scope = compact.scope.as_ref().unwrap();
    for request in members.iter().filter(|member| member.selected) {
        let member = reconstructed
            .workspace
            .packages
            .iter()
            .find(|member| member.root == request.root)
            .ok_or_else(|| Error::failure("requested package is not a workspace member"))?;
        if !scope.packages.is_empty() && !scope.packages.contains(&member.name) {
            return Err(uncovered(&member.name));
        }
    }
    let host = inputs.toolchain.target_info(Some(&context.host))?;
    let target = inputs.toolchain.target_info(Some(&context.target))?;
    let selected = resolve_selected_workspace(
        &reconstructed.complete,
        &reconstructed.catalog,
        inputs.options,
        members,
        TargetSelection {
            host_triple: &host.triple,
            host_cfg: &host.cfg,
            target_triple: &target.triple,
            target_cfg: &target.cfg,
        },
    )?;
    let reviewed = &reconstructed.scopes[compact
        .contexts
        .iter()
        .position(|candidate| candidate == context)
        .unwrap()];
    for member in selected.packages.iter().filter(|package| {
        package
            .local_manifest
            .as_ref()
            .is_some_and(|manifest| manifest.editable)
    }) {
        let Some(admitted) = reviewed
            .packages
            .iter()
            .find(|package| package.key == member.key)
        else {
            return Err(uncovered(&member.key.name));
        };
        if !member.compile_kinds.is_subset(&admitted.compile_kinds)
            || !member.target_features.is_subset(&admitted.target_features)
            || !member.host_features.is_subset(&admitted.host_features)
        {
            return Err(uncovered(&member.key.name));
        }
    }
    cover(&reconstructed.review, context, &selected)?;
    Ok(selected)
}

fn uncovered(package: &str) -> Error {
    Error::failure(format!("workspace admission does not cover the requested packages or features of `{package}`"))
        .with_help("review a covering scope with workspace-root `lorry vendor --locked --workspace --all-features`")
}

fn cover(review: &Review, context: &Context, selected: &Resolution) -> Result<()> {
    for package in &selected.packages {
        let kinds = package
            .compile_kinds
            .iter()
            .map(|kind| match kind {
                CompileKind::Host => crate::admission_state::UnitKind::Host,
                CompileKind::Target => crate::admission_state::UnitKind::Target,
            })
            .collect::<Vec<_>>();
        let admitted = match &package.source {
            ResolvedSource::Path { .. } => continue,
            ResolvedSource::CratesIo { checksum } => review
                .context_registry
                .iter()
                .find(|admitted| {
                    admitted.host == context.host
                        && admitted.target == context.target
                        && admitted.name == package.key.name
                        && admitted.version == package.key.version.to_string()
                        && admitted.checksum == hex(checksum)
                })
                .map(|admitted| {
                    (
                        &admitted.compile_kinds,
                        &admitted.host_features,
                        &admitted.target_features,
                    )
                }),
            ResolvedSource::Git { cargo_source, .. } => review
                .context_git
                .iter()
                .find(|admitted| {
                    admitted.host == context.host
                        && admitted.target == context.target
                        && admitted.name == package.key.name
                        && admitted.version == package.key.version.to_string()
                        && admitted.source == *cargo_source
                })
                .map(|admitted| {
                    (
                        &admitted.compile_kinds,
                        &admitted.host_features,
                        &admitted.target_features,
                    )
                }),
        };
        let Some((admitted_kinds, host, target)) = admitted else {
            return Err(uncovered(&package.key.name));
        };
        if !kinds.iter().all(|kind| admitted_kinds.contains(kind))
            || !package
                .host_features
                .iter()
                .all(|feature| host.contains(feature))
            || !package
                .target_features
                .iter()
                .all(|feature| target.contains(feature))
        {
            return Err(uncovered(&package.key.name));
        }
    }
    Ok(())
}

// The existing single-package compiler consumes dependency roots. Milestone 7
// consumes member roots directly and removes this transitional projection.
fn legacy_dependency_graph(mut selected: Resolution, root: &Path) -> Result<Resolution> {
    let position = selected
        .packages
        .iter()
        .position(|package| package.key.source == PackageSourceKey::Path(root.to_owned()))
        .ok_or_else(|| Error::failure("requested member is absent from selected resolution"))?;
    let member = selected.packages.remove(position);
    selected.root_edges = member
        .edges
        .into_iter()
        .filter(|edge| edge.kind != crate::sparse::DependencyKind::Dev)
        .map(|mut edge| {
            edge.parent_compile_kind = None;
            edge
        })
        .collect();
    compilation_manifests(&mut selected, &[])?;
    Ok(selected)
}

pub(crate) fn requests(
    workspace: &SourceWorkspace,
    scope: &ReviewScope,
) -> Result<Vec<MemberRequest>> {
    let roots = if scope.packages.is_empty() {
        workspace
            .packages
            .iter()
            .map(|member| member.root.clone())
            .collect()
    } else {
        scope.packages.iter().map(|name| {
            workspace.packages.iter().find(|member| member.name == *name)
                .map(|member| member.root.clone()).ok_or_else(|| {
                    Error::failure(format!("reviewed member `{name}` is absent from the workspace"))
                        .with_help("run workspace-root `lorry vendor --locked --workspace` to review the current members")
                })
        }).collect::<Result<BTreeSet<_>>>()?
    };
    member_requests(
        workspace,
        &roots,
        &FeatureSelection {
            features: scope.features.iter().cloned().collect(),
            all: scope.all_features,
            no_default: scope.no_default_features,
        },
        true,
    )
}

pub(crate) fn review(
    workspace: &SourceWorkspace,
    scope: ReviewScope,
    contexts: &[Context],
    resolutions: &[Resolution],
    evidence: &BTreeMap<PackageKey, PackageEvidence>,
    capabilities: Vec<Capability>,
) -> Result<Review> {
    let manifest = &workspace.packages[0];
    let lock = manifest
        .lock
        .as_ref()
        .ok_or_else(|| Error::failure("workspace review requires Cargo.lock"))?;
    let mut review = Review::from_graph(manifest, lock, contexts.to_vec())?;
    review.direct_registry.clear();
    review.direct_git.clear();
    review.root_features.clear();
    review.crates_io_patches.clear();
    review.scope = Some(scope);
    if contexts.len() != resolutions.len() {
        return Err(Error::failure(
            "workspace review contexts do not match their resolutions",
        ));
    }
    for (context, resolution) in contexts.iter().zip(resolutions) {
        review.add_context_resolution(context, resolution, evidence)?;
    }
    review.complete(capabilities)?;
    Ok(review)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn shared_compilation_admission_covers_every_selected_member_and_feature() {
        let fixture = super::super::super::tests::Fixture::new();
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[workspace]\nmembers = [\"a\", \"b\", \"shared\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        for name in ["a", "b", "shared"] {
            let root = fixture.0.join(name);
            fs::create_dir_all(root.join("src")).unwrap();
            fs::write(root.join("Cargo.toml"), format!("[package]\nname = \"{name}\"\nversion = \"1.0.0\"\nedition = \"2024\"\n[features]\nextra = []\n")).unwrap();
            fs::write(
                root.join("src/lib.rs"),
                "compile_error!(\"verification must not compile\");\n",
            )
            .unwrap();
        }
        for name in ["a", "b"] {
            let path = fixture.0.join(name).join("Cargo.toml");
            fs::write(
                &path,
                format!(
                    "{}[dependencies]\nshared = {{ path = \"../shared\" }}\n",
                    fs::read_to_string(&path).unwrap()
                ),
            )
            .unwrap();
        }
        fs::write(fixture.0.join("Cargo.lock"), "version = 4\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\ndependencies = [\"shared\"]\n[[package]]\nname = \"b\"\nversion = \"1.0.0\"\ndependencies = [\"shared\"]\n[[package]]\nname = \"shared\"\nversion = \"1.0.0\"\n").unwrap();
        let config = Config::default();
        let toolchain = Toolchain::discover(None, &config, false).unwrap();
        let target = toolchain.target_info(None).unwrap();
        let mut workspace = SourceWorkspace::load(&fixture.0, None).unwrap();
        workspace.load_locked_context().unwrap();
        let manifest = &workspace.packages[0];
        let options = resolver_options(manifest, &config, &toolchain).unwrap();
        let repositories = RepositorySet::open(
            &config.repositories,
            crate::source_tree::DEFAULT_LIMITS,
            config.policy.limits.max_package_bytes,
        )
        .unwrap();
        let source = RegistrySource::Lorry(&repositories);
        let direct = crate::git::DirectCatalog::default();
        let (complete, catalog) =
            resolve_locked(&workspace, &config, source, &direct, &options).unwrap();
        let scope = ReviewScope {
            packages: vec!["a".into(), "b".into()],
            ..ReviewScope::default()
        };
        let contexts = vec![Context {
            host: target.triple.clone(),
            target: target.triple.clone(),
        }];
        let reviewed = resolve_selected_workspace(
            &complete,
            &catalog,
            &options,
            &requests(&workspace, &scope).unwrap(),
            TargetSelection {
                host_triple: &target.triple,
                host_cfg: &target.cfg,
                target_triple: &target.triple,
                target_cfg: &target.cfg,
            },
        )
        .unwrap();
        let evidence = reviewed
            .packages
            .iter()
            .map(|package| {
                (
                    package.key.clone(),
                    PackageEvidence::from_path(package).unwrap(),
                )
            })
            .collect();
        let candidate = review(
            &workspace,
            scope.clone(),
            &contexts,
            &[reviewed],
            &evidence,
            vec![],
        )
        .unwrap();
        let compact = CompactState {
            scope: Some(scope),
            review_sha256: candidate.commitment().unwrap(),
            contexts: contexts.clone(),
            capabilities: vec![],
        };
        compact.write(&fixture.0).unwrap();
        let before_lock = fs::read(fixture.0.join("Cargo.lock")).unwrap();
        let before_record = fs::read(CompactState::path(&fixture.0)).unwrap();
        let inputs = ReviewInputs {
            manifest,
            config: &config,
            source,
            toolchain: &toolchain,
            options: &options,
            staging_parent: &fixture.0,
            direct: Some(&direct),
            prepare_context: Some(contexts[0].clone()),
        };
        let roots = [fixture.0.join("a"), fixture.0.join("b")].into();
        let members =
            member_requests(&workspace, &roots, &FeatureSelection::default(), false).unwrap();
        let verified = verify_requested(&inputs, &compact, &members).unwrap();
        let (actual_review, selected) = verified.into_parts();
        assert_eq!(actual_review, candidate);
        let selected = selected.unwrap();
        assert_eq!(selected.root_edges.len(), 2);
        assert_eq!(selected.packages.len(), 3);
        assert!(selected.packages.iter().all(|package| {
            package.local_manifest.as_ref().unwrap().workspace_root == workspace.root
        }));

        let extra = member_requests(
            &workspace,
            &roots,
            &FeatureSelection {
                features: ["b/extra".into()].into(),
                ..FeatureSelection::default()
            },
            false,
        )
        .unwrap();
        assert!(
            verify_requested(&inputs, &compact, &extra)
                .err()
                .unwrap()
                .render()
                .contains("features of `b`")
        );
        let unreviewed = member_requests(
            &workspace,
            &[fixture.0.join("shared")].into(),
            &FeatureSelection::default(),
            false,
        )
        .unwrap();
        assert!(
            verify_requested(&inputs, &compact, &unreviewed)
                .err()
                .unwrap()
                .render()
                .contains("features of `shared`")
        );
        assert_eq!(fs::read(fixture.0.join("Cargo.lock")).unwrap(), before_lock);
        assert_eq!(
            fs::read(CompactState::path(&fixture.0)).unwrap(),
            before_record
        );
        assert!(!fixture.0.join("target").exists());
    }

    #[test]
    fn compilation_projection_preserves_member_source_identity() {
        let fixture = super::super::super::tests::Fixture::new();
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[workspace]\nmembers = [\"app\", \"shared\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        for name in ["app", "shared"] {
            let root = fixture.0.join(name);
            fs::create_dir_all(root.join("src")).unwrap();
            fs::write(
                root.join("Cargo.toml"),
                format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"),
            )
            .unwrap();
            fs::write(root.join("src/lib.rs"), "pub fn value() {}\n").unwrap();
        }
        let mut workspace = SourceWorkspace::load(&fixture.0, None).unwrap();
        workspace.load_context(false).unwrap();
        let packages = workspace
            .packages
            .iter()
            .map(|manifest| ResolvedPackage {
                key: PackageKey {
                    name: manifest.name.clone(),
                    version: semver::Version::parse(&manifest.version.original).unwrap(),
                    source: PackageSourceKey::Path(manifest.root.clone()),
                },
                source: ResolvedSource::Path {
                    logical_root: manifest.root.clone(),
                    physical_root: manifest.root.clone(),
                    source_tree_sha256: crate::member_source::snapshot(manifest, true)
                        .unwrap()
                        .sha256,
                    patched_crates_io: false,
                },
                local_manifest: Some(manifest.clone()),
                feature_sets: BTreeMap::new(),
                compile_kinds: [CompileKind::Target].into(),
                target_features: BTreeSet::new(),
                host_features: BTreeSet::new(),
                edges: vec![],
                lock_edges: vec![],
            })
            .collect::<Vec<_>>();
        let before = PackageEvidence::from_path(&packages[1]).unwrap();
        let original = packages[1].local_manifest.as_ref().unwrap().clone();
        let projected = legacy_dependency_graph(
            Resolution {
                root_edges: vec![],
                packages,
            },
            &fixture.0.join("app"),
        )
        .unwrap();
        let shared = &projected.packages[0];
        let compilation = shared.local_manifest.as_ref().unwrap();
        let after = PackageEvidence::from_path(shared).unwrap_or_else(|error| {
            panic!(
                "{}; source workspace={}, compilation workspace={}",
                error.render(),
                original.workspace_root.display(),
                compilation.workspace_root.display()
            )
        });
        assert_eq!(before, after);
        assert_eq!(compilation.workspace_root, original.workspace_root);
        assert_eq!(compilation.workspace_members, original.workspace_members);
        assert!(compilation.editable);
        fs::write(compilation.root.join("src/lib.rs"), "pub fn edited() {}\n").unwrap();
        assert!(
            PackageEvidence::from_path(shared)
                .unwrap_err()
                .render()
                .contains("changed after resolution")
        );
    }

    #[test]
    fn reconstructs_recorded_scope_without_executing_member_code() {
        let fixture = super::super::super::tests::Fixture::new();
        fs::write(fixture.0.join("Cargo.toml"), "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[features]\nunused = []\n").unwrap();
        fs::write(
            fixture.0.join("src/lib.rs"),
            "compile_error!(\"inspection must not compile\");\n",
        )
        .unwrap();
        fs::write(
            fixture.0.join("Cargo.lock"),
            "version = 4\n[[package]]\nname = \"root\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let config = Config::default();
        let toolchain = Toolchain::discover(None, &config, false).unwrap();
        let host = toolchain.host.clone();
        let manifest = Manifest::load(&fixture.0).unwrap();
        let scope = ReviewScope::default();
        let contexts = vec![Context {
            host: host.clone(),
            target: host,
        }];
        let candidate = Review {
            scope: Some(scope.clone()),
            resolver_version: 2,
            contexts: contexts.clone(),
            ..Review::default()
        };
        let mut compact = CompactState {
            scope: Some(scope),
            review_sha256: candidate.commitment().unwrap(),
            contexts,
            capabilities: vec![],
        };
        let repositories = RepositorySet::open(
            &config.repositories,
            crate::source_tree::DEFAULT_LIMITS,
            config.policy.limits.max_package_bytes,
        )
        .unwrap();
        let inputs = ReviewInputs {
            manifest: &manifest,
            config: &config,
            source: RegistrySource::Lorry(&repositories),
            toolchain: &toolchain,
            options: &resolver_options(&manifest, &config, &toolchain).unwrap(),
            staging_parent: &fixture.0,
            direct: None,
            prepare_context: None,
        };
        assert_eq!(reconstruct(&inputs, &compact).unwrap().review, candidate);
        assert!(!fixture.0.join("target").exists());
        assert!(!fixture.0.join(".lorry").exists());
        // Even a path-only member must stay within the reviewed feature scope.
        fs::write(fixture.0.join("Cargo.toml"), "[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[features]\ndefault = [\"unused\"]\nunused = []\n").unwrap();
        let mut narrow = compact.clone();
        narrow.scope.as_mut().unwrap().no_default_features = true;
        let mut narrowed_review = candidate.clone();
        narrowed_review.scope = narrow.scope.clone();
        narrow.review_sha256 = narrowed_review.commitment().unwrap();
        let build_inputs = ReviewInputs {
            prepare_context: Some(compact.contexts[0].clone()),
            ..inputs
        };
        assert!(
            verify(&build_inputs, &narrow)
                .err()
                .unwrap()
                .render()
                .contains("does not cover")
        );
        compact.review_sha256 = "00".repeat(32);
        assert!(
            reconstruct(&build_inputs, &compact)
                .err()
                .unwrap()
                .render()
                .contains("commitment does not match")
        );
    }

    #[test]
    fn unused_member_declarations_do_not_change_workspace_review() {
        let fixture = super::super::super::tests::Fixture::new();
        fs::write(
            fixture.0.join("Cargo.lock"),
            "version = 4\n[[package]]\nname = \"root\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let contexts = vec![Context {
            host: "host".into(),
            target: "target".into(),
        }];
        let mut commitments = Vec::new();
        for feature in ["unused", "another-unused"] {
            fs::write(
                fixture.0.join("Cargo.toml"),
                format!(
                    "[package]\nname = \"root\"\nversion = \"0.1.0\"\n[features]\n{feature} = []\n"
                ),
            )
            .unwrap();
            let mut workspace = SourceWorkspace::load(&fixture.0, None).unwrap();
            workspace.load_locked_context().unwrap();
            let candidate = review(
                &workspace,
                ReviewScope::default(),
                &contexts,
                &[Resolution {
                    root_edges: vec![],
                    packages: vec![],
                }],
                &BTreeMap::new(),
                vec![],
            )
            .unwrap();
            commitments.push(candidate.commitment().unwrap());
            let scope = ReviewScope {
                packages: vec!["absent".into()],
                ..ReviewScope::default()
            };
            assert!(requests(&workspace, &scope).is_err());
        }
        assert_eq!(commitments[0], commitments[1]);
    }
}
