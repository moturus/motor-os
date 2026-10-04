use super::*;
use crate::admission_state::ReviewScope;
use crate::cli::FeatureSelection;
use crate::resolver::workspace::{
    MemberRequest, features::member_requests, resolve_selected_workspace,
};

pub(crate) struct Reconstructed {
    pub review: Review,
    pub workspace: SourceWorkspace,
    pub complete: Resolution,
    pub catalog: Catalog,
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
    })
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
        compact.review_sha256 = "00".repeat(32);
        assert!(
            reconstruct(&inputs, &compact)
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
