use super::*;
use crate::admission_state::ReviewScope;
use crate::cli::FeatureSelection;
use crate::resolver::workspace::{MemberRequest, features::member_requests};

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
