use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use super::MemberRequest;
use crate::cli::FeatureSelection;
use crate::diagnostic::{Error, Result};
use crate::manifest::{Manifest, Resolver, SourceWorkspace, TargetKind};

/// Route CLI features before solving; the solver validates dependency features.
pub(crate) fn member_requests(
    workspace: &SourceWorkspace,
    selected: &BTreeSet<PathBuf>,
    features: &FeatureSelection,
    dev: bool,
) -> Result<Vec<MemberRequest>> {
    let current = workspace
        .packages
        .iter()
        .find(|member| Some(member.root.as_path()) == workspace.manifest_path.parent());
    let legacy =
        !workspace.virtual_root && current.is_some_and(|member| member.resolver == Resolver::V1);
    let mut requests = BTreeMap::new();
    for member in &workspace.packages {
        let is_current = current.is_some_and(|current| current.root == member.root);
        if !selected.contains(&member.root) && !(legacy && is_current) {
            continue;
        }
        requests.insert(
            member.root.clone(),
            MemberRequest {
                root: member.root.clone(),
                features: BTreeSet::new(),
                default_features: !features.no_default || (legacy && !is_current),
                dev: dev && selected.contains(&member.root),
                selected: selected.contains(&member.root),
                target_units: selected.contains(&member.root)
                    && member
                        .targets
                        .iter()
                        .any(|target| dev || target.kind == TargetKind::Bin),
            },
        );
    }
    if selected.iter().any(|root| !requests.contains_key(root)) {
        return Err(Error::failure(
            "feature selection names a nonmember package",
        ));
    }
    if legacy {
        let current = current.unwrap();
        for feature in &features.features {
            let qualified = feature.split_once('/').and_then(|(name, feature)| {
                let name = name.strip_suffix('?').unwrap_or(name);
                workspace
                    .packages
                    .iter()
                    .find(|member| {
                        member.name == name
                            && member.root != current.root
                            && selected.contains(&member.root)
                    })
                    .map(|member| (&member.root, feature))
            });
            match qualified {
                Some((root, feature)) => {
                    requests
                        .get_mut(root)
                        .unwrap()
                        .features
                        .insert(feature.to_owned());
                }
                None => {
                    requests
                        .get_mut(&current.root)
                        .unwrap()
                        .features
                        .insert(feature.clone());
                }
            }
        }
    } else {
        for feature in &features.features {
            let mut found = false;
            for member in &workspace.packages {
                let Some(request) = requests.get_mut(&member.root) else {
                    continue;
                };
                if let Some(feature) = matching_feature(member, feature) {
                    request.features.insert(feature);
                    found = true;
                }
            }
            if !found {
                return Err(Error::failure(format!(
                    "none of the selected packages contains feature `{feature}`"
                )));
            }
        }
    }
    if features.all {
        for member in &workspace.packages {
            if let Some(request) = requests.get_mut(&member.root) {
                request.features.extend(all_features(member));
            }
        }
    }
    Ok(requests.into_values().collect())
}

fn matching_feature(member: &Manifest, feature: &str) -> Option<String> {
    let defines = |feature: &str| {
        member.features.contains_key(feature)
            || member
                .dependencies
                .iter()
                .any(|dependency| dependency.optional && dependency.alias == feature)
    };
    match feature.split_once('/') {
        None if defines(feature) => Some(feature.to_owned()),
        Some((name, requested)) => {
            let name = name.strip_suffix('?').unwrap_or(name);
            // Cargo prefers a dependency alias over the member's own name.
            if member
                .dependencies
                .iter()
                .any(|dependency| dependency.alias == name)
            {
                Some(feature.to_owned())
            } else if member.name == name && defines(requested) {
                Some(requested.to_owned())
            } else {
                None
            }
        }
        _ => None,
    }
}

pub(super) fn all_features(member: &Manifest) -> BTreeSet<String> {
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
    features
}
