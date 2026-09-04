use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use crate::dependency::PreparedGraph;
use crate::diagnostic::{Error, Result};
use crate::manifest::Manifest;
use crate::resolver::{PackageKey, ResolvedEdge, selected_root_features};
use crate::sparse::DependencyKind;
use crate::unit::CompilationPlan;

use super::package::{self, Identity};
use super::wire;

pub(super) fn no_dependencies(manifest: &Manifest) -> Result<wire::Metadata> {
    let root_id = package::package_id(manifest, Identity::Root)?;
    finish(
        manifest,
        root_id,
        vec![package::map(
            manifest,
            Identity::Root,
            &manifest.root,
            &BTreeMap::new(),
        )?],
        None,
    )
}

pub(crate) fn resolved(
    manifest: &Manifest,
    prepared: &PreparedGraph,
    plan: &CompilationPlan,
    presented_roots: &BTreeMap<PackageKey, PathBuf>,
    max_packages: u64,
) -> Result<wire::Metadata> {
    let package_count = prepared
        .resolution
        .packages
        .len()
        .checked_add(1)
        .ok_or_else(|| Error::failure("metadata package count overflowed"))?;
    if u64::try_from(package_count).unwrap_or(u64::MAX) > max_packages {
        return Err(Error::failure(format!(
            "metadata graph exceeds the package-count limit of {max_packages}"
        )));
    }

    let root_id = package::package_id(manifest, Identity::Root)?;
    let mut ids = BTreeMap::new();
    let mut dependency_roots = BTreeMap::new();
    dependency_roots.insert(
        fs::canonicalize(&manifest.root).map_err(path_error)?,
        manifest.root.clone(),
    );
    for resolved in &prepared.resolution.packages {
        let dependency = prepared.packages.get(&resolved.key).ok_or_else(|| {
            Error::failure(format!(
                "prepared graph omits resolved package `{} {}`",
                resolved.key.name, resolved.key.version
            ))
        })?;
        let root = presented_roots.get(&resolved.key).ok_or_else(|| {
            Error::failure(format!(
                "metadata source roots omit package `{} {}`",
                resolved.key.name, resolved.key.version
            ))
        })?;
        if ids
            .insert(
                resolved.key.clone(),
                package::package_id(&dependency.manifest, Identity::Resolved(resolved))?,
            )
            .is_some()
        {
            return Err(Error::failure(
                "metadata graph contains a duplicate package identity",
            ));
        }
        dependency_roots.insert(
            fs::canonicalize(&dependency.manifest.root).map_err(path_error)?,
            fs::canonicalize(root).map_err(path_error)?,
        );
    }

    let mut packages = vec![package::map(
        manifest,
        Identity::Root,
        &manifest.root,
        &dependency_roots,
    )?];
    for resolved in &prepared.resolution.packages {
        let dependency = &prepared.packages[&resolved.key];
        packages.push(package::map(
            &dependency.manifest,
            Identity::Resolved(resolved),
            &presented_roots[&resolved.key],
            &dependency_roots,
        )?);
    }
    packages.sort_by(|left, right| left.id.cmp(&right.id));

    let planned_features = planned_features(prepared, plan)?;
    let mut nodes = vec![map_node(
        &root_id,
        &prepared.resolution.root_edges,
        manifest,
        selected_root_features(manifest)?,
        &ids,
    )?];
    for resolved in &prepared.resolution.packages {
        let dependency = &prepared.packages[&resolved.key];
        nodes.push(map_node(
            &ids[&resolved.key],
            &resolved.edges,
            &dependency.manifest,
            planned_features[&resolved.key].clone(),
            &ids,
        )?);
    }
    nodes.sort_by(|left, right| left.id.cmp(&right.id));
    finish(
        manifest,
        root_id.clone(),
        packages,
        Some(wire::Resolve {
            nodes,
            root: Some(root_id),
        }),
    )
}

fn finish(
    manifest: &Manifest,
    root_id: String,
    packages: Vec<wire::Package>,
    resolve: Option<wire::Resolve>,
) -> Result<wire::Metadata> {
    let workspace_root = package::path_utf8(&manifest.workspace_root, "workspace root")?;
    let target_directory = package::path_utf8(
        &manifest.workspace_root.join("target"),
        "metadata target directory",
    )?;
    Ok(wire::Metadata {
        packages,
        workspace_members: vec![root_id.clone()],
        workspace_default_members: vec![root_id],
        resolve,
        workspace_root,
        target_directory: target_directory.clone(),
        build_directory: target_directory,
        workspace_metadata: serde_json::Value::Null,
        version: 1,
    })
}

fn planned_features(
    prepared: &PreparedGraph,
    plan: &CompilationPlan,
) -> Result<BTreeMap<PackageKey, BTreeSet<String>>> {
    let expected = prepared
        .resolution
        .packages
        .iter()
        .map(|package| {
            let mut features = package.target_features.clone();
            features.extend(package.host_features.iter().cloned());
            (package.key.clone(), features)
        })
        .collect::<BTreeMap<_, _>>();
    let mut actual = BTreeMap::<PackageKey, BTreeSet<String>>::new();
    for key in plan.units.keys() {
        actual
            .entry(key.package.clone())
            .or_default()
            .extend(key.features.iter().cloned());
    }
    if actual != expected {
        return Err(Error::failure(
            "development compilation plan does not match resolved metadata features",
        ));
    }
    Ok(actual)
}

fn map_node(
    id: &str,
    edges: &[ResolvedEdge],
    manifest: &Manifest,
    features: BTreeSet<String>,
    ids: &BTreeMap<PackageKey, String>,
) -> Result<wire::Node> {
    let mut aliases = BTreeMap::<String, (String, String)>::new();
    let mut dependencies = BTreeSet::new();
    let mut grouped = BTreeMap::<(String, String), BTreeSet<(u8, Option<String>)>>::new();
    for edge in edges {
        let dependency = manifest
            .dependencies
            .get(edge.dependency_index)
            .ok_or_else(|| {
                Error::failure(format!(
                    "metadata edge from `{}` has no declaration",
                    manifest.name
                ))
            })?;
        if dependency.alias != edge.alias || dependency.kind != edge.kind {
            return Err(Error::failure(format!(
                "metadata edge from `{}` does not match its dependency declaration",
                manifest.name
            )));
        }
        let package_id = ids.get(&edge.package).ok_or_else(|| {
            Error::failure(format!(
                "metadata edge from `{}` references unresolved package `{} {}`",
                manifest.name, edge.package.name, edge.package.version
            ))
        })?;
        let name = edge.alias.replace('-', "_");
        if let Some((previous_alias, previous_package)) =
            aliases.insert(name.clone(), (edge.alias.clone(), package_id.clone()))
            && (previous_alias != edge.alias || previous_package != *package_id)
        {
            return Err(Error::failure(format!(
                "dependency aliases `{previous_alias}` and `{}` collide as `{name}`",
                edge.alias
            )));
        }
        dependencies.insert(package_id.clone());
        grouped
            .entry((name, package_id.clone()))
            .or_default()
            .insert((kind_order(edge.kind), dependency.target.clone()));
    }
    let deps = grouped
        .into_iter()
        .map(|((name, pkg), kinds)| wire::NodeDep {
            name,
            pkg,
            dep_kinds: kinds
                .into_iter()
                .map(|(kind, target)| wire::DepKindInfo {
                    kind: match kind {
                        0 => None,
                        1 => Some(wire::DependencyKind::Dev),
                        2 => Some(wire::DependencyKind::Build),
                        _ => unreachable!(),
                    },
                    target,
                })
                .collect(),
        })
        .collect();
    Ok(wire::Node {
        id: id.to_owned(),
        deps,
        dependencies: dependencies.into_iter().collect(),
        features: features.into_iter().collect(),
    })
}

fn kind_order(kind: DependencyKind) -> u8 {
    match kind {
        DependencyKind::Normal => 0,
        DependencyKind::Dev => 1,
        DependencyKind::Build => 2,
    }
}

fn path_error(error: std::io::Error) -> Error {
    Error::failure(format!(
        "failed to canonicalize metadata source path: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;
    use crate::resolver::{CompileKind, FeatureContext, PackageSourceKey};
    use semver::Version;
    use std::path::Path;

    fn manifest() -> Manifest {
        Manifest::parse_dependency(
            Path::new("/metadata-root"),
            Path::new("/metadata-root/Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\n\
             [dependencies]\nfoo-bar = { package = \"one\", version = \"1\" }\n\
             foo_bar = { package = \"two\", version = \"1\" }\n",
        )
        .unwrap()
    }

    fn key(name: &str) -> PackageKey {
        PackageKey {
            name: name.to_owned(),
            version: Version::new(1, 0, 0),
            source: PackageSourceKey::CratesIo,
        }
    }

    fn edge(index: usize, alias: &str, package: PackageKey) -> ResolvedEdge {
        ResolvedEdge {
            dependency_index: index,
            alias: alias.to_owned(),
            kind: DependencyKind::Normal,
            parent_compile_kind: Some(CompileKind::Target),
            compile_kind: CompileKind::Target,
            context: FeatureContext::Unified,
            package,
        }
    }

    #[test]
    fn rejects_alias_collisions_after_crate_name_normalization() {
        let manifest = manifest();
        let one = key("one");
        let two = key("two");
        let ids = BTreeMap::from([
            (one.clone(), "registry#one@1.0.0".to_owned()),
            (two.clone(), "registry#two@1.0.0".to_owned()),
        ]);
        let error = map_node(
            "root",
            &[edge(0, "foo-bar", one), edge(1, "foo_bar", two)],
            &manifest,
            BTreeSet::new(),
            &ids,
        )
        .unwrap_err();
        assert!(error.to_string().contains("collide as `foo_bar`"));
    }

    #[test]
    fn rejects_an_edge_to_an_unresolved_package() {
        let manifest = manifest();
        let error = map_node(
            "root",
            &[edge(0, "foo-bar", key("one"))],
            &manifest,
            BTreeSet::new(),
            &BTreeMap::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("references unresolved package"));
    }
}
