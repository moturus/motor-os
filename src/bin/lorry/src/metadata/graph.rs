use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::diagnostic::{Error, Result};
use crate::manifest::{Manifest, SourceWorkspace};
use crate::resolver::{PackageKey, ResolvedEdge};
use crate::sparse::DependencyKind;

use super::package::{self, Identity};
use super::wire;

pub(crate) mod workspace;

pub(super) fn no_dependencies(workspace: &SourceWorkspace) -> Result<wire::Metadata> {
    let mut packages = workspace
        .packages
        .iter()
        .map(|manifest| package::map(manifest, Identity::Root, &manifest.root, &BTreeMap::new()))
        .collect::<Result<Vec<_>>>()?;
    packages.sort_by(|left, right| left.id.cmp(&right.id));
    let members = packages
        .iter()
        .map(|package| package.id.clone())
        .collect::<Vec<_>>();
    let mut default_members = workspace
        .packages
        .iter()
        .filter(|package| workspace.default_members.contains(&package.root))
        .map(|package| package::package_id(package, Identity::Root))
        .collect::<Result<Vec<_>>>()?;
    default_members.sort();
    finish(
        &workspace.root,
        members,
        default_members,
        packages,
        None,
        workspace.metadata.clone(),
    )
}

fn finish(
    root: &Path,
    workspace_members: Vec<String>,
    workspace_default_members: Vec<String>,
    packages: Vec<wire::Package>,
    resolve: Option<wire::Resolve>,
    workspace_metadata: serde_json::Value,
) -> Result<wire::Metadata> {
    let workspace_root = package::path_utf8(root, "workspace root")?;
    let target_directory = package::path_utf8(&root.join("target"), "metadata target directory")?;
    Ok(wire::Metadata {
        packages,
        workspace_members,
        workspace_default_members,
        resolve,
        workspace_root,
        target_directory: target_directory.clone(),
        build_directory: target_directory,
        workspace_metadata,
        version: 1,
    })
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
            .iter()
            .find(|dependency| {
                dependency.alias == edge.alias
                    && dependency.package == edge.package.name
                    && dependency.kind == edge.kind
                    && dependency.target == edge.target
            })
            .ok_or_else(|| {
                Error::failure(format!(
                    "metadata edge from `{}` has no declaration",
                    manifest.name
                ))
            })?;
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
            target: None,
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

    #[test]
    fn matches_sparse_edges_independently_of_manifest_order() {
        let manifest = Manifest::parse_dependency(
            Path::new("/metadata-root"),
            Path::new("/metadata-root/Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\n\
             [dependencies]\none = \"1\"\n\
             [target.'cfg(unix)'.dependencies]\none = \"1\"\n",
        )
        .unwrap();
        let one = key("one");
        let ids = BTreeMap::from([(one.clone(), "registry#one@1.0.0".to_owned())]);
        // Sparse records may interleave dev dependencies omitted by this parser.
        let ordinary = edge(4, "one", one.clone());
        let mut conditional = edge(0, "one", one);
        conditional.target = Some("cfg(unix)".to_owned());
        let node = map_node(
            "root",
            &[ordinary, conditional.clone()],
            &manifest,
            BTreeSet::new(),
            &ids,
        )
        .unwrap();
        assert_eq!(node.deps.len(), 1);
        assert_eq!(node.deps[0].dep_kinds.len(), 2);
        assert_eq!(node.deps[0].dep_kinds[0].target, None);
        assert_eq!(
            node.deps[0].dep_kinds[1].target.as_deref(),
            Some("cfg(unix)")
        );
        for mismatch in ["target", "kind", "package"] {
            let mut invalid = conditional.clone();
            match mismatch {
                "target" => invalid.target = Some("cfg(windows)".to_owned()),
                "kind" => invalid.kind = DependencyKind::Build,
                "package" => invalid.package.name = "another".to_owned(),
                _ => unreachable!(),
            }
            let error = map_node("root", &[invalid], &manifest, BTreeSet::new(), &ids).unwrap_err();
            assert!(
                error.to_string().contains("has no declaration"),
                "{mismatch}: {error}"
            );
        }
    }
}
