use cargo_metadata::{DependencyKind, Metadata};

fn parse(document: &str) -> Metadata {
    serde_json::from_str(document).expect("golden document must match cargo_metadata 0.23.1")
}

fn main() {
    let resolved = parse(include_str!("../golden/resolved.json"));
    assert_eq!(resolved.packages.len(), 2);
    assert_eq!(resolved.workspace_packages().len(), 1);
    assert_eq!(resolved.workspace_default_packages().len(), 1);
    assert_eq!(
        resolved.build_directory.as_ref(),
        Some(&resolved.target_directory)
    );

    let root = resolved.root_package().expect("resolved root package");
    assert_eq!(root.name.as_ref(), "app");
    assert_eq!(root.dependencies.len(), 1);
    assert_eq!(root.dependencies[0].kind, DependencyKind::Normal);
    assert_eq!(root.targets[0].required_features, Vec::<String>::new());
    assert!(!root.targets[0].doctest);

    let resolve = resolved.resolve.expect("resolved dependency graph");
    assert_eq!(resolve.nodes.len(), 2);
    assert_eq!(resolve.nodes[0].deps[0].name, "renamed_dep");
    assert_eq!(
        resolve.nodes[0].deps[0].dep_kinds[0].kind,
        DependencyKind::Normal
    );

    let no_deps = parse(include_str!("../golden/no-deps.json"));
    assert_eq!(no_deps.packages.len(), 1);
    assert!(no_deps.resolve.is_none());
    assert_eq!(no_deps.workspace_packages().len(), 1);
}
