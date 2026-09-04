use cargo_metadata::{DependencyKind, Metadata};
use serde_json::Value;
use std::fs;
use std::path::Path;

fn parse(document: &str) -> Metadata {
    serde_json::from_str(document).expect("golden document must match cargo_metadata 0.23.1")
}

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if let [command, lorry, cargo] = arguments.as_slice() {
        assert_eq!(command, "compare");
        compare(Path::new(lorry), Path::new(cargo));
        return;
    }
    assert!(
        arguments.is_empty(),
        "usage: metadata-schema [compare LORRY CARGO]"
    );
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

fn compare(lorry: &Path, cargo: &Path) {
    let lorry = fs::read_to_string(lorry).expect("read Lorry metadata");
    let cargo = fs::read_to_string(cargo).expect("read Cargo metadata");
    let _: Metadata = parse(&lorry);
    let _: Metadata = parse(&cargo);
    let mut lorry: Value = serde_json::from_str(&lorry).unwrap();
    let mut cargo: Value = serde_json::from_str(&cargo).unwrap();
    // Cargo omits an empty target required-features array while Lorry emits
    // the schema field explicitly. No other field is normalized here.
    add_empty_required_features(&mut lorry);
    add_empty_required_features(&mut cargo);
    assert_eq!(lorry, cargo);
}

fn add_empty_required_features(document: &mut Value) {
    for package in document["packages"].as_array_mut().unwrap() {
        for target in package["targets"].as_array_mut().unwrap() {
            target
                .as_object_mut()
                .unwrap()
                .entry("required-features")
                .or_insert_with(|| Value::Array(Vec::new()));
        }
    }
}
