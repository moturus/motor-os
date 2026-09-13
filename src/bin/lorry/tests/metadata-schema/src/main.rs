use cargo_metadata::{DependencyKind, Message, Metadata};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::io::BufReader;
use std::path::Path;

fn parse(document: &str) -> Metadata {
    serde_json::from_str(document).expect("golden document must match cargo_metadata 0.23.1")
}

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if let [command, path, metadata, success, ansi, fresh] = arguments.as_slice() {
        assert_eq!(command, "messages");
        check_messages(
            Path::new(path),
            Path::new(metadata),
            success == "success",
            ansi == "ansi",
            fresh == "fresh",
        );
        return;
    }
    if let [command, lorry, cargo] = arguments.as_slice() {
        match command.as_str() {
            "compare" => compare(Path::new(lorry), Path::new(cargo)),
            "compare-projection" => compare_projection(Path::new(lorry), Path::new(cargo)),
            "differential-messages" => compare_messages(Path::new(lorry), Path::new(cargo)),
            _ => panic!("unknown comparison command `{command}`"),
        }
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

fn compare_messages(lorry: &Path, cargo: &Path) {
    let lorry = read_messages(lorry);
    let cargo = read_messages(cargo);
    for messages in [&lorry, &cargo] {
        assert!(!messages.is_empty());
        assert!(
            !messages
                .iter()
                .any(|message| matches!(message, Message::TextLine(_)))
        );
        assert!(matches!(
            messages.last(),
            Some(Message::BuildFinished(finished)) if !finished.success
        ));
    }

    let diagnostics = |messages: &[Message]| {
        messages
            .iter()
            .filter_map(|message| match message {
                Message::CompilerMessage(message) => {
                    let mut diagnostic = serde_json::to_value(&message.message).unwrap();
                    diagnostic["rendered"] = Value::Null;
                    Some((
                        message.package_id.to_string(),
                        serde_json::to_string(&diagnostic).unwrap(),
                    ))
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>()
    };
    let lorry_diagnostics = diagnostics(&lorry);
    let cargo_diagnostics = diagnostics(&cargo);
    assert_eq!(lorry_diagnostics, cargo_diagnostics);
    let levels = lorry
        .iter()
        .filter_map(|message| match message {
            Message::CompilerMessage(message) => serde_json::to_value(message.message.level)
                .unwrap()
                .as_str()
                .map(str::to_owned),
            _ => None,
        })
        .collect::<BTreeSet<String>>();
    assert!(levels.contains("warning"));
    assert!(levels.contains("error"));

    let scripts = |messages: &[Message]| {
        messages
            .iter()
            .filter_map(|message| match message {
                Message::BuildScriptExecuted(script) => Some((
                    script.package_id.to_string(),
                    script.cfgs.clone(),
                    script.env.clone(),
                    fs::read_to_string(script.out_dir.join("generated.rs"))
                        .expect("read generated build-script output"),
                )),
                _ => None,
            })
            .collect::<BTreeSet<_>>()
    };
    let lorry_scripts = scripts(&lorry);
    assert!(!lorry_scripts.is_empty());
    assert_eq!(lorry_scripts, scripts(&cargo));
}

fn read_messages(path: &Path) -> Vec<Message> {
    Message::parse_stream(BufReader::new(fs::File::open(path).expect("read messages")))
        .map(|message| message.expect("parse Cargo message"))
        .collect()
}

fn check_messages(
    path: &Path,
    metadata_path: &Path,
    expected_success: bool,
    expect_ansi: bool,
    expect_fresh: bool,
) {
    let metadata = parse(&fs::read_to_string(metadata_path).expect("read metadata"));
    let input = fs::File::open(path).expect("read check messages");
    let messages = Message::parse_stream(BufReader::new(input))
        .map(|message| message.expect("read check message"))
        .collect::<Vec<_>>();
    assert!(!messages.is_empty());
    assert!(matches!(
        messages.last(),
        Some(Message::BuildFinished(finished)) if finished.success == expected_success
    ));
    assert_eq!(
        messages
            .iter()
            .filter(|message| matches!(message, Message::BuildFinished(_)))
            .count(),
        1
    );
    assert!(
        !messages
            .iter()
            .any(|message| matches!(message, Message::TextLine(_)))
    );
    for message in &messages {
        let (package_id, target) = match message {
            Message::CompilerArtifact(artifact) => (&artifact.package_id, Some(&artifact.target)),
            Message::CompilerMessage(message) => (&message.package_id, Some(&message.target)),
            Message::BuildScriptExecuted(script) => (&script.package_id, None),
            Message::BuildFinished(_) => continue,
            Message::TextLine(_) => unreachable!(),
            _ => continue,
        };
        let package = metadata
            .packages
            .iter()
            .find(|package| package.id == *package_id)
            .expect("message package id must come from metadata");
        if let Some(target) = target {
            assert!(package.targets.contains(target));
        }
    }
    assert!(messages.iter().any(|message| match message {
        Message::CompilerArtifact(artifact) => {
            artifact.filenames.iter().all(|path| path.is_file())
        }
        _ => false,
    }));
    assert!(messages.iter().any(|message| match message {
        Message::BuildScriptExecuted(script) => {
            script.out_dir.is_dir()
                && script.cfgs.iter().any(|cfg| cfg == "generated_fixture")
                && script
                    .env
                    .iter()
                    .any(|(name, value)| name == "GENERATED_FIXTURE" && value == "enabled")
        }
        _ => false,
    }));
    if expect_fresh {
        assert!(messages.iter().any(|message| {
            matches!(message, Message::CompilerArtifact(artifact) if artifact.fresh)
        }));
    }
    let rendered = messages.iter().filter_map(|message| match message {
        Message::CompilerMessage(message) => message.message.rendered.as_deref(),
        _ => None,
    });
    if expect_ansi {
        assert!(rendered.clone().any(|message| message.contains('\u{1b}')));
    } else {
        assert!(rendered.clone().all(|message| !message.contains('\u{1b}')));
    }
    if !expected_success {
        let diagnostics = messages.iter().filter_map(|message| match message {
            Message::CompilerMessage(message) => Some(message.message.message.as_str()),
            _ => None,
        });
        assert!(
            diagnostics
                .clone()
                .any(|message| message == "first check failure")
        );
        assert!(
            diagnostics
                .clone()
                .any(|message| message == "second check failure")
        );
    }
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

fn compare_projection(lorry: &Path, cargo: &Path) {
    let mut lorry: Value =
        serde_json::from_str(&fs::read_to_string(lorry).expect("read Lorry metadata projection"))
            .unwrap();
    let mut cargo: Value =
        serde_json::from_str(&fs::read_to_string(cargo).expect("read Cargo metadata projection"))
            .unwrap();
    let _: Metadata = serde_json::from_value(lorry.clone()).unwrap();
    let _: Metadata = serde_json::from_value(cargo.clone()).unwrap();
    normalize_projection(&mut lorry);
    normalize_projection(&mut cargo);
    assert_eq!(lorry, cargo);
}

fn normalize_projection(document: &mut Value) {
    // These are the complete allowed normalizations: Cargo may omit empty
    // required-features and non-path dependency paths; immutable registry/Git
    // source roots differ; and Cargo and Lorry order semantic sets differently.
    add_empty_required_features(document);
    for package in document["packages"].as_array_mut().unwrap() {
        for dependency in package["dependencies"].as_array_mut().unwrap() {
            dependency
                .as_object_mut()
                .unwrap()
                .entry("path")
                .or_insert(Value::Null);
        }
        normalize_source_root(package);
        sort_array(&mut package["dependencies"]);
        sort_array(&mut package["targets"]);
        for references in package["features"].as_object_mut().unwrap().values_mut() {
            sort_array(references);
        }
    }
    document["packages"]
        .as_array_mut()
        .unwrap()
        .sort_by_key(|package| package["id"].as_str().unwrap().to_owned());
    for field in ["workspace_members", "workspace_default_members"] {
        sort_array(&mut document[field]);
    }
    if let Some(resolve) = document["resolve"].as_object_mut() {
        for node in resolve["nodes"].as_array_mut().unwrap() {
            sort_array(&mut node["dependencies"]);
            sort_array(&mut node["deps"]);
            sort_array(&mut node["features"]);
            for dependency in node["deps"].as_array_mut().unwrap() {
                sort_array(&mut dependency["dep_kinds"]);
            }
        }
        resolve["nodes"]
            .as_array_mut()
            .unwrap()
            .sort_by_key(|node| node["id"].as_str().unwrap().to_owned());
    }
}

fn normalize_source_root(package: &mut Value) {
    if package["source"].is_null() {
        return;
    }
    let manifest = package["manifest_path"].as_str().unwrap().to_owned();
    let root = Path::new(&manifest).parent().unwrap();
    for target in package["targets"].as_array_mut().unwrap() {
        let source = target["src_path"].as_str().unwrap();
        let relative = Path::new(source).strip_prefix(root).unwrap();
        target["src_path"] = Value::String(format!("$SOURCE/{}", relative.display()));
    }
    package["manifest_path"] = Value::String("$SOURCE/Cargo.toml".to_owned());
}

fn sort_array(value: &mut Value) {
    value
        .as_array_mut()
        .unwrap()
        .sort_by_key(|item| serde_json::to_string(item).unwrap());
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
