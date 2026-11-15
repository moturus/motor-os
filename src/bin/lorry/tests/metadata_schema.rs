mod support;

use cargo_metadata::{DependencyKind, Message, Metadata, TargetKind};
use std::io::BufReader;
use support::Project;

#[test]
fn cargo_metadata_reads_metadata_and_compiler_messages() {
    let p = Project::new();
    p.package(
        ".",
        "app",
        "[dependencies]\nrenamed-dep={package=\"dep\",path=\"dep\"}\n[lib]\ndoctest=false\n",
    );
    p.package("dep", "dep", "");
    p.write("dep/src/lib.rs", "pub fn value() -> u32 { 42 }\n");
    p.write("src/lib.rs", "pub fn value() -> u32 { renamed_dep::value() }\n#[test] fn value_test() { assert_eq!(value(), 42); }\n");
    p.write(
        "src/main.rs",
        "fn main() { assert_eq!(app::value(), 42); }\n",
    );
    p.lock(&[("app", &["dep"]), ("dep", &[])]);
    p.admit();
    let output = p.success(&["metadata", "--offline", "--format-version", "1"]);
    let metadata: Metadata = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(metadata.packages.len(), 2);
    assert_eq!(metadata.workspace_packages().len(), 1);
    assert_eq!(metadata.workspace_default_packages().len(), 1);
    assert_eq!(
        metadata.build_directory.as_ref(),
        Some(&metadata.target_directory)
    );
    let root = metadata.root_package().unwrap();
    assert_eq!(root.name.as_ref(), "app");
    assert_eq!(root.dependencies.len(), 1);
    assert_eq!(root.dependencies[0].kind, DependencyKind::Normal);
    assert_eq!(root.dependencies[0].rename.as_deref(), Some("renamed-dep"));
    assert!(
        !root
            .targets
            .iter()
            .find(|t| t.name == "app" && t.kind.contains(&TargetKind::Lib))
            .unwrap()
            .doctest
    );
    let resolve = metadata.resolve.as_ref().unwrap();
    assert_eq!(resolve.nodes.len(), 2);
    let node = resolve
        .nodes
        .iter()
        .find(|node| node.id == root.id)
        .unwrap();
    assert_eq!(node.deps[0].name, "renamed_dep");
    assert_eq!(node.deps[0].dep_kinds[0].kind, DependencyKind::Normal);
    let output = p.success(&[
        "metadata",
        "--offline",
        "--format-version",
        "1",
        "--no-deps",
    ]);
    let no_deps: Metadata = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(no_deps.packages.len(), 1);
    assert!(no_deps.resolve.is_none());

    for args in [
        &["build"][..],
        &["check", "--all-targets"],
        &["test", "--no-run"],
    ] {
        for fresh in [false, true] {
            let mut args = args.to_vec();
            args.extend(["--offline", "--message-format=json"]);
            let output = p.success(&args);
            let messages: Vec<_> = Message::parse_stream(BufReader::new(output.stdout.as_slice()))
                .map(Result::unwrap)
                .collect();
            assert!(
                matches!(messages.last(), Some(Message::BuildFinished(finished)) if finished.success)
            );
            let mut artifacts = 0;
            let mut tests = 0;
            for message in messages {
                match message {
                    Message::CompilerArtifact(artifact) => {
                        artifacts += 1;
                        assert!(
                            metadata
                                .packages
                                .iter()
                                .any(|p| p.id == artifact.package_id)
                        );
                        assert!(artifact.manifest_path.is_file());
                        if fresh {
                            assert!(artifact.fresh);
                        }
                        if artifact.profile.test {
                            tests += 1;
                        }
                        if let Some(executable) = artifact.executable {
                            assert!(executable.is_file());
                            assert!(artifact.filenames.contains(&executable));
                        }
                        assert!(artifact.filenames.iter().all(|path| path.is_file()));
                    }
                    Message::TextLine(line) => panic!("invalid compiler event: {line}"),
                    _ => {}
                }
            }
            assert!(artifacts >= 2);
            if args[0] == "test" {
                assert!(tests > 0);
            }
        }
    }
}
