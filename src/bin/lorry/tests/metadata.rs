mod support;
use serde_json::{Value, json};
use support::Project;

fn metadata(p: &Project, arguments: &[&str]) -> Value {
    let mut args = vec!["metadata", "--format-version", "1", "--locked", "--offline"];
    args.extend_from_slice(arguments);
    serde_json::from_slice(&p.success(&args).stdout).unwrap()
}

#[test]
fn source_metadata_is_deterministic_and_does_not_admit_or_compile() {
    let p = Project::new();
    p.package(
        ".",
        "metadata-app",
        r#"
authors = ["Motor OS"]
description = "source metadata contract"
license = "MIT"
license-file = "LICENSE"
readme = "README.md"
repository = "https://example.test/repository"
homepage = "https://example.test"
documentation = "https://docs.example.test"
rust-version = "1.85"
default-run = "metadata-app"
[lib]
doc = false
doctest = false
[dependencies]
renamed-dep = { package = "dep", path = "dep", features = ["extra"] }
[features]
default = ["renamed-dep/extra"]
[package.metadata.editor]
commands = ["build", "check"]
[workspace.metadata]
name = "resolved workspace"
"#,
    );
    p.package("dep", "dep", "[lib]\ncrate-type = [\"rlib\"]\ndoc = false\n[features]\nextra = []\n[package.metadata.source]\nrole = \"dependency\"\n");
    p.lock(&[("metadata-app", &["dep"]), ("dep", &[])]);
    for file in [
        "src/lib.rs",
        "src/main.rs",
        "build.rs",
        "tests/integration.rs",
        "dep/src/lib.rs",
    ] {
        p.write(file, "compile_error!(\"metadata must not compile\");\n");
    }
    p.write("LICENSE", "MIT\n");
    p.write("README.md", "# metadata\n");
    p.write(".lorry/dependencies-v2.toml", "not an admission record\n");
    p.write("target/unchanged", b"marker");
    let lock = std::fs::read(p.root.join("Cargo.lock")).unwrap();
    let no_deps = metadata(&p, &["--no-deps"]);
    assert_eq!(no_deps["resolve"], Value::Null);
    assert_eq!(no_deps["packages"].as_array().unwrap().len(), 2); // path member
    std::fs::remove_dir_all(p.root.join(".lorry")).unwrap();
    let resolved = metadata(&p, &[]);
    assert_eq!(resolved, metadata(&p, &[]));
    assert!(!p.root.join(".lorry").exists());
    assert_eq!(
        std::fs::read(p.root.join("target/unchanged")).unwrap(),
        b"marker"
    );
    assert_eq!(std::fs::read(p.root.join("Cargo.lock")).unwrap(), lock);
    assert_eq!(resolved["metadata"], json!({"name": "resolved workspace"}));
    let package = resolved["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "metadata-app")
        .unwrap();
    for (key, expected) in [
        ("authors", json!(["Motor OS"])),
        ("description", json!("source metadata contract")),
        ("license", json!("MIT")),
        ("license_file", json!("LICENSE")),
        ("readme", json!("README.md")),
        ("rust_version", json!("1.85")),
        ("default_run", json!("metadata-app")),
        (
            "metadata",
            json!({"editor": {"commands": ["build", "check"]}}),
        ),
    ] {
        assert_eq!(package[key], expected, "{key}");
    }
    let targets = package["targets"].as_array().unwrap();
    for kind in ["lib", "bin", "test", "custom-build"] {
        assert!(
            targets.iter().any(|t| t["kind"] == json!([kind])),
            "{kind}: {targets:?}"
        );
    }
    let dep = &package["dependencies"][0];
    assert_eq!(dep["name"], "dep");
    assert_eq!(dep["rename"], "renamed-dep");
    assert_eq!(dep["features"], json!(["extra"]));
    let default = p.success(&["metadata", "--offline", "--no-deps"]);
    assert_eq!(
        serde_json::from_slice::<Value>(&default.stdout).unwrap(),
        no_deps
    );
    assert!(
        String::from_utf8_lossy(&default.stderr)
            .contains("please specify `--format-version` flag explicitly")
    );
    let quiet = p.success(&["metadata", "-q", "--offline", "--no-deps"]);
    // Debug Motor runtime diagnostics share stderr with the command.
    assert!(!String::from_utf8_lossy(&quiet.stderr).contains("please specify `--format-version`"));
}

#[test]
fn dependency_target_and_package_limits_are_enforced() {
    let p = Project::new();
    p.package(".", "app", "[workspace]\nexclude = [\"one\", \"two\"]\n[dependencies]\none = { path = \"one\" }\ntwo = { path = \"two\" }\n");
    p.write("src/main.rs", "fn main() {}\n");
    for name in ["one", "two"] {
        p.package(name, name, "");
        p.write(&format!("{name}/src/lib.rs"), "pub fn answer() {}\n");
    }
    p.lock(&[("app", &["one", "two"]), ("one", &[]), ("two", &[])]);
    p.fails(
        &["metadata", "--offline", "--locked", "--max-packages", "1"],
        "limit of 1 (set by --max-packages)",
    );
    assert_eq!(
        metadata(&p, &["--max-packages", "2"])["packages"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    for n in 1..=1024 {
        p.write(
            &format!("one/tests/case{n:04}.rs"),
            "#[test] fn sample() {}\n",
        );
    }
    metadata(&p, &[]);
    p.write("one/tests/overflow.rs", "#[test] fn sample() {}\n");
    p.fails(
        &["metadata", "--offline", "--locked"],
        "more than 1024 integration-test targets",
    );
}

#[test]
fn tree_reports_dependency_kinds_and_repeated_edges() {
    let p = Project::new();
    p.package(".", "tree-app", "[dependencies]\nshared = { path = \"shared\", features = [\"extra\"] }\n[build-dependencies]\nshared = { path = \"shared\" }\n[dev-dependencies]\ndev = { path = \"dev\" }\n");
    p.write("src/lib.rs", "");
    p.package("shared", "shared", "[features]\nextra = []\n");
    p.package("dev", "dev", "");
    p.write("shared/src/lib.rs", "");
    p.write("dev/src/lib.rs", "");
    p.lock(&[
        ("tree-app", &["dev", "shared"]),
        ("dev", &[]),
        ("shared", &[]),
    ]);
    let output = p.success(&["tree", "--locked", "--offline"]);
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in ["tree-app v1.0.0", "shared v1.0.0", "[build-dependencies]"] {
        assert!(text.contains(expected), "{text}");
    }
    assert_eq!(
        p.success(&["tree", "--locked", "--offline", "-p", "tree-app"])
            .stdout,
        text.as_bytes()
    );
    assert!(!p.root.join(".lorry").exists());
}
