mod support;

use serde_json::{Value, json};
use std::fs;
use support::Project;

fn metadata(p: &Project, directory: &str) -> Value {
    let output = p
        .command(&[
            "metadata",
            "--no-deps",
            "--locked",
            "--offline",
            "--format-version",
            "1",
        ])
        .current_dir(p.root.join(directory))
        .env("RUSTC", p.root.join("absent-rustc"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

fn names(document: &Value) -> Vec<&str> {
    let mut names: Vec<_> = document["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn unprepared_metadata_discovers_implicit_members_without_reading_lock_or_compiler() {
    let p = Project::new();
    let outside = Project::new();
    outside.package(".", "outside", "");
    outside.write("src/lib.rs", "");
    p.write(
        "Cargo.toml",
        r#"[workspace]
members=["app","shared"]
exclude=["tools/excluded"]
resolver="2"
[workspace.dependencies]
unprepared="1"
[profile.custom]
inherits="release"
rpath=true
[workspace.metadata]
title="editor tools"
enabled=true
count=7
ratio=0.5
nan=nan
date=2026-10-03
time=12:34:56
timestamp=2026-10-03T12:34:56Z
values=[1,"two",{three=false}]
[[workspace.metadata.commands]]
name="check"
[[workspace.metadata.commands]]
name="test"
"#,
    );
    p.package("app", "app", &format!("[dependencies]\nshared={{path=\"../shared\"}}\nhelper={{path=\"../tools/helper\"}}\nexcluded={{path=\"../tools/excluded\"}}\noutside={{path={:?}}}\n[dev-dependencies]\nunprepared=\"1\"\n[package.metadata.editor]\ncommands=[\"build\",\"check\"]\n", outside.root));
    p.package("shared", "shared", "[lib]\ncrate-type=[\"staticlib\"]\n");
    p.package(
        "tools/helper",
        "helper",
        "[dev-dependencies]\nnested={path=\"nested\"}\n",
    );
    p.package("tools/helper/nested", "nested", "");
    p.package("tools/excluded", "excluded", "");
    for directory in [
        "app",
        "shared",
        "tools/helper",
        "tools/helper/nested",
        "tools/excluded",
    ] {
        p.write(
            &format!("{directory}/src/lib.rs"),
            "compile_error!(\"metadata must not compile\");\n",
        );
    }
    let document = metadata(&p, ".");
    assert_eq!(names(&document), ["app", "helper", "nested", "shared"]);
    assert_eq!(
        document["metadata"],
        json!({"title":"editor tools","enabled":true,"count":7,"ratio":0.5,"nan":null,"date":{"$__toml_private_datetime":"2026-10-03"},"time":{"$__toml_private_datetime":"12:34:56"},"timestamp":{"$__toml_private_datetime":"2026-10-03T12:34:56Z"},"values":[1,"two",{"three":false}],"commands":[{"name":"check"},{"name":"test"}]})
    );
    for directory in ["app", "app/src", "tools/helper"] {
        let member = metadata(&p, directory);
        assert_eq!(member["packages"], document["packages"]);
        assert_eq!(member["workspace_members"], document["workspace_members"]);
        assert_eq!(
            member["workspace_default_members"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
    assert_eq!(names(&metadata(&p, "tools/excluded")), ["excluded"]);
    assert!(!p.root.join("Cargo.lock").exists());
    p.write("Cargo.lock", "not a Cargo lockfile\n");
    assert_eq!(metadata(&p, "."), document);
    assert_eq!(
        fs::read(p.root.join("Cargo.lock")).unwrap(),
        b"not a Cargo lockfile\n"
    );
    assert!(!p.root.join("target").exists());
    assert!(!p.root.join(".lorry").exists());
    p.fails(
        &["metadata", "--no-deps", "-p", "app"],
        "unexpected argument '-p'",
    );
}

#[test]
fn inherited_metadata_readmes_and_errors_use_workspace_paths() {
    let p = Project::new();
    let values = r#"version="1.2.3"
edition="2024"
rust-version="1.85.0"
authors=["Motor OS"]
keywords=["workspace"]
categories=["development-tools"]
description="inherited package description"
homepage="https://example.test"
documentation="https://example.test/docs"
repository="https://example.test/repo"
license="MIT"
license-file="./docs/../LICENSE"
readme="README.txt"
publish=false
include=["src/**"]
exclude=["ignored"]
"#;
    let fields = [
        "version",
        "edition",
        "rust-version",
        "authors",
        "keywords",
        "categories",
        "description",
        "homepage",
        "documentation",
        "repository",
        "license",
        "license-file",
        "readme",
        "publish",
        "include",
        "exclude",
    ];
    let package = |name: &str| {
        format!(
            "[package]\nname={name:?}\n{}",
            fields
                .iter()
                .map(|field| format!("{field}.workspace=true\n"))
                .collect::<String>()
        )
    };
    p.write("inner/Cargo.toml", package("inner"));
    p.write("inner/src/lib.rs", "");
    p.write("inner/README.md", "member README\n");
    p.write("README.txt", "workspace README\n");
    p.write("LICENSE", "MIT\n");
    p.write("docs/.keep", "");
    p.write("src/lib.rs", "");
    let root = format!(
        "{}[dependencies]\ninner={{path=\"inner\"}}\n[workspace]\nresolver=\"2\"\n[workspace.package]\n{values}",
        package("root")
    );
    p.write("Cargo.toml", &root);
    let document = metadata(&p, "inner");
    assert_eq!(names(&document), ["inner", "root"]);
    let inner = document["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "inner")
        .unwrap();
    for (key, value) in [
        ("version", json!("1.2.3")),
        ("edition", json!("2024")),
        ("rust_version", json!("1.85.0")),
        ("authors", json!(["Motor OS"])),
        ("keywords", json!(["workspace"])),
        ("categories", json!(["development-tools"])),
        ("description", json!("inherited package description")),
        ("publish", json!([])),
    ] {
        assert_eq!(inner[key], value, "{key}");
    }
    assert_eq!(inner["readme"], "../README.txt");
    assert_eq!(inner["license_file"], "../LICENSE");
    p.write(
        "Cargo.toml",
        root.replace("readme=\"README.txt\"", "readme=false"),
    );
    p.fails(
        &["metadata", "--no-deps", "--offline"],
        "workspace.package.readme",
    );
    p.write("Cargo.toml", root.replace("readme=\"README.txt\"\n", ""));
    let document = metadata(&p, "inner");
    let inner = document["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "inner")
        .unwrap();
    assert_eq!(inner["readme"], "../README.txt");
    for (readme, expected) in [("false", Value::Null), ("true", json!("README.md"))] {
        p.write(
            "inner/Cargo.toml",
            package("inner").replace("readme.workspace=true", &format!("readme={readme}")),
        );
        let document = metadata(&p, "inner");
        assert_eq!(
            document["packages"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["name"] == "inner")
                .unwrap()["readme"],
            expected
        );
    }
    for (setting, expected) in [
        ("true", Value::Null),
        ("[\"crates-io\"]", json!(["crates-io"])),
    ] {
        p.write(
            "Cargo.toml",
            root.replace("publish=false", &format!("publish={setting}")),
        );
        assert!(
            metadata(&p, ".")["packages"]
                .as_array()
                .unwrap()
                .iter()
                .all(|p| p["publish"] == expected)
        );
    }
    let bad = root.replace("authors=[\"Motor OS\"]", "authors=false");
    let line = bad
        .lines()
        .position(|line| line == "authors=false")
        .unwrap()
        + 1;
    p.write("Cargo.toml", bad);
    let output = p.fails(&["metadata", "--no-deps", "--offline"], "authors");
    assert!(String::from_utf8_lossy(&output.stderr).contains(&format!(
        "  --> {}:{line}",
        p.root.join("Cargo.toml").display()
    )));
}

#[test]
fn workspace_globs_exclusions_and_empty_workspaces_have_exact_membership() {
    let p = Project::new();
    for name in ["one", "two", "drop"] {
        p.package(&format!("crates/{name}"), name, "");
        p.write(&format!("crates/{name}/src/lib.rs"), "");
    }
    p.write("crates/README", "a file\n");
    for pattern in [
        "crates/*",
        "crates/???",
        "crates/[ot]*",
        "crates/[!d]*",
        "crates/[a-z]*",
    ] {
        p.write("Cargo.toml", format!("[workspace]\nmembers=[{pattern:?}]\nexclude=[\"crates/drop\"]\ndefault-members=[\"crates/t?o\"]\nresolver=\"2\"\n"));
        let document = metadata(&p, ".");
        assert_eq!(names(&document), ["one", "two"]);
        assert!(
            document["workspace_default_members"][0]
                .as_str()
                .unwrap()
                .ends_with("/crates/two#1.0.0")
        );
    }
    p.write(
        "Cargo.toml",
        "[workspace]\nmembers=[\"crates/*\",\"crates/drop\"]\nexclude=[\"crates/drop\"]\n",
    );
    assert_eq!(names(&metadata(&p, ".")), ["drop", "one", "two"]);
    for pattern in ["crates/absent-*", "crates/**"] {
        p.write(
            "Cargo.toml",
            format!("[workspace]\nmembers=[{pattern:?}]\n"),
        );
        assert!(
            !p.run(&["metadata", "--no-deps", "--offline"])
                .status
                .success()
        );
    }
    p.write(
        "Cargo.toml",
        "[workspace]\n[workspace.metadata]\nempty=true\n",
    );
    p.write(".cargo/config.toml", "[build]\ntarget-dir=\"configured\"\n");
    for target in [None, Some("env-output")] {
        let mut command = p.command(&[
            "metadata",
            "--no-deps",
            "--offline",
            "--format-version",
            "1",
        ]);
        command.env("RUSTC", p.root.join("absent-rustc"));
        if let Some(target) = target {
            command.env("CARGO_TARGET_DIR", target);
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let document: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(document["packages"], json!([]));
        assert_eq!(document["metadata"], json!({"empty":true}));
        assert_eq!(
            document["target_directory"],
            p.root
                .join(target.unwrap_or("configured"))
                .to_str()
                .unwrap()
        );
    }
    p.fails(&["metadata", "--offline"], "contains no package");
    for path in ["target", "configured", "env-output", ".lorry", "Cargo.lock"] {
        assert!(!p.root.join(path).exists(), "{path}");
    }
}
