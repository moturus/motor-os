mod support;
use serde_json::{Value, json};
use support::{Project, artifacts};

fn events(output: &std::process::Output) -> Vec<Value> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn project() -> Project {
    let p = Project::new();
    p.package(
        ".",
        "check-app",
        "[dependencies]\ncheck-dep = { path = \"dep\" }\n",
    );
    p.package("dep", "check-dep", "");
    p.write(
        "dep/build.rs",
        r#"
fn main() {
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(out.join("generated.rs"), "pub const VALUE: u8 = 42;\n").unwrap();
    println!("cargo:rustc-check-cfg=cfg(generated)");
    println!("cargo:rustc-cfg=generated");
    println!("cargo:rerun-if-changed=build.rs");
}
"#,
    );
    p.write("dep/src/lib.rs", "#[cfg(generated)] include!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));\npub const TRACKED: Option<&str> = option_env!(\"LORRY_CHECK_TRACKED\");\n");
    p.write("src/lib.rs", "#[deprecated] pub fn old_value() -> u8 { check_dep::VALUE }\npub fn value() -> u8 { check_dep::VALUE }\npub const TRACKED: Option<&str> = option_env!(\"LORRY_CHECK_MEMBER_TRACKED\");\n");
    p.write(
        "src/bin/first.rs",
        "fn main() { assert_eq!(check_app::old_value(), 42); }\n",
    );
    p.write(
        "src/bin/second.rs",
        "fn main() { assert_eq!(check_app::value(), 42); }\n",
    );
    p.write("tests/integration.rs", "const _: &str = env!(\"CARGO_BIN_EXE_first\");\n#[test] fn integration() { assert_eq!(check_app::value(), 42); }\n");
    p.lock(&[("check-app", &["check-dep"]), ("check-dep", &[])]);
    p.admit();
    p
}

#[test]
fn checks_select_targets_without_linking_roots_and_replay_diagnostics() {
    let p = project();
    let empty = p.success(&["check", "--offline", "--examples", "--message-format=json"]);
    assert!(artifacts(&empty).is_empty());
    let output = p.success(&["check", "--offline", "--message-format=json"]);
    let roots: Vec<_> = artifacts(&output)
        .into_iter()
        .filter(|a| a["package_id"].as_str().unwrap().contains("check-app"))
        .collect();
    let mut names: Vec<_> = roots
        .iter()
        .map(|a| a["target"]["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["check_app", "first", "second"]);
    for artifact in &roots {
        assert_eq!(artifact["executable"], Value::Null);
        for path in artifact["filenames"].as_array().unwrap() {
            assert!(!path.as_str().unwrap().ends_with(".rlib"));
        }
    }
    let fresh = p.success(&["check", "--offline", "--message-format=json"]);
    assert!(artifacts(&fresh).iter().all(|a| a["fresh"] == true));
    let diagnostics = |output| {
        events(output)
            .into_iter()
            .filter(|e| e["reason"] == "compiler-message")
            .collect::<Vec<_>>()
    };
    assert!(!diagnostics(&output).is_empty());
    assert_eq!(diagnostics(&output), diagnostics(&fresh));
    let all = p.success(&[
        "check",
        "--offline",
        "--all-targets",
        "--message-format=json",
    ]);
    assert!(
        artifacts(&all)
            .iter()
            .any(|a| a["target"]["name"] == "integration")
    );
    let lib = p.success(&["check", "--offline", "--lib", "--message-format=json"]);
    assert!(
        artifacts(&lib)
            .iter()
            .all(|a| a["target"]["kind"] != json!(["bin"]))
    );

    p.write(
        "src/bin/first.rs",
        "fn main() { compile_error!(\"first check failure\"); }\n",
    );
    p.write(
        "src/bin/second.rs",
        "fn main() { compile_error!(\"second check failure\"); }\n",
    );
    let first = p.fails(
        &["check", "--bins", "--offline", "-j1"],
        "first check failure",
    );
    assert_eq!(first.status.code(), Some(101));
    assert!(!String::from_utf8_lossy(&first.stderr).contains("second check failure"));
    let both = p.run(&[
        "check",
        "--bins",
        "--offline",
        "--keep-going",
        "--message-format=json",
    ]);
    assert_eq!(both.status.code(), Some(101));
    for error in ["first check failure", "second check failure"] {
        assert!(String::from_utf8_lossy(&both.stdout).contains(error));
    }
    assert_eq!(
        events(&both).last().unwrap(),
        &json!({"reason": "build-finished", "success": false})
    );

    // An out-of-workspace dependency must retain its real source location.
    let dependency = Project::new();
    dependency.package(".", "check-dep", "");
    dependency.write(
        "src/lib.rs",
        "compile_error!(\"remapped dependency failure\");\n",
    );
    p.package(
        ".",
        "check-app",
        &format!(
            "[dependencies]\ncheck-dep = {{ path = {:?} }}\n",
            dependency.root
        ),
    );
    p.admit();
    let output = p.run(&["check", "--lib", "--offline", "--message-format=json"]);
    assert_eq!(output.status.code(), Some(101));
    let path = dependency.root.join("src/lib.rs");
    assert!(diagnostics(&output).iter().any(|e| {
        e["message"]["spans"]
            .as_array()
            .unwrap()
            .iter()
            .any(|span| span["file_name"] == path.to_str().unwrap())
    }));
}

#[test]
fn tracked_environment_invalidates_only_readers_and_dependents() {
    let p = project();
    let check = |dependency: Option<&str>, member: Option<&str>, unrelated: &str| {
        let mut command = p.command(&["check", "--lib", "--offline", "--message-format=json"]);
        command
            .env_remove("LORRY_CHECK_TRACKED")
            .env_remove("LORRY_CHECK_MEMBER_TRACKED")
            .env("LORRY_CHECK_UNRELATED", unrelated);
        if let Some(value) = dependency {
            command.env("LORRY_CHECK_TRACKED", value);
        }
        if let Some(value) = member {
            command.env("LORRY_CHECK_MEMBER_TRACKED", value);
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{output:?}");
        artifacts(&output)
            .into_iter()
            .filter(|a| a["target"]["kind"] != json!(["custom-build"]))
            .map(|a| {
                (
                    a["target"]["name"].as_str().unwrap().to_owned(),
                    a["fresh"].as_bool().unwrap(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    check(None, None, "0");
    assert!(check(None, None, "1").values().all(|fresh| *fresh));
    assert!(check(Some("one"), None, "1").values().all(|fresh| !*fresh));
    assert!(check(Some("one"), None, "2").values().all(|fresh| *fresh));
    let member = check(Some("one"), Some("yes"), "2");
    assert!(!member["check_app"]);
    assert!(member["check_dep"]);
    assert!(check(None, None, "2").values().all(|fresh| !*fresh));
}

#[test]
fn clippy_lints_members_caps_dependency_lints_and_separates_check_cache() {
    let p = Project::new();
    p.write("Cargo.toml", "[workspace]\nmembers = [\"app\", \"shared\"]\nexclude = [\"external\"]\nresolver = \"2\"\n[workspace.lints.clippy]\nneedless_return = \"warn\"\n");
    p.package("app", "app", "[lints]\nworkspace = true\n[dependencies]\nshared = { path = \"../shared\" }\nexternal = { path = \"../external\" }\n");
    p.package("shared", "shared", "[lints]\nworkspace = true\n");
    p.package("external", "external", "[workspace]\n");
    p.write(
        "app/src/lib.rs",
        "pub fn value() -> u8 { return shared::value() + external::value(); }\n",
    );
    p.write("shared/src/lib.rs", "pub fn value() -> u8 { return 20; }\n");
    p.write(
        "external/src/lib.rs",
        "pub fn value() -> u8 { return 22; }\n",
    );
    p.write(
        "shared/build.rs",
        "fn main() { println!(\"cargo:rerun-if-changed=build.rs\"); return; }\n",
    );
    p.lock(&[
        ("app", &["shared", "external"]),
        ("shared", &[]),
        ("external", &[]),
    ]);
    p.admit();
    let checked = p.success(&[
        "check",
        "-p",
        "app",
        "--lib",
        "--offline",
        "--message-format=json",
    ]);
    assert!(
        events(&checked)
            .iter()
            .all(|e| e["reason"] != "compiler-message")
    );
    let arguments = [
        "clippy",
        "-p",
        "app",
        "--lib",
        "--offline",
        "--message-format=json",
    ];
    let linted = |output| {
        events(output)
            .into_iter()
            .filter(|e| {
                e["reason"] == "compiler-message"
                    && e["message"]["code"]["code"] == "clippy::needless_return"
                    && e["target"]["kind"] != json!(["custom-build"])
            })
            .map(|e| e["target"]["name"].as_str().unwrap().to_owned())
            .collect::<std::collections::BTreeSet<_>>()
    };
    let output = p.success(&arguments);
    assert_eq!(
        linted(&output),
        ["app".to_owned(), "shared".to_owned()].into()
    );
    let fresh = p.success(&arguments);
    assert_eq!(linted(&fresh), linted(&output));
    assert!(artifacts(&fresh).iter().all(|a| a["fresh"] == true));
    let no_deps = p
        .command(&arguments)
        .arg("--no-deps")
        .env("CARGO_PRIMARY_PACKAGE", "1")
        .output()
        .unwrap();
    assert!(no_deps.status.success(), "{no_deps:?}");
    assert_eq!(linted(&no_deps), ["app".to_owned()].into());
    let denied = p
        .command(&arguments)
        .args(["--no-deps", "--", "-D", "clippy::needless_return"])
        .output()
        .unwrap();
    assert_eq!(denied.status.code(), Some(101));
    assert_eq!(
        events(&denied).last().unwrap(),
        &json!({"reason": "build-finished", "success": false})
    );
}
