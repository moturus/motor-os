mod support;

use support::{Project, artifacts};

#[test]
fn explicit_inferred_disabled_and_harness_free_test_targets() {
    let p = Project::new();
    p.write("src/lib.rs", "pub fn answer() -> u32 { 42 }\n");
    let test = "#[test] fn basic() { assert_eq!(2 + 2, 4); }\n";
    for path in [
        "tests/basic.rs",
        "tests/directory/main.rs",
        "tests/disabled.rs",
    ] {
        p.write(path, test);
    }
    p.write("tests/free.rs", r#"#[cfg(test)] fn main() {
        assert_eq!(std::env::var("CARGO_PKG_NAME").unwrap(), "probe");
        assert_eq!(std::env::current_dir().unwrap(), std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    }"#);
    p.write(
        "tests/needs.rs",
        "compile_error!(\"unavailable feature target compiled\");\n",
    );
    p.lock(&[("probe", &[])]);
    for discovery in ["disabled", "automatic", "legacy"] {
        let edition = if discovery == "legacy" {
            "2015"
        } else {
            "2024"
        };
        let automatic = if discovery == "disabled" {
            "autotests = false\n"
        } else {
            ""
        };
        p.write(
            "Cargo.toml",
            format!(
                r#"[package]
name = "probe"
version = "1.0.0"
edition = "{edition}"
{automatic}
[features]
extra = []
[lib]
test = false
doctest = false
[[test]]
name = "basic"
[[test]]
name = "directory"
[[test]]
name = "free"
harness = false
[[test]]
name = "disabled"
test = false
[[test]]
name = "needs"
required-features = ["extra"]
"#
            ),
        );
        p.write(
            "tests/ignored.rs",
            if discovery == "automatic" {
                test
            } else {
                "compile_error!(\"autodiscovery should be disabled\");\n"
            },
        );
        p.admit();
        let output = p.success(&["test", "--offline", "--no-run", "--message-format=json"]);
        let mut names: Vec<_> = artifacts(&output)
            .into_iter()
            .filter(|a| a["profile"]["test"] == true)
            .map(|a| a["target"]["name"].as_str().unwrap().to_owned())
            .collect();
        names.sort();
        let expected = if discovery == "automatic" {
            vec!["basic", "directory", "free", "ignored"]
        } else {
            vec!["basic", "directory", "free"]
        };
        assert_eq!(names, expected, "{discovery}");
        let output = p.success(&[
            "check",
            "--offline",
            "--test",
            "free",
            "--message-format=json",
        ]);
        let checks = artifacts(&output);
        assert!(checks.iter().any(|a| a["target"]["name"] == "free"));
        assert!(checks.iter().all(|a| a["executable"].is_null()));
        p.success(&["test", "--offline", "--test", "free"]);
        p.success(&["test", "--offline", "--test", "disabled", "--no-run"]);
        p.fails(
            &["test", "--offline", "--test", "needs", "--no-run"],
            "requires the features:",
        );
    }
}

#[test]
fn harness_free_library_and_binary_receive_package_runtime_environment() {
    let p = Project::new();
    p.package(
        ".",
        "probe",
        "[lib]\nharness=false\ndoctest=false\n[[bin]]\nname=\"probe\"\nharness=false\n",
    );
    p.write("src/lib.rs", r#"
pub fn answer() -> u32 { 42 }
#[cfg(test)] fn main() {
    assert_eq!(answer(), 42);
    assert_eq!(std::env::var("CARGO_PKG_NAME").unwrap(), "probe");
    assert_eq!(std::env::current_dir().unwrap(), std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    println!("library test ran");
}"#);
    p.write("src/main.rs", r#"fn main() {
    assert_eq!(probe::answer(), 42);
    #[cfg(test)] {
        assert_eq!(std::env::var("CARGO_PKG_NAME").unwrap(), "probe");
        assert_eq!(std::env::current_dir().unwrap(), std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")));
        println!("binary test ran");
    }
}"#);
    p.lock(&[("probe", &[])]);
    p.admit();
    assert_eq!(
        p.success(&["test", "--offline"]).stdout,
        b"library test ran\nbinary test ran\n"
    );
    let output = p.success(&[
        "check",
        "--offline",
        "--all-targets",
        "--message-format=json",
    ]);
    let checks = artifacts(&output);
    assert!(
        checks
            .iter()
            .any(|a| a["target"]["kind"] == serde_json::json!(["bin"]))
    );
    assert!(
        checks
            .iter()
            .any(|a| a["target"]["kind"] == serde_json::json!(["lib"]))
    );
    assert!(checks.iter().all(|a| a["executable"].is_null()));
}

#[test]
fn binary_feature_gates_filter_implicit_targets_and_reject_named_targets() {
    let p = Project::new();
    p.write(
        "Cargo.toml",
        "[workspace]\nmembers=[\"app\",\"helper\"]\ndefault-members=[\"app\"]\nresolver=\"2\"\n",
    );
    let extra = r#"[features]
default = ["present"]
present = []
extra = ["helper/enabled"]
[dependencies]
helper = { path = "../helper" }
[dev-dependencies]
helper = { path = "../helper", features = ["enabled"] }
[[bin]]
name = "gated"
required-features = ["present", "extra"]
[[bin]]
name = "qualified"
required-features = ["helper/enabled"]
"#;
    p.package("app", "app", extra);
    p.package("helper", "helper", "[features]\nenabled=[]\n");
    p.write(
        "helper/src/lib.rs",
        "#[cfg(feature=\"enabled\")] pub fn value() -> u32 { 42 }\n",
    );
    p.write("app/src/lib.rs", "pub fn value() -> u32 { 42 }\n");
    p.write(
        "app/src/main.rs",
        "fn main() { println!(\"{}\", app::value()); }\n",
    );
    p.write("app/src/bin/gated.rs", "#[cfg(not(feature=\"extra\"))] compile_error!(\"disabled binary compiled\");\nfn main() { println!(\"{}\", helper::value()); }\n");
    p.write(
        "app/src/bin/qualified.rs",
        "fn main() { println!(\"{}\", helper::value()); }\n",
    );
    p.lock(&[("app", &["helper"]), ("helper", &[])]);
    p.admit();
    for verb in ["build", "check"] {
        for selection in [0, 1, 2] {
            let mut args = vec![verb, "--offline", "--message-format=json"];
            if selection != 0 {
                args.extend(["--features", "extra"]);
            }
            if selection == 2 {
                args.extend(["--bin", "gated"]);
            }
            let events = artifacts(&p.success(&args));
            let mut names: Vec<_> = events
                .iter()
                .filter(|a| a["target"]["kind"] == serde_json::json!(["bin"]))
                .map(|a| a["target"]["name"].as_str().unwrap())
                .collect();
            names.sort();
            assert_eq!(
                names,
                match selection {
                    0 => vec!["app"],
                    1 => vec!["app", "gated", "qualified"],
                    _ => vec!["gated"],
                }
            );
        }
    }
    p.fails(
        &["build", "--offline", "--bin", "gated"],
        "requires the features: `present`, `extra`",
    );
    p.package("app", "app", "autolib=false\nautobins=false\n[features]\npresent=[]\nextra=[]\n[[bin]]\nname=\"gated\"\nrequired-features=[\"present\",\"extra\"]\n");
    p.lock(&[("app", &[]), ("helper", &[])]);
    p.admit();
    let output = p.success(&["build", "--offline", "--message-format=json"]);
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        r#"{"reason":"build-finished","success":true}"#
    );
}

#[test]
fn workspace_groups_patterns_repeated_names_and_overlaps_select_exact_targets() {
    let p = Project::new();
    p.write(
        "Cargo.toml",
        "[workspace]\nmembers=[\"a\",\"b\"]\nresolver=\"2\"\n",
    );
    p.package("a", "a", "[lib]\ntest=false\ndoctest=false\n[[bin]]\nname=\"a\"\ntest=false\n[[example]]\nname=\"library\"\ncrate-type=[\"rlib\",\"staticlib\"]\n[dev-dependencies]\nb={path=\"../b\"}\n");
    p.package(
        "b",
        "b",
        "[lib]\ndoctest=false\n[dependencies]\na={path=\"../a\"}\n",
    );
    for name in ["a", "b"] {
        p.write(
            &format!("{name}/src/lib.rs"),
            "pub fn value() -> u32 { 42 }\n",
        );
        p.write(
            &format!("{name}/src/main.rs"),
            format!("fn main() {{ assert_eq!({name}::value(),42); }}\n"),
        );
    }
    p.write(
        "a/examples/demo.rs",
        "fn main() { assert_eq!(a::value(),42); }\n",
    );
    p.write(
        "a/examples/library.rs",
        "pub fn value() -> u32 { a::value() }\n",
    );
    for kind in ["tests", "benches"] {
        for name in ["first", "second"] {
            p.write(
                &format!("a/{kind}/{name}.rs"),
                "#[test] fn works() { assert_eq!(a::value(),b::value()); }\n",
            );
        }
    }
    p.lock(&[("a", &["b"]), ("b", &["a"])]);
    p.admit();
    let all = vec![
        ("bench", "first"),
        ("bench", "second"),
        ("example", "demo"),
        ("example", "library"),
        ("test", "first"),
        ("test", "second"),
    ];
    for (selection, expected) in [
        (vec!["--lib"], vec![]),
        (vec!["--bins"], vec![]),
        (vec!["--tests"], vec![("test", "first"), ("test", "second")]),
        (
            vec!["--examples"],
            vec![("example", "demo"), ("example", "library")],
        ),
        (
            vec!["--benches"],
            vec![("bench", "first"), ("bench", "second")],
        ),
        (vec!["--example", "library"], vec![("example", "library")]),
        (
            vec![
                "--bin",
                "a",
                "--bin",
                "b",
                "--test",
                "first",
                "--test",
                "second",
                "--example",
                "demo",
                "--example",
                "library",
                "--bench",
                "first",
                "--bench",
                "second",
            ],
            all.clone(),
        ),
        (
            vec![
                "--bin",
                "[ab]",
                "--test",
                "f*",
                "--test",
                "s?cond",
                "--example",
                "d*",
                "--example",
                "libra[!x]y",
                "--bench",
                "*",
            ],
            all.clone(),
        ),
        (
            vec![
                "--bin",
                "a*",
                "--bin",
                "a",
                "--test",
                "first*",
                "--test",
                "first",
                "--example",
                "demo*",
                "--example",
                "demo",
                "--bench",
                "second*",
                "--bench",
                "second",
            ],
            vec![("bench", "second"), ("example", "demo"), ("test", "first")],
        ),
        (vec!["--all-targets"], all.clone()),
        (
            vec![
                "--lib",
                "--bins",
                "--tests",
                "--examples",
                "--benches",
                "--bin",
                "missing",
                "--test",
                "missing",
                "--example",
                "missing",
                "--bench",
                "missing",
            ],
            all,
        ),
    ] {
        for action in ["build", "check", "test"] {
            let mut args = vec![action, "--workspace", "--offline", "--message-format=json"];
            if action == "test" {
                args.push("--no-run");
            }
            args.extend(&selection);
            let output = p.success(&args);
            let artifacts = artifacts(&output);
            let mut targets: Vec<_> = artifacts
                .iter()
                .filter_map(|a| {
                    let kind = a["target"]["kind"][0].as_str().unwrap();
                    ["bench", "example", "test"]
                        .contains(&kind)
                        .then(|| (kind, a["target"]["name"].as_str().unwrap()))
                })
                .collect();
            targets.sort();
            assert_eq!(targets, expected, "{action} {selection:?}");
            if action == "check" {
                assert!(artifacts.iter().all(|a| a["executable"].is_null()));
            }
            for artifact in artifacts {
                assert!(
                    artifact["filenames"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|p| std::path::Path::new(p.as_str().unwrap()).is_file())
                );
            }
        }
    }
}
