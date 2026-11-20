mod support;

use support::{Project, artifacts};

const RUNTIME: &str = r#"
fn assert_runtime(kind: &str) {
    assert_eq!(std::env::current_dir().unwrap(), std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    for (name, expected) in [("CARGO_PKG_NAME", env!("CARGO_PKG_NAME")), ("SCRIPT_OWNER", env!("CARGO_PKG_NAME")), ("OUT_DIR", env!("OUT_DIR"))] {
        assert_eq!(std::env::var(name).unwrap(), expected);
    }
    println!("{} {kind} manual={}", env!("CARGO_PKG_NAME"), cfg!(feature = "manual"));
}
"#;

fn workspace() -> Project {
    let p = Project::new();
    p.write(
        "Cargo.toml",
        "[workspace]\nmembers=[\"zeta\",\"alpha\"]\nresolver=\"2\"\n",
    );
    for name in ["alpha", "zeta"] {
        let dependencies = if name == "alpha" {
            "[dev-dependencies]\nzeta={path=\"../zeta\",features=[\"dev\"]}\n"
        } else {
            "[dependencies]\nalpha={path=\"../alpha\",features=[\"selected\"]}\n"
        };
        p.package(name, name, &format!("[lib]\nharness=false\ndoctest=false\n[[bin]]\nname={name:?}\nharness=false\n[[test]]\nname=\"integration\"\nharness=false\n[features]\nmanual=[]\nselected=[]\ndev=[]\n{dependencies}"));
        p.write(
            &format!("{name}/build.rs"),
            r#"
fn main() {
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(out.join("generated.rs"), "pub const GENERATED: u32 = 42;").unwrap();
    println!("cargo:rustc-env=SCRIPT_OWNER={}", std::env::var("CARGO_PKG_NAME").unwrap());
    println!("cargo:rerun-if-changed=build.rs");
}
"#,
        );
        p.write(&format!("{name}/assert-runtime.rs"), RUNTIME);
        p.write(
            &format!("{name}/src/lib.rs"),
            r#"
include!(concat!(env!("OUT_DIR"), "/generated.rs"));
pub fn value() -> u32 { GENERATED }
#[cfg(test)] include!(concat!(env!("CARGO_MANIFEST_DIR"), "/assert-runtime.rs"));
#[cfg(test)] fn main() { assert_runtime("library"); }
"#,
        );
        p.write(
            &format!("{name}/src/main.rs"),
            r#"
#[cfg(test)] include!(concat!(env!("CARGO_MANIFEST_DIR"), "/assert-runtime.rs"));
fn main() {
    #[cfg(test)] {
        assert_runtime("binary");
        if env!("CARGO_PKG_NAME") == "alpha" {
            if std::env::var_os("TEST_ABORT").is_some() { std::process::abort(); }
            if std::env::var_os("TEST_FAIL").is_some() { std::process::exit(7); }
        }
    }
    #[cfg(not(test))] print!("{}", env!("CARGO_PKG_NAME"));
}
"#,
        );
        p.write(
            &format!("{name}/tests/integration.rs"),
            format!(
                r#"
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/assert-runtime.rs"));
fn main() {{
    assert_eq!({name}::value(), 42);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_{name}")).output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"{name}");
    assert_runtime("integration");
}}
"#
            ),
        );
    }
    let source = std::fs::read_to_string(p.root.join("alpha/src/lib.rs")).unwrap();
    p.write(
        "alpha/src/lib.rs",
        format!("{source}\n#[cfg(test)] const _: fn() -> u32 = zeta::value;\n"),
    );
    p.lock(&[("alpha", &["zeta"]), ("zeta", &["alpha"])]);
    p.admit();
    p
}

fn expected(members: &[&str], kinds: &[&str], manual: bool) -> String {
    members
        .iter()
        .flat_map(|member| {
            kinds
                .iter()
                .map(move |kind| format!("{member} {kind} manual={manual}\n"))
        })
        .collect()
}

#[test]
fn harness_order_development_cycles_runtime_environment_and_bundles() {
    let p = workspace();
    let kinds = ["library", "binary", "integration"];
    for bundle in [false, true] {
        let mut args = vec!["test", "--workspace", "--offline"];
        if bundle {
            args.push("--bundle");
        }
        let output = p.success(&args);
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            expected(&["alpha", "zeta"], &kinds, false)
        );
        args.extend(["--features", "alpha/manual"]);
        let output = p.success(&args);
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            expected(&["alpha"], &kinds, true) + &expected(&["zeta"], &kinds, false)
        );
    }
    for (args, members, manual) in [
        (
            vec!["-p", "zeta", "-p", "alpha", "--test", "integration"],
            vec!["alpha", "zeta"],
            false,
        ),
        (
            vec![
                "-p",
                "alpha",
                "--features",
                "manual",
                "--test",
                "integration",
            ],
            vec!["alpha"],
            true,
        ),
    ] {
        let mut command = vec!["test", "--offline"];
        command.extend(args);
        assert_eq!(
            String::from_utf8(p.success(&command).stdout).unwrap(),
            expected(&members, &["integration"], manual)
        );
    }
    let output = p.success(&["test", "--workspace", "--bundle", "--no-run", "--offline"]);
    let paths: Vec<_> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(std::path::PathBuf::from)
        .collect();
    assert_eq!(
        paths
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap())
            .collect::<Vec<_>>(),
        ["alpha-test-bundle", "zeta-test-bundle"]
    );
    assert!(paths.iter().all(|p| p.is_file()));
    p.success(&["clean", "-p", "alpha"]);
    assert!(!paths[0].exists());
    assert!(paths[1].is_file());

    for all in [false, true] {
        let mut command = p.command(&["test", "--workspace", "--offline"]);
        command.env("TEST_FAIL", "1");
        if all {
            command.arg("--no-fail-fast");
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(if all { 101 } else { 7 }));
        let expected = if all {
            expected(&["alpha", "zeta"], &kinds, false)
        } else {
            expected(&["alpha"], &kinds[..2], false)
        };
        assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
        if all {
            assert!(String::from_utf8_lossy(&output.stderr).contains("1 test targets failed:"));
        }
    }
    let output = p
        .command(&["test", "--workspace", "--offline"])
        .env("TEST_ABORT", "1")
        .output()
        .unwrap();
    // Motor reports abort as -1; Unix reports a signal, mapped to 101.
    assert_eq!(
        output.status.code(),
        Some(if cfg!(target_os = "motor") { -1 } else { 101 })
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        expected(&["alpha"], &kinds[..2], false)
    );
    p.write(
        "zeta/tests/integration.rs",
        "compile_error!(\"later target failed\");\n",
    );
    let output = p.run(&[
        "test",
        "--workspace",
        "--no-fail-fast",
        "--offline",
        "--message-format=json",
    ]);
    assert_eq!(output.status.code(), Some(101));
    let events: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        events.last().unwrap(),
        &serde_json::json!({"reason":"build-finished", "success":false})
    );
    assert!(
        events
            .iter()
            .any(|e| e["reason"] == "compiler-message" && e["message"]["level"] == "error")
    );
    assert!(
        !events
            .iter()
            .any(|e| e["reason"] == "build-finished" && e["success"] == true)
    );
}

#[test]
fn examples_benches_feature_gates_and_check_placeholders() {
    let p = workspace();
    let manifest = std::fs::read_to_string(p.root.join("alpha/Cargo.toml")).unwrap();
    p.write(
        "alpha/Cargo.toml",
        format!(
            r#"{manifest}
[[example]]
name="compiled"
[[example]]
name="tested"
test=true
harness=false
[[example]]
name="library-tested"
crate-type=["rlib"]
test=true
harness=false
[[example]]
name="disabled"
path="examples/tested.rs"
required-features=["manual"]
[[bench]]
name="optin"
test=true
harness=false
"#
        ),
    );
    p.write(
        "alpha/examples/compiled.rs",
        "fn main() { panic!(\"compile-only example ran\"); }\n",
    );
    for (path, kind) in [
        ("examples/tested.rs", "tested"),
        ("examples/library-tested.rs", "library-tested"),
        ("benches/optin.rs", "bench"),
    ] {
        p.write(
            &format!("alpha/{path}"),
            format!(
                r#"
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/assert-runtime.rs"));
fn main() {{ assert_eq!(alpha::value(), zeta::value()); assert_runtime({kind:?}); }}
"#
            ),
        );
    }
    for bundle in [false, true] {
        for (selection, kinds) in [
            (
                vec![],
                vec![
                    "library",
                    "binary",
                    "integration",
                    "bench",
                    "library-tested",
                    "tested",
                ],
            ),
            (vec!["--example", "tested"], vec!["tested"]),
            (vec!["--example", "library-tested"], vec!["library-tested"]),
            (vec!["--bench", "optin"], vec!["bench"]),
            (
                vec![
                    "--test",
                    "integration",
                    "--example",
                    "tested",
                    "--example",
                    "library-tested",
                    "--bench",
                    "optin",
                ],
                vec!["integration", "bench", "library-tested", "tested"],
            ),
        ] {
            let mut args = vec!["test", "-p", "alpha", "--offline"];
            args.extend(selection);
            if bundle {
                args.push("--bundle");
            }
            let output = p.success(&args);
            assert_eq!(
                String::from_utf8(output.stdout).unwrap(),
                expected(&["alpha"], &kinds, false)
            );
        }
    }
    p.fails(
        &["check", "--workspace", "--example", "missing", "--offline"],
        "no example target named",
    );
    p.fails(
        &["check", "--workspace", "--bench", "missing", "--offline"],
        "no bench target named",
    );
    p.fails(
        &["check", "-p", "alpha", "--example", "disabled", "--offline"],
        "requires the features",
    );
    p.success(&[
        "check",
        "-p",
        "alpha",
        "--example",
        "disabled",
        "--features",
        "manual",
        "--offline",
    ]);
    for name in ["alpha", "zeta"] {
        let source =
            std::fs::read_to_string(p.root.join(format!("{name}/tests/integration.rs"))).unwrap();
        p.write(
            &format!("{name}/tests/integration.rs"),
            format!(
                r#"{source}
const BIN: &[u8] = env!("CARGO_BIN_EXE_{name}").as_bytes();
const _: () = assert!(BIN.len() == "placeholder:{name}".len() && BIN[0] == b'p');
const TMP: &[u8] = env!("CARGO_TARGET_TMPDIR").as_bytes();
const _: () = assert!(TMP[TMP.len()-3] == b't' && TMP[TMP.len()-1] == b'p');
"#
            ),
        );
    }
    let output = p.success(&[
        "check",
        "--workspace",
        "--all-targets",
        "--offline",
        "--message-format=json",
    ]);
    assert!(
        artifacts(&output)
            .iter()
            .filter(|a| a["target"]["kind"] != serde_json::json!(["custom-build"]))
            .all(|a| a["executable"].is_null())
    );
    let empty = Project::new();
    empty.package(".", "empty", "[lib]\ntest=false\ndoctest=false\n");
    empty.write("src/lib.rs", "compile_error!(\"unused library\");\n");
    empty.lock(&[("empty", &[])]);
    empty.admit();
    assert_eq!(
        String::from_utf8(
            empty
                .success(&["test", "--offline", "--message-format=json"])
                .stdout
        )
        .unwrap()
        .trim(),
        r#"{"reason":"build-finished","success":true}"#
    );
}
