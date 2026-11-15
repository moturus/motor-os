mod support;
use support::{Project, artifacts};

fn macro_workspace() -> Project {
    let p = Project::new();
    p.write("Cargo.toml", "[workspace]\nmembers = [\"app\", \"derive\", \"helper\"]\ndefault-members = [\"app\"]\nresolver = \"2\"\n");
    p.package("helper", "helper", "[lib]\ndoctest = false\n");
    p.write("helper/src/lib.rs", "pub fn value() -> u32 { 41 }\n");
    p.package("derive", "derive", "[lib]\nproc-macro = true\ndoctest = false\n[features]\ndefault = [\"checked\"]\nchecked = []\n[dependencies]\nhelper = { path = \"../helper\" }\n");
    p.write(
        "derive/build.rs",
        r#"
fn main() {
    assert!(cfg!(feature = "checked"));
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(out.join("generated.rs"), "const VALUE: u32 = 41;").unwrap();
    println!("cargo:rustc-env=SCRIPT_OWNER=derive");
    println!("cargo:rerun-if-changed=build.rs");
}
"#,
    );
    p.write("derive/src/lib.rs", r#"
extern crate proc_macro;
include!(concat!(env!("OUT_DIR"), "/generated.rs"));
#[proc_macro]
pub fn answer(_: proc_macro::TokenStream) -> proc_macro::TokenStream {
    assert_eq!(helper::value(), VALUE);
    VALUE.to_string().parse().unwrap()
}
#[test]
fn macro_harness() {
    assert!(cfg!(feature = "checked"));
    assert_eq!(helper::value(), 41);
    assert_eq!(std::env::var("SCRIPT_OWNER").unwrap(), "derive");
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    assert_eq!(std::fs::read_to_string(out.join("generated.rs")).unwrap(), "const VALUE: u32 = 41;");
}
"#);
    p.package("app", "app", "[dependencies]\nderive = { path = \"../derive\" }\nhelper = { path = \"../helper\" }\n[build-dependencies]\nhelper = { path = \"../helper\" }\n");
    p.write(
        "app/src/main.rs",
        "fn main() { assert_eq!(derive::answer!(), helper::value()); println!(\"42\"); }\n",
    );
    p.write(
        "app/build.rs",
        "fn main() { assert_eq!(helper::value(), 41); }\n",
    );
    p.lock(&[
        ("app", &["derive", "helper"]),
        ("derive", &["helper"]),
        ("helper", &[]),
    ]);
    p
}

#[test]
fn member_macros_generate_code_and_run_their_own_harnesses() {
    let p = macro_workspace();
    p.admit();
    for profile in [&[][..], &["--release"][..]] {
        for selection in [&[][..], &["--workspace"][..], &["-p", "derive"][..]] {
            for command in ["build", "check"] {
                let mut arguments = vec![command, "--locked", "--offline", "--message-format=json"];
                arguments.extend_from_slice(profile);
                arguments.extend_from_slice(selection);
                let output = p.success(&arguments);
                assert!(
                    artifacts(&output)
                        .iter()
                        .any(|a| a["target"]["kind"] == serde_json::json!(["proc-macro"]))
                );
            }
        }
        let mut arguments = vec!["run", "--offline", "-q"];
        arguments.extend_from_slice(profile);
        assert_eq!(p.success(&arguments).stdout, b"42\n");
        for bundle in [&[][..], &["--bundle"][..]] {
            let mut arguments = vec!["test", "--offline", "-p", "derive"];
            arguments.extend_from_slice(bundle);
            arguments.extend_from_slice(profile);
            p.success(&arguments);
        }
    }
    p.write(
        "derive/tests/imported.rs",
        "#[test] fn imported_macro() { assert_eq!(derive::answer!(), 41); }\n",
    );
    p.success(&["test", "--offline", "-p", "derive"]);
}

#[test]
fn compile_time_only_checks_skip_ordinary_sources() {
    let p = macro_workspace();
    p.write(
        "app/src/main.rs",
        "compile_error!(\"ordinary source must be skipped\");\n",
    );
    p.admit();
    let original = std::fs::read(p.root.join("Cargo.lock")).unwrap();
    let output = p.success(&[
        "check",
        "--workspace",
        "--all-targets",
        "--keep-going",
        "--compile-time-deps",
        "--offline",
        "--message-format=json",
    ]);
    let libraries: std::collections::BTreeSet<_> = artifacts(&output)
        .iter()
        .filter(|a| a["target"]["kind"] != serde_json::json!(["custom-build"]))
        .map(|a| a["target"]["name"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(libraries, ["derive".to_owned(), "helper".to_owned()].into());
    p.fails(
        &[
            "check",
            "--workspace",
            "--all-targets",
            "--keep-going",
            "--offline",
        ],
        "ordinary source must be skipped",
    );
    p.fails(&["clippy", "--compile-time-deps"], "unexpected argument");
    assert_eq!(std::fs::read(p.root.join("Cargo.lock")).unwrap(), original);
}

#[test]
fn explicit_library_types_build_check_and_test() {
    let p = Project::new();
    p.write(
        "Cargo.toml",
        "[workspace]\nmembers = [\"app\", \"shared\"]\nresolver = \"2\"\n",
    );
    p.write("shared/src/lib.rs", "#[inline(never)] pub fn value() -> u32 { std::hint::black_box(42) }\n#[test] fn shared_test() { assert_eq!(value(), 42); }\n");
    p.write("app/src/lib.rs", "pub fn value() -> u32 { shared::value() }\n#[test] fn app_test() { assert_eq!(value(), 42); }\n");
    p.write(
        "app/src/main.rs",
        "fn main() { println!(\"{}\", app::value()); }\n",
    );
    p.lock(&[("app", &["shared"]), ("shared", &[])]);
    for kind in ["lib", "rlib"] {
        let library = format!("[lib]\ncrate-type = [{kind:?}]\ndoctest = false\n");
        p.package("shared", "shared", &library);
        p.package(
            "app",
            "app",
            &format!("{library}[dependencies]\nshared = {{ path = \"../shared\" }}\n"),
        );
        p.admit();
        for command in ["build", "check", "test"] {
            let output = p.success(&[command, "--workspace", "--offline", "--message-format=json"]);
            assert!(
                artifacts(&output)
                    .iter()
                    .any(|a| a["target"]["crate_types"] == serde_json::json!([kind]))
            );
        }
        assert_eq!(
            p.success(&["run", "-p", "app", "--offline", "-q"]).stdout,
            b"42\n"
        );
    }
}

#[cfg(target_os = "motor")]
#[test]
fn motor_drops_unsupported_dynamic_outputs() {
    let p = Project::new();
    p.write("src/lib.rs", "pub fn answer() -> u32 { 42 }\n");
    p.lock(&[("probe", &[])]);
    for types in [
        "\"rlib\",\"cdylib\"",
        "\"rlib\",\"dylib\"",
        "\"staticlib\",\"cdylib\"",
        "\"cdylib\"",
        "\"dylib\"",
    ] {
        p.package(".", "probe", &format!("[lib]\ncrate-type = [{types}]\n"));
        p.admit();
        for command in ["build", "check"] {
            let output = p.run(&[command, "--offline", "--message-format=json"]);
            if command == "build" && !types.contains(',') {
                assert_eq!(output.status.code(), Some(101));
                assert!(
                    String::from_utf8_lossy(&output.stderr)
                        .contains("does not support these crate types")
                );
            } else {
                assert!(output.status.success(), "{output:?}");
                assert_eq!(artifacts(&output).len(), 1);
                assert!(
                    String::from_utf8_lossy(&output.stdout)
                        .contains("dropping unsupported crate type")
                );
            }
        }
    }
}
