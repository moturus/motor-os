mod support;

use std::fs;
use support::{Project, artifacts};

fn build(p: &Project, args: &[&str], fresh: bool) -> std::process::Output {
    let mut command = vec!["-v"];
    command.extend_from_slice(args);
    command.push("--offline");
    let output = p.success(&command);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr.contains("accepted fresh root profile before dependency admission"),
        fresh,
        "{args:?}: {stderr}"
    );
    if fresh {
        assert!(!stderr.contains("Running build script"), "{stderr}");
        assert!(!stderr.contains("Compiling "), "{stderr}");
    }
    output
}

fn value(p: &Project, expected: &str) {
    let output = std::process::Command::new(p.root.join("target/lorry/debug/app"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), expected);
}

#[test]
fn workspace_profiles_track_selections_sources_scripts_and_admission() {
    let p = Project::new();
    let manifest = "[workspace]\nmembers=[\"app\",\"util\",\"other\"]\nresolver=\"2\"\n";
    p.write("Cargo.toml", manifest);
    p.package("app", "app", "[dependencies]\nutil={path=\"../util\"}\n");
    let script = r#"fn main() {
        let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
        std::fs::write(out.join("generated.rs"), "const _: () = ();\n").unwrap();
        println!("cargo:rerun-if-changed=build.rs");
        println!("cargo:rustc-env=APP_SCRIPT=one");
    }"#;
    p.write("app/build.rs", script);
    p.write(
        "app/src/main.rs",
        r#"include!(concat!(env!("OUT_DIR"), "/generated.rs"));
        fn main() { println!("{} {}", env!("APP_SCRIPT"), util::describe()); }"#,
    );
    p.package("util", "util", "[features]\nextra=[]\n");
    let util = "pub fn describe() -> &'static str { if cfg!(feature=\"extra\") { \"extra\" } else { \"plain\" } }\n";
    p.write("util/src/lib.rs", util);
    p.package(
        "other",
        "other",
        "[dependencies]\nutil={path=\"../util\",features=[\"extra\"]}\n",
    );
    p.write(
        "other/src/lib.rs",
        "pub fn value() -> &'static str { util::describe() }\n",
    );
    p.lock(&[("app", &["util"]), ("util", &[]), ("other", &["util"])]);
    p.admit();

    for (selection, expected) in [
        (vec!["build"], "one extra"),
        (vec!["build", "-p", "app"], "one plain"),
        (vec!["build"], "one extra"),
    ] {
        build(&p, &selection, false);
        value(&p, expected);
        build(&p, &selection, true);
    }
    p.write("util/src/lib.rs", format!("{util}// edited\n"));
    let output = build(&p, &["build"], false);
    assert!(String::from_utf8_lossy(&output.stderr).contains("Compiling util v1.0.0"));
    build(&p, &["build"], true);
    p.write(
        "app/build.rs",
        script.replace("APP_SCRIPT=one", "APP_SCRIPT=two"),
    );
    let output = build(&p, &["build"], false);
    assert!(String::from_utf8_lossy(&output.stderr).contains("Running build script app"));
    value(&p, "two extra");
    build(&p, &["build"], true);
    for (selection, expected) in [
        (
            vec!["build", "-p", "app", "--features", "util/extra"],
            "two extra",
        ),
        (vec!["build", "-p", "app"], "two plain"),
        (vec!["build", "--bin", "app"], "two extra"),
    ] {
        build(&p, &selection, false);
        value(&p, expected);
        build(&p, &selection, true);
    }
    build(&p, &["run", "-p", "app"], false);
    assert_eq!(
        build(&p, &["run", "-p", "app"], true).stdout,
        b"two plain\n"
    );
    build(&p, &["check"], false);
    build(&p, &["check"], true);
    p.write(
        "util/src/lib.rs",
        format!("{util}fn unused_marker() {{}}\n"),
    );
    for fresh in [false, true] {
        let output = build(&p, &["check"], fresh);
        assert!(String::from_utf8_lossy(&output.stderr).contains("unused_marker"));
    }
    build(&p, &["check", "--tests"], false);
    build(&p, &["check", "--tests"], true);
    build(&p, &["check"], true);
    for _ in 0..2 {
        build(&p, &["clippy"], false);
    }

    p.package("added", "added", "");
    p.write("added/src/lib.rs", "pub fn added() {}\n");
    p.write(
        "Cargo.toml",
        manifest.replace("\"other\"]", "\"other\",\"added\"]"),
    );
    p.lock(&[
        ("app", &["util"]),
        ("util", &[]),
        ("other", &["util"]),
        ("added", &[]),
    ]);
    p.admit();
    let output = build(&p, &["build"], false);
    assert!(String::from_utf8_lossy(&output.stderr).contains("Compiling added v1.0.0"));
    build(&p, &["build"], true);
    let admission = fs::read_to_string(p.root.join(".lorry/dependencies-v2.toml")).unwrap();
    let altered = admission
        .lines()
        .map(|line| {
            if line.starts_with("review-sha256 =") {
                format!("review-sha256 = {:?}", "0".repeat(64))
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert_ne!(altered, admission.trim_end());
    p.write(".lorry/dependencies-v2.toml", altered);
    p.fails(
        &["build", "--offline"],
        "workspace admission commitment does not match",
    );
    p.write(".lorry/dependencies-v2.toml", admission);
    build(&p, &["build"], true);
    build(&p, &["build", "-p", "app"], false);
    build(&p, &["build", "-p", "app"], true);
    let other = fs::read_to_string(p.root.join("other/Cargo.toml")).unwrap();
    p.write("other/Cargo.toml", format!("{other}\n"));
    build(&p, &["build", "-p", "app"], false);
    p.success(&["run", "-p", "app", "--offline"]);
    for _ in 0..2 {
        build(&p, &["build", "-p", "app"], true);
        build(&p, &["run", "-p", "app"], true);
    }
}

#[test]
fn single_package_profiles_keep_distinct_binary_and_check_records() {
    let p = Project::new();
    p.package(".", "single", "[features]\nx=[]\n");
    for binary in ["a", "b"] {
        p.write(
            &format!("src/bin/{binary}.rs"),
            format!("fn main() {{ println!({binary:?}); }}\n"),
        );
    }
    p.lock(&[("single", &[])]);
    p.admit();
    let selections = [
        vec!["build"],
        vec!["run", "--bin", "a"],
        vec!["run", "--bin", "b"],
        vec!["check"],
        vec!["check", "--bin", "a"],
    ];
    for selection in &selections {
        build(&p, selection, false);
    }
    for _ in 0..2 {
        for selection in &selections {
            build(&p, selection, true);
        }
    }
    p.write(
        "examples/demo.rs",
        "fn main() { println!(\"{}\", if cfg!(feature=\"x\") { \"x\" } else { \"plain\" }); }\n",
    );
    build(&p, &["build", "--example", "demo"], false);
    build(&p, &["build", "--examples", "--features", "x"], false);
    let executable = p.root.join("target/lorry/debug/examples/demo");
    assert_eq!(
        std::process::Command::new(&executable)
            .output()
            .unwrap()
            .stdout,
        b"x\n"
    );
    build(&p, &["build", "--example", "demo"], false);
    assert_eq!(
        std::process::Command::new(&executable)
            .output()
            .unwrap()
            .stdout,
        b"plain\n"
    );
    let output = build(
        &p,
        &["build", "--example", "demo", "--message-format=json"],
        true,
    );
    assert!(
        artifacts(&output)
            .iter()
            .all(|artifact| artifact["fresh"] == true)
    );
}
