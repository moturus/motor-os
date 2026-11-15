mod support;

use std::fs;
use support::{Project, artifacts};

#[test]
fn target_directory_precedence_and_workspace_configuration() {
    let p = Project::new();
    p.write(
        "Cargo.toml",
        "[workspace]\nmembers=[\"app\"]\nresolver=\"2\"\n",
    );
    p.package("app", "app", "");
    p.write(
        "app/src/main.rs",
        "fn main() { println!(\"target-dir-ok\"); }\n",
    );
    p.write(".cargo/config.toml", "[build]\ntarget-dir=\"configured\"\n");
    p.lock(&[("app", &[])]);
    p.admit();
    let member = |arguments: &[&str], env: bool| {
        let mut command = p.command(arguments);
        command.current_dir(p.root.join("app"));
        if env {
            command.env("CARGO_TARGET_DIR", "env-output");
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{arguments:?}: {output:?}");
        output
    };
    member(&["build", "--offline"], false);
    assert!(p.root.join("configured/lorry/debug/app").is_file());
    member(&["build", "--offline"], true);
    assert!(p.root.join("app/env-output/lorry/debug/app").is_file());
    member(&["build", "--offline", "--target-dir", "cli-output"], true);
    assert!(p.root.join("app/cli-output/lorry/debug/app").is_file());
    assert_eq!(
        member(&["run", "--offline", "--target-dir", "cli-output"], true).stdout,
        b"target-dir-ok\n"
    );
    member(
        &[
            "test",
            "--offline",
            "--target-dir",
            "cli-output",
            "--no-run",
        ],
        true,
    );
    member(
        &["check", "--offline", "--target-dir", "check-output"],
        true,
    );
    assert!(p.root.join("app/check-output/lorry/check").is_dir());
    member(&["clean", "--target-dir", "cli-output"], true);
    assert!(!p.root.join("app/cli-output/lorry").exists());
    assert!(
        p.root
            .join("app/cli-output/.lorry-artifacts.lock")
            .is_file()
    );
    assert!(p.root.join("app/env-output/lorry/debug/app").is_file());
    p.write("app/.cargo/config.toml", "[build]\ntarget-dir=\"member-configured\"\n[alias]\nagent-build=[\"build\",\"-p\",\"app\"]\n");
    p.admit();
    p.success(&["build", "--offline", "-p", "app"]);
    p.success(&[
        "check",
        "--offline",
        "--manifest-path",
        "app/Cargo.toml",
        "--bin",
        "app",
    ]);
    assert!(!p.root.join("app/member-configured").exists());
    member(&["build", "--offline"], false);
    assert!(
        p.root
            .join("app/member-configured/lorry/debug/app")
            .is_file()
    );
    assert!(
        !p.command(&["agent-build"])
            .current_dir(p.root.join("app"))
            .status()
            .unwrap()
            .success()
    );
    p.write(
        "app/lorry.toml",
        "config-version=1\n[repositories]\nkeep-sources=true\n",
    );
    p.fails(
        &["build", "--offline", "-p", "app"],
        "move project settings to",
    );
    fs::rename(p.root.join("app/lorry.toml"), p.root.join("lorry.toml")).unwrap();
    p.success(&["build", "--offline", "-p", "app"]);
    p.write(
        "lorry.toml",
        "config-version=1\n[toolchain]\nrustc=\"/bin/false\"\n",
    );
    p.fails(
        &["build", "--offline", "-p", "app"],
        "project configuration cannot set `toolchain`",
    );
}

#[test]
fn selected_cache_replays_diagnostics_and_revalidates_admission() {
    let p = Project::new();
    p.package(".", "selected-cache", "");
    p.write(
        "src/lib.rs",
        "fn unused_cache_warning() {}\npub fn value() -> u8 { 42 }\n",
    );
    p.write(
        "src/main.rs",
        "fn main() { assert_eq!(selected_cache::value(), 42); }\n",
    );
    p.lock(&[("selected-cache", &[])]);
    p.admit();
    let warning = "function `unused_cache_warning` is never used";
    assert!(
        String::from_utf8_lossy(&p.success(&["build", "--offline", "--verbose"]).stderr)
            .contains(warning)
    );
    assert!(p.root.join("target/lorry/.cache/v1/units/sha256").is_dir());
    fs::remove_dir_all(p.root.join("target/lorry/debug")).unwrap();
    let restored = p.success(&["build", "--offline", "--verbose"]);
    let stderr = String::from_utf8_lossy(&restored.stderr);
    assert!(
        stderr.contains("Fresh selected-cache v1.0.0 (verified Lorry cache)"),
        "{stderr}"
    );
    assert!(stderr.contains(warning));
    for format in ["json", "json-diagnostic-rendered-ansi"] {
        let output = p.success(&["build", "--offline", "--quiet", "--message-format", format]);
        assert!(String::from_utf8_lossy(&output.stdout).contains(warning));
        assert!(artifacts(&output).iter().all(|a| a["fresh"] == true));
    }
    p.success(&["test", "--offline", "--no-run"]);
    let output = p.success(&["test", "--offline", "--no-run", "--message-format=json"]);
    assert!(String::from_utf8_lossy(&output.stdout).contains(warning));
    assert!(artifacts(&output).iter().all(|a| a["fresh"] == true));

    p.package("helper", "cache-helper", "");
    p.write("helper/src/lib.rs", "pub fn value() {}\n");
    p.write(
        "helper/build.rs",
        r#"use std::io::Write;
fn main() {
    std::fs::OpenOptions::new().create(true).append(true)
        .open(std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("script-runs"))
        .unwrap().write_all(b"x").unwrap();
}"#,
    );
    p.package(
        ".",
        "selected-cache",
        "[dependencies]\ncache-helper={path=\"helper\"}\n",
    );
    p.lock(&[("selected-cache", &["cache-helper"]), ("cache-helper", &[])]);
    p.admit();
    let scripts = p.root.join("target/lorry/debug/build/cache-helper");
    assert!(!scripts.exists());
    p.success(&["build", "--offline"]);
    let counters = find(&scripts, "script-runs");
    assert_eq!(counters.len(), 1);
    assert_eq!(fs::read(&counters[0]).unwrap(), b"x");
    let output = p.success(&["build", "--offline", "--message-format=json"]);
    assert!(artifacts(&output).iter().all(|a| a["fresh"] == true));
    for _ in 0..2 {
        p.success(&["run", "--offline"]);
    }
    assert_eq!(fs::read(&counters[0]).unwrap(), b"x");
    let state = fs::read_to_string(p.root.join(".lorry/dependencies-v2.toml")).unwrap();
    let tampered = state
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
    p.write(".lorry/dependencies-v2.toml", tampered);
    p.fails(
        &["build", "--offline"],
        "workspace admission commitment does not match",
    );
    assert_eq!(fs::read(&counters[0]).unwrap(), b"x");
}

fn find(root: &std::path::Path, name: &str) -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            paths.extend(find(&entry.path(), name));
        } else if entry.file_name() == name {
            paths.push(entry.path());
        }
    }
    paths
}

#[test]
fn build_script_metadata_and_link_search_propagate_to_dependents() {
    let p = Project::new();
    #[cfg(target_os = "motor")]
    p.write(
        ".cargo/config.toml",
        // This case explicitly links libc, so use Motor's C runtime recipe.
        "[target.x86_64-unknown-motor]\nlinker=\"/user/bin/dev/cc\"\nrustflags=[\"-Clink-self-contained=no\",\"-Cdefault-linker-libraries=yes\"]\n",
    );
    p.write(
        "Cargo.toml",
        "[workspace]\nmembers=[\"app\",\"sys\"]\nresolver=\"2\"\n",
    );
    p.package("sys", "demo-sys", "links=\"demo\"\n");
    let script = r#"fn main() {
    println!("cargo:root=/opt/demo-root");
    println!("cargo::metadata=include=include-dir");
    let out = std::env::var("OUT_DIR").unwrap();
    std::fs::write(std::path::Path::new(&out).join("libdemo.a"), b"!<arch>\n").unwrap();
    println!("cargo:rustc-link-search=native={out}");
    println!("cargo:rustc-link-lib=static:-bundle=demo");
}"#;
    p.write("sys/build.rs", script);
    p.write("sys/src/lib.rs", "pub fn value() -> u32 { 7 }\n");
    p.package("app", "app", "[dependencies]\ndemo-sys={path=\"../sys\"}\n");
    p.write(
        "app/build.rs",
        r#"fn main() {
    let root = std::env::var("DEP_DEMO_ROOT").unwrap();
    let include = std::env::var("DEP_DEMO_INCLUDE").unwrap();
    println!("cargo:rustc-env=DEMO={root}:{include}");
    println!("cargo:rustc-flags=-l c");
    println!("cargo:rustc-link-arg-bins=-Wl,--as-needed");
}"#,
    );
    p.write(
        "app/src/main.rs",
        "fn main() { println!(\"{} {}\", env!(\"DEMO\"), demo_sys::value()); }\n",
    );
    p.lock(&[("app", &["demo-sys"]), ("demo-sys", &[])]);
    p.admit();
    assert_eq!(
        p.success(&["run", "--offline", "-p", "app"]).stdout,
        b"/opt/demo-root:include-dir 7\n"
    );
    p.write(
        "sys/build.rs",
        script.replace("/opt/demo-root", "/opt/other-root"),
    );
    assert_eq!(
        p.success(&["run", "--offline", "-p", "app"]).stdout,
        b"/opt/other-root:include-dir 7\n"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn dependency_build_script_cannot_read_a_sibling_package() {
    let p = Project::new();
    p.package("app", "app", "[dependencies]\ndep={path=\"../dep\"}\n");
    p.write(
        "app/src/main.rs",
        "fn main() { println!(\"{}\", dep::READ); }\n",
    );
    p.write("app/secret.txt", "secret\n");
    p.package("dep", "dep", "");
    p.write(
        "dep/src/lib.rs",
        "pub const READ: &str = env!(\"ROOT_READ\");\n",
    );
    p.write(
        "dep/build.rs",
        r#"fn main() {
        let read = if std::fs::read("../app/secret.txt").is_ok() { "read" } else { "denied" };
        println!("cargo:rustc-env=ROOT_READ={read}");
    }"#,
    );
    p.write("app/Cargo.lock", "version=4\n[[package]]\nname=\"app\"\nversion=\"1.0.0\"\ndependencies=[\"dep\"]\n[[package]]\nname=\"dep\"\nversion=\"1.0.0\"\n");
    p.success(&[
        "vendor",
        "--manifest-path",
        "app/Cargo.toml",
        "--locked",
        "--offline",
        "--accept-all",
    ]);
    assert_eq!(
        p.success(&["run", "--offline", "--manifest-path", "app/Cargo.toml"])
            .stdout,
        b"denied\n"
    );
}
