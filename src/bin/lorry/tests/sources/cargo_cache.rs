use super::{Registry, locked};
use serde_json::json;
use std::fs;

pub fn run() {
    let r = Registry::new();
    let p = &r.project;
    let cache = r.state.root.join("cargo-home");
    r.default_cargo_cache("");
    let packages = [
        (
            "scripted",
            "",
            vec![
                (
                    "build.rs",
                    "fn main() { println!(\"cargo:rustc-env=SCRIPTED=from-build-script\"); }\n",
                ),
                (
                    "src/lib.rs",
                    "pub const VALUE: &str = env!(\"SCRIPTED\");\n",
                ),
            ],
        ),
        (
            "derive-answer",
            "[lib]\nproc-macro=true\n",
            vec![(
                "src/lib.rs",
                "extern crate proc_macro;\n#[proc_macro] pub fn answer(_: proc_macro::TokenStream) -> proc_macro::TokenStream { \"42\".parse().unwrap() }\n",
            )],
        ),
    ];
    let mut lock = "version=4\n[[package]]\nname=\"app\"\nversion=\"1.0.0\"\ndependencies=[\"scripted\",\"derive-answer\"]\n".to_owned();
    for (name, extra, files) in packages {
        let checksum = r.package(name, extra, &files, json!([]));
        lock += &locked(name, &checksum);
        let source = format!("cargo-home/registry/src/index.crates.io-test/{name}-1.0.0");
        r.state.write(&format!("{source}/Cargo.toml"), format!("[package]\nname={name:?}\nversion=\"1.0.0\"\nedition=\"2024\"\nlicense=\"MIT\"\n{extra}"));
        for (path, text) in files {
            r.state.write(&format!("{source}/{path}"), text);
        }
        r.state.write(&format!("{source}/.cargo-ok"), r#"{"v":1}"#);
        let archive = fs::read(
            r.state
                .root
                .join(format!("network/archives/{name}/{name}-1.0.0.crate")),
        )
        .unwrap();
        r.state.write(
            &format!("cargo-home/registry/cache/index.crates.io-test/{name}-1.0.0.crate"),
            archive,
        );
    }
    p.package(
        ".",
        "app",
        "[dependencies]\nscripted=\"1\"\nderive-answer=\"1\"\n",
    );
    p.write(
        "build.rs",
        "fn main() { println!(\"cargo:rustc-env=MEMBER=member-script\"); }\n",
    );
    let source = "fn main() { println!(\"{} {} {}\", scripted::VALUE, derive_answer::answer!(), env!(\"MEMBER\")); }\n";
    p.write("src/main.rs", source);
    p.write("Cargo.lock", lock);
    let run = |args: &[&str]| p.command(args).env("CARGO_HOME", &cache).output().unwrap();
    let success = |args: &[&str]| {
        let output = run(args);
        assert!(output.status.success(), "{args:?}: {output:?}");
        output
    };
    let failure = |args: &[&str], error: &str| {
        let output = run(args);
        assert!(!output.status.success(), "{args:?}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        if error == "admission" {
            assert!(
                stderr.contains("workspace admission") || stderr.contains("Lorry repositories"),
                "{stderr}"
            );
        } else {
            assert!(stderr.contains(error), "{stderr}");
        }
        output
    };
    assert_eq!(
        success(&["run", "-q", "--offline"]).stdout,
        b"from-build-script 42 member-script\n"
    );
    assert!(!p.root.join(".lorry").exists());
    success(&["build", "-q", "--offline"]);
    let fresh = success(&["build", "-v", "--offline"]);
    assert!(
        String::from_utf8_lossy(&fresh.stderr)
            .contains("accepted fresh root profile before dependency admission")
    );
    let output = success(&["metadata", "--format-version", "1", "--offline"]);
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let packages = metadata["packages"].as_array().unwrap();
    assert_eq!(packages.len(), 3);
    for package in packages.iter().filter(|p| p["name"] != "app") {
        assert!(
            std::path::Path::new(package["manifest_path"].as_str().unwrap())
                .starts_with(cache.join("registry/src/index.crates.io-test"))
        );
    }
    assert!(!r.state.root.join("cache/sources").exists());
    r.default_cargo_cache(&format!(
        "[workspaces.{:?}.policy.rules.no-scripted]\naction=\"deny\"\nname=\"scripted\"\n",
        p.root.to_str().unwrap()
    ));
    failure(&["build", "--offline"], "no-scripted");
    r.default_cargo_cache("");
    failure(
        &["--no-use-cargo-registry", "build", "--offline"],
        "admission",
    );
    r.configure("");
    failure(&["build", "--offline"], "admission");
    r.default_cargo_cache("");
    p.write("lorry.toml", "config-version=1\nuse-cargo-registry=false\n");
    failure(
        &["build", "--offline"],
        "project configuration cannot set `use-cargo-registry`",
    );
    fs::remove_file(p.root.join("lorry.toml")).unwrap();
    p.write("src/main.rs", format!("{source}// edited\n"));
    let extracted = cache.join("registry/src/index.crates.io-test/derive-answer-1.0.0");
    fs::rename(&extracted, r.state.root.join("moved")).unwrap();
    let fallback = failure(&["build", "-v", "--offline"], "admission");
    let stderr = String::from_utf8_lossy(&fallback.stderr);
    assert!(stderr.contains("Using Lorry repositories because Cargo's cache cannot be used"));
    assert_eq!(
        stderr
            .lines()
            .filter(|line| *line == "Verifying dependency state")
            .count(),
        1
    );
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with("Using ") && line.contains("rustc"))
            .count(),
        1
    );
    failure(
        &["--use-cargo-registry", "build", "--offline"],
        "does not contain both the archive and extracted source",
    );
    fs::rename(r.state.root.join("moved"), extracted).unwrap();
    let absent = p
        .command(&["build", "--offline"])
        .env("CARGO_HOME", r.state.root.join("absent"))
        .output()
        .unwrap();
    assert!(!absent.status.success());
    assert!(r.requests().is_empty());
    println!("PASS: default Cargo source cache, explicit denial and repository fallback");
}
