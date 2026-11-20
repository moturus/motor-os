#[path = "sources/cargo_cache.rs"]
mod cargo_cache;
#[cfg(unix)]
#[path = "sources/git.rs"]
mod git;
#[cfg(unix)]
#[path = "sources/git_http.rs"]
mod git_http;
#[path = "sources/registry.rs"]
mod registry;
#[path = "sources/review.rs"]
mod review;
#[path = "sources/scripts.rs"]
mod scripts;
mod support;
#[path = "sources/trust.rs"]
mod trust;
#[path = "sources/upgrade.rs"]
mod upgrade;

use registry::Registry;
use serde_json::{Value, json};
use std::fs;

fn main() {
    if std::env::args().any(|arg| arg == "--url") {
        #[cfg(unix)]
        if std::env::args().any(|arg| arg.contains("LORRY-CURL-GIT-1")) {
            git_http::run();
            return;
        }
        registry::curl();
        return;
    }
    registry_review_and_source_views();
    fetch_preserves_lock_and_admission();
    mixed_case_names();
    scripted_registry_requires_explicit_acceptance();
    macro_fetch_uses_host_dependencies();
    review::run();
    scripts::run();
    trust::run_all();
    cargo_cache::run();
    upgrade::run();
    #[cfg(unix)]
    git::run();
}

fn messages(output: &std::process::Output) -> Vec<Value> {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

fn locked(name: &str, checksum: &str) -> String {
    format!(
        "[[package]]\nname={name:?}\nversion=\"1.0.0\"\nsource=\"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum={checksum:?}\n"
    )
}

fn registry_review_and_source_views() {
    let r = Registry::new();
    let p = &r.project;
    let checksum = r.package(
        "registry-leaf",
        "",
        &[("src/lib.rs", "pub fn value() -> u32 { 42 }\n")],
        json!([]),
    );
    let index_path = format!("network/index/{}", registry::sparse("registry-leaf"));
    let index = fs::read_to_string(r.state.root.join(&index_path)).unwrap();
    r.state.write(&index_path, format!("{index}{}\n{}\n",
        json!({"name":"registry-leaf","vers":"0.0.1","deps":[{"name":"core","req":"^1","features":["a","a"]}],"cksum":"0".repeat(64),"features":{},"yanked":false}),
        json!({"name":"registry-leaf","vers":"0.0.2","deps":"unreadable","cksum":"0".repeat(64),"features":{},"yanked":false})));
    p.package(
        ".",
        "consumer",
        "[dependencies]\nregistry-leaf=\"=1.0.0\"\n",
    );
    p.write(
        "src/main.rs",
        "fn main() { assert_eq!(registry_leaf::value(), 42); }\n",
    );
    let lock = format!(
        "version=4\n{}[[package]]\nname=\"consumer\"\nversion=\"1.0.0\"\ndependencies=[\"registry-leaf\"]\n",
        locked("registry-leaf", &checksum)
    );
    p.write("Cargo.lock", &lock);
    let declined = p.fails(
        &["-q", "--lorry-messages", "vendor"],
        "no interactive terminal",
    );
    assert!(!p.root.join(".lorry/dependencies-v2.toml").exists());
    assert_eq!(fs::read_to_string(p.root.join("Cargo.lock")).unwrap(), lock);
    let accepted = p.success(&["-q", "--lorry-messages", "vendor", "--accept-all"]);
    assert!(accepted.stdout.is_empty());
    let accepted = messages(&accepted);
    let declined = messages(&declined);
    assert_eq!(accepted.len(), 1);
    assert_eq!(declined.len(), 2);
    assert_eq!(accepted[0], declined[0]);
    let review = &accepted[0];
    assert_eq!(review["reason"], "lorry-vendor-change");
    assert_eq!(review["added"].as_array().unwrap().len(), 1);
    assert_eq!(review["added"][0]["name"], "registry-leaf");
    assert_eq!(review["added"][0]["checksum"], checksum);
    for key in ["removed", "capabilities_added", "capabilities_removed"] {
        assert_eq!(review[key], json!([]));
    }
    for verbose in [false, true] {
        fs::remove_dir_all(p.root.join(".lorry")).unwrap();
        fs::remove_dir_all(r.state.root.join("repository")).unwrap();
        let mut args = vec!["vendor", "--accept-all"];
        if verbose {
            args.push("--verbose");
        }
        let output = p.success(&args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        for text in [
            "New crates.io packages (1):",
            "member users: consumer",
            "Updating crates.io index",
            "Downloading registry-leaf v1.0.0",
            "Resolving dependency graph",
            "Checking dependency repository state",
            "Verifying selected dependency sources",
        ] {
            assert!(stderr.contains(text), "{stderr}");
        }
        assert_eq!(stderr.contains("repeats feature `a`"), verbose, "{stderr}");
        assert_eq!(
            stderr.contains("skipped version 0.0.2"),
            verbose,
            "{stderr}"
        );
    }
    let before = r.requests();
    p.success(&["vendor", "--accept-all"]);
    assert!(!r.requests()[before.len()..].contains("https://static.crates.io/"));
    let metadata = p.success(&["metadata", "--format-version", "1", "--locked", "--offline"]);
    let parsed: Value = serde_json::from_slice(&metadata.stdout).unwrap();
    let leaf = parsed["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "registry-leaf")
        .unwrap();
    let source = leaf["manifest_path"].as_str().unwrap();
    assert!(
        source.contains("/cache/sources/registry-leaf-1.0.0-"),
        "{source}"
    );
    assert!(std::path::Path::new(source).is_file());
    assert_eq!(
        p.success(&["metadata", "--format-version", "1", "--locked", "--offline"])
            .stdout,
        metadata.stdout
    );
    p.success(&["run", "--locked", "--offline"]);
    println!("PASS: registry review, sparse-index diagnostics and stable source views");
}

fn fetch_preserves_lock_and_admission() {
    let r = Registry::new();
    let p = &r.project;
    let leaf = r.package(
        "fetch-leaf",
        "",
        &[("src/lib.rs", "pub fn value() {}\n")],
        json!([]),
    );
    let inactive = r.package("fetch-inactive", "", &[("src/lib.rs", "")], json!([]));
    p.write(
        "Cargo.toml",
        "[workspace]\nmembers=[\"app\"]\nresolver=\"2\"\n",
    );
    let manifest = "[dependencies]\nfetch-leaf={version=\"=1.0.0\",optional=true}\n[target.'cfg(windows)'.dependencies]\nfetch-inactive=\"=1.0.0\"\n[features]\ndefault=[\"dep:fetch-leaf\"]\n";
    p.package("app", "app", manifest);
    p.write(
        "app/src/lib.rs",
        "compile_error!(\"fetch must not compile\");\n",
    );
    let lock = format!(
        "version=4\n{}{}[[package]]\nname=\"app\"\nversion=\"1.0.0\"\ndependencies=[\"fetch-leaf\",\"fetch-inactive\"]\n",
        locked("fetch-leaf", &leaf),
        locked("fetch-inactive", &inactive)
    );
    p.write("Cargo.lock", &lock);
    let admission = "existing admission bytes";
    p.write(".lorry/dependencies-v2.toml", admission);
    r.configure(
        "[policy.rules.veto]\naction=\"deny\"\nname=\"fetch-leaf\"\nsource=\"crates.io\"\n",
    );
    p.fails(&["fetch", "--locked"], "denied by policy rule");
    assert!(r.requests().is_empty());
    r.configure("");
    let host = if cfg!(target_os = "motor") {
        "x86_64-unknown-motor"
    } else {
        "x86_64-unknown-linux-gnu"
    };
    p.success(&["fetch", "--locked", "--target", host]);
    assert!(
        r.requests()
            .contains("https://static.crates.io/crates/fetch-leaf/")
    );
    assert!(
        !r.requests()
            .contains("https://static.crates.io/crates/fetch-inactive/")
    );
    let requests = r.requests();
    p.success(&["fetch", "--locked", "--offline", "--target", host]);
    p.success(&["tree", "--offline", "-p", "app", "--target", host]);
    p.fails(
        &["metadata", "--offline", "--format-version", "1"],
        "lorry fetch",
    );
    assert_eq!(r.requests(), requests);
    p.success(&["fetch", "--locked"]);
    assert!(
        r.requests()
            .contains("https://static.crates.io/crates/fetch-inactive/")
    );
    assert_eq!(fs::read_to_string(p.root.join("Cargo.lock")).unwrap(), lock);
    assert_eq!(
        fs::read_to_string(p.root.join(".lorry/dependencies-v2.toml")).unwrap(),
        admission
    );
    let requests = r.requests();
    p.success(&[
        "fetch",
        "--offline",
        "--target",
        host,
        "--target",
        "x86_64-pc-windows-gnu",
    ]);
    fs::remove_file(p.root.join(".lorry/dependencies-v2.toml")).unwrap();
    p.admit();
    let admission = fs::read(p.root.join(".lorry/dependencies-v2.toml")).unwrap();
    p.write(
        "app/src/lib.rs",
        "pub fn value() { fetch_leaf::value(); }\n",
    );
    p.success(&["build", "--offline"]);
    p.success(&["build", "--offline"]);
    fs::remove_file(p.root.join(".lorry/dependencies-v2.toml")).unwrap();
    p.fails(&["build", "--offline"], "requires");
    p.write(".lorry/dependencies-v2.toml", &admission);
    let narrowed = p.success(&[
        "-q",
        "--lorry-messages",
        "vendor",
        "--offline",
        "--locked",
        "-p",
        "app",
        "--no-default-features",
        "--accept-all",
    ]);
    let changes = messages(&narrowed);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0]["previous_review_available"], true);
    assert_eq!(changes[0]["added"], json!([]));
    assert_eq!(changes[0]["removed"][0]["name"], "fetch-leaf");
    p.fails(&["build", "--offline"], "does not cover");
    p.admit();
    assert_eq!(
        fs::read(p.root.join(".lorry/dependencies-v2.toml")).unwrap(),
        admission
    );
    p.package(
        "app",
        "app",
        &format!("{manifest}[dependencies.fetch-missing]\nversion=\"=1.0.0\"\n"),
    );
    p.fails(
        &["fetch", "--offline"],
        "Cargo.lock has no crates.io package",
    );
    assert_eq!(r.requests(), requests);
    assert_eq!(fs::read_to_string(p.root.join("Cargo.lock")).unwrap(), lock);
    assert_eq!(
        fs::read(p.root.join(".lorry/dependencies-v2.toml")).unwrap(),
        admission
    );
    println!("PASS: fetch preserves lock and admission, target selection and cached review scope");
}

fn mixed_case_names() {
    let r = Registry::new();
    let p = &r.project;
    r.package(
        "MixedCase",
        "",
        &[(
            "src/lib.rs",
            "#![allow(non_snake_case)]\npub fn answer() -> u32 { 42 }\n",
        )],
        json!([]),
    );
    p.package(".", "consumer", "[dependencies]\nMixedCase=\"=1.0.0\"\n");
    p.write(
        "src/main.rs",
        "fn main() { println!(\"answer {}\", MixedCase::answer()); }\n",
    );
    p.success(&["vendor", "--accept-all"]);
    assert!(
        r.requests()
            .contains("https://index.crates.io/mi/xe/mixedcase\n")
    );
    assert!(
        r.requests()
            .contains("https://static.crates.io/crates/MixedCase/MixedCase-1.0.0.crate\n")
    );
    assert!(
        fs::read_to_string(p.root.join("Cargo.lock"))
            .unwrap()
            .contains("name = \"MixedCase\"")
    );
    assert_eq!(
        p.success(&["run", "--offline", "-q"]).stdout,
        b"answer 42\n"
    );
    p.package(
        "lower",
        "consumer",
        "[dependencies]\nmixedcase=\"=1.0.0\"\n",
    );
    p.write("lower/src/main.rs", "fn main() {}\n");
    let output = p
        .command(&["vendor", "--accept-all"])
        .current_dir(p.root.join("lower"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("`mixedcase`"), "{error}");
    assert!(!error.contains("contains package"), "{error}");
    println!("PASS: sparse paths use lowercase while package identity preserves case");
}

fn scripted_registry_requires_explicit_acceptance() {
    let r = Registry::new();
    let p = &r.project;
    let checksum = r.package(
        "registry-scripted",
        "",
        &[
            (
                "build.rs",
                "fn main() { println!(\"cargo:rustc-env=VALUE=42\"); }\n",
            ),
            ("src/lib.rs", "pub const VALUE: &str = env!(\"VALUE\");\n"),
        ],
        json!([]),
    );
    p.package(
        ".",
        "consumer",
        "[dependencies]\nregistry-scripted=\"=1.0.0\"\n",
    );
    p.write(
        "src/main.rs",
        "fn main() { assert_eq!(registry_scripted::VALUE, \"42\"); }\n",
    );
    p.write("Cargo.lock", format!("version=4\n{}[[package]]\nname=\"consumer\"\nversion=\"1.0.0\"\ndependencies=[\"registry-scripted\"]\n", locked("registry-scripted", &checksum)));
    p.fails(&["vendor", "--locked"], "contains a build script");
    p.success(&["vendor", "--locked", "--accept-all"]);
    p.success(&["run", "--offline"]);
    println!("PASS: registry build scripts require and retain explicit acceptance");
}

fn macro_fetch_uses_host_dependencies() {
    let r = Registry::new();
    let p = &r.project;
    let host = if cfg!(target_os = "motor") {
        "motor"
    } else {
        "linux"
    };
    let leaf = r.package("macro-host", "", &[("src/lib.rs", "")], json!([]));
    let target = r.package("macro-target", "", &[("src/lib.rs", "")], json!([]));
    let deps = [("macro-host", host), ("macro-target", "windows")].map(|(name, platform)| {
        json!({
            "name":name,"req":"=1.0.0","features":[],"optional":false,"default_features":true,
            "target":format!("cfg(target_os = {platform:?})"),"kind":"normal","registry":null
        })
    });
    let macro_checksum = r.package("registry-macro", &format!(
        "[lib]\nproc-macro=true\n[target.'cfg(target_os = {host:?})'.dependencies]\nmacro-host=\"=1.0.0\"\n[target.'cfg(windows)'.dependencies]\nmacro-target=\"=1.0.0\"\n"
    ), &[("src/lib.rs", "compile_error!(\"fetch must not compile a macro\");\n")], json!(deps));
    p.package(
        ".",
        "consumer",
        "[dependencies]\nregistry-macro=\"=1.0.0\"\n",
    );
    p.write(
        "src/lib.rs",
        "compile_error!(\"fetch must not compile its root\");\n",
    );
    p.write("Cargo.lock", format!("version=4\n{}{}{}dependencies=[\"macro-host\",\"macro-target\"]\n[[package]]\nname=\"consumer\"\nversion=\"1.0.0\"\ndependencies=[\"registry-macro\"]\n",
        locked("macro-host", &leaf), locked("macro-target", &target), locked("registry-macro", &macro_checksum)));
    let original = fs::read(p.root.join("Cargo.lock")).unwrap();
    p.success(&["fetch", "--locked", "--target", "x86_64-pc-windows-gnu"]);
    let requests = r.requests();
    assert!(requests.contains("https://static.crates.io/crates/registry-macro/"));
    assert!(requests.contains("https://static.crates.io/crates/macro-host/"));
    assert!(!requests.contains("https://static.crates.io/crates/macro-target/"));
    p.success(&["fetch", "--offline", "--target", "x86_64-pc-windows-gnu"]);
    assert_eq!(r.requests(), requests);
    assert_eq!(fs::read(p.root.join("Cargo.lock")).unwrap(), original);
    assert!(!p.root.join(".lorry/dependencies-v2.toml").exists());
    println!("PASS: registry macro fetch uses host cfg without executing code");
}
