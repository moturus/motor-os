use crate::{messages, registry::Registry};
use sha2::{Digest, Sha256};
use std::fs;

pub fn run() {
    committed_review();
    workspace_migration();
}

fn committed_review() {
    let r = Registry::new();
    let p = &r.project;
    let dependency = "[dependencies]\nreview-helper={path=\"helper\"}\n";
    p.package(".", "review-app", dependency);
    p.write(
        "src/main.rs",
        "fn main() { println!(\"{}\", review_helper::answer()); }\n",
    );
    p.package("helper", "review-helper", "");
    p.write("helper/src/lib.rs", "pub fn answer() -> u32 { 42 }\n");
    p.lock(&[("review-app", &["review-helper"]), ("review-helper", &[])]);
    p.success(&["vendor", "--accept-all"]);
    r.forget_accept_all();
    p.package(
        ".",
        "review-app",
        &format!("{dependency}[features]\nautomated-change=[]\n"),
    );
    let inputs = || {
        ["Cargo.toml", "Cargo.lock", ".lorry/dependencies-v2.toml"]
            .map(|path| fs::read(p.root.join(path)).unwrap())
    };
    let before = inputs();
    p.success(&["vendor"]);
    assert_eq!(inputs(), before);
    p.fails(
        &["vendor", "--features", "automated-change"],
        "no interactive terminal",
    );
    assert_eq!(inputs(), before);
    let output = p.success(&["vendor", "--features", "automated-change", "--accept-all"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("automated-change") && !stderr.contains("[y/N]"));
    let after = inputs();
    assert_eq!(&after[..2], &before[..2]);
    assert_ne!(after[2], before[2]);
    let retained = p.success(&["vendor"]);
    assert!(String::from_utf8_lossy(&retained.stderr).contains(
        "Review scope: all workspace members; default features; features: automated-change"
    ));
    let before = tree(&p.root);
    let review = p.success(&["review"]);
    assert_eq!(tree(&p.root), before);
    let digest = format!("{:x}", Sha256::digest(&review.stdout));
    let admission = fs::read_to_string(p.root.join(".lorry/dependencies-v2.toml")).unwrap();
    assert!(admission.contains(&format!("review-sha256 = {digest:?}")));
    p.fails(
        &["--use-cargo-registry", "review"],
        "cannot be combined with `review`",
    );
    for selection in [
        &["-p", "review-app"][..],
        &["--features", "extra"],
        &["--all-features"],
    ] {
        let mut args = vec!["review"];
        args.extend_from_slice(selection);
        p.fails(&args, "does not accept package or feature selection");
    }
    p.write(
        ".lorry/dependencies-v2.toml",
        admission.replace(&digest, &"0".repeat(64)),
    );
    p.fails(&["review"], "workspace admission commitment does not match");
    let output = p.success(&["vendor", "--accept-all"]);
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("Previous review cannot be reconstructed; showing the complete candidate.")
    );
    p.success(&["review"]);
    let admission = fs::read_to_string(p.root.join(".lorry/dependencies-v2.toml")).unwrap();
    p.write(
        ".lorry/dependencies-v2.toml",
        admission.replace("review-format-version = 5", "review-format-version = 3"),
    );
    p.success(&["vendor", "--accept-all"]);
    p.success(&["review"]);
    println!("PASS: read-only review commitment and explicit feature-scope approval");
}

fn tree(
    root: &std::path::Path,
) -> std::collections::BTreeMap<std::path::PathBuf, (Vec<u8>, std::time::SystemTime)> {
    let mut files = std::collections::BTreeMap::new();
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            files.extend(tree(&entry.path()));
        } else {
            files.insert(
                entry.path(),
                (
                    fs::read(entry.path()).unwrap(),
                    entry.metadata().unwrap().modified().unwrap(),
                ),
            );
        }
    }
    files
}

fn workspace_migration() {
    let r = Registry::new();
    let p = &r.project;
    r.configure("[policy.limits]\nmax-packages=1\n");
    p.write("Cargo.toml", "[workspace]\nmembers=[\"app\",\"shared\"]\ndefault-members=[\"app\"]\nexclude=[\"outside\",\"second\"]\nresolver=\"2\"\n");
    for name in ["app", "shared", "outside", "second"] {
        p.write(&format!("{name}/Cargo.toml"), format!("[package]\nname={name:?}\nversion=\"1.0.0\"\nedition=\"2018\"\nrust-version=\"1.60\"\n"));
        p.write(
            &format!("{name}/src/lib.rs"),
            "compile_error!(\"vendor must not compile\");\n",
        );
    }
    let append = |path: &str, extra: &str| {
        let text = fs::read_to_string(p.root.join(path)).unwrap();
        p.write(path, format!("{text}{extra}"));
    };
    append(
        "app/Cargo.toml",
        "[dependencies]\nshared={path=\"../shared\"}\n",
    );
    append(
        "shared/Cargo.toml",
        "[dependencies]\noutside={path=\"../outside\",optional=true}\n",
    );
    p.success(&["vendor", "--accept-all"]);
    let saved = || {
        ["Cargo.lock", ".lorry/dependencies-v2.toml"]
            .map(|path| fs::read(p.root.join(path)).unwrap())
    };
    let initial = saved();
    let lock = String::from_utf8_lossy(&initial[0]);
    assert!(lock.contains("version = 3") && lock.contains("name = \"outside\""));
    append("app/Cargo.toml", "[features]\nunused=[]\n");
    p.success(&["vendor"]);
    assert_eq!(saved(), initial);
    append(
        "shared/Cargo.toml",
        "second={path=\"../second\",optional=true}\n",
    );
    p.fails(&["vendor", "--accept-all"], "outside the workspace");
    assert_eq!(saved(), initial);
    p.success(&["--max-packages", "2", "vendor", "--accept-all"]);
    let reconciled = saved();
    assert!(String::from_utf8_lossy(&reconciled[0]).contains("name = \"second\""));
    for name in ["app", "shared", "outside", "second"] {
        let path = format!("{name}/Cargo.toml");
        let text = fs::read_to_string(p.root.join(&path)).unwrap();
        p.write(&path, text.replace("rust-version=\"1.60\"\n", ""));
    }
    p.success(&["--max-packages", "2", "vendor", "--accept-all"]);
    assert_eq!(saved()[0], reconciled[0]);
    let workspace = saved()[1].clone();
    let mut old = String::from_utf8(workspace.clone())
        .unwrap()
        .replace("review-format-version = 5", "review-format-version = 3");
    let start = old.find("[review-scope]").unwrap();
    let end = start + old[start..].find("[[context]]").unwrap();
    old.replace_range(start..end, "");
    p.write(".lorry/dependencies-v2.toml", &old);
    p.fails(
        &["--max-packages", "2", "build", "-p", "app"],
        "retired review format",
    );
    p.success(&[
        "--max-packages",
        "2",
        "vendor",
        "--locked",
        "--offline",
        "--accept-all",
    ]);
    p.write(".lorry/dependencies-v2.toml", &workspace);
    for name in ["app", "shared", "outside"] {
        p.write(&format!("{name}/.lorry/dependencies-v2.toml"), &old);
    }
    p.write("app/.lorry/sentinel", "unrelated state");
    r.forget_accept_all();
    p.fails(
        &[
            "--max-packages",
            "2",
            "vendor",
            "--locked",
            "--offline",
            "-p",
            "app",
        ],
        "no interactive terminal",
    );
    assert_eq!(saved()[1], workspace);
    assert_eq!(
        fs::read_to_string(p.root.join("app/.lorry/dependencies-v2.toml")).unwrap(),
        old
    );
    let output = p.success(&[
        "--max-packages",
        "2",
        "--lorry-messages",
        "vendor",
        "--locked",
        "--offline",
        "-p",
        "app",
        "--accept-all",
    ]);
    let events = messages(&output);
    let reasons: Vec<_> = events
        .iter()
        .map(|event| event["reason"].as_str().unwrap())
        .collect();
    assert_eq!(
        reasons,
        [
            "lorry-admission-migration",
            "lorry-vendor-change",
            "lorry-admission-migration"
        ]
    );
    assert_eq!(events[0]["stage"], "proposed");
    assert_eq!(events[2]["stage"], "completed");
    assert!(!p.root.join("app/.lorry/dependencies-v2.toml").exists());
    assert_eq!(
        fs::read_to_string(p.root.join("app/.lorry/sentinel")).unwrap(),
        "unrelated state"
    );
    #[cfg(unix)]
    {
        fs::rename(
            p.root.join("shared/.lorry"),
            p.root.join("shared/saved-lorry"),
        )
        .unwrap();
        std::os::unix::fs::symlink("../outside/.lorry", p.root.join("shared/.lorry")).unwrap();
        let before = saved();
        p.fails(
            &[
                "--max-packages",
                "2",
                "vendor",
                "--locked",
                "--offline",
                "--workspace",
                "--accept-all",
            ],
            "not a real directory",
        );
        assert_eq!(saved(), before);
        fs::remove_file(p.root.join("shared/.lorry")).unwrap();
        fs::rename(
            p.root.join("shared/saved-lorry"),
            p.root.join("shared/.lorry"),
        )
        .unwrap();
    }
    p.success(&[
        "--max-packages",
        "2",
        "vendor",
        "--locked",
        "--offline",
        "--workspace",
        "--accept-all",
    ]);
    assert!(!p.root.join("shared/.lorry/dependencies-v2.toml").exists());
    assert_eq!(
        fs::read_to_string(p.root.join("outside/.lorry/dependencies-v2.toml")).unwrap(),
        old
    );
    let review = p.success(&["--max-packages", "2", "review"]);
    let member = p
        .command(&["--max-packages", "2", "review"])
        .current_dir(p.root.join("app"))
        .output()
        .unwrap();
    assert!(member.status.success());
    assert_eq!(review.stdout, member.stdout);
    println!("PASS: workspace package caps and approval-scoped migration preserve unrelated state");
}
