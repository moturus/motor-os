use crate::registry::Registry;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::process::Command;

const URL: &str = "https://fixture.invalid/repository.git";
const SCRIPT_GRANT: &str = "[policy.rules.demo-script]\naction=\"allow\"\nname=\"demo\"\nversion=\"=1.2.3\"\nsource=\"git\"\nallow-build-script=true\n";

fn git(directory: &Path, args: &[&str]) -> String {
    let output = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(directory)
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "{args:?}: {output:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn sources(commit: &str, pinned: &str) -> Vec<(&'static str, String)> {
    [
        ("demo", format!("?branch=main#{commit}")),
        ("head-demo", format!("#{commit}")),
        ("tag-demo", format!("?tag=v1#{commit}")),
        ("named-demo", format!("?rev=refs%2Fheads%2Ftopic#{commit}")),
        ("pinned-demo", format!("?rev={pinned}#{pinned}")),
    ]
    .into_iter()
    .map(|(name, selector)| (name, format!("git+{URL}{selector}")))
    .collect()
}

pub fn run() {
    let r = Registry::new();
    r.configure(SCRIPT_GRANT);
    let p = &r.project;
    let state = &r.state;
    state.write("source/Cargo.toml", "[workspace]\nmembers=[\"demo\",\"head-demo\",\"tag-demo\",\"named-demo\",\"pinned-demo\"]\nresolver=\"2\"\n");
    for name in ["demo", "head-demo", "tag-demo", "named-demo", "pinned-demo"] {
        state.write(
            &format!("source/{name}/Cargo.toml"),
            format!(
                "[package]\nname={name:?}\nversion=\"1.2.3\"\nedition=\"2024\"\nlicense=\"MIT\"\n"
            ),
        );
        state.write(
            &format!("source/{name}/src/lib.rs"),
            "pub fn answer() -> u32 { 42 }\n",
        );
    }
    let source = state.root.join("source");
    git(&source, &["init", "-q", "-b", "main"]);
    git(&source, &["config", "user.name", "Lorry Test"]);
    git(&source, &["config", "user.email", "lorry@example.invalid"]);
    git(&source, &["add", "."]);
    git(&source, &["commit", "-qm", "initial"]);
    let initial = git(&source, &["rev-parse", "HEAD"]);
    git(&source, &["branch", "topic"]);
    git(&source, &["tag", "v1"]);
    let remote = state.root.join("git/repository.git");
    fs::create_dir(state.root.join("git")).unwrap();
    git(
        &source,
        &["clone", "-q", "--bare", ".", remote.to_str().unwrap()],
    );
    p.write(
        "Cargo.toml",
        format!(
            r#"
[workspace]
members=["app"]
resolver="2"
[patch.crates-io]
renamed={{package="demo",git="{URL}",branch="main"}}
head-demo={{git="{URL}"}}
tag-demo={{git="{URL}",tag="v1"}}
named-demo={{git="{URL}",rev="refs/heads/topic"}}
pinned-demo={{git="{URL}",rev="{initial}"}}
"#
        ),
    );
    p.package("app", "app", "[dependencies]\nrenamed={package=\"demo\",version=\"=1.2.3\"}\nhead-demo=\"=1.2.3\"\ntag-demo=\"=1.2.3\"\nnamed-demo=\"=1.2.3\"\npinned-demo=\"=1.2.3\"\n");
    p.write(
        "app/src/main.rs",
        "fn main() { println!(\"{}\", renamed::answer()); }\n",
    );
    let identities = sources(&initial, &initial);
    let mut lock =
        "version=4\n[[package]]\nname=\"app\"\nversion=\"1.0.0\"\ndependencies=[\n".to_owned();
    for (name, source) in &identities {
        lock.push_str(&format!("{name:?}, # {source}\n"));
    }
    lock.push_str("]\n");
    for (name, source) in &identities {
        lock.push_str(&format!(
            "[[package]]\nname={name:?}\nversion=\"1.2.3\"\nsource={source:?}\n"
        ));
    }
    p.write("Cargo.lock", &lock);
    let manifests =
        ["Cargo.toml", "app/Cargo.toml"].map(|path| fs::read(p.root.join(path)).unwrap());
    p.fails(&["vendor", "-p", "app"], "no interactive terminal");
    assert_eq!(fs::read_to_string(p.root.join("Cargo.lock")).unwrap(), lock);
    assert!(!p.root.join(".lorry/dependencies-v2.toml").exists());
    p.success(&["vendor", "-p", "app", "--accept-all"]);
    r.forget_accept_all();
    assert!(!p.root.join(".lorry/vendor/renamed").exists());
    for (_, source) in &identities {
        let digest = format!("{:x}", Sha256::digest(source.as_bytes()));
        assert!(
            p.root
                .join(format!(".lorry/vendor/git/{digest}/git.toml"))
                .is_file()
        );
    }
    p.success(&["vendor", "-p", "app"]);
    let saved = || {
        ["Cargo.lock", ".lorry/dependencies-v2.toml"]
            .map(|path| fs::read(p.root.join(path)).unwrap())
    };
    let initial_state = saved();
    state.write("source/demo/src/lib.rs", "pub fn answer() -> u32 { 43 }\n");
    state.write("source/demo/build.rs", "fn main() {}\n");
    git(&source, &["add", "."]);
    git(&source, &["commit", "-qm", "script"]);
    let second = git(&source, &["rev-parse", "HEAD"]);
    git(&source, &["push", "-q", remote.to_str().unwrap(), "main"]);
    for offline in [false, true] {
        let mut args = vec!["vendor", "--locked", "-p", "app"];
        if offline {
            args.push("--offline");
        }
        p.success(&args);
        assert_eq!(saved(), initial_state);
    }
    let declined = p.fails(&["vendor", "-p", "app"], "no interactive terminal");
    let text = String::from_utf8_lossy(&declined.stderr);
    assert!(text.contains(&format!("old commit: {initial}")), "{text}");
    assert!(text.contains(&format!("new commit: {second}")), "{text}");
    assert_eq!(saved(), initial_state);
    let accepted = p.success(&["vendor", "-p", "app", "--accept-all"]);
    let text = String::from_utf8_lossy(&accepted.stderr);
    assert_eq!(text.matches("Git patch candidate:").count(), 2, "{text}");
    assert!(text.contains("+ capability:"), "{text}");
    r.forget_accept_all();
    let second_state = saved();
    state.write(
        "source/demo/src/lib.rs",
        "#![deny(dead_code)]\nfn intentionally_unused() {}\npub fn answer() -> u32 { 44 }\n",
    );
    git(&source, &["add", "."]);
    git(&source, &["commit", "-qm", "retarget"]);
    let third = git(&source, &["rev-parse", "HEAD"]);
    git(&source, &["tag", "-f", "v1"]);
    git(&source, &["branch", "-f", "topic", "HEAD"]);
    git(
        &source,
        &[
            "push",
            "-q",
            "--force",
            remote.to_str().unwrap(),
            "main",
            "v1",
            "topic",
        ],
    );
    let declined = p.fails(&["vendor", "-p", "app"], "no interactive terminal");
    let text = String::from_utf8_lossy(&declined.stderr);
    assert_eq!(text.matches("Git patch candidate:").count(), 4, "{text}");
    assert!(text.contains("[WARNING: RETARGETED TAG]"), "{text}");
    assert_eq!(saved(), second_state);
    let accepted = p.success(&["vendor", "-p", "app", "--accept-all"]);
    assert_eq!(
        String::from_utf8_lossy(&accepted.stderr)
            .matches("Git patch candidate:")
            .count(),
        4
    );
    r.forget_accept_all();
    let third_state = saved();
    for (_, source) in sources(&third, &initial) {
        assert!(String::from_utf8_lossy(&third_state[0]).contains(&source));
    }
    git(&source, &["rm", "-q", "named-demo/Cargo.toml"]);
    git(&source, &["commit", "-qm", "invalid"]);
    let bad = git(&source, &["rev-parse", "HEAD"]);
    git(&source, &["tag", "-f", "v1"]);
    git(&source, &["branch", "-f", "topic", "HEAD"]);
    git(
        &source,
        &[
            "push",
            "-q",
            "--force",
            remote.to_str().unwrap(),
            "main",
            "v1",
            "topic",
        ],
    );
    p.fails(&["vendor", "-p", "app", "--accept-all"], "named-demo");
    assert_eq!(saved(), third_state);
    let identity = format!("git+{URL}?rev=refs%2Fheads%2Ftopic#{bad}");
    let digest = format!("{:x}", Sha256::digest(identity.as_bytes()));
    assert!(
        p.root
            .join(format!(".lorry/vendor/git/{digest}/git.toml"))
            .is_file()
    );
    git(
        &source,
        &[
            "push",
            "-q",
            "--force",
            remote.to_str().unwrap(),
            &format!("{third}:refs/heads/main"),
            &format!("{third}:refs/heads/topic"),
            &format!("{third}:refs/tags/v1"),
        ],
    );
    r.configure("[policy.rules.deny-demo]\naction=\"deny\"\nname=\"demo\"\nsource=\"git\"\n");
    p.fails(
        &["vendor", "-p", "app", "--accept-all"],
        "denied by policy rule `deny-demo`",
    );
    assert_eq!(saved(), third_state);
    r.configure(SCRIPT_GRANT);
    for command in ["build", "test"] {
        p.success(&[command, "--offline", "-p", "app"]);
    }
    assert_eq!(
        p.success(&["run", "--offline", "-p", "app", "-q"]).stdout,
        b"44\n"
    );
    let review = String::from_utf8(p.success(&["review"]).stdout).unwrap();
    assert!(review.contains("[[locked-git]]") && review.contains("[[git-source]]"));
    assert!(!review.contains("[[crates-io-patch]]"));
    let metadata = String::from_utf8(
        p.success(&["metadata", "--format-version", "1", "--offline"])
            .stdout,
    )
    .unwrap();
    assert!(metadata.contains(&format!("git+{URL}?branch=main#demo@1.2.3")));
    assert!(metadata.contains("/cache/sources/demo-1.2.3-"));
    let tree = String::from_utf8(p.success(&["tree", "--offline", "-p", "app"]).stdout).unwrap();
    for (_, identity) in sources(&third, &initial) {
        let (selector, commit) = identity
            .strip_prefix("git+")
            .unwrap()
            .rsplit_once('#')
            .unwrap();
        assert!(
            tree.contains(&format!("({selector}#{})", &commit[..8])),
            "{tree}"
        );
    }
    assert_eq!(
        ["Cargo.toml", "app/Cargo.toml"].map(|path| fs::read(p.root.join(path)).unwrap()),
        manifests
    );
    println!(
        "PASS: Git patch approval, selector movement, atomic rejection and offline source identity"
    );
}
