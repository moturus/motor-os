mod support;

use std::fs;
use support::{Project, artifacts};

fn workspace() -> Project {
    let p = Project::new();
    p.write("Cargo.toml", "[workspace]\nmembers=[\"app\",\"tool\",\"shared\"]\ndefault-members=[\"app\"]\nresolver=\"2\"\n");
    p.package(
        "shared",
        "shared",
        "[features]\ndefault=[\"present\"]\npresent=[]\n",
    );
    p.write("shared/src/lib.rs", "pub const VALUE: u32 = 42;\n");
    for name in ["app", "tool"] {
        p.package(name, name, "[dependencies]\nshared={path=\"../shared\"}\n");
        p.write(
            &format!("{name}/src/main.rs"),
            format!("fn main() {{ assert_eq!(shared::VALUE,42); println!({name:?}); }}\n"),
        );
    }
    p.lock(&[("app", &["shared"]), ("tool", &["shared"]), ("shared", &[])]);
    p.admit();
    p
}

#[test]
fn package_selection_from_nested_directories_and_manifest_paths() {
    let p = workspace();
    for args in [
        vec!["-p", "app", "-p", "app@1.0"],
        vec!["--workspace", "--exclude", "app", "--exclude", "s*"],
        vec![
            "--workspace",
            "-p",
            "missing",
            "--exclude",
            "app",
            "--exclude",
            "s*",
        ],
    ] {
        let mut command = vec!["check", "--offline"];
        command.extend(args);
        p.success(&command);
    }
    let output = p.success(&[
        "check",
        "--workspace",
        "--exclude",
        "app",
        "--exclude",
        "s*",
        "--exclude",
        "missing",
        "--offline",
    ]);
    assert_eq!(
        String::from_utf8_lossy(&output.stderr)
            .matches("warning: excluded package")
            .count(),
        1
    );
    for args in [
        vec!["--workspace", "-p", "missing"],
        vec!["--workspace", "--exclude", "*"],
        vec!["--exclude", "app"],
    ] {
        let mut command = vec!["check", "--offline"];
        command.extend(args);
        assert!(!p.run(&command).status.success());
    }
    assert!(
        !p.run(&["run", "-p", "app", "-p", "app", "--offline"])
            .status
            .success()
    );
    let shared = p.root.join("shared");
    for selector in [
        "shared@1".to_owned(),
        "shared@1.0".into(),
        "shared@1.0.0".into(),
        "sha*".into(),
        format!("path+file://{}#1.0.0", shared.display()),
        format!("file://{}#shared@1.0", shared.display()),
    ] {
        let output = p
            .command(&["check", "--offline", "-p", &selector, "--lib"])
            .current_dir(p.root.join("app/src"))
            .output()
            .unwrap();
        assert!(output.status.success(), "{selector}: {output:?}");
    }
    for selector in [
        "shared@9",
        "^shared",
        "path+file:///not-this-workspace#shared@1.0.0",
    ] {
        assert!(
            !p.run(&["check", "-p", selector, "--offline"])
                .status
                .success()
        );
    }
    for directory in [&p.root, &p.root.join("app"), &p.root.join("app/src")] {
        let output = p
            .command(&["run", "-p", "app", "-q", "--offline"])
            .current_dir(directory)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, b"app\n");
    }
    let manifest = p.root.join("Cargo.toml");
    for action in ["review", "build", "test", "clean"] {
        let mut command = p.command(&[action, "--manifest-path", manifest.to_str().unwrap()]);
        command.current_dir(p.root.parent().unwrap());
        if action != "review" {
            command.args(["-p", "app"]);
        }
        if !["clean", "review"].contains(&action) {
            command.arg("--offline");
        }
        if action == "test" {
            command.arg("--no-run");
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{action}: {output:?}");
    }
}

#[test]
fn only_selected_profiles_reject_unsupported_settings() {
    let p = workspace();
    let manifest = fs::read_to_string(p.root.join("Cargo.toml")).unwrap();
    for (profile, allowed, denied) in [
        ("release", vec!["check"], vec!["build", "--release"]),
        ("dev", vec!["build", "--release"], vec!["check"]),
        ("test", vec!["build"], vec!["test", "--no-run"]),
    ] {
        p.write(
            "Cargo.toml",
            format!("{manifest}\n[profile.{profile}]\nrpath=true\n"),
        );
        let mut allowed = allowed;
        allowed.extend(["-p", "tool", "--offline"]);
        p.success(&allowed);
        let mut denied = denied;
        denied.extend(["-p", "tool", "--offline"]);
        p.fails(
            &denied,
            &format!("unsupported selected profile key `profile.{profile}.rpath`"),
        );
    }
    p.write(
        "Cargo.toml",
        format!("{manifest}\n[profile.test]\nopt-level=3\n"),
    );
    let output = p.success(&[
        "test",
        "-p",
        "tool",
        "--offline",
        "--no-run",
        "--message-format=json",
    ]);
    let harnesses: Vec<_> = artifacts(&output)
        .into_iter()
        .filter(|a| a["profile"]["test"] == true)
        .collect();
    assert!(!harnesses.is_empty());
    assert!(harnesses.iter().all(|a| a["profile"]["opt_level"] == "3"));
    let app = fs::read_to_string(p.root.join("app/Cargo.toml")).unwrap();
    for lint in ["unused=\"force-warn\"", "unused={level=\"force-warn\"}"] {
        p.write("app/Cargo.toml", format!("{app}\n[lints.rust]\n{lint}\n"));
        p.fails(
            &["build", "-p", "app", "--offline"],
            "unsupported rustc lint level `force-warn`",
        );
    }
}

#[test]
fn editable_sources_track_external_inputs_and_nested_package_boundaries() {
    let p = workspace();
    p.write("shared/foreign/Cargo.toml", "not a manifest\n");
    p.write("shared/large-editable-input", vec![0; 70_000]);
    p.write("external.txt", "outside-before");
    p.write(
        "shared/src/lib.rs",
        "pub const VALUE: &str = include_str!(\"../../external.txt\");\n",
    );
    p.write(
        "tool/src/main.rs",
        "fn main() { println!(\"{}\", shared::VALUE); }\n",
    );
    let run = |value: &str| {
        assert_eq!(
            p.success(&["run", "-q", "-p", "tool", "--offline"]).stdout,
            format!("{value}\n").as_bytes()
        );
    };
    run("outside-before");
    let output = p.success(&["build", "-v", "-p", "tool", "--offline"]);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("Compiling "));
    p.write("external.txt", "outside-after");
    run("outside-after");
    #[cfg(unix)]
    {
        p.write("first.txt", "link-before");
        p.write("second.txt", "link-after");
        let link = p.root.join("shared/link.txt");
        std::os::unix::fs::symlink("../first.txt", &link).unwrap();
        p.write(
            "shared/src/lib.rs",
            "pub const VALUE: &str = include_str!(\"../link.txt\");\n",
        );
        run("link-before");
        fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink("../second.txt", &link).unwrap();
        run("link-after");
    }
    p.success(&["build", "--strict-validation", "-p", "tool", "--offline"]);
    p.success(&["check", "-p", "tool", "--offline"]);
    p.success(&["clean", "-p", "tool"]);
    let output = p.success(&["build", "-v", "-p", "tool", "--offline"]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("Fresh shared v1.0.0"));
}

#[test]
fn keep_going_finishes_independent_members_and_collisions_compile_both_owners() {
    let p = Project::new();
    p.write(
        "Cargo.toml",
        "[workspace]\nmembers=[\"first\",\"second\"]\nresolver=\"2\"\n",
    );
    for name in ["first", "second"] {
        p.package(name, name, "");
        p.write(
            &format!("{name}/src/lib.rs"),
            if name == "first" {
                "compile_error!(\"expected member failure\");\n"
            } else {
                "pub fn value() {}\n"
            },
        );
    }
    p.lock(&[("first", &[]), ("second", &[])]);
    p.admit();
    let output = p.run(&[
        "build",
        "--workspace",
        "--keep-going",
        "-j1",
        "--offline",
        "--message-format=json",
    ]);
    assert_eq!(output.status.code(), Some(101));
    let events: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let failure = events
        .iter()
        .position(|e| {
            e["reason"] == "compiler-message"
                && e["message"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("expected member failure")
        })
        .unwrap();
    let good = events
        .iter()
        .position(|e| e["reason"] == "compiler-artifact" && e["target"]["name"] == "second")
        .unwrap();
    assert!(failure < good);
    assert!(
        events[good]["filenames"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| std::path::Path::new(p.as_str().unwrap()).is_file())
    );
    assert_eq!(
        events.last().unwrap(),
        &serde_json::json!({"reason":"build-finished","success":false})
    );
    for name in ["first", "second"] {
        fs::remove_file(p.root.join(format!("{name}/src/lib.rs"))).unwrap();
        p.package(name, name, "[[bin]]\nname=\"same\"\npath=\"src/main.rs\"\n");
        p.write(
            &format!("{name}/src/main.rs"),
            format!("fn main() {{ println!({name:?}); }}\n"),
        );
    }
    let output = p.success(&["build", "--workspace", "--offline", "--message-format=json"]);
    let errors = String::from_utf8_lossy(&output.stderr);
    for expected in [
        "output filename collision",
        "package `first v1.0.0",
        "package `second v1.0.0",
    ] {
        assert!(errors.contains(expected), "{errors}");
    }
    let artifacts = artifacts(&output);
    assert_eq!(artifacts.len(), 2);
    assert_ne!(artifacts[0]["package_id"], artifacts[1]["package_id"]);
    assert!(
        artifacts
            .iter()
            .all(|a| std::path::Path::new(a["executable"].as_str().unwrap()).is_file())
    );
    let quiet = p.success(&["build", "--workspace", "--offline", "--quiet"]);
    assert!(!String::from_utf8_lossy(&quiet.stderr).contains("output filename collision"));
}
