mod support;

use std::fs;
use support::Project;

fn project() -> Project {
    let project = Project::new();
    project.write("Cargo.toml", "[workspace]\nmembers=[\"one\",\"two\"]\nexclude=[\"dep\"]\nresolver=\"2\"\n[profile.custom]\ninherits=\"release\"\n");
    project.write(
        "dep/Cargo.toml",
        "[package]\nname=\"dep\"\nversion=\"1.0.0\"\nedition=\"2024\"\n",
    );
    project.write("dep/src/lib.rs", "pub fn value() -> u32 { 42 }\n");
    for member in ["one", "two"] {
        project.write(&format!("{member}/Cargo.toml"), format!("[package]\nname=\"{member}\"\nversion=\"1.0.0\"\nedition=\"2024\"\n[dependencies]\ndep={{path=\"../dep\"}}\n"));
        project.write(
            &format!("{member}/src/main.rs"),
            "fn main() { println!(\"{}\", dep::value()); }\n",
        );
    }
    project.write("Cargo.lock", "version = 4\n[[package]]\nname = \"dep\"\nversion = \"1.0.0\"\n[[package]]\nname = \"one\"\nversion = \"1.0.0\"\ndependencies = [\"dep\"]\n[[package]]\nname = \"two\"\nversion = \"1.0.0\"\ndependencies = [\"dep\"]\n");
    project.admit();
    project
}

#[test]
fn selected_clean_preserves_dependency_outputs_other_profiles_and_the_lock() {
    let project = project();
    let locked = fs::read(project.root.join("Cargo.lock")).unwrap();
    let output = project.root.join("output/lorry");
    for selection in [
        &["-p", "one", "-p", "two", "-p", "one"][..],
        &["--workspace"],
    ] {
        project.success(&[
            "build",
            "--offline",
            "--workspace",
            "--target-dir",
            "output",
        ]);
        project.success(&[
            "build",
            "--offline",
            "--workspace",
            "--release",
            "--target-dir",
            "output",
        ]);
        let mut arguments = vec!["clean", "--target-dir", "output"];
        arguments.extend_from_slice(selection);
        project.success(&arguments);
        for member in ["one", "two"] {
            assert!(!output.join("debug").join(member).exists());
            assert!(output.join("release").join(member).is_file());
        }
        assert!(output.join("debug/build/dep").is_dir());
        project.success(&[
            "clean",
            "--workspace",
            "--release",
            "--target-dir",
            "output",
        ]);
        for member in ["one", "two"] {
            assert!(!output.join("release").join(member).exists());
        }
        assert!(output.join("release/build/dep").is_dir());
        assert_eq!(fs::read(project.root.join("Cargo.lock")).unwrap(), locked);
    }

    project.success(&[
        "build",
        "--offline",
        "--workspace",
        "--target-dir",
        "output",
    ]);
    project.success(&[
        "build",
        "--offline",
        "--workspace",
        "--profile",
        "custom",
        "--target-dir",
        "output",
    ]);
    project.success(&[
        "clean",
        "-p",
        "one",
        "--profile",
        "custom",
        "--target-dir",
        "output",
    ]);
    assert!(!output.join("custom/one").exists());
    assert!(output.join("custom/two").is_file());
    assert!(output.join("debug/one").is_file());
    assert!(output.join("debug/two").is_file());

    let manifest = fs::read_to_string(project.root.join("Cargo.toml")).unwrap();
    project.write("Cargo.toml", format!("{manifest}rpath = true\n"));
    project.success(&["clean", "--profile", "custom", "--target-dir", "output"]);
    assert!(!output.join("custom").exists());
    assert!(output.join("debug/two").is_file());
    project.write("Cargo.toml", manifest);
    let error = project.run(&["clean", "--profile", "missing", "--target-dir", "output"]);
    assert!(!error.status.success());
    assert!(String::from_utf8_lossy(&error.stderr).contains("profile `missing` is not defined"));
    assert_eq!(fs::read(project.root.join("Cargo.lock")).unwrap(), locked);
}

#[test]
fn member_clean_removes_the_shared_tree_and_source_only_clean_needs_no_lock() {
    let project = project();
    project.success(&["build", "--offline", "--workspace"]);
    let output = project
        .command(&["clean"])
        .current_dir(project.root.join("one"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(!project.root.join("target/lorry").exists());
    fs::remove_file(project.root.join("Cargo.lock")).unwrap();
    project.write("empty/Cargo.toml", "[workspace]\nmembers=[]\n");
    project.write("empty/target/lorry/debug/stale", "stale output");
    project.success(&[
        "clean",
        "--workspace",
        "--manifest-path",
        "empty/Cargo.toml",
    ]);
    assert!(!project.root.join("empty/target/lorry").exists());
    project.success(&["clean", "--workspace", "--target-dir", "output"]);
}
