mod support;

use std::fs;
use std::process::Command;
use support::{Project, artifacts};

fn workspace() -> Project {
    let p = Project::new();
    p.write(
        "Cargo.toml",
        "[workspace]\nmembers=[\"app\",\"shared\",\"builder\"]\nresolver=\"2\"\n",
    );
    p.package("builder", "builder", "[lib]\ndoctest=false\n");
    p.write("builder/src/lib.rs", "pub fn value() -> u32 { 42 }\n");
    p.package(
        "shared",
        "shared",
        "[lib]\ndoctest=false\n[build-dependencies]\nbuilder={path=\"../builder\"}\n",
    );
    p.write(
        "shared/build.rs",
        r#"
fn main() {
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(out.join("generated.rs"), builder::value().to_string()).unwrap();
    println!("cargo:rustc-env=BUILD_PROFILE={}", std::env::var("PROFILE").unwrap());
}
"#,
    );
    p.write(
        "shared/src/lib.rs",
        r#"
pub fn value() -> u32 { include!(concat!(env!("OUT_DIR"), "/generated.rs")) }
pub fn profile() -> &'static str { env!("BUILD_PROFILE") }
"#,
    );
    p.package(
        "app",
        "app",
        "[dependencies]\nshared={path=\"../shared\"}\n",
    );
    p.write("app/src/main.rs", r#"
fn main() { assert_eq!(shared::value(), 42); println!("{} {}", shared::profile(), cfg!(debug_assertions)); }
#[test] fn generated_value() { assert_eq!(shared::value(), 42); }
"#);
    p.lock(&[
        ("app", &["shared"]),
        ("shared", &["builder"]),
        ("builder", &[]),
    ]);
    p
}

#[test]
fn profiles_control_compilation_scripts_and_harnesses() {
    let p = workspace();
    let manifest = fs::read_to_string(p.root.join("Cargo.toml")).unwrap();
    // JSON describes the selected target profile; build dependencies use the
    // host profile even when the target enables optimization or debug info.
    let cases = [
        ("release", "", "3", false),
        ("release", "strip=false", "3", false),
        ("release", "strip=\"none\"", "3", false),
        ("release", "strip=\"debuginfo\"", "3", false),
        ("release", "strip=\"symbols\"", "3", false),
        ("release", "debug=1\nopt-level=1", "1", false),
        ("release", "debug=true\nopt-level=\"s\"", "s", false),
        (
            "release",
            "debug=\"line-tables-only\"\nopt-level=0",
            "0",
            false,
        ),
        ("release", "debug=false\nopt-level=\"z\"", "z", false),
        ("dev", "panic=\"abort\"", "0", true),
        ("dev", "debug=1\nopt-level=1", "1", true),
        ("dev", "debug=true", "0", true),
        ("dev", "debug=false\nopt-level=\"z\"", "z", true),
        (
            "dev",
            "opt-level=1\nlto=\"thin\"\nstrip=\"symbols\"\ncodegen-units=2\ndebug-assertions=false\noverflow-checks=false\nincremental=false",
            "1",
            false,
        ),
        (
            "release",
            "debug-assertions=true\noverflow-checks=true\nincremental=true",
            "3",
            true,
        ),
        (
            "opt",
            "inherits=\"release\"\nopt-level=\"s\"\ncodegen-units=1\nstrip=true",
            "s",
            false,
        ),
        (
            "developer",
            "inherits=\"dev\"\ndebug=1\nopt-level=2",
            "2",
            true,
        ),
        (
            "integration",
            "inherits=\"test\"\ndebug=false\nopt-level=1",
            "1",
            true,
        ),
        ("test", "", "0", true),
    ];
    for (profile, settings, opt, debug) in cases {
        p.write(
            "Cargo.toml",
            format!("{manifest}\n[profile.{profile}]\n{settings}\n"),
        );
        p.admit();
        for command in ["build", "check"] {
            let output = p.success(&[
                command,
                "--workspace",
                "--offline",
                "--profile",
                profile,
                "--message-format=json",
            ]);
            let events = artifacts(&output);
            let app = events
                .iter()
                .find(|a| a["target"]["name"] == "app")
                .unwrap();
            assert_eq!(app["profile"]["opt_level"], opt, "{profile}: {app}");
            assert_eq!(
                app["profile"]["debug_assertions"], debug,
                "{profile}: {app}"
            );
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains(&format!("Finished `{profile}` profile"))
            );
        }
        let output = p.success(&["run", "--offline", "--profile", profile, "-p", "app", "-q"]);
        let script_profile = if profile == "release" || profile == "opt" {
            "release"
        } else {
            "debug"
        };
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("{script_profile} {debug}\n")
        );
        if ["opt", "developer", "integration", "test"].contains(&profile) {
            p.success(&["test", "--offline", "--profile", profile, "--workspace"]);
        }
    }
    for profile in ["test", "bench"] {
        for panic in ["\"bogus\"", "true"] {
            p.write(
                "Cargo.toml",
                format!("{manifest}\n[profile.{profile}]\npanic={panic}\n"),
            );
            p.fails(&["build", "--offline", "--profile", profile], "panic");
        }
    }
    p.write("Cargo.toml", &manifest);
    let output = p
        .command(&["check", "--offline"])
        .env("CARGO_PROFILE_DEV_RPATH", "true")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(
            "unsupported selected profile environment variable `CARGO_PROFILE_DEV_RPATH`"
        )
    );
    let output = p
        .command(&["build", "--release", "--offline"])
        .env("CARGO_PROFILE_RELEASE_INCREMENTAL", "invalid")
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn static_and_mixed_archives_are_published_and_restored() {
    let p = Project::new();
    p.write("Cargo.toml", "[workspace]\nmembers=[\"archive\",\"mixed\",\"helper\",\"app\"]\ndefault-members=[\"archive\",\"mixed\",\"app\"]\nresolver=\"2\"\n[profile.release]\nlto=\"fat\"\n");
    p.package("helper", "helper", "");
    p.write(
        "helper/src/lib.rs",
        "#[inline(never)] pub fn value() -> u32 { std::hint::black_box(42) }\n",
    );
    for (name, types) in [
        ("archive", "\"staticlib\""),
        ("mixed", "\"rlib\",\"staticlib\""),
    ] {
        p.package(
            name,
            name,
            &format!(
                "[lib]\ncrate-type=[{types}]\n[dependencies]\nhelper={{path=\"../helper\"}}\n"
            ),
        );
        p.write(
            &format!("{name}/src/lib.rs"),
            "#[unsafe(no_mangle)] pub extern \"C\" fn value() -> u32 { helper::value() }\n",
        );
    }
    p.package("app", "app", "[dependencies]\nmixed={path=\"../mixed\"}\n");
    p.write(
        "app/src/main.rs",
        "fn main() { println!(\"{}\", mixed::value()); }\n",
    );
    p.lock(&[
        ("app", &["mixed"]),
        ("mixed", &["helper"]),
        ("archive", &["helper"]),
        ("helper", &[]),
    ]);
    p.admit();
    for profile in [&[][..], &["--release"][..]] {
        for selection in [&[][..], &["-p", "archive"][..], &["-p", "mixed"][..]] {
            let mut args = vec!["build", "--offline", "--message-format=json"];
            args.extend_from_slice(profile);
            args.extend_from_slice(selection);
            let output = p.success(&args);
            let archives: Vec<_> = artifacts(&output)
                .iter()
                .flat_map(|event| {
                    event["filenames"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter_map(|path| {
                            let path = path.as_str().unwrap();
                            path.ends_with(".a").then(|| path.to_owned())
                        })
                        .collect::<Vec<_>>()
                })
                .collect();
            assert_eq!(archives.len(), if selection.is_empty() { 2 } else { 1 });
            let bytes: Vec<_> = archives
                .iter()
                .map(|path| fs::read(path).unwrap())
                .collect();
            for (path, contents) in archives.iter().zip(&bytes) {
                assert!(contents.starts_with(b"!<arch>\n"));
                fs::remove_file(path).unwrap();
            }
            let restored = p.success(&args);
            assert!(artifacts(&restored).iter().all(|a| a["fresh"] == true));
            for (path, expected) in archives.iter().zip(bytes) {
                assert_eq!(fs::read(path).unwrap(), expected);
            }
            args[0] = "check";
            p.success(&args);
        }
        let directory = if profile.is_empty() {
            "debug"
        } else {
            "release"
        };
        let output = Command::new(p.root.join(format!("target/lorry/{directory}/app")))
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, b"42\n");
    }
}

#[test]
fn environment_profile_overrides_follow_selected_and_inherited_profiles() {
    let p = workspace();
    let base = fs::read_to_string(p.root.join("Cargo.toml")).unwrap();
    p.write("Cargo.toml", format!("{base}\n[profile.dev]\nopt-level=3\ndebug=true\n[profile.opt]\ninherits=\"release\"\nopt-level=\"s\"\ncodegen-units=1\nstrip=true\n"));
    p.admit();
    for (profile, environment, opt, assertions) in [
        (
            "dev",
            vec![
                ("CARGO_PROFILE_DEV_OPT_LEVEL", "1"),
                ("CARGO_PROFILE_DEV_DEBUG", "false"),
                ("CARGO_PROFILE_DEV_DEBUG_ASSERTIONS", "false"),
                ("CARGO_PROFILE_DEV_OVERFLOW_CHECKS", "false"),
                ("CARGO_PROFILE_DEV_INCREMENTAL", "false"),
            ],
            "1",
            false,
        ),
        (
            "release",
            vec![
                ("CARGO_PROFILE_RELEASE_OPT_LEVEL", "z"),
                ("CARGO_PROFILE_RELEASE_DEBUG", "true"),
                ("CARGO_PROFILE_RELEASE_STRIP", "none"),
                ("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "2"),
            ],
            "z",
            false,
        ),
        (
            "opt",
            vec![
                ("CARGO_PROFILE_RELEASE_OPT_LEVEL", "0"),
                ("CARGO_PROFILE_OPT_OPT_LEVEL", "1"),
                ("CARGO_PROFILE_OPT_LTO", "off"),
                ("CARGO_PROFILE_UNUSED_RPATH", "true"),
            ],
            "1",
            false,
        ),
        (
            "opt",
            vec![
                ("CARGO_PROFILE_RELEASE_OPT_LEVEL", "1"),
                ("CARGO_PROFILE_RELEASE_DEBUG", "1"),
                ("CARGO_PROFILE_RELEASE_LTO", "off"),
            ],
            "s",
            false,
        ),
    ] {
        for action in ["build", "check"] {
            let output = p
                .command(&[
                    action,
                    "--workspace",
                    "--offline",
                    "--profile",
                    profile,
                    "--message-format=json",
                ])
                .envs(environment.iter().copied())
                .output()
                .unwrap();
            assert!(output.status.success(), "{profile}: {output:?}");
            let events = artifacts(&output);
            let app = events
                .iter()
                .find(|a| a["target"]["name"] == "app")
                .unwrap();
            assert_eq!(app["profile"]["opt_level"], opt);
            assert_eq!(app["profile"]["debug_assertions"], assertions);
        }
    }
}
