mod support;

use std::process::Output;
use support::Project;

fn project() -> Project {
    let p = Project::new();
    p.package(
        ".",
        "output-app",
        "[dependencies]\noutput-dep={path=\"dep\"}\n",
    );
    p.package("dep", "output-dep", "");
    p.write("dep/src/lib.rs", "pub fn value() {}\n");
    p.write("dep/build-input", "ok");
    p.write("dep/build.rs", "fn main() { println!(\"cargo:rerun-if-changed=build-input\"); assert_eq!(std::fs::read_to_string(\"build-input\").unwrap(), \"ok\", \"expected script failure\"); }\n");
    p.write("src/lib.rs", "pub fn value() { output_dep::value(); }\n");
    for name in ["first", "second"] {
        p.write(
            &format!("src/bin/{name}.rs"),
            "fn main() { output_app::value(); }\n",
        );
    }
    p.lock(&[("output-app", &["output-dep"]), ("output-dep", &[])]);
    p.admit();
    p
}

// Only the measured duration varies between Cargo-compatible status lines.
fn without_elapsed(output: &Output) -> String {
    let stderr = String::from_utf8(output.stderr.clone()).unwrap();
    let (text, elapsed) = stderr.rsplit_once(" in ").unwrap();
    let elapsed = elapsed.strip_suffix("s\n").unwrap();
    if let Some((minutes, seconds)) = elapsed.split_once("m ") {
        minutes.parse::<u64>().unwrap();
        assert!(seconds.parse::<u64>().unwrap() < 60);
    } else {
        elapsed.parse::<f64>().unwrap();
        assert_eq!(elapsed.rsplit_once('.').unwrap().1.len(), 2);
    }
    text.to_owned()
}

#[test]
fn build_status_matches_cargo_with_amber_and_one_line_per_package() {
    for color in ["never", "always"] {
        let p = project();
        let status = |action: &str| {
            if color == "always" {
                format!("\x1b[1m\x1b[38;5;214m{action:>12}\x1b[0m")
            } else {
                format!("{action:>12}")
            }
        };
        let output = p.success(&["build", "--offline", "-j4", "--color", color]);
        assert!(output.stdout.is_empty());
        let finished = format!(
            "{} `dev` profile [unoptimized + debuginfo] target(s)",
            status("Finished")
        );
        assert_eq!(
            without_elapsed(&output),
            format!(
                "{} output-dep v1.0.0 ({})\n{} output-app v1.0.0 ({})\n{finished}",
                status("Compiling"),
                p.root.join("dep").display(),
                status("Compiling"),
                p.root.display(),
            )
        );
        let fresh = p.success(&["build", "--offline", "-j4", "--color", color]);
        assert!(fresh.stdout.is_empty());
        assert_eq!(without_elapsed(&fresh), finished);
        let quiet = p.success(&["build", "--offline", "-j4", "--color", color, "--quiet"]);
        assert!(quiet.stdout.is_empty());
        assert!(quiet.stderr.is_empty());
    }
}

#[test]
fn redirected_output_profiles_and_failed_builds() {
    let p = project();
    let output = p.success(&["build", "--offline"]);
    assert!(!output.stderr.contains(&b'\x1b'));
    let manifest = std::fs::read_to_string(p.root.join("Cargo.toml")).unwrap();
    p.write(
        "Cargo.toml",
        format!("{manifest}\n[profile.small]\ninherits=\"release\"\nopt-level=\"z\"\ndebug=1\n"),
    );
    for (arguments, profile) in [
        (vec!["--release"], "`release` profile [optimized]"),
        (
            vec!["--profile", "small"],
            "`small` profile [optimized + debuginfo]",
        ),
    ] {
        let mut command = vec!["build", "--offline", "--color=never"];
        command.extend(arguments);
        let output = p.success(&command);
        assert!(without_elapsed(&output).ends_with(&format!("    Finished {profile} target(s)")));
    }
    p.write(
        "src/lib.rs",
        "compile_error!(\"expected output failure\");\n",
    );
    let failed = p.fails(&["build", "--offline"], "expected output failure");
    assert!(!String::from_utf8_lossy(&failed.stderr).contains("Finished"));
}

#[test]
fn a_rerun_build_script_reports_its_package_before_failing() {
    let p = project();
    p.success(&["build", "--offline"]);
    p.write("dep/build-input", "fail");
    let failed = p.fails(&["build", "--offline"], "expected script failure");
    let stderr = String::from_utf8(failed.stderr).unwrap();
    assert!(stderr.starts_with(&format!(
        "   Compiling output-dep v1.0.0 ({})\n",
        p.root.join("dep").display()
    )));
    assert!(!stderr.contains("Finished"));
}
