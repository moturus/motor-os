mod support;

use support::Project;

const PROGRAM: &str = r#"fn main() {
    println!("{}|{}", env!("CARGO_PKG_NAME"), std::env::args().skip(1).collect::<Vec<_>>().join("|"));
}"#;

#[test]
fn run_selects_default_members_binaries_and_examples_without_building_other_targets() {
    let p = Project::new();
    let workspace = |defaults: &str| {
        p.write("Cargo.toml", format!("[workspace]\nmembers=[\"library\",\"app\",\"other\"]\ndefault-members={defaults}\nresolver=\"2\"\n"))
    };
    workspace("[\"library\",\"app\"]");
    for member in ["library", "app", "other"] {
        p.package(member, member, "");
    }
    p.write("library/src/lib.rs", "pub fn value() -> u32 { 42 }\n");
    for member in ["app", "other"] {
        p.write(&format!("{member}/src/main.rs"), PROGRAM);
    }
    p.lock(&[("library", &[]), ("app", &[]), ("other", &[])]);
    p.admit();
    let run = |arguments: &[&str], expected: &str| {
        let mut args = vec!["run", "--quiet", "--offline"];
        args.extend_from_slice(arguments);
        assert_eq!(
            p.success(&args).stdout,
            expected.as_bytes(),
            "{arguments:?}"
        );
    };
    let reject = |arguments: &[&str], error| {
        let mut args = vec!["run", "--offline"];
        args.extend_from_slice(arguments);
        p.fails(&args, error);
    };
    run(&["--", "one", "two words"], "app|one|two words\n");
    run(&["--bin", "app", "--", "explicit"], "app|explicit\n");
    run(&["-p", "other", "--", "selected"], "other|selected\n");
    reject(&["--bin", "missing"], "no bin target named");
    reject(&["-p", "library"], "a bin target must be available");
    workspace("[\"library\",\"app\",\"other\"]");
    p.admit();
    reject(&[], "could not determine which binary to run");
    run(&["--bin", "app"], "app|\n");

    let broken = "[[bin]]\nname=\"broken\"\npath=\"src/broken.rs\"\n";
    p.write(
        "app/src/broken.rs",
        "compile_error!(\"unselected binary must not compile\"); fn main() {}\n",
    );
    p.package("app", "app", &format!("default-run=\"app\"\n{broken}"));
    p.admit();
    run(&[], "app|\n");
    run(&["--bin", "other"], "other|\n");
    let duplicate = "[[bin]]\nname=\"app\"\npath=\"src/duplicate.rs\"\n";
    p.package("other", "other", duplicate);
    p.write("other/src/duplicate.rs", PROGRAM);
    p.admit();
    reject(&["--bin", "app"], "can run at most one executable");
    reject(&[], "can run at most one executable");
    run(&["-p", "app"], "app|\n");
    p.package(
        "other",
        "other",
        &format!("default-run=\"other\"\n{duplicate}"),
    );
    p.admit();
    reject(&[], "could not determine which binary to run");
    run(&["-p", "other"], "other|\n");

    p.package(
        "app",
        "app",
        &format!(
            r#"default-run="app"
{broken}
[dev-dependencies]
library = {{ path = "../library" }}
[features]
example-feature = []
[[example]]
name = "demo"
required-features = ["example-feature"]
[[example]]
name = "archive"
crate-type = ["rlib"]
"#
        ),
    );
    p.write(
        "app/examples/demo.rs",
        PROGRAM.replace(
            "fn main() {",
            "fn main() { assert_eq!(library::value(), 42);",
        ),
    );
    p.write("app/examples/archive.rs", "pub fn example() {}\n");
    p.lock(&[("library", &[]), ("app", &["library"]), ("other", &[])]);
    p.admit();
    reject(&["--example", "demo"], "requires the features");
    run(
        &[
            "--example",
            "demo",
            "--features",
            "app/example-feature",
            "--",
            "example",
            "two words",
        ],
        "app|example|two words\n",
    );
    run(
        &[
            "-p",
            "app",
            "--example",
            "demo",
            "--features",
            "example-feature",
            "--",
            "explicit",
        ],
        "app|explicit\n",
    );
    reject(
        &["--example", "archive"],
        "is a library and cannot be executed",
    );
    reject(&["--example", "missing"], "no example target named");
    p.write("other/examples/demo.rs", PROGRAM);
    p.admit();
    reject(
        &["--example", "demo", "--features", "app/example-feature"],
        "can run at most one executable",
    );
    run(
        &["-p", "other", "--example", "demo", "--", "other-example"],
        "other|other-example\n",
    );
}
