mod support;
use support::Project;

#[test]
fn configured_environment_is_shared_by_build_scripts_compilation_and_execution() {
    let p = Project::new();
    p.package(
        ".",
        "env-app",
        "[dependencies]\nenv-dep = { path = \"dep\" }\n",
    );
    p.package("dep", "env-dep", "");
    p.lock(&[("env-app", &["env-dep"]), ("env-dep", &[])]);
    let config = r#"
[env]
LORRY_ENV_VALUE = "project-default"
LORRY_ENV_FORCED = { value = "forced", force = true }
LORRY_ENV_EMPTY = ""
LORRY_ENV_PATH = { value = "assets", relative = true }
CARGO_PKG_NAME = { value = "must-not-replace-package-metadata", force = true }
CFLAGS_x86_64_unknown_motor = "--target=x86_64-unknown-motor"
"#;
    p.write(".cargo/config.toml", config);
    p.write("dep/build.rs", r#"
fn main() {
    println!("cargo:rerun-if-env-changed=LORRY_ENV_VALUE");
    println!("cargo:rustc-env=SCRIPT_VALUE={}", std::env::var("LORRY_ENV_VALUE").unwrap());
    assert_eq!(std::env::var("LORRY_ENV_FORCED").unwrap(), "forced");
    assert_eq!(std::env::var("LORRY_ENV_EMPTY").unwrap(), "");
    assert_eq!(std::env::var("CARGO_PKG_NAME").unwrap(), "env-dep");
    assert_eq!(std::env::var("CFLAGS_x86_64_unknown_motor").unwrap(), "--target=x86_64-unknown-motor");
}
"#);
    p.write(
        "dep/src/lib.rs",
        "pub const VALUE: &str = env!(\"SCRIPT_VALUE\");\n",
    );
    p.write(
        "src/main.rs",
        r#"
fn verify() {
    assert_eq!(env!("LORRY_ENV_VALUE"), std::env::var("LORRY_ENV_VALUE").unwrap());
    assert_eq!(env!("LORRY_ENV_VALUE"), env_dep::VALUE);
    assert_eq!(env!("LORRY_ENV_FORCED"), "forced");
    assert_eq!(std::env::var("LORRY_ENV_FORCED").unwrap(), "forced");
    assert_eq!(env!("LORRY_ENV_EMPTY"), "");
    assert_eq!(env!("CARGO_PKG_NAME"), "env-app");
    assert_eq!(std::env::var("CARGO_PKG_NAME").unwrap(), "env-app");
}
fn main() {
    verify();
    println!("{}|{}", env!("LORRY_ENV_VALUE"), env!("LORRY_ENV_PATH"));
}
#[test] fn configured_environment() { verify(); }
"#,
    );
    p.fails(&["build", "--offline"], "you have not approved");
    p.admit();
    for value in [None, Some("caller-value"), Some(""), Some("changed-caller")] {
        let mut command = p.command(&["run", "--offline", "-q"]);
        command
            .env_remove("LORRY_ENV_VALUE")
            .env("LORRY_ENV_FORCED", "caller");
        if let Some(value) = value {
            command.env("LORRY_ENV_VALUE", value);
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!(
                "{}|{}/assets\n",
                value.unwrap_or("project-default"),
                p.root.display()
            )
        );
    }
    for arguments in [
        &["test", "--offline"][..],
        &["test", "--offline", "--bundle"],
    ] {
        let output = p
            .command(arguments)
            .env_remove("LORRY_ENV_VALUE")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    }
    p.write(
        ".cargo/config.toml",
        config.replace("project-default", "changed-config"),
    );
    p.admit();
    let output = p
        .command(&["run", "--offline", "-q"])
        .env_remove("LORRY_ENV_VALUE")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.starts_with(b"changed-config|"));
    for reserved in ["CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN"] {
        p.write(
            ".cargo/config.toml",
            format!("[env]\n{reserved} = \"forbidden\"\n"),
        );
        p.fails(
            &["build", "--offline"],
            &format!("Cargo does not allow `{reserved}` in `[env]`"),
        );
    }
}

#[test]
fn configured_paths_keep_their_spelling_and_participate_in_cache_identity() {
    let p = Project::new();
    p.package(".", "env-path", "");
    p.lock(&[("env-path", &[])]);
    p.write(
        "src/main.rs",
        "fn main() { println!(\"{}\", env!(\"ASSET_DIR\")); }\n",
    );
    for spelling in [
        "assets".to_owned(),
        "./assets".to_owned(),
        "a//b".to_owned(),
        "a/./b/.".to_owned(),
        format!("{}/absolute//assets/.", p.root.display()),
    ] {
        p.write(
            ".cargo/config.toml",
            format!("[env]\nASSET_DIR = {{ value = {spelling:?}, relative = true }}\n"),
        );
        p.admit();
        let output = p
            .command(&["run", "--offline", "-q"])
            .env_remove("ASSET_DIR")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim_end(),
            p.root.join(&spelling).to_str().unwrap()
        );
    }
}

#[test]
fn runtime_metadata_uses_the_selected_package_and_preserves_the_run_directory() {
    let p = Project::new();
    p.write(
        "Cargo.toml",
        "[workspace]\nmembers=[\"app\"]\nresolver=\"2\"\n",
    );
    p.package("app", "app", "authors=[\"Motor OS\"]\ndescription=\"runtime metadata\"\nlicense=\"MIT\"\nhomepage=\"https://example.invalid\"\nrepository=\"https://example.invalid/repo\"\nreadme=\"README.md\"\nrust-version=\"1.85\"\n");
    p.write("app/README.md", "runtime metadata\n");
    let mut verify = "fn environment() {\nassert_eq!(std::env::var_os(\"CARGO\").unwrap(), std::env::var_os(\"LORRY_EXPECT_CARGO\").unwrap());\n".to_owned();
    for name in [
        "CARGO_MANIFEST_DIR",
        "CARGO_MANIFEST_PATH",
        "CARGO_PKG_NAME",
        "CARGO_PKG_VERSION",
        "CARGO_PKG_VERSION_MAJOR",
        "CARGO_PKG_VERSION_MINOR",
        "CARGO_PKG_VERSION_PATCH",
        "CARGO_PKG_VERSION_PRE",
        "CARGO_PKG_AUTHORS",
        "CARGO_PKG_DESCRIPTION",
        "CARGO_PKG_HOMEPAGE",
        "CARGO_PKG_LICENSE",
        "CARGO_PKG_LICENSE_FILE",
        "CARGO_PKG_README",
        "CARGO_PKG_REPOSITORY",
        "CARGO_PKG_RUST_VERSION",
    ] {
        verify +=
            &format!("assert_eq!(std::env::var({name:?}).unwrap(), env!({name:?}), {name:?});\n");
    }
    verify += r#"
    let libraries = std::env::var_os("LD_LIBRARY_PATH").unwrap();
    let libraries: Vec<_> = std::env::split_paths(&libraries).collect();
    for name in ["LORRY_EXPECT_PROFILE", "LORRY_EXPECT_SYSROOT_LIB", "LORRY_EXPECT_INHERITED_LIB"] {
        let expected = std::path::PathBuf::from(std::env::var_os(name).unwrap());
        assert!(libraries.contains(&expected), "{name}: {libraries:?}");
    }
}
fn main() {
    if std::env::args().any(|arg| arg == "--print-libraries") {
        println!("{}", std::env::var("LD_LIBRARY_PATH").unwrap());
    } else {
        environment();
        assert_eq!(std::env::current_dir().unwrap(), std::path::PathBuf::from(std::env::var_os("LORRY_EXPECT_CWD").unwrap()));
        println!("app");
    }
}
#[test] fn runtime_metadata() {
    environment();
    assert_eq!(std::env::current_dir().unwrap(), std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")));
}
"#;
    p.write("app/src/main.rs", verify);
    p.write("app/tests/environment.rs", r#"#[test] fn integration_environment() {
        assert_eq!(std::env::current_dir().unwrap(), std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")));
        assert_eq!(std::env::var("CARGO_MANIFEST_PATH").unwrap(), env!("CARGO_MANIFEST_PATH"));
        assert_eq!(std::env::var("CARGO_BIN_EXE_app").unwrap(), env!("CARGO_BIN_EXE_app"));
        assert_eq!(std::env::var_os("CARGO").unwrap(), std::env::var_os("LORRY_EXPECT_CARGO").unwrap());
    }"#);
    p.lock(&[("app", &[])]);
    p.admit();
    let output = std::process::Command::new(p.rustc())
        .args(["--print", "target-libdir"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let sysroot = String::from_utf8(output.stdout).unwrap();
    let inherited = p.root.join("inherited-libraries");
    let command = |args: &[&str]| {
        let mut command = p.command(args);
        command
            .env("CARGO_PKG_NAME", "stale")
            .env("LORRY_EXPECT_CARGO", env!("CARGO_BIN_EXE_lorry"))
            .env("LORRY_EXPECT_PROFILE", p.root.join("target/lorry/debug"))
            .env("LORRY_EXPECT_SYSROOT_LIB", sysroot.trim())
            .env("LORRY_EXPECT_INHERITED_LIB", &inherited)
            .env("LD_LIBRARY_PATH", &inherited);
        command
    };
    for directory in [&p.root, &p.root, &p.root.join("app")] {
        let output = command(&["run", "-p", "app", "--offline", "-q"])
            .current_dir(directory)
            .env("LORRY_EXPECT_CWD", directory)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, b"app\n");
    }
    let output = command(&["test", "--offline", "-p", "app"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let libraries = command(&[
        "run",
        "--offline",
        "-p",
        "app",
        "-q",
        "--",
        "--print-libraries",
    ])
    .output()
    .unwrap();
    assert!(libraries.status.success());
    let inherited = String::from_utf8(libraries.stdout.clone()).unwrap();
    let again = command(&[
        "run",
        "--offline",
        "-p",
        "app",
        "-q",
        "--",
        "--print-libraries",
    ])
    .env("LD_LIBRARY_PATH", inherited.trim())
    .output()
    .unwrap();
    assert!(again.status.success());
    assert_eq!(libraries.stdout, again.stdout);
}
