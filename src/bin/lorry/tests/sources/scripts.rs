use super::registry::Registry;
use crate::support::Project;
use std::fs;

pub fn run() {
    let r = Registry::new();
    let p = &r.project;
    p.write("Cargo.toml", "[workspace]\nmembers=[\"a\",\"b\",\"builder\"]\ndefault-members=[\"a\",\"b\"]\nresolver=\"2\"\n");
    p.package("builder", "builder", "[features]\nbuild=[]\n");
    p.write("builder/src/lib.rs", "pub fn value() -> &'static str { if cfg!(feature=\"build\") { \"host\" } else { \"target\" } }\n");
    let script = r#"fn main() {
        assert_eq!(option_env!("CARGO_PRIMARY_PACKAGE"), Some("1"));
        assert!(std::env::var_os("CARGO_PRIMARY_PACKAGE").is_none());
        assert_eq!(builder::value(), "host");
        let value = std::env::var("SCRIPT_INPUT").unwrap_or_else(|_| "absent".into());
        std::fs::write(std::path::Path::new(&std::env::var_os("OUT_DIR").unwrap()).join("generated.rs"), format!("{value:?}")).unwrap();
        println!("cargo:rustc-cfg=scripted");
        println!("cargo:rustc-check-cfg=cfg(scripted)");
        println!("cargo:rustc-env=FROM_SCRIPT=present");
        println!("cargo:rustc-link-arg=-Wl,--gc-sections");
        println!("cargo:rustc-link-arg=-Wl,--as-needed");
        println!("cargo:rerun-if-env-changed=SCRIPT_INPUT");
    }"#;
    let program = r#"#[cfg(not(scripted))] compile_error!("missing member script cfg");
        fn main() {
            assert_eq!(env!("FROM_SCRIPT"), "present");
            println!("{}", include!(concat!(env!("OUT_DIR"), "/generated.rs")));
        }"#;
    for member in ["a", "b"] {
        p.package(
            member,
            member,
            "[build-dependencies]\nbuilder={path=\"../builder\",features=[\"build\"]}\n",
        );
        p.write(&format!("{member}/build.rs"), script);
        p.write(&format!("{member}/src/main.rs"), program);
    }
    p.write("a/src/lib.rs", "#[cfg(not(scripted))] compile_error!(\"missing library script cfg\");\npub const VALUE: &str = include!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));\n");
    p.lock(&[("a", &["builder"]), ("b", &["builder"]), ("builder", &[])]);
    let grant = |name: &str, expose: bool| {
        format!(
            "[workspaces.{:?}.policy.rules.{name}]\naction=\"allow\"\nname={name:?}\nsource=\"path\"\nallow-build-script=true\ncaller-env={}\n",
            p.root.to_str().unwrap(),
            if expose { "[\"SCRIPT_INPUT\"]" } else { "[]" }
        )
    };
    r.configure(&grant("b", true));
    let denied = p.fails(
        &["build", "--offline", "--message-format=json"],
        "build script without an explicit matching policy grant",
    );
    assert_eq!(
        String::from_utf8(denied.stdout).unwrap().trim(),
        r#"{"reason":"build-finished","success":false}"#
    );
    assert!(!p.root.join("target/lorry/debug/build/a").exists());
    r.configure(&format!("{}{}", grant("a", true), grant("b", true)));
    for command in ["build", "check", "clippy"] {
        for selection in [&[][..], &["--workspace"][..], &["-p", "a"][..]] {
            let mut args = vec![command, "--offline", "-j1", "--message-format=json"];
            args.extend_from_slice(selection);
            let output = p
                .command(&args)
                .env("SCRIPT_INPUT", "visible")
                .output()
                .unwrap();
            assert!(output.status.success(), "{args:?}: {output:?}");
            let events: Vec<serde_json::Value> = String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(
                events.last().unwrap(),
                &serde_json::json!({"reason":"build-finished","success":true})
            );
            assert!(
                events
                    .iter()
                    .any(|event| event["reason"] == "build-script-executed")
            );
            if command == "build" {
                value(p, "a", "visible");
                if selection.is_empty() || selection[0] == "--workspace" {
                    value(p, "b", "visible");
                }
            }
        }
    }
    r.configure(&format!("{}{}", grant("a", true), grant("b", false)));
    let output = p
        .command(&["build", "--offline", "-j1"])
        .env("SCRIPT_INPUT", "private-marker")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    value(p, "a", "private-marker");
    value(p, "b", "absent");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("hidden caller variable `SCRIPT_INPUT`"));
    assert!(!stderr.contains("private-marker"));
    r.configure(&format!("{}{}", grant("a", true), grant("b", true)));

    let runtime = r#"fn main() {
        assert_eq!(std::env::var("FROM_SCRIPT").unwrap(), "present");
        assert_eq!(std::env::var("OUT_DIR").unwrap(), env!("OUT_DIR"));
        assert_eq!(std::env::current_dir().unwrap(), std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap());
        assert_eq!(std::env::args().skip(1).collect::<Vec<_>>(), ["argument", "two words"]);
        println!("{}", include!(concat!(env!("OUT_DIR"), "/generated.rs")));
    }"#;
    p.write("a/src/main.rs", runtime);
    p.write("a/examples/scripted.rs", runtime);
    p.write(
        "a/src/bin/unselected.rs",
        "compile_error!(\"run built an unselected binary\");\n",
    );
    for (kind, name) in [("--bin", "a"), ("--example", "scripted")] {
        for json in [false, false, true] {
            let mut args = vec![
                "run",
                "--offline",
                "-p",
                "a",
                kind,
                name,
                "--features",
                "builder/build",
            ];
            if json {
                args.push("--message-format=json");
            }
            args.extend(["--", "argument", "two words"]);
            let output = p
                .command(&args)
                .env("SCRIPT_INPUT", "visible")
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            let text = String::from_utf8(output.stdout).unwrap();
            assert_eq!(text.lines().last(), Some("visible"));
            assert!(!text.contains("unselected"));
            if json {
                assert!(text.contains("build-script-executed"));
            }
        }
    }
    fs::remove_file(p.root.join("a/src/bin/unselected.rs")).unwrap();
    p.write("a/src/main.rs", program);
    scripts_run(p, "visible");
    p.write("b/src/main.rs", format!("{program}\n"));
    assert_eq!(scripts_run(p, "visible"), Vec::<String>::new());
    assert_eq!(scripts_run(p, "changed"), ["a", "b"]);
    value(p, "b", "changed");
    p.write("a/data.txt", "one\n");
    p.write(
        "a/build.rs",
        script.replace(
            "rerun-if-env-changed=SCRIPT_INPUT",
            "rerun-if-changed=data.txt",
        ),
    );
    p.write(
        "b/build.rs",
        script.replace("println!(\"cargo:rerun-if-env-changed=SCRIPT_INPUT\");", ""),
    );
    assert_eq!(scripts_run(p, "changed"), ["a", "b"]);
    p.write("a/src/main.rs", format!("{program}\n"));
    assert_eq!(scripts_run(p, "changed"), Vec::<String>::new());
    p.write("b/src/main.rs", format!("{program}\n\n"));
    assert_eq!(scripts_run(p, "changed"), ["b"]);
    p.write("a/data.txt", "two\n");
    assert_eq!(scripts_run(p, "changed"), ["a"]);
    p.write(
        "a/build.rs",
        script.replace(
            "rerun-if-env-changed=SCRIPT_INPUT",
            "rerun-if-changed=missing.txt",
        ),
    );
    for _ in 0..2 {
        assert_eq!(scripts_run(p, "changed"), ["a"]);
    }
    println!("PASS: member script grants, runtime environments and tracked inputs");
}

fn value(p: &Project, name: &str, expected: &str) {
    let output = std::process::Command::new(p.root.join(format!("target/lorry/debug/{name}")))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), expected);
}

fn scripts_run(p: &Project, input: &str) -> Vec<String> {
    let output = p
        .command(&["build", "--offline", "-j1"])
        .env("SCRIPT_INPUT", input)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let mut scripts: Vec<_> = String::from_utf8_lossy(&output.stderr)
        .lines()
        .filter_map(|line| line.strip_prefix("Running build script "))
        .map(|line| line.split_whitespace().next().unwrap().to_owned())
        .collect();
    scripts.sort();
    scripts
}
