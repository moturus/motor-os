mod support;

use std::fs;
use std::io::Write;
use std::process::{Command, Output};
use support::Project;

fn main() {
    if let Ok(mode) = std::env::var("LORRY_COMPILER_CONTRACT") {
        compiler(&mode);
        return;
    }
    queries();
    rustflags();
}

fn compiler(mode: &str) {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let env: Vec<_> = [
        "RUSTUP_TOOLCHAIN",
        "CARGO_LOG",
        "__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS",
        "RUSTC_BOOTSTRAP",
    ]
    .map(|name| std::env::var(name).ok())
    .into();
    let mut log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(std::env::var_os("LORRY_COMPILER_LOG").unwrap())
        .unwrap();
    writeln!(log, "{}", serde_json::json!({"args":args,"env":env})).unwrap();
    if mode == "query" {
        if args.iter().any(|arg| arg == "--version") {
            println!("rustc 1.99.0-dev\nrelease: 1.99.0-dev\nhost: x86_64-unknown-linux-gnu");
        } else if args.iter().any(|arg| arg == "target-spec-json") {
            println!(r#"{{"arch":"x86_64","os":"motor"}}"#);
        } else if args.iter().any(|arg| arg == "-O") {
            println!("query_cfg_output");
            std::process::exit(
                std::env::var("LORRY_QUERY_STATUS")
                    .unwrap_or_else(|_| "0".into())
                    .parse()
                    .unwrap(),
            );
        } else {
            println!("target_pointer_width=\"64\"\nunix");
        }
    } else {
        let status = Command::new(std::env::var_os("LORRY_REAL_RUSTC").unwrap())
            .args(
                args.iter()
                    .filter(|arg| !arg.starts_with("--cfg=lorry_rf_")),
            )
            .status()
            .unwrap();
        std::process::exit(status.code().unwrap_or(101));
    }
}

fn logged(p: &Project) -> Vec<serde_json::Value> {
    fs::read_to_string(p.root.join("compiler.log"))
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn wrapped(p: &Project, args: &[&str], mode: &str) -> Command {
    // Query and forwarding modes must not share a compiler-query cache entry.
    let compiler = p.root.join("rustc-wrapper");
    if !compiler.exists() {
        fs::copy(std::env::current_exe().unwrap(), &compiler).unwrap();
        support::executable_permissions(&compiler).unwrap();
    }
    let mut command = p.command(args);
    command
        .env("RUSTC", compiler)
        .env("LORRY_COMPILER_CONTRACT", mode)
        .env("LORRY_COMPILER_LOG", p.root.join("compiler.log"))
        .env("LORRY_REAL_RUSTC", p.rustc());
    command
}

fn success(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    output
}

fn queries() {
    let p = Project::new();
    p.package(".", "queries", "");
    p.write("src/lib.rs", "pub fn answer() -> u32 { 42 }\n");
    p.write(".cargo/config.toml", "[build]\nrustflags=[\"--cfg=lorry_query_build\"]\n[target.x86_64-unknown-motor]\nrustflags=[\"--cfg=lorry_query_exact\"]\n[target.'cfg(target_pointer_width = \"64\")']\nrustflags=[\"--cfg=lorry_query_pointer\"]\n[target.'cfg(unix)']\nrustflags=[\"--cfg=lorry_query_unix\"]\n");
    let manifest = p.root.join("Cargo.toml");
    for args in [
        vec!["locate-project"],
        vec!["locate-project", "--workspace"],
        vec!["locate-project", "--message-format=json"],
    ] {
        let output = p.success(&args);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
            serde_json::json!({"root":manifest})
        );
    }
    let output = p
        .command(&["locate-project", "--message-format", "plain"])
        .current_dir(p.root.join("src"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        manifest.to_str().unwrap()
    );
    let original = fs::read(&manifest).unwrap();
    let roots = [".", "workspace", "empty"];
    p.write("workspace/Cargo.toml", "[workspace]\nmembers=[\"app\",\"other\"]\nresolver=\"2\"\n[profile.custom]\ninherits=\"release\"\n");
    for member in ["app", "other"] {
        p.package(&format!("workspace/{member}"), member, "");
        p.write(
            &format!("workspace/{member}/src/lib.rs"),
            "pub fn value() {}\n",
        );
    }
    p.write("empty/Cargo.toml", "[workspace]\n");
    let output = p.success(&[
        "locate-project",
        "--workspace",
        "--manifest-path",
        "workspace/app/Cargo.toml",
    ]);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["root"],
        p.root.join("workspace/Cargo.toml").to_str().unwrap()
    );
    let query = |root, print, trailing| {
        let mut command = wrapped(
            &p,
            &[
                "rustc",
                "-Z",
                "unstable-options",
                "--print",
                print,
                "--target",
                "x86_64-unknown-motor",
                "--",
            ],
            "query",
        );
        command
            .current_dir(p.root.join(root))
            .args(trailing)
            .env("RUSTUP_TOOLCHAIN", "ambient-toolchain")
            .env("CARGO_LOG", "trace")
            .env("__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS", "nightly")
            .env("RUSTC_BOOTSTRAP", "ambient-bootstrap");
        command
    };
    for root in roots {
        assert_eq!(
            success(&mut query(root, "cfg", &["-O"][..])).stdout,
            b"query_cfg_output\n"
        );
        assert_eq!(
            success(&mut query(
                root,
                "target-spec-json",
                &["-Z", "unstable-options"][..]
            ))
            .stdout,
            b"{\"arch\":\"x86_64\",\"os\":\"motor\"}\n"
        );
        for path in ["target", "Cargo.lock", ".lorry"] {
            assert!(!p.root.join(root).join(path).exists());
        }
    }
    let log = logged(&p);
    for record in &log {
        let target = record["args"]
            .as_array()
            .unwrap()
            .iter()
            .any(|arg| arg == "target-spec-json");
        assert_eq!(
            record["env"],
            if target {
                serde_json::json!([null, null, null, "1"])
            } else {
                serde_json::json!([null, null, null, null])
            }
        );
    }
    let flags = [
        "--cfg=lorry_query_exact",
        "--cfg=lorry_query_pointer",
        "--cfg=lorry_query_unix",
    ];
    for (print, args) in [
        (
            "cfg",
            vec!["--print", "cfg", "-O", "--target", "x86_64-unknown-motor"],
        ),
        (
            "target-spec-json",
            vec![
                "--print",
                "target-spec-json",
                "--target",
                "x86_64-unknown-motor",
                "-Z",
                "unstable-options",
            ],
        ),
    ] {
        let mut expected = args;
        expected.extend(flags);
        assert!(
            log.iter()
                .any(|record| record["args"] == serde_json::json!(expected)),
            "{print}: {log:?}"
        );
    }
    let output = query(".", "cfg", &["-O"][..])
        .env("LORRY_QUERY_STATUS", "7")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(output.stdout, b"query_cfg_output\n");
    let before = fs::read(p.root.join("compiler.log")).unwrap();
    assert!(
        !query(".", "cfg", &["-g"][..])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(fs::read(p.root.join("compiler.log")).unwrap(), before);
    assert!(
        !p.run(&[
            "-Z",
            "unstable-options",
            "config",
            "get",
            "--format",
            "toml",
            "--show-origin"
        ])
        .status
        .success()
    );
    assert_eq!(fs::read(manifest).unwrap(), original);
    #[cfg(unix)]
    {
        p.write("proxy/rustup", "#!/bin/sh\nprintf '%s|%s\\n' \"$*\" \"$RUSTUP_TOOLCHAIN\" >>\"$LORRY_RUSTUP_LOG\"\n[ \"$*\" = 'which rustc' ] || exit 2\nprintf '%s\\n' \"$LORRY_DIRECT_RUSTC\"\n");
        support::executable_permissions(&p.root.join("proxy/rustup")).unwrap();
        std::os::unix::fs::symlink("rustup", p.root.join("proxy/rustc")).unwrap();
        let mut paths = vec![p.root.join("proxy")];
        paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
        let before = logged(&p).len();
        let mut command = wrapped(
            &p,
            &[
                "rustc",
                "-Z",
                "unstable-options",
                "--print",
                "cfg",
                "--target",
                "x86_64-unknown-motor",
                "--",
                "-O",
            ],
            "query",
        );
        command
            .env_remove("RUSTC")
            .env("PATH", std::env::join_paths(paths).unwrap())
            .env("LORRY_DIRECT_RUSTC", std::env::current_exe().unwrap())
            .env("LORRY_RUSTUP_LOG", p.root.join("proxy.log"))
            .env("RUSTUP_TOOLCHAIN", "proxy-toolchain");
        success(&mut command);
        assert_eq!(
            fs::read_to_string(p.root.join("proxy.log")).unwrap(),
            "which rustc|proxy-toolchain\n"
        );
        let records = logged(&p);
        assert!(records.len() > before);
        assert!(
            records[before..]
                .iter()
                .all(|r| r["env"] == serde_json::json!([null, null, null, null]))
        );
    }
    println!("PASS: exact compiler queries, clean environment and read-only project discovery");
}

fn find(root: &std::path::Path, name: &str) -> Vec<std::path::PathBuf> {
    let mut result = Vec::new();
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            result.extend(find(&entry.path(), name));
        } else if entry.file_name() == name {
            result.push(entry.path());
        }
    }
    result
}

fn rustflags() {
    let p = Project::new();
    let trace = Project::new();
    p.package(".", "flags", "[dependencies]\ndep={path=\"dep\"}\n");
    p.write("src/main.rs", "fn main() { dep::value(); }\n");
    p.package("dep", "dep", "");
    p.write("dep/src/lib.rs", "pub fn value() {}\n");
    p.write("dep/build.rs", "fn main() { std::fs::write(std::path::PathBuf::from(std::env::var_os(\"OUT_DIR\").unwrap()).join(\"flags.seen\"), std::env::var(\"CARGO_ENCODED_RUSTFLAGS\").unwrap()).unwrap(); }\n");
    p.lock(&[("flags", &["dep"]), ("dep", &[])]);
    p.admit();
    let host = if cfg!(target_os = "motor") {
        "x86_64-unknown-motor"
    } else {
        "x86_64-unknown-linux-gnu"
    };
    let target_env = format!(
        "CARGO_TARGET_{}_RUSTFLAGS",
        host.to_uppercase().replace('-', "_")
    );
    let plain = "  --cfg=lorry_rf_plain  --cfg=lorry_rf_quote\"literal --cfg=lorry_rf_back\\slash --cfg=lorry_rf_tab\tinside  ";
    let encoded = "--cfg=lorry_rf_encoded one\u{1f}--cfg=lorry_rf_second";
    for (case, exact, variable, value, expected) in [
        ("build", false, "", "", vec!["--cfg=lorry_rf_build"]),
        (
            "build-env",
            false,
            "CARGO_BUILD_RUSTFLAGS",
            "--cfg=lorry_rf_build_env",
            vec!["--cfg=lorry_rf_build", "--cfg=lorry_rf_build_env"],
        ),
        (
            "target",
            true,
            "",
            "",
            vec!["--cfg=lorry_rf_exact", "--cfg=lorry_rf_pointer"],
        ),
        (
            "target-env",
            true,
            target_env.as_str(),
            "--cfg=lorry_rf_target_env",
            vec![
                "--cfg=lorry_rf_exact",
                "--cfg=lorry_rf_target_env",
                "--cfg=lorry_rf_pointer",
            ],
        ),
        (
            "plain",
            false,
            "RUSTFLAGS",
            plain,
            vec![
                "--cfg=lorry_rf_plain",
                "--cfg=lorry_rf_quote\"literal",
                "--cfg=lorry_rf_back\\slash",
                "--cfg=lorry_rf_tab\tinside",
            ],
        ),
        (
            "encoded-empty",
            false,
            "CARGO_ENCODED_RUSTFLAGS",
            "",
            vec![],
        ),
        (
            "encoded",
            false,
            "CARGO_ENCODED_RUSTFLAGS",
            encoded,
            vec!["--cfg=lorry_rf_encoded one", "--cfg=lorry_rf_second"],
        ),
    ] {
        let config = if exact {
            format!(
                "[build]\nrustflags=[\"--cfg=lorry_rf_build\"]\n[target.{host}]\nrustflags=[\"--cfg=lorry_rf_exact\"]\n[target.'cfg(target_pointer_width = \"64\")']\nrustflags=[\"--cfg=lorry_rf_pointer\"]\n"
            )
        } else {
            "[build]\nrustflags=[\"--cfg=lorry_rf_build\"]\n".to_owned()
        };
        p.write(".cargo/config.toml", config);
        trace.write("compiler.log", "");
        let output_dir = p.root.join(format!("target/flags-{case}"));
        let mut args = vec![
            "build",
            "--locked",
            "--offline",
            "-j1",
            "--target-dir",
            output_dir.to_str().unwrap(),
        ];
        if exact {
            args.extend(["--target", host]);
        }
        let mut command = wrapped(&p, &args, "flags");
        command.env("LORRY_COMPILER_LOG", trace.root.join("compiler.log"));
        for name in [
            "CARGO_ENCODED_RUSTFLAGS",
            "RUSTFLAGS",
            "CARGO_BUILD_RUSTFLAGS",
            &target_env,
        ] {
            command.env_remove(name);
        }
        if !variable.is_empty() {
            command.env(variable, value);
        }
        success(&mut command);
        let mut compiled = 0;
        for record in logged(&trace) {
            let args: Vec<_> = record["args"]
                .as_array()
                .unwrap()
                .iter()
                .map(|arg| arg.as_str().unwrap())
                .collect();
            if !args.contains(&"--crate-name") {
                continue;
            }
            compiled += 1;
            let flags: Vec<_> = args
                .iter()
                .filter(|arg| arg.starts_with("--cfg=lorry_rf_"))
                .copied()
                .collect();
            let build_script = args.iter().any(|arg| arg.ends_with("build.rs"));
            assert_eq!(
                flags,
                if exact && build_script {
                    vec![]
                } else {
                    expected.clone()
                },
                "{case}: {args:?}"
            );
        }
        assert_eq!(compiled, 3, "{case}");
        let evidence = find(&output_dir, "flags.seen");
        assert!(
            !evidence.is_empty(),
            "{case}: build-script evidence is absent"
        );
        for path in evidence {
            assert_eq!(
                fs::read_to_string(path).unwrap(),
                expected.join("\u{1f}"),
                "{case}"
            );
        }
    }
    println!(
        "PASS: compiler flags and build-script encoded flags preserve precedence and argument boundaries"
    );
}
