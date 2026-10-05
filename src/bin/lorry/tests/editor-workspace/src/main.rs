use rust_analyzer_smoke::case::SemanticCase;
use rust_analyzer_smoke::semantic::{Toolchain, file_uri, uri_path};
use serde_json::{Value, json};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn main() -> io::Result<()> {
    if env::current_exe()?
        .file_name()
        .is_some_and(|name| name == "cargo")
    {
        return wrapper();
    }
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    assert_eq!(
        args.len(),
        3,
        "usage: lorry-editor-workspace LORRY REPOSITORY WORK"
    );
    let lorry = Path::new(&args[0]).canonicalize()?;
    let repo = Path::new(&args[1]).canonicalize()?;
    let work = Path::new(&args[2]).canonicalize()?;
    let toolchain = Toolchain::discover(&repo)?;
    for custom in [false, true] {
        run(&lorry, &toolchain, &work, custom)?;
    }
    println!(
        "PASS: actual editor commands share workspace features, generated code, target directories, and save diagnostics"
    );
    Ok(())
}

fn run(lorry: &Path, toolchain: &Toolchain, work: &Path, custom: bool) -> io::Result<()> {
    let case_root = work.join(if custom { "custom" } else { "default" });
    let root = case_root.join("project");
    let home = case_root.join("home");
    let wrappers = case_root.join("wrapper");
    fs::create_dir_all(home.join(".config/lorry"))?;
    fs::create_dir_all(home.join(".cargo"))?;
    fs::create_dir_all(wrappers.join("invocations"))?;
    fixture(&root)?;
    fs::write(
        home.join(".config/lorry/lorry.toml"),
        format!(
            "config-version = 1\n[cache]\ndirectory = {:?}\n",
            case_root.join("cache")
        ),
    )?;
    let cargo = wrappers.join("cargo");
    fs::copy(env::current_exe()?, &cargo)?;
    fs::write(
        wrappers.join("lorry-path"),
        lorry.to_string_lossy().as_bytes(),
    )?;
    let rustc = toolchain.sysroot.join("bin/rustc");
    let mut admission = Command::new(lorry);
    admission.args(["vendor", "--locked", "--offline", "--accept-all"]);
    if custom {
        admission.args(["--features", "app/selected", "--no-default-features"]);
    }
    let status = admission
        .current_dir(&root)
        .env("HOME", &home)
        .env("RUSTC", &rustc)
        .status()?;
    assert!(
        status.success(),
        "editor fixture admission failed: {status}"
    );

    let target = if custom {
        "custom-artifacts"
    } else {
        "target/rust-analyzer"
    };
    let mut override_command = vec![
        cargo.to_string_lossy().into_owned(),
        "check".into(),
        "--workspace".into(),
        "--message-format=json".into(),
        "--all-targets".into(),
        "--keep-going".into(),
        "--compile-time-deps".into(),
        "--target".into(),
        "x86_64-unknown-motor".into(),
        "--target-dir".into(),
        target.into(),
    ];
    if custom {
        override_command.extend([
            "--features".into(),
            "app/selected".into(),
            "--no-default-features".into(),
        ]);
    }
    let mut options = json!({
        "cargo": {"target": "x86_64-unknown-motor", "targetDir": true,
            "sysroot": "discover", "features": [], "noDefaultFeatures": custom,
            "buildScripts": {"enable": true, "useRustcWrapper": false, "overrideCommand": override_command}},
        "check": {"targets": ["x86_64-unknown-motor"]},
        "procMacro": {"enable": false}, "files": {"watcher": "client"}
    });
    if custom {
        options["cargo"]["targetDir"] = json!(target);
        options["cargo"]["features"] = json!(["app/selected"]);
    }
    let mut server = Command::new(&toolchain.rust_analyzer);
    let mut paths = vec![wrappers.clone(), toolchain.sysroot.join("bin")];
    paths.extend(env::split_paths(&env::var_os("PATH").unwrap_or_default()));
    server
        .current_dir(&root)
        .env("CARGO", &cargo)
        .env("RUSTC", &rustc)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env("HOME", &home)
        .env("CARGO_HOME", home.join(".cargo"))
        .env("CARGO_NET_OFFLINE", "true")
        .env("PATH", env::join_paths(paths).unwrap())
        .env("RA_LOG", "project_model=info,flycheck=info");
    let mut case = SemanticCase::start_command(
        server,
        &root,
        &[("workspace", &root)],
        options,
        Instant::now() + Duration::from_secs(90),
    )?;
    case.wait_for_quiescence()?;
    case.wait_for_flychecks(1)?;
    let source = root.join("app/src/lib.rs");
    case.open(&source)?;
    let generated = uri_path(&case.definition(&source, "GENERATED")?)?;
    assert!(
        generated.starts_with(root.join(target).join("lorry")),
        "unexpected generated definition: {}",
        generated.display()
    );
    let expected = if custom { 73 } else { 42 };
    assert_eq!(
        fs::read_to_string(&generated)?,
        format!("pub const GENERATED: u32 = {expected};\n")
    );
    assert!(
        case.hover(&source, "GENERATED")?
            .to_string()
            .contains(&expected.to_string())
    );
    let saved =
        "pub fn value() -> u32 { generated::GENERATED }\ncompile_error!(\"editor save marker\");\n";
    fs::write(&source, saved)?;
    case.save_text(&source, 2, saved)?;
    case.wait_for_flychecks(1)?;
    case.wait_for_rustc_message(&file_uri(&source), "editor save marker")?;
    case.shutdown()?;
    validate_calls(
        &wrappers.join("invocations"),
        &root,
        target,
        custom,
        &override_command,
    )?;
    let default_entries = fs::read_dir(root.join("target/lorry"))?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    assert_eq!(default_entries, [std::ffi::OsString::from(".vendor.lock")]);
    Ok(())
}

fn fixture(root: &Path) -> io::Result<()> {
    for name in ["app", "generated"] {
        fs::create_dir_all(root.join(name).join("src"))?;
    }
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = ['app', 'generated']\nresolver = '2'\n",
    )?;
    fs::write(
        root.join("Cargo.lock"),
        "version = 4\n[[package]]\nname = 'app'\nversion = '1.0.0'\ndependencies = ['generated']\n[[package]]\nname = 'generated'\nversion = '1.0.0'\n",
    )?;
    fs::write(
        root.join("app/Cargo.toml"),
        "[package]\nname = 'app'\nversion = '1.0.0'\nedition = '2024'\n[lib]\ndoctest = false\n[dependencies]\ngenerated = {path = '../generated', default-features = false}\n[features]\nselected = ['generated/selected']\n",
    )?;
    fs::write(
        root.join("app/src/lib.rs"),
        "pub fn value() -> u32 { generated::GENERATED }\n",
    )?;
    fs::write(
        root.join("generated/Cargo.toml"),
        "[package]\nname = 'generated'\nversion = '1.0.0'\nedition = '2024'\n[lib]\ndoctest = false\n[features]\ndefault = ['default-setting']\ndefault-setting = []\nselected = []\n",
    )?;
    fs::write(
        root.join("generated/src/lib.rs"),
        "include!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));\n",
    )?;
    fs::write(
        root.join("generated/build.rs"),
        r#"fn main() {
    let selected = std::env::var_os("CARGO_FEATURE_SELECTED").is_some();
    let default = std::env::var_os("CARGO_FEATURE_DEFAULT_SETTING").is_some();
    let value = if selected && !default { 73 } else { 42 };
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(output.join("generated.rs"), format!("pub const GENERATED: u32 = {value};\n")).unwrap();
}
"#,
    )?;
    fs::write(
        root.join("lorry.toml"),
        "config-version = 1\n[policy.rules.generated]\naction = 'allow'\nsource = 'path'\nname = 'generated'\nallow-build-script = true\n",
    )
}

fn validate_calls(
    log: &Path,
    root: &Path,
    target: &str,
    custom: bool,
    override_command: &[String],
) -> io::Result<()> {
    let calls = fs::read_dir(log)?
        .map(|entry| {
            serde_json::from_slice::<Value>(&fs::read(entry?.path())?).map_err(io::Error::other)
        })
        .collect::<io::Result<Vec<_>>>()?;
    let args = |call: &Value| {
        call["argv"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    let build_pass = calls
        .iter()
        .find(|call| args(call).iter().any(|a| a == "--compile-time-deps"))
        .expect("missing compile-time pass");
    assert_eq!(args(build_pass), override_command[1..]);
    assert_eq!(build_pass["cwd"], root.to_string_lossy().as_ref());
    let root_calls = calls
        .iter()
        .filter(|call| call["cwd"] == root.to_string_lossy().as_ref())
        .collect::<Vec<_>>();
    for call in root_calls.iter().filter(|call| {
        args(call)
            .first()
            .is_some_and(|a| a == "metadata" || a == "check")
    }) {
        let argv = args(call);
        assert_eq!(
            argv.iter().any(|arg| arg == "--no-default-features"),
            custom,
            "{argv:?}"
        );
        if custom {
            assert!(argv.iter().any(|arg| arg == "app/selected"), "{argv:?}");
        }
        if argv[0] == "check" {
            let directory = PathBuf::from(
                &argv[argv.iter().position(|arg| arg == "--target-dir").unwrap() + 1],
            );
            assert_eq!(
                if directory.is_absolute() {
                    directory
                } else {
                    root.join(directory)
                },
                root.join(target)
            );
            for line in fs::read_to_string(call["stdout"].as_str().unwrap())?.lines() {
                let event: Value = serde_json::from_str(line)?;
                if event["reason"] == "compiler-artifact" {
                    for filename in event["filenames"].as_array().unwrap() {
                        assert!(
                            Path::new(filename.as_str().unwrap())
                                .starts_with(root.join(target).join("lorry"))
                        );
                    }
                }
            }
        }
    }
    assert!(
        root_calls
            .iter()
            .filter(|call| args(call).first().is_some_and(|a| a == "metadata"))
            .count()
            >= 2
    );
    assert!(root_calls.iter().any(|call| {
        args(call)
            .iter()
            .any(|arg| arg == "--message-format=json-diagnostic-rendered-ansi")
    }));
    Ok(())
}

fn wrapper() -> io::Result<()> {
    let directory = env::current_exe()?.parent().unwrap().to_owned();
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let stdout = directory.join(format!("stdout-{}-{nonce:x}", std::process::id()));
    let stderr = directory.join(format!("stderr-{}-{nonce:x}", std::process::id()));
    let output = Command::new(fs::read_to_string(directory.join("lorry-path"))?)
        .args(&args)
        .output()?;
    fs::write(&stdout, &output.stdout)?;
    fs::write(&stderr, &output.stderr)?;
    let record = json!({"argv": args.iter().map(|a| a.to_string_lossy()).collect::<Vec<_>>(),
        "cwd": env::current_dir()?.to_string_lossy(), "stdout": stdout, "stderr": stderr});
    fs::write(
        directory
            .join("invocations")
            .join(format!("{}-{nonce:x}.json", std::process::id())),
        serde_json::to_vec(&record)?,
    )?;
    io::stdout().write_all(&output.stdout)?;
    io::stderr().write_all(&output.stderr)?;
    std::process::exit(output.status.code().unwrap_or(1));
}
