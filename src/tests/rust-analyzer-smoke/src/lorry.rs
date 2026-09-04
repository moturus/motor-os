use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::case::SemanticCase;
use crate::semantic::{Toolchain, file_uri};

const TIMEOUT: Duration = Duration::from_secs(90);

pub fn run(lorry: &Path) -> io::Result<()> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .ok_or_else(|| invalid("cannot locate repository root"))?
        .canonicalize()?;
    let toolchain = Toolchain::discover(&repository)?;
    let temporary = TemporaryDirectory::new()?;
    let root = temporary.path.join("project");
    copy_tree(
        &repository.join("src/tests/rust-analyzer-smoke/fixtures/lorry"),
        &root,
    )?;
    let home = temporary.path.join("home");
    let wrapper = temporary.path.join("wrapper");
    let log = wrapper.join("invocations");
    fs::create_dir_all(home.join(".config/lorry"))?;
    fs::create_dir(home.join(".cargo"))?;
    fs::create_dir(&wrapper)?;
    fs::create_dir(&log)?;
    fs::write(
        home.join(".config/lorry/lorry.toml"),
        format!(
            "config-version = 1\n[cache]\ndirectory = {:?}\n",
            temporary.path.join("cache")
        ),
    )?;

    let rustc = toolchain.sysroot.join("bin/rustc");
    let lorry = lorry.canonicalize()?;
    let status = Command::new(&lorry)
        .args(["vendor", "--accept-all"])
        .current_dir(&root)
        .env("HOME", &home)
        .env("RUSTC", &rustc)
        .env("CARGO_NET_OFFLINE", "true")
        .status()?;
    if !status.success() {
        return Err(invalid(format!("lorry vendor failed with {status}")));
    }

    let current = env::current_exe()?.canonicalize()?;
    let cargo = wrapper.join("cargo");
    fs::copy(&current, &cargo)?;
    fs::write(
        wrapper.join("lorry-path"),
        lorry.as_os_str().as_encoded_bytes(),
    )?;
    let mut command = Command::new(&toolchain.rust_analyzer);
    command
        .current_dir(&root)
        .env("CARGO", &cargo)
        .env("RUSTC", &rustc)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env("HOME", &home)
        .env("CARGO_HOME", home.join(".cargo"))
        .env("CARGO_NET_OFFLINE", "true")
        .env("RA_LOG", "project_model=info,flycheck=info");
    command.env("PATH", executable_path(&toolchain, &wrapper)?);
    let options = json!({
        "cargo": {
            "target": "x86_64-unknown-motor",
            "targetDir": true,
            "sysroot": "discover",
            "buildScripts": {"enable": true, "useRustcWrapper": false},
            "extraEnv": {"CARGO_NET_OFFLINE": "true"}
        },
        "check": {"targets": ["x86_64-unknown-motor"]},
        "procMacro": {"enable": false},
        "files": {"watcher": "client"}
    });
    let deadline = Instant::now() + TIMEOUT;
    let mut case =
        SemanticCase::start_command(command, &root, &[("lorry", &root)], options, deadline)?;
    case.wait_for_quiescence()?;
    case.wait_for_flychecks(1)?;
    let source = root.join("src/lib.rs");
    let source_uri = file_uri(&source);
    let diagnostics = case
        .latest_diagnostics(&source_uri)
        .ok_or_else(|| invalid("flycheck published no root diagnostics"))?;
    if !diagnostics.as_array().is_some_and(|diagnostics| {
        diagnostics.iter().any(|diagnostic| {
            diagnostic["source"] == "rustc"
                && diagnostic["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("lorry flycheck marker"))
        })
    }) {
        return Err(invalid(format!(
            "flycheck omitted the rustc marker diagnostic: {diagnostics}"
        )));
    }
    case.shutdown()?;
    let stderr = case.stderr_tail();
    validate_invocations(&log, &root, &toolchain.sysroot, &stderr)?;
    println!("rust-analyzer Lorry acceptance PASS");
    Ok(())
}

fn executable_path(toolchain: &Toolchain, wrapper: &Path) -> io::Result<std::ffi::OsString> {
    let mut paths = vec![wrapper.to_owned(), toolchain.sysroot.join("bin")];
    if let Some(current) = env::var_os("PATH") {
        paths.extend(env::split_paths(&current));
    }
    env::join_paths(paths).map_err(|error| invalid(format!("cannot construct test PATH: {error}")))
}

fn validate_invocations(log: &Path, root: &Path, sysroot: &Path, stderr: &str) -> io::Result<()> {
    let mut calls = fs::read_dir(log)?
        .map(|entry| {
            let path = entry?.path();
            serde_json::from_slice::<Value>(&fs::read(path)?)
                .map_err(|error| invalid(format!("invalid invocation record: {error}")))
        })
        .collect::<io::Result<Vec<_>>>()?;
    calls.sort_by_key(Value::to_string);
    let root_manifest = root.join("Cargo.toml");
    let target_dir = root.join("target/rust-analyzer");
    let sysroot_src = sysroot.join("lib/rustlib/src/rust/library");
    let sysroot_manifest = sysroot_src.join("Cargo.toml");
    let root_manifest = root_manifest.to_string_lossy().into_owned();
    let target_dir = target_dir.to_string_lossy().into_owned();
    let sysroot_manifest = sysroot_manifest.to_string_lossy().into_owned();
    let mut expected = Vec::new();
    for _ in 0..2 {
        expected.push(record(vec!["--version"], root, sysroot, &[]));
        expected.push(record(
            vec![
                "locate-project",
                "--workspace",
                "--manifest-path",
                &root_manifest,
            ],
            root,
            sysroot,
            &[],
        ));
        expected.push(record(
            vec![
                "-Z",
                "unstable-options",
                "config",
                "get",
                "--format",
                "toml",
                "--show-origin",
            ],
            root,
            sysroot,
            &[("RUSTC_BOOTSTRAP", "1")],
        ));
        expected.push(record(
            vec![
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
            root,
            sysroot,
            &[("__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS", "nightly")],
        ));
        expected.push(record(
            vec![
                "rustc",
                "-Z",
                "unstable-options",
                "--print",
                "target-spec-json",
                "--target",
                "x86_64-unknown-motor",
                "--",
                "-Z",
                "unstable-options",
            ],
            root,
            sysroot,
            &[("RUSTC_BOOTSTRAP", "1")],
        ));
        for no_deps in [false, true] {
            let mut root_args = vec!["metadata", "--format-version", "1"];
            if no_deps {
                root_args.push("--no-deps");
            }
            root_args.extend([
                "--manifest-path",
                &root_manifest,
                "--filter-platform",
                "x86_64-unknown-motor",
            ]);
            expected.push(record(root_args, root, sysroot, &[]));

            let mut sysroot_args = vec!["metadata", "--format-version", "1"];
            if no_deps {
                sysroot_args.push("--no-deps");
            }
            sysroot_args.extend([
                "--manifest-path",
                &sysroot_manifest,
                "--filter-platform",
                "x86_64-unknown-motor",
            ]);
            if !no_deps {
                sysroot_args.push("--locked");
            }
            expected.push(record(
                sysroot_args,
                &sysroot_src,
                sysroot,
                &[("__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS", "nightly")],
            ));
        }
    }
    expected.push(record(
        vec![
            "check",
            "--quiet",
            "--workspace",
            "--message-format=json",
            "--manifest-path",
            &root_manifest,
            "--target-dir",
            &target_dir,
            "--target",
            "x86_64-unknown-motor",
            "--keep-going",
            "--all-targets",
        ],
        root,
        sysroot,
        &[],
    ));
    expected.push(record(
        vec![
            "check",
            "--workspace",
            "--message-format=json-diagnostic-rendered-ansi",
            "--manifest-path",
            &root_manifest,
            "--keep-going",
            "--target",
            "x86_64-unknown-motor",
            "--all-targets",
            "--target-dir",
            &target_dir,
        ],
        root,
        sysroot,
        &[("CARGO_LOG", "cargo::core::compiler::fingerprint=info")],
    ));
    expected.sort_by_key(Value::to_string);
    if calls != expected {
        return Err(invalid(format!(
            "rust-analyzer Cargo invocation drift\nexpected: {}\nactual: {}",
            serde_json::to_string_pretty(&expected).unwrap(),
            serde_json::to_string_pretty(&calls).unwrap()
        )));
    }

    let metadata_errors = stderr
        .lines()
        .filter(|line| line.contains(" ERROR "))
        .collect::<Vec<_>>();
    let expected_error = format!("`cargo metadata` failed on `{sysroot_manifest}`");
    if metadata_errors.len() != 2
        || !metadata_errors
            .iter()
            .all(|line| line.contains(&expected_error))
    {
        return Err(invalid(format!(
            "rust-analyzer did not report exactly two expected sysroot metadata errors: {stderr}"
        )));
    }
    let out_dir = root.join("target/rust-analyzer/lorry");
    if !stderr.contains("cfgs: [Flag(\"generated_fixture\")]")
        || !stderr.contains("\"GENERATED_ENV\": \"from-build-script\"")
        || !stderr.contains(out_dir.to_string_lossy().as_ref())
    {
        return Err(invalid(format!(
            "rust-analyzer did not consume Lorry's build-script data: {stderr}"
        )));
    }
    Ok(())
}

fn record(
    argv: Vec<&str>,
    cwd: &Path,
    sysroot: &Path,
    extra_environment: &[(&str, &str)],
) -> Value {
    let mut environment = serde_json::Map::from_iter([
        ("CARGO_NET_OFFLINE".to_owned(), json!("true")),
        ("RUSTUP_AUTO_INSTALL".to_owned(), json!("0")),
        (
            "RUSTUP_TOOLCHAIN".to_owned(),
            json!(sysroot.to_string_lossy()),
        ),
    ]);
    environment.extend(
        extra_environment
            .iter()
            .map(|(name, value)| ((*name).to_owned(), json!(value))),
    );
    json!({
        "argv": argv,
        "cwd": cwd.to_string_lossy(),
        "environment": environment,
    })
}

fn copy_tree(source: &Path, destination: &Path) -> io::Result<()> {
    fs::create_dir(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new() -> io::Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = env::temp_dir().join(format!("lorry-ra-{}-{nonce:x}", std::process::id()));
        fs::create_dir(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
