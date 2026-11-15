#![cfg(unix)]

use std::io;
use std::path::Path;
use std::time::Duration;

use serde_json::json;

use motor_analyzer_tests::case::SemanticCase;
use motor_analyzer_tests::semantic::{Toolchain, uri_path};

const CASE_TIMEOUT: Duration = Duration::from_secs(60);

#[test]
fn target_semantics_and_sysroot_definitions() -> io::Result<()> {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .ok_or_else(|| invalid("cannot locate repository root"))?
        .canonicalize()?;
    let toolchain = Toolchain::discover(&repo)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let fixtures = std::env::temp_dir().join(format!("analyzer-{}-{nonce}", std::process::id()));
    for kind in ["motor", "linux", "inline"] {
        let root = fixtures.join(kind);
        create_workspace(kind, &root)?;
    }
    run_motor(&toolchain, &fixtures.join("motor")).map_err(|error| context("Motor", error))?;
    #[cfg(not(target_os = "motor"))]
    run_linux(&toolchain, &fixtures.join("linux")).map_err(|error| context("Linux", error))?;
    run_inline(&toolchain, &fixtures.join("inline"))
        .map_err(|error| context("inline Motor", error))?;
    println!("rust-analyzer-smoke PASS");
    std::fs::remove_dir_all(fixtures)?;
    Ok(())
}

fn run_motor(toolchain: &Toolchain, root: &Path) -> io::Result<()> {
    let source = root.join("src/lib.rs");
    let options = cargo_options(Some("x86_64-unknown-motor"));
    let mut case = SemanticCase::start(
        toolchain,
        &toolchain.sysroot.join("bin/cargo"),
        root,
        &[("motor", root)],
        options,
        CASE_TIMEOUT,
    )?;
    case.wait_for_quiescence()?;
    case.wait_for_flychecks(1)?;
    let source_uri = case.open(&source)?;

    let std_uri = case.definition(&source, "rt_version")?;
    let std_path = uri_path(&std_uri)?;
    require_below(
        &std_path,
        &toolchain.sysroot_src.join("std/src/os/motor"),
        "Motor std definition",
    )?;
    case.open(&std_path)?;
    let moto_rt_path = uri_path(&case.definition(&std_path, "RT_VERSION")?)?;
    let vendor = toolchain.sysroot_src.join("vendor");
    require_below(&moto_rt_path, &vendor, "moto_rt definition")?;
    if !moto_rt_path
        .strip_prefix(&vendor)
        .ok()
        .and_then(|path| path.components().next())
        .and_then(|component| component.as_os_str().to_str())
        .is_some_and(|name| name.starts_with("moto-rt-"))
    {
        return Err(invalid("moto_rt definition lacks its vendored crate root"));
    }

    let hover = case.hover(&source, "GeneratedByProcMacro")?;
    if !hover.to_string().contains("GeneratedByProcMacro") {
        return Err(invalid("local procedural macro did not expand"));
    }
    require_no_wrong_target(&case, &source_uri, "Motor")?;
    case.shutdown()
}

fn run_linux(toolchain: &Toolchain, root: &Path) -> io::Result<()> {
    let source = root.join("src/lib.rs");
    let mut case = SemanticCase::start(
        toolchain,
        &toolchain.sysroot.join("bin/cargo"),
        root,
        &[("linux", root)],
        cargo_options(None),
        CASE_TIMEOUT,
    )?;
    case.wait_for_quiescence()?;
    case.wait_for_flychecks(1)?;
    let source_uri = case.open(&source)?;
    let definition = uri_path(&case.definition(&source, "MetadataExt")?)?;
    require_below(
        &definition,
        &toolchain.sysroot_src.join("std/src/os/linux"),
        "Linux std definition",
    )?;
    require_no_wrong_target(&case, &source_uri, "Linux")?;
    case.shutdown()
}

fn run_inline(toolchain: &Toolchain, root: &Path) -> io::Result<()> {
    let source = root.join("lib.rs").canonicalize()?;
    let root = root.canonicalize()?;
    let path = |path: &Path| {
        path.to_str()
            .map(str::to_owned)
            .ok_or_else(|| invalid("inline project path is not UTF-8"))
    };
    let project = json!({
        "sysroot": path(&toolchain.sysroot)?,
        "sysroot_src": path(&toolchain.sysroot_src)?,
        "crates": [{
            "display_name": "inline-motor-ra-smoke",
            "root_module": path(&source)?,
            "edition": "2024",
            "deps": [],
            "is_workspace_member": true,
            "source": {"include_dirs": [path(&root)?], "exclude_dirs": []},
            "cfg": toolchain.target_cfgs("x86_64-unknown-motor")?,
            "target": "x86_64-unknown-motor",
            "env": {"CARGO_PKG_NAME": "inline-motor-ra-smoke"}
        }]
    });
    let options = json!({
        "linkedProjects": [project],
        "cargo": {
            "target": "x86_64-unknown-motor",
            "buildScripts": {"enable": false},
            "extraEnv": {"CARGO_NET_OFFLINE": "true"}
        },
        "procMacro": {"enable": false}
    });
    let mut case = SemanticCase::start(
        toolchain,
        &toolchain.sysroot.join("bin/cargo"),
        &root,
        &[("inline", &root)],
        options,
        CASE_TIMEOUT,
    )?;
    case.wait_for_quiescence()?;
    let source_uri = case.open(&source)?;
    let definition = uri_path(&case.definition(&source, "rt_version")?)?;
    require_below(
        &definition,
        &toolchain.sysroot_src.join("std/src/os/motor"),
        "inline Motor std definition",
    )?;
    require_no_wrong_target(&case, &source_uri, "inline Motor")?;
    case.shutdown()
}

fn cargo_options(target: Option<&str>) -> serde_json::Value {
    let mut options = json!({
        "cargo": {
            "targetDir": true,
            "sysroot": "discover",
            "buildScripts": {"enable": true, "useRustcWrapper": false},
            "extraEnv": {"CARGO_NET_OFFLINE": "true"}
        },
        "check": {},
        "procMacro": {"enable": true}
    });
    if let Some(target) = target {
        options["cargo"]["target"] = json!(target);
        options["check"]["targets"] = json!([target]);
    }
    options
}

fn require_no_wrong_target(case: &SemanticCase, uri: &str, description: &str) -> io::Result<()> {
    if case
        .latest_diagnostics(uri)
        .is_some_and(|diagnostics| diagnostics.to_string().contains("wrong target"))
    {
        Err(invalid(format!(
            "{description} fixture activated its wrong-target sentinel"
        )))
    } else {
        Ok(())
    }
}

fn require_below(path: &Path, root: &Path, description: &str) -> io::Result<()> {
    if path.starts_with(root) {
        Ok(())
    } else {
        Err(invalid(format!(
            "{description} escaped {}: {}",
            root.display(),
            path.display()
        )))
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn context(case: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{case} case: {error}"))
}

fn create_workspace(kind: &str, root: &Path) -> io::Result<()> {
    for (name, text) in WORKSPACES {
        if let Some(name) = name.strip_prefix(&format!("{kind}/")) {
            let path = root.join(name);
            std::fs::create_dir_all(path.parent().unwrap())?;
            std::fs::write(path, text)?;
        }
    }
    Ok(())
}

const WORKSPACES: &[(&str, &str)] = &[
    (
        "inline/lib.rs",
        r####"#![feature(motor_ext)]

#[cfg(not(target_os = "motor"))]
compile_error!("inline Motor fixture used the wrong target");

pub fn motor_runtime_version() -> u64 {
    std::os::motor::rt_version()
}
"####,
    ),
    (
        "linux/Cargo.lock",
        r####"# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "linux-ra-smoke"
version = "0.1.0"
"####,
    ),
    (
        "linux/Cargo.toml",
        r####"[package]
name = "linux-ra-smoke"
version = "0.1.0"
edition = "2024"
publish = false
"####,
    ),
    (
        "linux/src/lib.rs",
        r####"#[cfg(not(target_os = "linux"))]
compile_error!("Linux fixture used the wrong target");

use std::os::linux::fs::MetadataExt;

pub fn inode(metadata: &std::fs::Metadata) -> u64 {
    metadata.st_ino()
}
"####,
    ),
    (
        "motor/Cargo.lock",
        r####"# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "motor-ra-smoke"
version = "0.1.0"
dependencies = [
 "motor-ra-smoke-macro",
]

[[package]]
name = "motor-ra-smoke-macro"
version = "0.1.0"
"####,
    ),
    (
        "motor/Cargo.toml",
        r####"[package]
name = "motor-ra-smoke"
version = "0.1.0"
edition = "2024"
publish = false

[dependencies]
motor-ra-smoke-macro = { path = "proc-macro" }
"####,
    ),
    (
        "motor/proc-macro/Cargo.toml",
        r####"[package]
name = "motor-ra-smoke-macro"
version = "0.1.0"
edition = "2024"
publish = false

[lib]
proc-macro = true
"####,
    ),
    (
        "motor/proc-macro/src/lib.rs",
        r####"extern crate proc_macro;

use proc_macro::TokenStream;

#[proc_macro]
pub fn define_marker(_input: TokenStream) -> TokenStream {
    "pub struct GeneratedByProcMacro;".parse().unwrap()
}
"####,
    ),
    (
        "motor/src/lib.rs",
        r####"#![feature(motor_ext)]

#[cfg(not(target_os = "motor"))]
compile_error!("Motor fixture used the wrong target");

motor_ra_smoke_macro::define_marker!();

pub fn consumes_marker(_: GeneratedByProcMacro) {}

pub fn motor_runtime_version() -> u64 {
    std::os::motor::rt_version()
}
"####,
    ),
];
