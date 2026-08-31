use std::io;
use std::path::Path;
use std::time::Duration;

use serde_json::json;

use crate::case::SemanticCase;
use crate::semantic::{Toolchain, uri_path};

const CASE_TIMEOUT: Duration = Duration::from_secs(60);

pub fn run() -> io::Result<()> {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .ok_or_else(|| invalid("cannot locate repository root"))?
        .canonicalize()?;
    let toolchain = Toolchain::discover(&repo)?;
    let fixtures = repo.join("src/tests/rust-analyzer-smoke/fixtures");
    run_motor(&toolchain, &fixtures.join("motor")).map_err(|error| context("Motor", error))?;
    run_linux(&toolchain, &fixtures.join("linux")).map_err(|error| context("Linux", error))?;
    run_inline(&toolchain, &fixtures.join("inline"))
        .map_err(|error| context("inline Motor", error))?;
    println!("rust-analyzer-smoke PASS");
    Ok(())
}

fn run_motor(toolchain: &Toolchain, root: &Path) -> io::Result<()> {
    let source = root.join("src/lib.rs");
    let options = cargo_options(Some("x86_64-unknown-motor"));
    let mut case = SemanticCase::start(toolchain, root, &[("motor", root)], options, CASE_TIMEOUT)?;
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
            "buildScripts": {"enable": true},
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
