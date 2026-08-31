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
    run_motor(&toolchain, &fixtures.join("motor"))?;
    println!("rust-analyzer-smoke PASS");
    Ok(())
}

fn run_motor(toolchain: &Toolchain, root: &Path) -> io::Result<()> {
    let source = root.join("src/lib.rs");
    let options = json!({
        "cargo": {
            "target": "x86_64-unknown-motor",
            "targetDir": true,
            "sysroot": "discover",
            "buildScripts": {"enable": true},
            "extraEnv": {"CARGO_NET_OFFLINE": "true"}
        },
        "check": {"targets": ["x86_64-unknown-motor"]},
        "procMacro": {"enable": true}
    });
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
    if case
        .latest_diagnostics(&source_uri)
        .is_some_and(|diagnostics| diagnostics.to_string().contains("wrong target"))
    {
        return Err(invalid("Motor fixture activated its wrong-target sentinel"));
    }
    case.shutdown()
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
