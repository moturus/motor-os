//! Guest memory backing of the installed runner: one sparse lazy reservation
//! per memory, limited to 4 GiB, whose pages are released when the runner exits.

use wasm_smoke_suite::used_memory;

use super::{Result, Suite, fs};

const WASMI: &str = "MOTOR_OS_CAPS=0 /user/bin/dev/wasmi";
/// Bounds the used-memory drift across repeated runs; the faulted pages
/// alone are several times larger.
const CLEANUP_SLACK: u64 = 8 << 20;

pub(super) fn run(suite: &mut Suite) -> Result<()> {
    fs::write(
        suite.root.join("backing.wasm"),
        include_bytes!(concat!(env!("OUT_DIR"), "/backing.wasm")),
    )?;
    suite.command(
        "memory-grow-to-limit",
        &format!("{WASMI} backing.wasm --invoke grow-to-limit"),
        0,
    )?;
    let before = used_memory()?;
    suite.command(
        "memory-touch",
        &format!("{WASMI} backing.wasm --invoke touch"),
        0,
    )?;
    let after = used_memory()?;
    println!("memory-cleanup: used_before={before} used_after={after}");
    if after > before + CLEANUP_SLACK {
        return Err(format!("memory-cleanup: used grew from {before} to {after}").into());
    }
    Ok(())
}
