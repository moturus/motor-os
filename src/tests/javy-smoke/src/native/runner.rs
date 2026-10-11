//! WASI preview1 behavior of the installed runner, from hand-written modules.

use super::{Result, Suite, fs};

const WASMI: &str = "MOTOR_OS_CAPS=0 /devtools/bin/wasmi";

fn expect_stdout(label: &str, stdout: &str, expected: &str) -> Result<()> {
    if stdout != expected {
        return Err(format!("{label}: unexpected output {stdout:?}").into());
    }
    Ok(())
}

pub(super) fn run(suite: &mut Suite) -> Result<()> {
    fs::write(
        suite.root.join("wasi.wasm"),
        include_bytes!(concat!(env!("OUT_DIR"), "/wasi.wasm")),
    )?;
    fs::write(
        suite.root.join("mistyped.wasm"),
        include_bytes!(concat!(env!("OUT_DIR"), "/mistyped.wasm")),
    )?;
    // Exit statuses are WASI errnos: BADF is 8 and INVAL is 28.
    for (name, code) in [
        ("duplicate-exit", 0),
        ("close-twice", 8),
        ("read-closed", 8),
        ("write-closed", 8),
        ("stat-closed", 8),
        ("clock-invalid", 28),
        ("clock-cputime", 8),
        ("clocks", 0),
    ] {
        suite.command(name, &format!("{WASMI} wasi.wasm --invoke {name}"), code)?;
    }
    suite.refusal(
        "mistyped-import",
        &format!("{WASMI} mistyped.wasm"),
        "fd_write has type",
    )?;
    // A guest exit ends the run: the trap after it must not execute.
    suite.command(
        "exit-then-trap",
        &format!("{WASMI} runner.wasm --invoke exit-zero --invoke trap"),
        0,
    )?;
    // Stdin stays open in these two: the runner must read only what the guest
    // asks for, and return a short read instead of waiting for EOF.
    let (stdout, _) = suite.command_with_input(
        "stdin-unread",
        &format!("{WASMI} wasi.wasm --invoke write-ready"),
        0,
        Some(b""),
    )?;
    expect_stdout("stdin-unread", &stdout, "ready\n")?;
    let (stdout, _) = suite.command_with_input(
        "stdin-partial",
        &format!("{WASMI} wasi.wasm --invoke read-once"),
        0,
        Some(b"partial\n"),
    )?;
    expect_stdout("stdin-partial", &stdout, "partial\n")?;
    let (stdout, _) = suite.command(
        "stdin-eof",
        &format!("{WASMI} wasi.wasm --invoke read-once"),
        0,
    )?;
    expect_stdout("stdin-eof", &stdout, "")
}
