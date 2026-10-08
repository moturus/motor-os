//! Installed `wasmtime-rt` checks with the precompiled fixtures that the
//! Wasmtime add-on builds from the runtime's own sources.
use std::fs;

use wasm_smoke_suite::{Result, Suite};

const RUNTIME: &str = "/devtools/bin/wasmtime-rt";
const FIXTURES: &str = "/devtools/cfg/wasmtime/fixtures";
/// Upstream p2 socket programs carrying Motor's accepted socket semantics.
const SOCKET_PROGRAMS: [&str; 13] = [
    "p2_tcp_bind",
    "p2_tcp_bind_listen_order",
    "p2_tcp_connect",
    "p2_tcp_sample_application",
    "p2_tcp_sockopts",
    "p2_tcp_states",
    "p2_tcp_streams",
    "p2_udp_bind",
    "p2_udp_connect",
    "p2_udp_sample_application",
    "p2_udp_send_to_closed_receiver",
    "p2_udp_sockopts",
    "p2_udp_states",
];
const TYPESCRIPT_OUTPUT: &str = "{\"version\":\"5.9.3\",\"output\":\";\\nconst item = { value: 42 };\\nconsole.log(item.value);\\n\",\"diagnostics\":0}\n";

/// `wasmtime-rt run` of a fixture with a capability mask and extra options.
fn invocation(caps: &str, options: &str, fixture: &str) -> String {
    format!(
        "MOTOR_OS_CAPS={caps} {RUNTIME} run --allow-precompiled {options} {FIXTURES}/{fixture}.cwasm"
    )
}

fn expect(label: &str, actual: &str, expected: &str) -> Result<()> {
    if actual != expected {
        return Err(format!("{label}: expected {expected:?}, got {actual:?}").into());
    }
    Ok(())
}

pub fn run_suite(suite: &mut Suite) -> Result<()> {
    let (version, _) = suite.command(
        "version",
        &format!("MOTOR_OS_CAPS=0 {RUNTIME} --version"),
        0,
    )?;
    expect("version", version.trim(), "wasmtime 48.0.1")?;
    suite.refusal(
        "role-refusal",
        &format!("{RUNTIME} run --allow-precompiled {FIXTURES}/lifecycle.cwasm"),
        "role None",
    )?;
    suite.refusal(
        "cap-refusal",
        &invocation("0x104", "", "lifecycle"),
        "excess capabilities",
    )?;

    // Command lifecycle: stdio, exit status, traps and interruption.
    let (stdout, stderr) = suite.command("stdio", &invocation("0", "", "lifecycle"), 0)?;
    expect("stdio stdout", &stdout, "out\n")?;
    expect("stdio stderr", &stderr, "err\n")?;
    suite.command(
        "exit-seven",
        &invocation("0", "--invoke exit-seven", "lifecycle"),
        7,
    )?;
    let (_, stderr) = suite.command("trap", &invocation("0", "--invoke trap", "lifecycle"), -1)?;
    if !stderr.contains("unreachable") {
        return Err(format!("trap: missing trap diagnostic: {stderr}").into());
    }
    let (_, stderr) = suite.command(
        "timeout",
        &invocation("0", "-W timeout=1s --invoke loop", "lifecycle-epoch"),
        -1,
    )?;
    if !stderr.contains("interrupt") {
        return Err(format!("timeout: missing interrupt diagnostic: {stderr}").into());
    }
    for round in 0..8 {
        suite.command(
            &format!("repeat-{round}"),
            &invocation("0", "", "lifecycle"),
            0,
        )?;
    }

    // Artifacts that do not match the runtime are refused before running; the
    // runtime cannot compile, so a damaged artifact is refused as uncompilable.
    suite.refusal(
        "epoch-mismatch",
        &invocation("0", "--invoke loop", "lifecycle-epoch"),
        "epoch interruption",
    )?;
    suite.refusal(
        "native-artifact",
        &invocation("0", "", "lifecycle-native"),
        "lifecycle-native.cwasm",
    )?;
    let artifact = fs::read(format!("{FIXTURES}/lifecycle.cwasm"))?;
    fs::write(
        suite.root.join("truncated.cwasm"),
        &artifact[..artifact.len() / 2],
    )?;
    fs::write(suite.root.join("not-an-artifact.cwasm"), b"not an artifact")?;
    for name in ["truncated", "not-an-artifact"] {
        suite.refusal(
            name,
            &format!("MOTOR_OS_CAPS=0 {RUNTIME} run --allow-precompiled {name}.cwasm"),
            "compiling modules was disabled",
        )?;
    }

    // Store defaults, their overrides, and the fixed memory reservations.
    suite.refusal(
        "tables-default",
        &invocation("0", "", "limits-tables"),
        "table count too high",
    )?;
    suite.command(
        "tables-override",
        &invocation("0", "-W max-tables=17", "limits-tables"),
        0,
    )?;
    suite.refusal(
        "elements-default",
        &invocation("0", "", "limits-elements"),
        "exceeds table limits",
    )?;
    suite.command(
        "elements-override",
        &invocation("0", "-W max-table-elements=40000", "limits-elements"),
        0,
    )?;
    suite.refusal(
        "memories-default",
        &invocation("0", "", "limits-memories"),
        "reservation limits",
    )?;
    suite.refusal(
        "memories-fixed",
        &invocation("0", "-W max-memories=5", "limits-memories"),
        "reservation limits",
    )?;
    suite.refusal(
        "memory-too-large",
        &invocation("0", "", "memory-too-large"),
        "exceeds",
    )?;
    let (stdout, _) = suite.command(
        "memory-to-limit",
        &(invocation("0", "--invoke grow", "memory-grow") + " 1535"),
        0,
    )?;
    expect("memory-to-limit", stdout.trim(), "1")?;
    let (stdout, _) = suite.command(
        "memory-beyond-limit",
        &(invocation("0", "--invoke grow", "memory-grow") + " 1536"),
        0,
    )?;
    expect("memory-beyond-limit", stdout.trim(), "-1")?;

    // The mandatory TypeScript workload, compiled by Javy and precompiled.
    let (stdout, _) = suite.command("typescript", &invocation("0", "", "typescript"), 0)?;
    expect("typescript", &stdout, TYPESCRIPT_OUTPUT)?;

    // WASI p2 sockets with network authority, and their denial without it.
    for program in SOCKET_PROGRAMS {
        suite.command(
            program,
            &invocation("0x100", "-S inherit-network=y", program),
            0,
        )?;
    }
    let (_, stderr) = suite.command(
        "network-denied",
        &invocation("0", "-S inherit-network=y", "p2_tcp_sample_application"),
        -1,
    )?;
    if !stderr.contains("access-denied") {
        return Err(format!("network-denied: missing access-denied: {stderr}").into());
    }
    Ok(())
}

pub fn run() -> Result<()> {
    let mut suite = Suite::new("wasmtime-smoke", "/devtools/cfg/wasmtime/sources.txt")?;
    run_suite(&mut suite)?;
    suite.finish()
}
