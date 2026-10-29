//! Installed Wasmtime tools with fixtures from the same fork and configuration.
use std::fs;
use std::io::Write;
use std::time::{Duration, Instant};

use wasm_smoke_suite::{Job, Result, Suite, process_active};

mod compiler;
mod filesystem;
mod http;
mod p3;
mod roles;

const RUNTIME: &str = "/devtools/bin/wasmtime-rt";
const COMPILER: &str = "/devtools/bin/wasmtime";
/// Precompiled fixtures that test-wasm.sh uploads; they are not part of the images.
const FIXTURES: &str = "/none/wasm-tests/wasmtime-tests";
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
    // The upstream CLI appends commit/date metadata when built from Git.
    let version = version
        .trim()
        .split_once(" (")
        .map_or(version.trim(), |v| v.0);
    expect("version", version, "wasmtime 50.0.0")?;
    compiler::run(suite)?;
    suite.command(
        "engine-tests",
        &format!("MOTOR_OS_CAPS=0x200 {FIXTURES}/engine-tests"),
        0,
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
        "bounds-trap",
        &(invocation("0", "--invoke load", "memory-grow") + " 65536"),
        -1,
    )?;
    if !stderr.contains("out of bounds memory access") {
        return Err(format!("bounds-trap: missing trap diagnostic: {stderr}").into());
    }
    let (_, stderr) = suite.command(
        "timeout",
        &invocation("0", "-W timeout=1s --invoke loop", "lifecycle-epoch"),
        -1,
    )?;
    if !stderr.contains("interrupt") {
        return Err(format!("timeout: missing interrupt diagnostic: {stderr}").into());
    }
    interruption(suite)?;
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
        "pulley-needs-target",
        &invocation("0", "", "lifecycle-pulley"),
        "compiled for architecture 'pulley64'",
    )?;
    suite.command(
        "explicit-pulley",
        &invocation("0", "--target pulley64", "lifecycle-pulley"),
        0,
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

    // Upstream store defaults, explicit limits, and lazy memory growth.
    suite.command("tables-default", &invocation("0", "", "limits-tables"), 0)?;
    suite.refusal(
        "tables-limited",
        &invocation("0", "-W max-tables=16", "limits-tables"),
        "table count too high",
    )?;
    suite.command(
        "tables-override",
        &invocation("0", "-W max-tables=17", "limits-tables"),
        0,
    )?;
    suite.command(
        "elements-default",
        &invocation("0", "", "limits-elements"),
        0,
    )?;
    suite.refusal(
        "elements-limited",
        &invocation("0", "-W max-table-elements=32768", "limits-elements"),
        "exceeds table limits",
    )?;
    suite.command(
        "elements-override",
        &invocation("0", "-W max-table-elements=40000", "limits-elements"),
        0,
    )?;
    // Memory64 may exceed 4 GiB; limits must be requested explicitly.
    suite.command(
        "memories-default",
        &invocation("0", "", "limits-memories"),
        0,
    )?;
    suite.refusal(
        "memories-limited",
        &invocation("0", "-W max-memories=4", "limits-memories"),
        "memory count too high",
    )?;
    suite.command(
        "memories-override",
        &invocation("0", "-W max-memories=5", "limits-memories"),
        0,
    )?;
    suite.command(
        "memory64-large-initial",
        &invocation("0", "", "memory-too-large"),
        0,
    )?;
    suite.refusal(
        "memory-size-limited",
        &invocation("0", "-W max-memory-size=4294967296", "memory-too-large"),
        "exceeds",
    )?;
    // Growing to 4 GiB touches no page, or the VM could not hold it.
    let (stdout, _) = suite.command(
        "memory-to-limit",
        &(invocation("0", "--invoke grow", "memory-grow") + " 65535"),
        0,
    )?;
    expect("memory-to-limit", stdout.trim(), "1")?;
    let (stdout, _) = suite.command(
        "memory-size-override",
        &(invocation(
            "0",
            "-W max-memory-size=1048576 --invoke grow",
            "memory-grow",
        ) + " 16"),
        0,
    )?;
    expect("memory-size-override", stdout.trim(), "-1")?;
    let (stdout, _) = suite.command(
        "memory64-to-4gib",
        &(invocation("0", "--invoke grow", "memory64-grow") + " 65535"),
        0,
    )?;
    expect("memory64-to-4gib", stdout.trim(), "1")?;
    let (stdout, _) = suite.command(
        "memory64-beyond-4gib",
        &(invocation("0", "--invoke grow", "memory64-grow") + " 65536"),
        0,
    )?;
    expect("memory64-beyond-4gib", stdout.trim(), "1")?;

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

    // WASI p2 filesystem and stdio.
    filesystem::run(suite)?;
    p3::run(suite)?;
    http::run(suite)
}

/// Ctrl+C on the terminal ends a foreground `run` spinning in Pulley with
/// status 130, and a runtime whose shell is killed ends once the shell is
/// reaped.
fn interruption(suite: &mut Suite) -> Result<()> {
    let spin = invocation("0", "--invoke ready-loop", "lifecycle");
    let mut job = suite.start("ctrl-c", &spin, true)?;
    job.wait_stdout("out\n")?;
    let runtime = runtime_pid(&job)?;
    job.ctrl_c()?;
    suite.wait(&mut job, 130)?;
    // The shell is still held, so it has not killed its children: the
    // runtime ended because Ctrl+C reached it rather than the shell.
    if process_active(runtime)? {
        return Err("ctrl-c: the runtime outlived its interrupted shell".into());
    }

    let mut job = suite.start("parent-exit", &spin, false)?;
    job.wait_stdout("out\n")?;
    let runtime = runtime_pid(&job)?;
    job.kill()?;
    suite.wait(&mut job, -1)?;
    drop(job);
    let reaped = Instant::now();
    while process_active(runtime)? {
        if reaped.elapsed() >= Duration::from_secs(10) {
            return Err("parent-exit: the runtime outlived its reaped shell".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn runtime_pid(job: &Job) -> Result<u64> {
    match job.children()?.as_slice() {
        [(pid, name)] if name.contains("wasmtime") => Ok(*pid),
        other => Err(format!("expected one Wasmtime child, found {other:?}").into()),
    }
}

pub fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--roles"] {
        let result = roles::run();
        let report = match &result {
            Ok(()) => "PASS".to_owned(),
            Err(error) => format!("FAIL: {error}"),
        };
        writeln!(roles::open_log()?, "{report}")?;
        fs::write("/none/wasm-services/roles-result.tmp", report)?;
        fs::rename(
            "/none/wasm-services/roles-result.tmp",
            "/none/wasm-services/roles-result",
        )?;
        return result;
    }
    let mut suite = Suite::new("wasmtime-smoke", "/devtools/wasmtime/sources.txt")?;
    match args.as_slice() {
        [] => run_suite(&mut suite)?,
        [arg] if arg == "--services" => http::services()?,
        _ => return Err("usage: wasmtime-smoke [--services | --roles]".into()),
    }
    suite.finish()
}
