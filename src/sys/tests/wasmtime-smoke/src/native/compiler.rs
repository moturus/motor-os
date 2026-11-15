//! Native compilation and direct loading through the installed CLIs.
use super::{COMPILER, FIXTURES, RUNTIME, Result, Suite, TYPESCRIPT_OUTPUT, expect};

pub(super) fn run(suite: &mut Suite) -> Result<()> {
    let (help, _) = suite.command("full-help", &format!("{COMPILER} --help"), 0)?;
    if !help.contains("compile") || !help.contains("serve") {
        return Err("full CLI help is missing commands".into());
    }
    let (out, err) = suite.command(
        "native-raw-run",
        &format!("MOTOR_OS_CAPS=0 {COMPILER} run {FIXTURES}/lifecycle.wat"),
        0,
    )?;
    expect("native stdout", &out, "out\n")?;
    expect("native stderr", &err, "err\n")?;
    suite.command(
        "native-compile",
        &format!("MOTOR_OS_CAPS=0x200 {COMPILER} compile {FIXTURES}/lifecycle.wat -o native.cwasm"),
        0,
    )?;
    for (name, tool) in [("full", COMPILER), ("runtime", RUNTIME)] {
        let (out, err) = suite.command(
            &format!("native-load-{name}"),
            &format!("MOTOR_OS_CAPS=0 {tool} run --allow-precompiled native.cwasm"),
            0,
        )?;
        expect("loaded stdout", &out, "out\n")?;
        expect("loaded stderr", &err, "err\n")?;
    }
    suite.refusal(
        "runtime-no-compiler",
        &format!("MOTOR_OS_CAPS=0 {RUNTIME} run {FIXTURES}/typescript.wasm"),
        "compiling modules was disabled",
    )?;
    let (out, _) = suite.command(
        "native-typescript-raw",
        &format!("MOTOR_OS_CAPS=0 {COMPILER} run {FIXTURES}/typescript.wasm"),
        0,
    )?;
    expect("native TypeScript", &out, TYPESCRIPT_OUTPUT)?;
    let (out, _) = suite.command(
        "native-p3-raw",
        &format!("MOTOR_OS_CAPS=0 {COMPILER} run {FIXTURES}/p3_cli_hello_stdout.wasm"),
        0,
    )?;
    expect("native p3", &out, "hello, world\n")?;
    let (out, err) = suite.command(
        "pulley-raw-run",
        &format!("MOTOR_OS_CAPS=0 {COMPILER} run --target pulley64 {FIXTURES}/lifecycle.wat"),
        0,
    )?;
    expect("Pulley stdout", &out, "out\n")?;
    expect("Pulley stderr", &err, "err\n")
}
