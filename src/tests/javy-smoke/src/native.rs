use std::fs;

pub(super) use wasm_smoke_suite::{Result, Suite};

mod behavior;
mod runner;

const SUPPORT_DIR: &str = "/devtools/cfg/javy";

/// Javy compilation and Wasmi execution through the installed tools.
trait JavyTools {
    fn compile(&mut self, label: &str, input: &str, output: &str, flags: &str) -> Result<()>;
    fn execute(&mut self, label: &str, module: &str, flags: &str, expected: &str) -> Result<()>;
}

impl JavyTools for Suite {
    fn compile(&mut self, label: &str, input: &str, output: &str, flags: &str) -> Result<()> {
        self.command(
            label,
            &format!("MOTOR_OS_CAPS=0x200 /devtools/bin/javy build {input} -o {output} {flags}"),
            0,
        )?;
        Ok(())
    }

    fn execute(&mut self, label: &str, module: &str, flags: &str, expected: &str) -> Result<()> {
        let (stdout, stderr) = self.command(
            label,
            &format!("MOTOR_OS_CAPS=0 /devtools/bin/wasmi {module} {flags}"),
            0,
        )?;
        if stdout != expected || !stderr.is_empty() {
            return Err(format!("{label}: unexpected output {stdout:?}, stderr {stderr:?}").into());
        }
        Ok(())
    }
}

pub fn run() -> Result<()> {
    let mut suite = Suite::new("javy-smoke", &format!("{SUPPORT_DIR}/sources.txt"))?;
    let (version, _) = suite.command(
        "javy-version",
        "MOTOR_OS_CAPS=0 /devtools/bin/javy --version",
        0,
    )?;
    assert_eq!(version.trim(), "javy 9.1.0");
    suite.command(
        "wasmi-version",
        "MOTOR_OS_CAPS=0 /devtools/bin/wasmi --version",
        0,
    )?;
    suite.refusal(
        "compiler-role-refusal",
        "/devtools/bin/javy build missing.js -o forbidden.wasm",
        "role None",
    )?;
    suite.refusal(
        "runner-role-refusal",
        "/devtools/bin/wasmi missing.wasm",
        "role None",
    )?;
    // The driver can pass its spawn capability; ordinary children do not inherit CAP_LOG.
    suite.refusal(
        "compiler-cap-refusal",
        "MOTOR_OS_CAPS=0x204 /devtools/bin/javy build missing.js -o forbidden.wasm",
        "excess capabilities",
    )?;
    suite.refusal(
        "runner-cap-refusal",
        "MOTOR_OS_CAPS=0x104 /devtools/bin/wasmi missing.wasm",
        "excess capabilities",
    )?;
    fs::write(
        suite.root.join("hello.js"),
        "console.log('hello from Motor', 6 * 7);\n",
    )?;
    suite.compile("hello-static", "hello.js", "hello.wasm", "-C deterministic")?;
    suite.execute("hello-execute", "hello.wasm", "", "hello from Motor 42\n")?;
    suite.compile(
        "hello-explicit-plugin",
        "hello.js",
        "explicit.wasm",
        &format!("-C deterministic -C plugin={SUPPORT_DIR}/plugin.wasm"),
    )?;
    suite.same_bytes("hello.wasm", "explicit.wasm")?;
    suite.compile(
        "hello-repeat",
        "hello.js",
        "repeat.wasm",
        "-C deterministic",
    )?;
    suite.same_bytes("hello.wasm", "repeat.wasm")?;
    suite.command(
        "emit-plugin",
        "MOTOR_OS_CAPS=0x200 /devtools/bin/javy emit-plugin -o emitted.wasm",
        0,
    )?;
    suite.same_bytes("emitted.wasm", &format!("{SUPPORT_DIR}/plugin.wasm"))?;
    suite.compile(
        "hello-dynamic",
        "hello.js",
        "dynamic.wasm",
        "-C dynamic -C plugin=emitted.wasm",
    )?;
    suite.execute(
        "dynamic-execute",
        "dynamic.wasm",
        "--plugin emitted.wasm",
        "hello from Motor 42\n",
    )?;
    suite.command(
        "missing-dynamic-plugin",
        "MOTOR_OS_CAPS=0 /devtools/bin/wasmi dynamic.wasm",
        1,
    )?;
    behavior::run(&mut suite)?;
    suite.compile(
        "typescript",
        &format!("{SUPPORT_DIR}/typescript-workload.js"),
        "typescript.wasm",
        "",
    )?;
    suite.execute("typescript-execute", "typescript.wasm", "", "{\"version\":\"5.9.3\",\"output\":\";\\nconst item = { value: 42 };\\nconsole.log(item.value);\\n\",\"diagnostics\":0}\n")?;
    fs::write(
        suite.root.join("runner.wasm"),
        include_bytes!(concat!(env!("OUT_DIR"), "/runner.wasm")),
    )?;
    for (name, code) in [
        ("_start", 0),
        ("exit-zero", 0),
        ("exit-seven", 7),
        ("trap", 1),
        ("missing", 1),
        ("loop", 1),
    ] {
        suite.command(
            name,
            &format!("MOTOR_OS_CAPS=0 /devtools/bin/wasmi runner.wasm --invoke {name} --fuel 1000"),
            code,
        )?;
    }
    runner::run(&mut suite)?;
    fs::write(suite.root.join("invalid.js"), "function { invalid")?;
    suite.command(
        "syntax-error",
        "MOTOR_OS_CAPS=0x200 /devtools/bin/javy build invalid.js -o invalid.wasm",
        1,
    )?;
    assert!(!suite.root.join("invalid.wasm").exists());
    suite.command(
        "direct-output-denial",
        "MOTOR_OS_CAPS=0 /devtools/bin/javy emit-plugin -o denied.wasm",
        1,
    )?;
    assert!(!suite.root.join("denied.wasm").exists());
    suite.finish()
}
