use super::{Result, SUPPORT_DIR, Suite, fs};

pub(super) fn run(suite: &mut Suite) -> Result<()> {
    fs::write(
        suite.root.join("modern.js"),
        r#"
const values = new Map([['answer', 42]]);
const encoded = new TextEncoder().encode('Motor');
console.log(JSON.stringify({answer: values.get('answer'), text: new TextDecoder().decode(encoded), big: String(2n ** 64n)}));
"#,
    )?;
    suite.compile("modern-js", "modern.js", "modern.wasm", "")?;
    suite.execute(
        "modern-execute",
        "modern.wasm",
        "",
        "{\"answer\":42,\"text\":\"Motor\",\"big\":\"18446744073709551616\"}\n",
    )?;
    fs::write(
        suite.root.join("promise.js"),
        "Promise.resolve(42).then(value => console.log(value));",
    )?;
    suite.compile("promise", "promise.js", "promise.wasm", "-J event-loop=y")?;
    suite.execute("promise-execute", "promise.wasm", "", "42\n")?;
    fs::write(
        suite.root.join("exports.js"),
        "export function answer() { console.log(42); }",
    )?;
    fs::write(
        suite.root.join("exports.wit"),
        "package motor:test; world exports { export answer: func(); }",
    )?;
    suite.compile(
        "wit-export",
        "exports.js",
        "exports.wasm",
        "-C wit=exports.wit -C wit-world=exports",
    )?;
    suite.execute("wit-invoke", "exports.wasm", "--invoke answer", "42\n")?;
    fs::write(
        suite.root.join("throw.js"),
        "throw new Error('expected runtime exception');",
    )?;
    suite.compile("runtime-error-compile", "throw.js", "throw.wasm", "")?;
    suite.refusal(
        "runtime-error",
        "MOTOR_OS_CAPS=0 /devtools/bin/wasmi throw.wasm",
        "expected runtime exception",
    )?;
    suite.command("invalid-config", "MOTOR_OS_CAPS=0x200 /devtools/bin/javy build hello.js -J unknown-option=y -o invalid-config.wasm", 2)?;
    assert!(!suite.root.join("invalid-config.wasm").exists());
    suite.command(
        "plugin-schema",
        "MOTOR_OS_CAPS=0 /devtools/bin/javy build hello.js -J help",
        0,
    )?;
    suite.command("plugin-initialize", &format!("MOTOR_OS_CAPS=0x200 /devtools/bin/javy init-plugin {SUPPORT_DIR}/plugin.wasm --deterministic -o initialized.wasm"), 0)?;
    suite.compile(
        "initialized-plugin",
        "hello.js",
        "initialized-hello.wasm",
        "-C plugin=initialized.wasm",
    )?;
    suite.execute(
        "initialized-plugin-execute",
        "initialized-hello.wasm",
        "",
        "hello from Motor 42\n",
    )?;
    // Malformed plugins are refused before compilation and leave no output.
    fs::write(suite.root.join("not-wasm.wasm"), "not a plugin")?;
    let plugin = fs::read(format!("{SUPPORT_DIR}/plugin.wasm"))?;
    fs::write(
        suite.root.join("truncated.wasm"),
        &plugin[..plugin.len() / 2],
    )?;
    fs::write(
        suite.root.join("no-exports.wasm"),
        include_bytes!(concat!(env!("OUT_DIR"), "/runner.wasm")),
    )?;
    for (name, diagnostic) in [
        ("not-wasm", "Expected Wasm module"),
        ("truncated", "end-of-file"),
        (
            "no-exports",
            "missing export for function named `initialize-runtime`",
        ),
    ] {
        suite.refusal(
            &format!("plugin-{name}"),
            &format!(
                "MOTOR_OS_CAPS=0x200 /devtools/bin/javy build hello.js -C plugin={name}.wasm -o {name}-output.wasm"
            ),
            diagnostic,
        )?;
        assert!(!suite.root.join(format!("{name}-output.wasm")).exists());
    }
    for mode in ["omitted", "uncompressed"] {
        suite.compile(
            &format!("source-{mode}"),
            "hello.js",
            &format!("{mode}.wasm"),
            &format!("-C source={mode}"),
        )?;
        suite.execute(
            &format!("source-{mode}-execute"),
            &format!("{mode}.wasm"),
            "",
            "hello from Motor 42\n",
        )?;
    }
    Ok(())
}
