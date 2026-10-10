//! Custom plugins built on the host from `plugins/`, initialized here: the p1
//! plugin adds QuickJS intrinsics and globals, the p2 one is a component.

use super::{JavyTools, Result, Suite, TEST_INPUTS, fs};

const JAVY: &str = "MOTOR_OS_CAPS=0x200 /devtools/bin/javy";

/// Initializes `plugin-{name}.wasm` deterministically into `{output}.wasm`.
fn initialize(suite: &mut Suite, name: &str, output: &str) -> Result<()> {
    suite.command(
        &format!("{output}-initialize"),
        &format!(
            "{JAVY} init-plugin {TEST_INPUTS}/plugin-{name}.wasm --deterministic -o {output}.wasm"
        ),
        0,
    )?;
    Ok(())
}

/// Initializes `{name}.wasm`; with `repeat`, a second time to the same bytes.
fn initialize_checked(suite: &mut Suite, name: &str, repeat: bool) -> Result<()> {
    initialize(suite, name, name)?;
    if repeat {
        let again = format!("{name}-repeat");
        initialize(suite, name, &again)?;
        suite.same_bytes(&format!("{name}.wasm"), &format!("{again}.wasm"))?;
    }
    Ok(())
}

fn compile_p1(suite: &mut Suite, output: &str) -> Result<()> {
    suite.compile(
        output,
        "p1.js",
        &format!("{output}.wasm"),
        "-C deterministic -C plugin=p1.wasm",
    )
}

pub(super) fn run(suite: &mut Suite, repeat: bool) -> Result<()> {
    initialize_checked(suite, "p1", repeat)?;
    let (stdout, _) = suite.command(
        "p1-schema",
        "MOTOR_OS_CAPS=0 /devtools/bin/javy build hello.js -J help -C plugin=p1.wasm",
        0,
    )?;
    if !stdout.contains("-J  event-loop") {
        return Err(format!("p1-schema: no event-loop option in {stdout:?}").into());
    }
    fs::write(
        suite.root.join("p1.js"),
        r#"
const target = {answer: motorAnswer()};
const ref = new WeakRef(target);
gc();
console.log(JSON.stringify({
  greeting: motorGreeting,
  answer: ref.deref().answer,
  decoded: atob('TW90b3I='),
  exception: new DOMException('stop', 'AbortError').name,
  kind: typeof qjs.getStringKind('Motor'),
  now: typeof performance.now(),
}));
"#,
    )?;
    compile_p1(suite, "p1-program")?;
    if repeat {
        compile_p1(suite, "p1-program-repeat")?;
        suite.same_bytes("p1-program.wasm", "p1-program-repeat.wasm")?;
    }
    suite.execute(
        "p1-program-execute",
        "p1-program.wasm",
        "",
        "{\"greeting\":\"hello from a custom plugin\",\"answer\":42,\"decoded\":\"Motor\",\
         \"exception\":\"AbortError\",\"kind\":\"number\",\"now\":\"number\"}\n",
    )?;

    initialize_checked(suite, "p2", repeat)?;
    fs::write(
        suite.root.join("p2.js"),
        "if (motorAnswer() !== 42 || motorGreeting !== 'hello from a custom plugin') {\n\
         throw new Error('wrong custom globals');\n}\n",
    )?;
    suite.compile(
        "p2-program",
        "p2.js",
        "p2-program.wasm",
        "-C plugin=p2.wasm",
    )?;
    suite.execute("p2-program-execute", "p2-program.wasm", "", "")
}
