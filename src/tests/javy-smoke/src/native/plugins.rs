//! Custom plugins built on the host from `plugins/`, initialized here: the p1
//! plugin adds QuickJS intrinsics and globals, the p2 one is a component.

use super::{JavyTools, Result, Suite, TEST_INPUTS, fs};

const JAVY: &str = "MOTOR_OS_CAPS=0x200 /devtools/bin/javy";

/// Initializes `plugin-{name}.wasm` twice, deterministically, into `{name}.wasm`.
fn initialize(suite: &mut Suite, name: &str) -> Result<()> {
    for output in [name.to_string(), format!("{name}-repeat")] {
        suite.command(
            &format!("{output}-initialize"),
            &format!(
                "{JAVY} init-plugin {TEST_INPUTS}/plugin-{name}.wasm --deterministic -o {output}.wasm"
            ),
            0,
        )?;
    }
    suite.same_bytes(&format!("{name}.wasm"), &format!("{name}-repeat.wasm"))
}

pub(super) fn run(suite: &mut Suite) -> Result<()> {
    initialize(suite, "p1")?;
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
    for output in ["p1-program", "p1-program-repeat"] {
        suite.compile(
            output,
            "p1.js",
            &format!("{output}.wasm"),
            "-C deterministic -C plugin=p1.wasm",
        )?;
    }
    suite.same_bytes("p1-program.wasm", "p1-program-repeat.wasm")?;
    suite.execute(
        "p1-program-execute",
        "p1-program.wasm",
        "",
        "{\"greeting\":\"hello from a custom plugin\",\"answer\":42,\"decoded\":\"Motor\",\
         \"exception\":\"AbortError\",\"kind\":\"number\",\"now\":\"number\"}\n",
    )?;

    initialize(suite, "p2")?;
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
