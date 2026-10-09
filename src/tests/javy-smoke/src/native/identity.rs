use sha2::{Digest, Sha256};

use super::{JavyTools, Result, SUPPORT_DIR, Suite, fs};

/// Each output must equal what Linux Javy 9.1.0 builds from the same inputs
/// and flags; src/build-javy.sh records those digests.
pub(super) fn run(suite: &mut Suite) -> Result<()> {
    let flags = format!("-C deterministic -C plugin={SUPPORT_DIR}/plugin.wasm");
    let mut outputs = Vec::new();
    for mode in ["compressed", "uncompressed", "omitted"] {
        let output = format!("hello-{mode}.wasm");
        let mode_flags = format!("{flags} -C source={mode}");
        suite.compile(&format!("hello-{mode}"), "hello.js", &output, &mode_flags)?;
        outputs.push(output);
    }
    // Brotli's f32 log2 shapes the compressed source of a large input.
    suite.compile(
        "typescript-compressed",
        &format!("{SUPPORT_DIR}/typescript-workload.js"),
        "typescript-compressed.wasm",
        &format!("{flags} -C source=compressed"),
    )?;
    outputs.push("typescript-compressed.wasm".into());

    let reference = fs::read_to_string(format!("{SUPPORT_DIR}/linux-reference.txt"))?;
    let mut listed = Vec::new();
    for line in reference.lines() {
        let (linux, name) = line.split_once("  ").ok_or("malformed Linux reference")?;
        let motor: String = Sha256::digest(fs::read(suite.root.join(name))?)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if motor != linux {
            return Err(format!("{name}: Motor sha256 {motor}, Linux {linux}").into());
        }
        listed.push(name.to_string());
    }
    listed.sort();
    outputs.sort();
    if listed != outputs {
        return Err(format!("Linux reference lists {listed:?}, not {outputs:?}").into());
    }
    println!(
        "linux-identity: {} outputs equal Linux Javy's",
        outputs.len()
    );
    Ok(())
}
