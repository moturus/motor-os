#[path = "src/inputs.rs"]
#[allow(dead_code)]
mod inputs;
fn main() {
    println!("cargo:rerun-if-changed=src/inputs.rs");
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    for (name, source) in [
        ("runner", inputs::RUNNER),
        ("wasi", inputs::WASI),
        ("mistyped", inputs::MISTYPED),
        ("backing", inputs::BACKING),
    ] {
        let bytes = wat::parse_str(source).unwrap();
        std::fs::write(output.join(format!("{name}.wasm")), bytes).unwrap();
    }
}
