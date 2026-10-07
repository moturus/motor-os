fn main() {
    println!("cargo:rerun-if-changed=fixtures/runner.wat");
    let bytes = wat::parse_file("fixtures/runner.wat").unwrap();
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(output.join("runner.wasm"), bytes).unwrap();
}
