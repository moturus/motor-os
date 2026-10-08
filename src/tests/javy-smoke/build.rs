fn main() {
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    for name in ["runner", "wasi", "mistyped"] {
        let source = format!("fixtures/{name}.wat");
        println!("cargo:rerun-if-changed={source}");
        let bytes = wat::parse_file(&source).unwrap();
        std::fs::write(output.join(format!("{name}.wasm")), bytes).unwrap();
    }
}
