fn main() {
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(
        output.join("generated.rs"),
        "pub const BUILD_VALUE: &str = \"build-script\";\n",
    )
    .unwrap();
    println!("cargo:rerun-if-changed=build.rs");
}
