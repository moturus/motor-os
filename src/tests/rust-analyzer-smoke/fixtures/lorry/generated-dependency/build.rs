fn main() {
    let out = std::env::var_os("OUT_DIR").unwrap();
    std::fs::write(
        std::path::Path::new(&out).join("generated.rs"),
        "pub const GENERATED: u32 = 42;\n",
    )
    .unwrap();
    println!("cargo:rustc-check-cfg=cfg(generated_fixture)");
    println!("cargo:rustc-cfg=generated_fixture");
    println!("cargo:rustc-env=GENERATED_ENV=from-build-script");
}
