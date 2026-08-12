use std::path::PathBuf;

fn parse_version(contents: &str, prefix: &str, suffix: char) -> u64 {
    let value = contents
        .lines()
        .find_map(|line| line.trim().strip_prefix(prefix))
        .unwrap_or_else(|| panic!("missing version declaration starting with {prefix:?}"));
    value
        .trim()
        .strip_suffix(suffix)
        .unwrap_or_else(|| panic!("version declaration {value:?} has no {suffix:?} suffix"))
        .parse()
        .unwrap_or_else(|_| panic!("version declaration {value:?} is not an integer"))
}

fn main() {
    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let header = manifest_dir.join("moto_rt.h");
    let rust_source = manifest_dir.join("../moto-rt/src/lib.rs");

    println!("cargo:rerun-if-changed={}", header.display());
    println!("cargo:rerun-if-changed={}", rust_source.display());

    let header_source = std::fs::read_to_string(&header).unwrap();
    let rust_source = std::fs::read_to_string(&rust_source).unwrap();
    let header_version = parse_version(&header_source, "#define MOTO_RT_VERSION ", 'u');
    let rust_version = parse_version(&rust_source, "pub const RT_VERSION: u64 = ", ';');

    assert_eq!(
        header_version, rust_version,
        "MOTO_RT_VERSION in moto_rt.h must match moto_rt::RT_VERSION"
    );
}
