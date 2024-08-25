fn build_bootup_bsp(out_dir: &str) {
    use std::process::Command;

    println!("cargo:rerun-if-changed=src/bootup_bsp.s");

    let status = Command::new("as")
        .arg("-o")
        .arg(format!("{}/libbsp.a", out_dir))
        .arg("src/bootup_bsp.s")
        .status()
        .expect("failed to run as");
    if !status.success() {
        panic!("as failed with exit status {}", status);
    }

    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static:+verbatim=libbsp.a");
}

fn build_bootup_ap(out_dir: &str) {
    use std::process::Command;

    println!("cargo:rerun-if-changed=src/bootup_ap.s");

    let status = Command::new("nasm")
        .arg("-f")
        .arg("bin")
        .arg("-o")
        .arg(format!("{}/bootup_ap", out_dir))
        .arg("src/bootup_ap.s")
        .status()
        .expect("failed to run nasm");
    if !status.success() {
        panic!("nasm failed with exit status {}", status);
    }
}

fn main() {
    println!("cargo:rerun-if-changed=src/bootup_bsp.s");
    println!("cargo:rerun-if-changed=kloader.json");
    println!("cargo:rerun-if-changed=layout.ld");

    let out_dir = std::env::var("OUT_DIR").unwrap();

    build_bootup_bsp(&out_dir);
    build_bootup_ap(&out_dir);
}
