use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn required_path(name: &str) -> PathBuf {
    let value = env::var_os(name).unwrap_or_else(|| {
        panic!("{name} is required; build through the top-level `make dns-resolver` target")
    });
    let path = PathBuf::from(value);
    assert!(path.exists(), "{name} does not exist: {}", path.display());
    path
}

fn require_file(path: &Path) {
    assert!(
        path.is_file(),
        "required resolver SDK file is missing: {}",
        path.display()
    );
}

fn main() {
    println!("cargo:rerun-if-changed=bridge.c");
    println!("cargo:rerun-if-changed=bridge.h");
    println!("cargo:rerun-if-env-changed=MOTOR_DNS_CLANG");
    println!("cargo:rerun-if-env-changed=MOTOR_DNS_SDK");
    println!("cargo:rerun-if-env-changed=MOTOR_DNS_SYSROOT");

    let clang = required_path("MOTOR_DNS_CLANG");
    let sdk = required_path("MOTOR_DNS_SDK");
    let sysroot = required_path("MOTOR_DNS_SYSROOT");
    let include = sdk.join("include");
    let lib = sdk.join("lib");
    assert!(include.is_dir(), "resolver SDK has no include directory");
    assert!(lib.is_dir(), "resolver SDK has no lib directory");

    let archives = [
        "libmoto_rt_cabi.a",
        "libc++abi.a",
        "libunwind.a",
        "libc.a",
        "libclang_rt.builtins-x86_64.a",
    ];
    for archive in archives {
        require_file(&lib.join(archive));
    }
    require_file(&lib.join("crt1.o"));

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is not set"));
    let object = out_dir.join("motor_dns_bridge.o");
    let status = Command::new(&clang)
        .arg("--no-default-config")
        .arg("--target=x86_64-unknown-motor")
        .arg(format!("--sysroot={}", sysroot.display()))
        .arg("-D_GNU_SOURCE")
        .arg("-fPIC")
        .arg("-ffunction-sections")
        .arg("-fdata-sections")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-isystem")
        .arg(&include)
        .arg("-c")
        .arg("bridge.c")
        .arg("-o")
        .arg(&object)
        .status()
        .expect("failed to execute Motor clang");
    assert!(status.success(), "failed to compile the resolver C bridge");

    // The top-level build opts this Rust+C binary into the Motor clang
    // ToolChain's standard crt1 + mlibc runtime recipe. crt1's strong
    // `motor_start` must own process startup so mlibc is fully initialized.
    println!("cargo:rustc-link-arg={}", object.display());
}
