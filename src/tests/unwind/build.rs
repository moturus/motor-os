use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};

fn required(name: &str) -> OsString {
    env::var_os(name)
        .unwrap_or_else(|| panic!("{name} is required when the cxx feature is enabled"))
}

fn run(tool: &OsString, command: &mut Command) -> ExitStatus {
    command
        .status()
        .unwrap_or_else(|error| panic!("failed to run {}: {error}", tool.to_string_lossy()))
}

fn main() {
    println!("cargo:rerun-if-changed=src/cxx.cpp");
    for name in ["MOTOR_TEST_CXX", "MOTOR_TEST_AR", "MOTOR_TEST_CXX_LIB"] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    if env::var_os("CARGO_FEATURE_CXX").is_none() {
        return;
    }

    let cxx = required("MOTOR_TEST_CXX");
    let ar = required("MOTOR_TEST_AR");
    let library_dir = PathBuf::from(required("MOTOR_TEST_CXX_LIB"));
    let output = PathBuf::from(required("OUT_DIR"));
    let object = output.join("cxx.o");
    let archive = output.join("libmotor_unwind_cxx.a");
    let source = PathBuf::from(required("CARGO_MANIFEST_DIR")).join("src/cxx.cpp");

    let status = run(
        &cxx,
        Command::new(&cxx)
            .arg("-std=c++20")
            .arg("-fexceptions")
            .arg("-fPIC")
            .arg("-c")
            .arg(source)
            .arg("-o")
            .arg(&object),
    );
    assert!(status.success(), "cross C++ compilation failed: {status}");
    let status = run(&ar, Command::new(&ar).arg("crs").arg(&archive).arg(&object));
    assert!(status.success(), "cross archive creation failed: {status}");

    println!("cargo:rustc-link-search=native={}", output.display());
    println!("cargo:rustc-link-lib=static=motor_unwind_cxx");
    println!("cargo:rustc-link-search=native={}", library_dir.display());
    for library in ["c++", "c++abi"] {
        println!("cargo:rustc-link-lib=static={library}");
    }
}
