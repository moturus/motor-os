use std::path::Path;
use std::process::Command;

#[test]
#[ignore = "full-native-test.sh --full prepares the pinned Helix sources and dependencies"]
fn native_helix() {
    let checkout = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../external-sources/helix");
    assert!(
        checkout.join("Cargo.toml").is_file(),
        "missing Helix checkout: {}",
        checkout.display()
    );
    let mut command = Command::new(env!("CARGO_BIN_EXE_lorry"));
    command.current_dir(&checkout);
    assert!(
        command
            .args(["vendor", "--locked", "--offline", "--accept-all"])
            .status()
            .unwrap()
            .success()
    );
    let mut command = Command::new(env!("CARGO_BIN_EXE_lorry"));
    command
        .current_dir(&checkout)
        .args(["build", "--locked", "--offline", "-p", "helix-term"]);
    if !cfg!(debug_assertions) {
        command.arg("--release");
    }
    assert!(command.status().unwrap().success());
}
