//! Run the executable built with the requested panic profile. Cargo forces
//! its test targets to unwind, even when the selected profile says `abort`.
#[test]
fn selected_profile() {
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_motor-unwind-test"))
        .status()
        .unwrap();
    assert!(status.success(), "unwind suite failed: {status}");
}
