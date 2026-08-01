//! End-to-end smoke tests over the built binary.

use std::process::Command;

fn gears() -> Command {
    Command::new(env!("CARGO_BIN_EXE_gears"))
}

#[test]
fn version_prints_and_exits_zero() {
    let out = gears().arg("--version").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.starts_with("gears "), "{stdout}");
}

#[test]
fn help_prints_usage() {
    let out = gears().arg("--help").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("Usage: gears"), "{stdout}");
}

#[test]
fn unknown_flag_exits_two() {
    let out = gears().arg("--frobnicate").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("--frobnicate"), "{stderr}");
}

#[test]
fn missing_explicit_config_is_reported() {
    let path = std::env::temp_dir().join(format!("gears-smoke-none-{}.toml", std::process::id()));
    let out = gears().arg("--config").arg(&path).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("config:"), "{stderr}");
    assert!(stderr.contains(path.to_str().unwrap()), "{stderr}");
}

#[test]
fn log_file_flag_starts_the_tracer() {
    let path = std::env::temp_dir().join(format!("gears-smoke-log-{}.log", std::process::id()));
    let out = gears().arg("--log-file").arg(&path).output().unwrap();
    assert_eq!(out.status.code(), Some(1)); // still the not-implemented exit
    let log = std::fs::read_to_string(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(log.contains("INFO] gears "), "{log}");
    assert!(log.contains("starting"), "{log}");
}

#[test]
fn valid_explicit_config_loads() {
    let path = std::env::temp_dir().join(format!("gears-smoke-cfg-{}.toml", std::process::id()));
    std::fs::write(&path, "version = 1\n").unwrap();
    let out = gears().arg("--config").arg(&path).output().unwrap();
    std::fs::remove_file(&path).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    // Config accepted; only the not-yet-implemented notice remains.
    assert!(!stderr.contains("config:"), "{stderr}");
    assert!(stderr.contains("not implemented"), "{stderr}");
}
