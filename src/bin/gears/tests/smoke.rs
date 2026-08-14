//! End-to-end smoke tests over the built binary: the things every run does
//! before it does anything interesting.

use std::path::PathBuf;
use std::process::Command;

fn gears() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gears"));
    // Hermetic on purpose: with the developer's own key in the environment, a
    // bare `gears` would open a session and sit waiting for a prompt instead
    // of exiting, and this file would hang rather than fail.
    command.env_remove("OPENROUTER_API_KEY");
    command
}

fn temp(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("gears-smoke-{name}-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

/// A valid config that cannot reach the network: the key file it names is not
/// there, so every run using it stops at the same, obvious place.
fn keyless_config(name: &str) -> PathBuf {
    let key = temp(&format!("{name}-absent.key"));
    let path = temp(&format!("{name}.toml"));
    std::fs::write(
        &path,
        format!(
            "version = 1\n[provider]\nmodel = \"test/model\"\nkey_file = \"{}\"\n",
            key.display()
        ),
    )
    .unwrap();
    path
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
    let path = temp("none.toml");
    let out = gears().arg("--config").arg(&path).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("config:"), "{stderr}");
    assert!(stderr.contains(path.to_str().unwrap()), "{stderr}");
}

#[test]
fn log_file_flag_starts_the_tracer() {
    let config = keyless_config("log");
    let path = temp("log.log");
    let out = gears()
        .args(["--config".as_ref(), config.as_os_str()])
        .arg("--log-file")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let log = std::fs::read_to_string(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_file(&config).unwrap();
    assert!(log.contains("INFO] gears "), "{log}");
    assert!(log.contains("starting"), "{log}");
}

/// The config is accepted, and the run gets as far as looking for the key —
/// which is the first thing after it that can fail.
#[test]
fn a_valid_config_loads_and_the_run_reaches_the_key() {
    let config = keyless_config("cfg");
    let out = gears().arg("--config").arg(&config).output().unwrap();
    std::fs::remove_file(&config).unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(!stderr.contains("config:"), "{stderr}");
    assert!(stderr.contains("absent.key"), "{stderr}");
}

#[test]
fn invalid_resources_fail_before_session_or_artifact_state_is_opened() {
    let config = temp("bad-resources.toml");
    let workspace = temp("bad-resources-workspace");
    std::fs::write(
        &config,
        "version = 1\n[resources]\nmax_artifact_bytes = 2\nmax_session_artifact_bytes = 1\n",
    )
    .unwrap();
    std::fs::create_dir(&workspace).unwrap();

    let out = gears()
        .arg("--config")
        .arg(&config)
        .arg("--workspace")
        .arg(&workspace)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("max_artifact_bytes"), "{stderr}");
    assert!(!workspace.join(".gears").exists());

    std::fs::remove_file(config).unwrap();
    std::fs::remove_dir(workspace).unwrap();
}
