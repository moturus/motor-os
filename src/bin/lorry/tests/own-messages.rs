use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn lorry(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lorry"))
        .args(arguments)
        .output()
        .unwrap()
}

fn error_message(output: &Output, code: i32) -> Value {
    assert_eq!(output.status.code(), Some(code));
    assert!(output.stdout.is_empty());
    let value: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(value["reason"], "lorry-error");
    assert_eq!(value["exit_code"], code);
    value
}

#[test]
fn parse_errors_use_json_only_when_the_option_is_requested() {
    let human = lorry(&["unknown-command"]);
    assert_eq!(human.status.code(), Some(1));
    assert!(human.stderr.starts_with(b"error: unknown command"));
    for arguments in [
        ["--lorry-messages", "unknown-command"],
        ["unknown-command", "--lorry-messages"],
    ] {
        let value = error_message(&lorry(&arguments), 1);
        assert_eq!(value["kind"], "usage");
        assert!(value["file"].is_null());
        assert!(value["line"].is_null());
        assert!(value["help"].is_string());
    }
    let child_option = lorry(&["unknown-command", "--", "--lorry-messages"]);
    assert!(child_option.stderr.starts_with(b"error:"));
}

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "lorry-own-messages-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
        Self(root)
    }

    fn lorry(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_lorry"))
            .args(arguments)
            .env("HOME", &self.0)
            .env("CARGO_HOME", self.0.join("cargo-home"))
            .current_dir(&self.0)
            .output()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn manifest_errors_have_structured_locations_and_preserve_stdout() {
    let fixture = Fixture::new();
    let path = fixture.0.join("Cargo.toml");
    fs::write(&path, "[package\n").unwrap();
    let value = error_message(
        &fixture.lorry(&[
            "metadata",
            "--no-deps",
            "--lorry-messages",
            "--manifest-path",
            path.to_str().unwrap(),
        ]),
        101,
    );
    assert_eq!(value["kind"], "failure");
    assert_eq!(value["file"], path.to_str().unwrap());
    assert_eq!(value["line"], 1);
    assert!(!value["text"].as_str().unwrap().contains("\n  -->"));

    fs::write(
        &path,
        "[package]\nname = \"own-messages\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    let output = fixture.lorry(&[
        "metadata",
        "--no-deps",
        "--format-version=1",
        "--lorry-messages",
        "--manifest-path",
        path.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let metadata: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(metadata["version"], 1);
    assert!(metadata.get("reason").is_none());
}

#[cfg(target_os = "linux")]
#[test]
fn an_interrupted_compiler_query_finishes_the_cargo_stream_unsuccessfully() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    fs::write(
        fixture.0.join("Cargo.toml"),
        "[package]\nname = \"interrupted\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    let rustc = fixture.0.join("rustc-interrupted");
    fs::write(
        fixture.0.join("Cargo.lock"),
        "version = 4\n[[package]]\nname = \"interrupted\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::write(&rustc, "#!/bin/sh\nexit 130\n").unwrap();
    fs::set_permissions(&rustc, fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_lorry"))
        .args([
            "build",
            "--quiet",
            "--lorry-messages",
            "--message-format=json",
        ])
        .env("RUSTC", rustc)
        .env("HOME", &fixture.0)
        .current_dir(&fixture.0)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(130),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["kind"], "interrupted");
    assert_eq!(error["exit_code"], 130);
    let finished: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(finished["reason"], "build-finished");
    assert_eq!(finished["success"], false);

    // A successful version query must not let target-query context turn an
    // interruption into an ordinary unsupported-target failure.
    fs::write(fixture.0.join("rustc-interrupted"), "#!/bin/sh\nif [ \"$1\" = --version ]; then\n  printf 'release: 1.99.0\\nhost: x86_64-unknown-linux-gnu\\n'\n  exit 0\nfi\nexit 130\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_lorry"))
        .args([
            "build",
            "--quiet",
            "--lorry-messages",
            "--message-format=json",
        ])
        .env("RUSTC", fixture.0.join("rustc-interrupted"))
        .env("HOME", &fixture.0)
        .current_dir(&fixture.0)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(130),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["kind"], "interrupted");
    assert!(error["help"].is_null());
    let finished: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(finished["success"], false);
}

#[cfg(target_os = "linux")]
#[test]
fn a_full_output_device_is_an_error_not_an_abort() {
    let full = || {
        fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap()
    };
    let stdout = Command::new(env!("CARGO_BIN_EXE_lorry"))
        .arg("--version")
        .stdout(full())
        .output()
        .unwrap();
    assert_eq!(stdout.status.code(), Some(101));
    let stderr = String::from_utf8(stdout.stderr).unwrap();
    assert!(
        stderr.starts_with("error: failed to write to stdout:"),
        "{stderr}"
    );
    let stderr = Command::new(env!("CARGO_BIN_EXE_lorry"))
        .arg("unknown-command")
        .stderr(full())
        .status()
        .unwrap();
    assert_eq!(stderr.code(), Some(101));
}
