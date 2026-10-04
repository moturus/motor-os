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
        &lorry(&[
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
    let output = lorry(&[
        "metadata",
        "--no-deps",
        "--format-version=1",
        "--lorry-messages",
        "--manifest-path",
        path.to_str().unwrap(),
    ]);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let metadata: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(metadata["version"], 1);
    assert!(metadata.get("reason").is_none());
}
