use std::process::{Command, Output, Stdio};

use gears::batteries::memory::{Action, Change};
use gears::batteries::memory_format::{Entry, Target};
use gears::batteries::paths::ToolContext;
use serde_json::Value;

struct Fixture {
    path: std::path::PathBuf,
    context: ToolContext,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("batteries-cli-{label}-{}", std::process::id()));
        std::fs::create_dir_all(path.join("workspace")).unwrap();
        let context = ToolContext::new(
            path.join("workspace"),
            path.join("state"),
            "cli".into(),
            None,
        )
        .unwrap();
        Self { path, context }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_gears-batteries"))
            .args(args)
            .arg("--root")
            .arg(self.context.state.path())
            .arg("--workspace")
            .arg(&self.context.workspace)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap()
    }

    fn json(&self, args: &[&str]) -> Value {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.path).unwrap();
    }
}

fn add(target: Target, id: &str, text: &str) -> Change {
    Change {
        version: 2,
        target,
        action: Action::Add,
        before: None,
        after: Some(Entry {
            id: id.into(),
            date: "2026-10-15".into(),
            session: "cli".into(),
            text: text.into(),
        }),
    }
}

#[test]
fn history_pages_the_log_and_status_describes_the_files() {
    let fixture = Fixture::new("history");
    let first = add(Target::User, "u1", "Prefer small patches.");
    let second = add(Target::Workspace, "w1", "Paths are relative.");
    for (change, yes) in [(&first, true), (&second, true)] {
        gears::batteries::memory::apply(&fixture.context, change).unwrap();
        gears::batteries::memory::log(&fixture.context, change, yes).unwrap();
    }
    gears::batteries::memory::log(
        &fixture.context,
        &add(Target::Global, "g1", "Declined."),
        false,
    )
    .unwrap();
    let page = fixture.json(&["history", "--limit", "2"]);
    assert_eq!(page["total"], 3);
    assert_eq!(page["unreadable"], 0);
    assert_eq!(page["next_offset"], 2);
    assert_eq!(page["records"][1]["id"], "w1");
    let rest = fixture.json(&["history", "--offset", "2"]);
    assert_eq!(rest["records"][0]["decision"], "no");
    assert!(rest["next_offset"].is_null());
    let status = fixture.json(&["status"]);
    assert_eq!(status["offer_lessons"], false);
    assert_eq!(
        status["entries"],
        serde_json::json!({"user": 1, "global": 0, "workspace": 1})
    );
    assert_eq!(
        status["decisions"],
        serde_json::json!({"yes": 2, "no": 1, "unreadable": 0})
    );
    assert_eq!(status["skills"], serde_json::json!([]));
    use std::io::Write;
    let log = fixture
        .context
        .state
        .file(std::path::Path::new("batteries/changes.jsonl"))
        .unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(log)
        .unwrap()
        .write_all(b"{broken}\n")
        .unwrap();
    assert_eq!(fixture.json(&["history"])["unreadable"], 1);
    assert_eq!(fixture.json(&["status"])["decisions"]["unreadable"], 1);
}

#[test]
fn removed_commands_and_bad_options_fail_without_output() {
    let fixture = Fixture::new("usage");
    for args in [
        vec!["pending"],
        vec!["cleanup", "--since", "2026-01-01"],
        vec!["review"],
        vec!["eval"],
        vec!["history", "--limit", "0"],
        vec!["status", "--offset", "1"],
    ] {
        let output = fixture.run(&args);
        assert!(!output.status.success(), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(!output.stderr.is_empty(), "{args:?}");
    }
}
