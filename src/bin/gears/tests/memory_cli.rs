use std::io::Write;
use std::process::{Command, Output, Stdio};

use gears::batteries::memory_format::{Document, Entry, Target};
use gears::batteries::paths::ToolContext;
use gears::batteries::pending::Proposal;
use serde_json::{Value, json};

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

    fn run(&self, args: &[&str], input: &[u8]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_gears-batteries"))
            .args(args)
            .arg("--root")
            .arg(self.context.state.path())
            .arg("--workspace")
            .arg(&self.context.workspace)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    }

    fn success(&self, args: &[&str], input: &[u8]) -> String {
        let output = self.run(args, input);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn history(&self, args: &[&str]) -> Value {
        serde_json::from_str(&self.success(args, b"")).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.path).unwrap();
    }
}

fn entry(target: Target, text: &str) -> Entry {
    serde_json::from_value(
        json!({"metadata": {"id": "preference", "kind": "user", "scope": target.scope(),
        "source": {"session": "source", "entries": ["evidence"]}, "date_ms": 1}, "text": text}),
    )
    .unwrap()
}

#[test]
fn the_binary_reviews_postponed_changes_and_refuses_stale_approvals_without_logging_them() {
    let fixture = Fixture::new("pending");
    let entry = entry(Target::User, "Prefer Rust.");
    let mut proposal = Proposal {
        version: 1,
        target: Target::User,
        before: None,
        after: Some(entry.clone()),
        source: entry.metadata.source.clone(),
        date_ms: 2,
    };
    let id = gears::batteries::memory::propose(&fixture.context, &proposal)
        .unwrap()
        .unwrap();
    let listing = fixture.success(&["pending", "--list"], b"approve\n");
    for expected in [
        &id,
        "Prefer Rust.",
        "evidence",
        "sessions_with_old_snapshot",
        "list_only",
    ] {
        assert!(listing.contains(expected), "{listing}");
    }
    assert!(
        gears::batteries::memory::load(&fixture.context, Target::User)
            .unwrap()
            .entries
            .is_empty()
    );
    assert!(fixture.success(&["pending"], b"").contains("postpone"));
    fixture.success(&["pending", "--postpone", &id], b"");
    let invalid = fixture.run(&["pending"], b"yes\n");
    assert!(!invalid.status.success());
    assert!(
        String::from_utf8(invalid.stderr)
            .unwrap()
            .contains("item remains pending")
    );
    assert_eq!(fixture.history(&["history"])["total"], 0);
    fixture.success(&["pending"], b"approve\n");
    assert_eq!(
        gears::batteries::memory::load(&fixture.context, Target::User)
            .unwrap()
            .entries
            .as_slice(),
        std::slice::from_ref(&entry)
    );
    let status: Value = serde_json::from_str(&fixture.success(&["status"], b"")).unwrap();
    assert_eq!(status["pending_global"]["count"], 0);
    assert_eq!(status["reviews"], "experimental");
    proposal.before = Some(entry);
    proposal.after.as_mut().unwrap().text = "Prefer native Rust.".into();
    let stale = gears::batteries::memory::propose(&fixture.context, &proposal)
        .unwrap()
        .unwrap();
    fixture
        .context
        .state
        .replace_file(Target::User.relative(), b"# Gears memory v1\n")
        .unwrap();
    let failed = fixture.run(&["pending", "--approve", &stale], b"");
    assert!(!failed.status.success());
    assert!(
        String::from_utf8(failed.stderr)
            .unwrap()
            .contains("removed since")
    );
    assert_eq!(fixture.history(&["history"])["total"], 1);
    assert_eq!(
        gears::batteries::pending::list(&fixture.context, Target::User)
            .unwrap()
            .len(),
        1
    );
    fixture.success(&["pending", "--deny", &stale], b"");
    let page = fixture.history(&["history", "--offset", "1", "--limit", "1"]);
    assert_eq!(page["total"], 2);
    assert_eq!(page["records"][0]["decision"], "deny");
    assert!(page["next_offset"].is_null());
}

#[test]
fn imported_workspace_approval_is_bound_to_the_bytes_listed_by_the_binary() {
    let fixture = Fixture::new("import");
    let root = gears::state::StateRoot::new(fixture.context.workspace.clone()).unwrap();
    let mut document = Document {
        entries: vec![entry(Target::Workspace, "This project uses Rust.")],
    };
    let bytes = document.encode(Target::Workspace, 2200).unwrap();
    root.replace_file(Target::Workspace.relative(), bytes.as_bytes())
        .unwrap();
    let (hash, _) = gears::batteries::workspace_memory::current(&fixture.context)
        .unwrap()
        .unwrap();
    assert!(fixture.success(&["pending", "--list"], b"").contains(&hash));
    assert!(!gears::batteries::workspace_memory::approved(&fixture.context, &hash).unwrap());
    fixture.success(&["pending", "--approve", &hash], b"");
    assert!(gears::batteries::workspace_memory::approved(&fixture.context, &hash).unwrap());
    assert_eq!(fixture.history(&["history"])["records"][0]["memory"], bytes);
    document.entries[0].text = "This project also uses C.".into();
    root.replace_file(
        Target::Workspace.relative(),
        document.encode(Target::Workspace, 2200).unwrap().as_bytes(),
    )
    .unwrap();
    assert!(
        !fixture
            .run(&["pending", "--approve", &hash], b"")
            .status
            .success()
    );
    assert_eq!(fixture.history(&["history"])["total"], 1);
    let status: Value = serde_json::from_str(&fixture.success(&["status"], b"")).unwrap();
    assert_eq!(status["workspace_memory"]["approved"], false);
}

#[test]
fn status_reports_model_pairs_and_invalid_optional_configuration() {
    let fixture = Fixture::new("review-status");
    let settings = std::path::Path::new("batteries.toml");
    fixture.context.state.replace_file(settings, b"version=1\n[reviews]\nenabled=true\nmax_proposals=2\n[reviews.executor]\nprovider='local'\nmodel='executor'\n[reviews.reviewer]\nprovider='openrouter'\nmodel='vendor/reviewer'\n").unwrap();
    let status = fixture.history(&["status"]);
    assert_eq!(status["reviews"], "experimental");
    assert_eq!(status["review_settings"]["enabled"], true);
    assert_eq!(status["review_settings"]["max_proposals"], 2);
    assert_eq!(status["review_settings"]["executor"]["provider"], "local");
    assert_eq!(
        status["review_settings"]["reviewer"]["model"],
        "vendor/reviewer"
    );
    fixture
        .context
        .state
        .replace_file(settings, b"version=2")
        .unwrap();
    let status = fixture.history(&["status"]);
    assert!(
        status["review_settings"]["unavailable"]
            .as_str()
            .unwrap()
            .contains("unsupported")
    );
    assert_eq!(status["pending_global"]["count"], 0);
}
