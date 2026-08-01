//! Confinement, checked the way an agent would hit it: every tool, by name,
//! with JSON arguments, against a workspace that has symlinks pointing out of
//! it and an API key file sitting inside it.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use gears::tools::{Registry, ToolResult, Workspace, fs};
use serde_json::{Value, json};

const KEY: &str = "sk-fake-key-the-model-must-not-see";

struct Fixture {
    base: PathBuf,
    root: PathBuf,
    outside: PathBuf,
    registry: Registry,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let base = std::env::temp_dir().join(format!("gears-tools-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("work");
        let outside = base.join("outside");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
        std::fs::write(outside.join("secret.txt"), "top secret\n").unwrap();
        let key = root.join("openrouter.key");
        std::fs::write(&key, format!("{KEY}\n")).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
            std::os::unix::fs::symlink(outside.join("secret.txt"), root.join("secret-link"))
                .unwrap();
        }

        let workspace = Arc::new(Workspace::new(&root).unwrap().deny(&key));
        let mut registry = Registry::new();
        for tool in fs::tools(workspace) {
            registry.register(tool);
        }
        Fixture {
            root: root.canonicalize().unwrap(),
            outside: outside.canonicalize().unwrap(),
            base,
            registry,
        }
    }

    fn call(&self, tool: &str, args: Value) -> ToolResult {
        self.registry.dispatch(tool, &args.to_string())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// Ways out of the workspace: upwards, absolute, and — the ones a lexical
/// check alone would miss — through symlinks, including to a file that does
/// not exist yet.
fn escapes(outside: &Path) -> Vec<String> {
    let mut paths = vec![
        "..".to_string(),
        "../outside/secret.txt".to_string(),
        "/etc".to_string(),
        outside.join("secret.txt").display().to_string(),
    ];
    if cfg!(unix) {
        paths.extend([
            "escape".to_string(),
            "escape/secret.txt".to_string(),
            "secret-link".to_string(),
            "escape/planted.txt".to_string(),
        ]);
    }
    paths
}

fn refused(out: &ToolResult) -> bool {
    out.is_error
        && (out.content.contains("outside the workspace")
            || out.content.contains("'..'")
            || out.content.contains("off limits"))
}

#[test]
fn nothing_outside_the_workspace_is_readable() {
    let fixture = Fixture::new("read");
    for path in escapes(&fixture.outside) {
        for (tool, args) in [
            ("read_file", json!({ "path": path })),
            ("list_dir", json!({ "path": path })),
            ("grep", json!({"pattern": "secret", "path": path})),
        ] {
            let out = fixture.call(tool, args);
            assert!(refused(&out), "{tool} '{path}': {out:?}");
            assert!(
                !out.content.contains("top secret"),
                "{tool} '{path}' leaked"
            );
        }
    }
}

#[test]
fn nothing_outside_the_workspace_is_writable() {
    let fixture = Fixture::new("write");
    for path in escapes(&fixture.outside) {
        for (tool, args) in [
            ("write_file", json!({"path": path, "content": "planted"})),
            (
                "edit_file",
                json!({"path": path, "old": "top", "new": "no"}),
            ),
        ] {
            let out = fixture.call(tool, args);
            assert!(refused(&out), "{tool} '{path}': {out:?}");
        }
    }
    assert_eq!(
        std::fs::read_to_string(fixture.outside.join("secret.txt")).unwrap(),
        "top secret\n"
    );
    assert!(!fixture.outside.join("planted.txt").exists());
}

/// The other half of step 2's redaction guarantee: the key gears sends is
/// also a file the agent is standing next to.
#[test]
fn the_agent_cannot_reach_its_own_key() {
    let fixture = Fixture::new("key");
    let out = fixture.call("read_file", json!({"path": "openrouter.key"}));
    assert!(refused(&out), "{out:?}");

    // Nor by searching for it: the deny list has to hold for a tool that
    // walks the tree itself, not just for one that resolves a given path.
    for args in [
        json!({"pattern": "sk-"}),
        json!({"pattern": "sk-", "include": "*.key"}),
    ] {
        let out = fixture.call("grep", args);
        assert!(!out.content.contains(KEY), "{out:?}");
    }

    let out = fixture.call(
        "write_file",
        json!({"path": "openrouter.key", "content": "x"}),
    );
    assert!(refused(&out), "{out:?}");
    assert!(
        std::fs::read_to_string(fixture.root.join("openrouter.key"))
            .unwrap()
            .contains(KEY)
    );
}

/// The control: with the same fixture, ordinary work inside the workspace
/// goes through — so the refusals above are not refusing everything.
#[test]
fn the_tools_do_work_inside_the_workspace() {
    let fixture = Fixture::new("inside");
    assert_eq!(
        fixture
            .call("read_file", json!({"path": "src/main.rs"}))
            .content,
        "fn main() {}\n"
    );
    for (tool, args) in [
        (
            "write_file",
            json!({"path": "src/lib.rs", "content": "pub fn f() {}\n"}),
        ),
        (
            "edit_file",
            json!({"path": "src/lib.rs", "old": "pub fn f", "new": "pub fn g"}),
        ),
    ] {
        let out = fixture.call(tool, args);
        assert!(!out.is_error, "{tool}: {out:?}");
    }
    let out = fixture.call("grep", json!({"pattern": "pub fn g"}));
    assert_eq!(out.content, "src/lib.rs:1:pub fn g() {}");
}
