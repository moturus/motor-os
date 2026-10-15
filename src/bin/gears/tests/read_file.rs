#![cfg(unix)]

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn executable_pages_files_and_refuses_gears_state() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tools/read_file");
    let registry = gears::tools::Registry::load(
        &[gears::config::ToolDirectory {
            directory: directory.clone(),
            enabled: true,
        }],
        &directory,
    )
    .unwrap();
    let tool = &registry.tools()[0];
    assert!(tool.read_only);
    assert_eq!(tool.name, "read_file");
    let root = std::env::temp_dir().join(format!("batteries-read-cli-{}", std::process::id()));
    std::fs::create_dir_all(root.join("workspace")).unwrap();
    std::fs::create_dir_all(root.join(".gears")).unwrap();
    std::fs::write(root.join("workspace/source"), "first\nsecond\n").unwrap();
    std::fs::write(root.join(".gears/key"), "secret").unwrap();
    let invoke = |path: &str| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_gears-batteries"))
            .args(["tool", "read_file"])
            .env("HOME", &root)
            .env("GEARS_WORKSPACE", root.join("workspace"))
            .env("GEARS_SESSION_ID", "fixture")
            .env_remove("GEARS_SESSION_PATH")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(serde_json::json!({"path":path}).to_string().as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    };
    let result = invoke("source");
    assert!(result.status.success(), "{result:?}");
    let page: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(page["content"], "1: first\n2: second\n");
    assert_eq!(page["all_pages_read"], true);
    let refused = invoke(root.join(".gears/key").to_str().unwrap());
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&refused.stderr).contains("secret"));
    std::fs::remove_dir_all(root).unwrap();
}
