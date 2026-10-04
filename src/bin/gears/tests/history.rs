#![cfg(unix)]

use std::io::Write;
use std::process::{Command, Stdio};

use gears::mock::{MockServer, sse_response};
use gears::provider::{Message, ToolCall};
use gears::session::Store;

#[test]
fn interactive_resume_displays_history_without_a_provider_request() {
    let root = std::env::temp_dir().join(format!("gears-line-history-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let server = MockServer::start_one(sse_response(&[
        r#"{"choices":[{"index":0,"delta":{"content":"new answer"},"finish_reason":"stop"}]}"#,
    ]))
    .unwrap();
    let config = root.join("gears.toml");
    std::fs::write(&config, format!(
        "version = 1\n[net]\negress_allowlist = ['127.0.0.1']\nplain_http_allowlist = ['127.0.0.1']\n[provider]\nbase_url = '{}'\nmodel = 'test/model'\n", server.url("/v1")
    )).unwrap();
    let store = Store::with_root(&root, root.join(".gears/sessions")).unwrap();
    let mut session = store.create(false, None).unwrap();
    session
        .append_message(&Message::user("saved question\x1b"))
        .unwrap();
    let branch = session
        .append_message(&Message::assistant_response(
            "saved answer".into(),
            vec![ToolCall::new("c1", "sh", "{\"command\":\"pwd\"}")],
        ))
        .unwrap();
    session
        .append_message(&Message::assistant("abandoned answer"))
        .unwrap();
    session.select(&branch).unwrap();
    session
        .append_message(&Message::tool_result("c1", "sh", "saved result", false))
        .unwrap();
    session
        .append_message(&Message::assistant("saved conclusion"))
        .unwrap();
    let id = session.id().to_string();
    drop(session);

    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gears"));
        command
            .env("HOME", &root)
            .env("OPENROUTER_API_KEY", "fixture-key")
            .args(["--ui", "line", "--config"])
            .arg(&config)
            .arg("--workspace")
            .arg(&root);
        command
    };
    for mode in ["resume", "continue", "command"] {
        let mut command = command();
        match mode {
            "resume" => {
                command.arg("--resume").arg(&id);
            }
            "continue" => {
                command.arg("--continue");
            }
            _ => {}
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = if mode == "command" {
            format!("/resume {id}\n/quit\n")
        } else {
            "/quit\n".into()
        };
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let visible = String::from_utf8(output.stdout).unwrap();
        for text in ["saved question", "saved answer", "saved result"] {
            assert!(visible.contains(text), "{mode} missing {text:?}: {visible}");
        }
        assert!(!visible.contains("abandoned answer"));
        assert!(!visible.contains('\x1b'));
        assert!(server.requests().is_empty());
    }

    // Replaying an interactive transcript must not change one-shot output.
    let output = command()
        .arg("--resume")
        .arg(&id)
        .args(["-p", "next question"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"new answer\n");
    assert_eq!(server.requests().len(), 1);
    std::fs::remove_dir_all(root).unwrap();
}
