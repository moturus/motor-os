#![cfg(unix)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use gears::mock::{MockServer, sse_response};

fn fixture(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("gears-smoke-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn config(root: &Path, server: &MockServer) -> PathBuf {
    let path = root.join("gears.toml");
    std::fs::write(
        &path,
        format!(
            r#"version = 1
[net]
egress_allowlist = ["127.0.0.1"]
plain_http_allowlist = ["127.0.0.1"]
[provider]
base_url = "{}"
model = "test/model"
"#,
            server.url("/v1")
        ),
    )
    .unwrap();
    path
}

fn gears(root: &Path, workspace: &Path, config: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gears"));
    command
        .env("HOME", root)
        .env("OPENROUTER_API_KEY", "test-key")
        .args(["--ui", "line", "--ephemeral", "--config"])
        .arg(config)
        .arg("--workspace")
        .arg(workspace);
    command
}

#[test]
fn reset_asks_then_keeps_only_the_installation() {
    let root = fixture("reset");
    let workspace = root.join("workspace");
    for directory in [
        ".gears/tools/sh",
        ".gears/sessions/group",
        "workspace/.gears",
    ] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    for file in [
        ".gears/gears.toml",
        ".gears/openrouter.key",
        "workspace/.gears/MEMORY.md",
    ] {
        std::fs::write(root.join(file), "x").unwrap();
    }
    let reset = |answer: &[u8]| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_gears"))
            .arg("reset")
            .current_dir(&workspace)
            .env("HOME", &root)
            .env_remove(gears::directory::ENV)
            .env_remove("GEARS_LOCK_OWNER")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(answer).unwrap();
        child.wait_with_output().unwrap()
    };
    let declined = reset(b"no\n");
    assert!(!declined.status.success());
    assert!(String::from_utf8_lossy(&declined.stdout).contains("Reset cancelled."));
    assert!(root.join(".gears/openrouter.key").is_file());
    let output = reset(b"yes\n");
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("Reset Gears: remove keys"), "{stdout}");
    assert!(!stdout.contains("openrouter.key"), "{stdout}");
    assert!(root.join(".gears/gears.toml").is_file());
    assert!(root.join(".gears/tools/sh").is_dir());
    assert!(!root.join(".gears/openrouter.key").exists());
    assert!(!root.join(".gears/sessions").exists());
    assert!(!workspace.join(".gears").exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn batteries_hook_uses_the_gears_sibling_even_when_path_contains_another_program() {
    // Parallel spawns can inherit a writable copy fd until exec. Prepare and
    // run these executables in a process with no other process-creating tests.
    const CHILD: &str = "GEARS_SIBLING_FIXTURE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .env(CHILD, "1")
            .args([
                "--exact",
                "batteries_hook_uses_the_gears_sibling_even_when_path_contains_another_program",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let root = fixture("batteries-sibling");
    let workspace = root.join("workspace");
    let binaries = root.join("bin");
    let other = root.join("other");
    for path in [&workspace, &binaries, &other] {
        std::fs::create_dir(path).unwrap();
    }
    std::fs::copy(env!("CARGO_BIN_EXE_gears"), binaries.join("gears")).unwrap();
    for (directory, label) in [(&binaries, "sibling-hook-ran"), (&other, "path-hook-ran")] {
        let path = directory.join("gears-batteries");
        std::fs::write(
            &path,
            format!("#!/bin/sh\ncat >/dev/null\nprintf '%s' '{{\"notice\":\"{label}\"}}'\n"),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let server = MockServer::start_one(sse_response(&[
        r#"{"choices":[{"index":0,"delta":{"content":"done"},"finish_reason":"stop"}]}"#,
    ]))
    .unwrap();
    let cfg = config(&root, &server);
    let mut file = std::fs::OpenOptions::new().append(true).open(&cfg).unwrap();
    writeln!(file, "\n[[hooks]]\nname = 'batteries'\nevents = ['initialize']\ncommand = ['gears-batteries', 'hook']").unwrap();
    let output = Command::new(binaries.join("gears"))
        .env("HOME", &root)
        .env("OPENROUTER_API_KEY", "test-key")
        .env("PATH", format!("{}:/usr/bin:/bin", other.display()))
        .args(["--ui", "line", "--ephemeral", "--config"])
        .arg(cfg)
        .arg("--workspace")
        .arg(workspace)
        .args(["-p", "hello"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("sibling-hook-ran"), "{stderr}");
    assert!(!stderr.contains("path-hook-ran"), "{stderr}");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn hook_questions_and_commands_work_in_line_ui_and_never_prompt_in_one_shots() {
    for mode in ["interactive", "text", "jsonl"] {
        let root = fixture(&format!("hook-question-{mode}"));
        let workspace = root.join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let server = MockServer::start_one(sse_response(&[
            r#"{"choices":[{"index":0,"delta":{"content":"done"},"finish_reason":"stop"}]}"#,
        ]))
        .unwrap();
        let config = config(&root, &server);
        let log = root.join("answers.jsonl");
        let hook = root.join("hook.sh");
        let question = serde_json::json!({"id": "q1", "text": "Publish proposal?", "choices": [
            {"value": "yes", "label": "Publish"}, {"value": "no", "label": "Discard"}]});
        let initialize = serde_json::json!({"commands": [{"name": "review", "help": "Review this work"}], "question": question});
        let ask = serde_json::json!({"question": question});
        std::fs::write(&hook, format!("event=$(cat)\ncase \"$event\" in\n*'\"event\":\"initialize\"'*) printf '%s' '{initialize}' ;;\n*'\"event\":\"answer\"'*) printf '%s\\n' \"$event\" >> \"$1\"; printf '{{\"hint\":\"decision saved\"}}' ;;\n*) printf '%s' '{ask}' ;;\nesac\n")).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&config)
            .unwrap();
        writeln!(file, "\n[[hooks]]\nname = 'question'\ncommand = ['/bin/sh', '{}', '{}']\nevents = ['initialize', 'command', 'turn_end', 'answer']", hook.display(), log.display()).unwrap();
        let output = if mode == "interactive" {
            let mut child = gears(&root, &workspace, &config)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"2\n/help\n/review literal focus\nyes\nhello\n2\n/quit\n")
                .unwrap();
            child.wait_with_output().unwrap()
        } else {
            gears(&root, &workspace, &config)
                .args(["-p", "hello", "--output", mode])
                .output()
                .unwrap()
        };
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{mode}: {stderr}");
        let answers = std::fs::read_to_string(log)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        if mode == "interactive" {
            assert!(stderr.contains("/review - Review this work"), "{stderr}");
            assert!(stderr.contains("1. Publish\n  2. Discard"), "{stderr}");
            assert!(stderr.contains("decision saved"), "{stderr}");
            assert_eq!(
                answers
                    .iter()
                    .map(|event| event["payload"]["answer"].as_str().unwrap())
                    .collect::<Vec<_>>(),
                ["no", "yes", "no"]
            );
        } else {
            assert!(!stderr.contains("Publish proposal?"), "{stderr}");
            assert!(!String::from_utf8_lossy(&output.stdout).contains("answer [number"));
            assert_eq!(answers.len(), 2);
            assert!(
                answers
                    .iter()
                    .all(|event| event["payload"]["answer"].is_null()
                        && event["payload"]["attended"] == false)
            );
            if mode == "jsonl" {
                let records = jsonl_records(&output.stdout);
                assert!(
                    records.iter().any(
                        |record| record["type"] == "hint" && record["text"] == "decision saved"
                    )
                );
            }
        }
        assert_eq!(server.requests().len(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn help_version_and_bad_arguments_need_no_configuration() {
    let version = Command::new(env!("CARGO_BIN_EXE_gears"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(version.status.success());
    assert!(
        String::from_utf8(version.stdout)
            .unwrap()
            .starts_with("gears ")
    );

    let help = Command::new(env!("CARGO_BIN_EXE_gears"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(
        String::from_utf8(help.stdout)
            .unwrap()
            .contains("--ephemeral")
    );

    let bad = Command::new(env!("CARGO_BIN_EXE_gears"))
        .arg("--removed-flag")
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(2));
}

#[test]
fn a_second_gears_is_refused_while_the_first_holds_the_directory_lock() {
    let root = fixture("directory-lock");
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let other_workspace = root.join("other-workspace");
    std::fs::create_dir(&other_workspace).unwrap();
    let server = MockServer::start_one(sse_response(&[])).unwrap();
    let config = config(&root, &server);
    std::fs::create_dir_all(root.join(".gears")).unwrap();
    std::fs::write(root.join(".gears/.gears-tmp-crashed"), "partial").unwrap();
    let mut first = gears(&root, &workspace, &config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = first.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut prompt = [0_u8; 7];
        let result = stdout.read_exact(&mut prompt).map(|()| prompt);
        let _ = sender.send(result);
    });
    let prompt = match receiver.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(prompt)) => prompt,
        other => {
            let _ = first.kill();
            let _ = first.wait();
            panic!("first Gears did not reach its prompt: {other:?}");
        }
    };
    assert_eq!(&prompt, b"gears> ");
    assert!(!root.join(".gears/.gears-tmp-crashed").exists());

    let second = gears(&root, &other_workspace, &config)
        .args(["-p", "hello"])
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains(&format!(
        "Another gears session {} is running. Exiting.",
        first.id()
    )));
    first.stdin.take().unwrap().write_all(b"/quit\n").unwrap();
    assert!(first.wait().unwrap().success());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn one_shot_streams_from_the_hermetic_backend() {
    let root = fixture("stream");
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    std::fs::create_dir_all(root.join(".gears")).unwrap();
    std::fs::write(root.join(".gears/gears.lock"), "0\n").unwrap();
    let server = MockServer::start_one(sse_response(&[
        r#"{"choices":[{"index":0,"delta":{"content":"hello "}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"content":"mock"}}]}"#,
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
    ]))
    .unwrap();
    let config = config(&root, &server);
    let output = gears(&root, &workspace, &config)
        .args(["-p", "hello"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("hello mock")
    );
    assert_eq!(server.requests().len(), 1);
    std::fs::remove_dir_all(root).unwrap();
}

fn jsonl_records(bytes: &[u8]) -> Vec<serde_json::Value> {
    std::str::from_utf8(bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn jsonl_one_shot_streams_reasoning_text_and_numeric_usage() {
    let root = fixture("jsonl-text");
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let server = MockServer::start_one(sse_response(&[
        r#"{"choices":[{"index":0,"delta":{"reasoning":"thinking\n"}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"content":"hello\nmock"}}]}"#,
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":3,"total_tokens":13,"cost":0.01}}"#,
    ])).unwrap();
    let cfg = config(&root, &server);
    let output = gears(&root, &workspace, &cfg)
        .args(["-p", "hello", "--output", "jsonl"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let records = jsonl_records(&output.stdout);
    assert_eq!(
        records
            .iter()
            .map(|record| record["type"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["session", "reasoning", "text", "usage", "turn_end", "final"]
    );
    assert_eq!(records[0]["version"], 1);
    assert_eq!(records[0]["session_format_version"], 1);
    assert!(records[0]["session_id"].as_str().is_some());
    assert!(records[0]["path"].is_null());
    assert_eq!(records[1]["text"], "thinking\n");
    assert_eq!(records[2]["text"], "hello\nmock");
    assert_eq!(records[4]["status"], "completed");
    assert_eq!(records[4]["tool_rounds"], 0);
    assert!(records[4]["last_entry_id"].as_str().is_some());
    let last = records.last().unwrap();
    assert_eq!(last["success"], true);
    assert_eq!(last["answer"], "hello\nmock");
    assert_eq!(last["usage"]["total_tokens"], 13);
    assert_eq!(last["usage"]["cost_usd"], 0.01);
    assert!(last["error"].is_null());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn jsonl_tool_records_report_allowed_and_unattended_denied_calls() {
    for allowed in [false, true] {
        let root = fixture(if allowed {
            "jsonl-tool-allow"
        } else {
            "jsonl-tool-deny"
        });
        let workspace = root.join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let call = r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_jsonl","function":{"name":"sh","arguments":"{\"command\":\"printf 'tool output\\n'; printf 'tool error\\n' >&2\"}"}}]},"finish_reason":"tool_calls"}]}"#;
        let server = MockServer::start(vec![sse_response(&[call]), sse_response(&[
            r#"{"choices":[{"index":0,"delta":{"content":"finished"},"finish_reason":"stop"}]}"#,
        ])]).unwrap();
        let cfg = config(&root, &server);
        let mut text = std::fs::read_to_string(&cfg).unwrap();
        text.push_str(&format!(
            "\n[[tools]]\ndirectory = {:?}\nenabled = true\n",
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tools/sh")
                .to_str()
                .unwrap()
        ));
        if allowed {
            text.push_str("\n[[hooks]]\nname = 'policy'\nevents = ['permission']\ncommand = ['/bin/sh', '-c', \"cat >/dev/null; printf '{\\\"decision\\\":\\\"allow\\\"}'\"]\n");
        }
        std::fs::write(&cfg, text).unwrap();
        let output = gears(&root, &workspace, &cfg)
            .args(["-p", "work", "--output", "jsonl"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let records = jsonl_records(&output.stdout);
        let start = records
            .iter()
            .find(|record| record["type"] == "tool_start")
            .unwrap();
        let result = records
            .iter()
            .find(|record| record["type"] == "tool_result")
            .unwrap();
        assert_eq!(start["call_id"], "call_jsonl");
        assert_eq!(result["call_id"], start["call_id"]);
        assert_eq!(
            result["outcome"],
            if allowed { "completed" } else { "not_started" }
        );
        assert_eq!(result["is_error"], !allowed);
        let output = records
            .iter()
            .filter(|record| record["type"] == "tool_output")
            .collect::<Vec<_>>();
        if allowed {
            for (stream, text) in [("stdout", "tool output\n"), ("stderr", "tool error\n")] {
                assert!(
                    output
                        .iter()
                        .any(|record| record["stream"] == stream && record["text"] == text)
                );
            }
        } else {
            assert!(output.is_empty());
        }
        assert_eq!(records.last().unwrap()["answer"], "finished");
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn jsonl_failed_turn_ends_with_a_final_error_and_nonzero_status() {
    let root = fixture("jsonl-error");
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let server =
        MockServer::start_one(gears::mock::Script::new().write(
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 3\r\nConnection: close\r\n\r\nbad",
        ))
        .unwrap();
    let cfg = config(&root, &server);
    let output = gears(&root, &workspace, &cfg)
        .args(["-p", "hello", "--output", "jsonl"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let records = jsonl_records(&output.stdout);
    assert_eq!(records.first().unwrap()["type"], "session");
    assert_eq!(records[records.len() - 2]["type"], "turn_end");
    let last = records.last().unwrap();
    assert_eq!(last["type"], "final");
    assert_eq!(last["success"], false);
    assert!(last["error"].as_str().unwrap().contains("400"));
    assert!(last["answer"].is_null());
    assert_eq!(last["usage"]["completions"], 0);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn owned_nested_gears_stops_only_its_tool_and_parents_stop_everything() {
    use gears::process::{Cancellation, Request, run};
    fn stopped(pid: &str) -> bool {
        std::fs::read_to_string(format!("/proc/{}/stat", pid.trim())).map_or(true, |stat| {
            matches!(
                stat.rsplit_once(") ").unwrap().1.split_whitespace().next(),
                Some("Z" | "X" | "x")
            )
        })
    }
    fn call(id: &str, command: &str, timeout: u64) -> String {
        let arguments = serde_json::json!({"command": command, "timeout": timeout}).to_string();
        serde_json::json!({"choices": [{"index": 0, "delta": {"tool_calls": [{
            "index": 0, "id": id, "function": {"name": "sh", "arguments": arguments}
        }]}, "finish_reason": "tool_calls"}]})
        .to_string()
    }
    let tree = "printf '%s' $$ > child.pid; sleep 30 & printf '%s' $! > grandchild.pid; printf nested-ready; wait";
    let done =
        r#"{"choices":[{"index":0,"delta":{"content":"nested done"},"finish_reason":"stop"}]}"#;
    for mode in ["normal", "cancel", "timeout"] {
        let root = fixture(&format!("nested-{mode}"));
        let workspace = root.join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let scripts = match mode {
            // A background job must not outlive its tool or block the next call.
            "normal" => vec![
                sse_response(&[&call(
                    "first",
                    "sleep 30 & printf '%s' $! > leftover.pid; printf nested-normal",
                    30,
                )]),
                sse_response(&[&call("second", "printf second-ran", 30)]),
                sse_response(&[done]),
            ],
            "cancel" => vec![sse_response(&[&call("tree", tree, 30)])],
            _ => vec![
                sse_response(&[&call("tree", tree, 1)]),
                sse_response(&[done]),
            ],
        };
        let server = MockServer::start(scripts).unwrap();
        let cfg = config(&root, &server);
        let mut text = std::fs::read_to_string(&cfg).unwrap();
        text.push_str(&format!(
            "\n[[tools]]\ndirectory = {:?}\nenabled = true\n",
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tools/sh")
                .to_str()
                .unwrap()
        ));
        text.push_str("\n[[hooks]]\nname = 'policy'\nevents = ['permission']\ncommand = ['/bin/sh', '-c', \"cat >/dev/null; printf '{\\\"decision\\\":\\\"allow\\\"}'\"]\n");
        std::fs::write(&cfg, text).unwrap();
        let cancellation = Cancellation::new();
        let mut streamed = String::new();
        let output = run(&Request {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), "exec \"$1\" --config \"$2\" --workspace \"$3\" --ephemeral --output jsonl -p nested".into(),
                "wrapper".into(), env!("CARGO_BIN_EXE_gears").into(), cfg.display().to_string(), workspace.display().to_string()],
            cwd: workspace.clone(), stdin: None, timeout: Duration::from_secs(10), max_output_bytes: 65536,
            env: vec![("HOME".into(), root.display().to_string()), ("OPENROUTER_API_KEY".into(), "test-key".into())],
            remove_env: Vec::new(),
        }, &cancellation, &mut |stream, text| {
            if stream == gears::process::Stream::Stdout {
                streamed.push_str(text);
                if mode == "cancel" && streamed.lines()
                    .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                    .any(|record| record["type"] == "tool_output"
                        && record["text"].as_str().is_some_and(|text| text.contains("nested-ready"))) {
                    cancellation.cancel();
                }
            }
        }).unwrap();
        assert!(!output.timed_out, "{mode}: {output:?}");
        if mode == "cancel" {
            assert!(output.cancelled, "{output:?}");
            assert!(
                output.code.is_none(),
                "nested run was not killed: {output:?}"
            );
        } else {
            assert_eq!(output.code, Some(0), "{mode}: {output:?}");
            assert!(output.stdout.contains("nested done"), "{mode}: {output:?}");
        }
        if mode == "normal" {
            assert!(output.stdout.contains("second-ran"), "{output:?}");
            let pid = std::fs::read_to_string(workspace.join("leftover.pid")).unwrap();
            assert!(stopped(&pid), "background job {pid} still running");
        } else {
            assert!(streamed.contains("nested-ready"), "{mode}: {output:?}");
            if mode == "timeout" {
                assert!(output.stdout.contains("timed out"), "{output:?}");
            }
            for name in ["child.pid", "grandchild.pid"] {
                let pid = std::fs::read_to_string(workspace.join(name)).unwrap();
                assert!(stopped(&pid), "{mode}: {name} {pid} still running");
            }
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn configured_tools_are_validated_before_a_provider_request() {
    let root = fixture("tool-validation");
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let server = MockServer::start_one(sse_response(&[])).unwrap();
    let config = config(&root, &server);
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str("\n[[tools]]\ndirectory = 'tools/missing'\nenabled = false\n");
    std::fs::write(&config, text).unwrap();
    let output = gears(&root, &workspace, &config)
        .args(["-p", "hello"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("tools/missing"));
    assert!(server.requests().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn malformed_line_commands_report_errors_and_keep_the_session_open() {
    let root = fixture("line-command-errors");
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let server = MockServer::start_one(sse_response(&[
        r#"{"choices":[{"index":0,"delta":{"content":"still open"},"finish_reason":"stop"}]}"#,
    ]))
    .unwrap();
    let config = config(&root, &server);
    let mut child = gears(&root, &workspace, &config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            b"/tool enable\n/tool enable missing\n/permission revoke sh --unknown\nhello\n/quit\n",
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("still open"));
    let errors = String::from_utf8_lossy(&output.stderr);
    assert!(errors.contains("usage: /tool"), "{errors}");
    assert!(errors.contains("unknown directory tool"), "{errors}");
    assert!(errors.contains("usage: /permission"), "{errors}");
    assert_eq!(server.requests().len(), 1);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn one_shot_uses_the_selected_named_provider() {
    let root = fixture("named-provider");
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let server = MockServer::start_one(sse_response(&[
        r#"{"choices":[{"index":0,"delta":{"content":"named answer"}}]}"#,
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
    ]))
    .unwrap();
    let config = root.join("gears.toml");
    std::fs::write(
        &config,
        format!(
            "version = 1\ndefault_provider = 'local'\ndefault_model = 'test/model'\n[net]\negress_allowlist = ['127.0.0.1']\nplain_http_allowlist = ['127.0.0.1']\n[providers.local]\nbase_url = '{}'\n",
            server.url("/v1")
        ),
    )
    .unwrap();
    let output = gears(&root, &workspace, &config)
        .args(["--provider", "local", "-p", "hello"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("named answer"));
    assert_eq!(server.requests().len(), 1);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn continued_session_uses_its_recorded_provider() {
    let root = fixture("continued-provider");
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let response = || {
        sse_response(&[
            r#"{"choices":[{"index":0,"delta":{"content":"local answer"}}]}"#,
            r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
        ])
    };
    let local = MockServer::start(vec![response(), response()]).unwrap();
    let remote = MockServer::start_one(sse_response(&[])).unwrap();
    let config = root.join("gears.toml");
    std::fs::write(
        &config,
        format!(
            "version = 1\ndefault_provider = 'remote'\ndefault_model = 'test/model'\n[net]\negress_allowlist = ['127.0.0.1']\nplain_http_allowlist = ['127.0.0.1']\n[providers.local]\nbase_url = '{}'\n[providers.remote]\nbase_url = '{}'\n",
            local.url("/v1"),
            remote.url("/v1")
        ),
    )
    .unwrap();
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gears"));
        command
            .env("HOME", &root)
            .env("OPENROUTER_API_KEY", "test-key")
            .args(["--ui", "line", "--config"])
            .arg(&config)
            .arg("--workspace")
            .arg(&workspace);
        command
    };
    let first = command()
        .args(["--provider", "local", "-p", "one"])
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let second = command()
        .args(["--continue", "-p", "two"])
        .output()
        .unwrap();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(local.requests().len(), 2);
    assert!(remote.requests().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn line_command_switches_provider_before_the_next_turn() {
    let root = fixture("line-provider-switch");
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let local = MockServer::start_one(sse_response(&[
        r#"{"choices":[{"index":0,"delta":{"content":"from local"}}]}"#,
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
    ]))
    .unwrap();
    let remote = MockServer::start_one(sse_response(&[])).unwrap();
    let config = root.join("gears.toml");
    std::fs::write(
        &config,
        format!(
            "version = 1\ndefault_provider = 'remote'\ndefault_model = 'test/model'\n[net]\negress_allowlist = ['127.0.0.1']\nplain_http_allowlist = ['127.0.0.1']\n[providers.local]\nbase_url = '{}'\n[providers.remote]\nbase_url = '{}'\n",
            local.url("/v1"),
            remote.url("/v1")
        ),
    )
    .unwrap();
    let mut child = gears(&root, &workspace, &config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"/provider local\nhello\n/quit\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("from local"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("provider: local"));
    assert_eq!(local.requests().len(), 1);
    assert!(remote.requests().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn line_commands_save_provider_and_model_defaults() {
    let root = fixture("saved-provider-choice");
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let local = MockServer::start_one(sse_response(&[
        r#"{"choices":[{"index":0,"delta":{"content":"saved choice"}}]}"#,
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
    ]))
    .unwrap();
    let remote = MockServer::start_one(sse_response(&[])).unwrap();
    let config = root.join("custom-config.toml");
    std::fs::write(
        &config,
        format!(
            "version = 1\ndefault_provider = 'remote'\ndefault_model = 'old/model'\n[net]\negress_allowlist = ['127.0.0.1']\nplain_http_allowlist = ['127.0.0.1']\n[providers.local]\nbase_url = '{}'\n[providers.remote]\nbase_url = '{}'\n",
            local.url("/v1"),
            remote.url("/v1")
        ),
    )
    .unwrap();
    let mut child = gears(&root, &workspace, &config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"/provider local --default\n/model chosen/model --default\n/quit\n")
        .unwrap();
    assert!(child.wait().unwrap().success());
    assert!(root.join(".gears/provider.toml").exists());

    let output = gears(&root, &workspace, &config)
        .args(["-p", "hello"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("saved choice"));
    let requests = local.requests();
    assert_eq!(requests.len(), 1);
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["model"], "chosen/model");
    assert!(remote.requests().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn unattended_sh_is_denied_and_the_turn_continues() {
    let root = fixture("deny");
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let call = r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"sh","arguments":"{\"command\":\"touch denied-file\"}"}}]},"finish_reason":"tool_calls"}]}"#;
    let server = MockServer::start(vec![
        sse_response(&[call]),
        sse_response(&[
            r#"{"choices":[{"index":0,"delta":{"content":"denied safely"}}]}"#,
            r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
        ]),
    ])
    .unwrap();
    let config = config(&root, &server);
    let output = gears(&root, &workspace, &config)
        .args(["-p", "try it"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!workspace.join("denied-file").exists());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("denied safely")
    );
    assert_eq!(server.requests().len(), 2);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn http_refuses_implicit_credentials_and_preserves_explicit_precedence() {
    let root = fixture("http-keys");
    let key_dir = root.join(".config/gears");
    std::fs::create_dir_all(&key_dir).unwrap();
    let default_key = key_dir.join("openrouter.key");
    std::fs::write(&default_key, "fixture-default-key").unwrap();
    let explicit_key = root.join("local.key");
    std::fs::write(&explicit_key, "fixture-local-key").unwrap();
    for (key_file, env_key, expected) in [
        (None, None, None),
        (Some(&explicit_key), None, Some("fixture-local-key")),
        (
            Some(&explicit_key),
            Some("fixture-env-key"),
            Some("fixture-env-key"),
        ),
        (None, Some("fixture-env-key"), Some("fixture-env-key")),
        (Some(&default_key), None, Some("fixture-default-key")),
    ] {
        let server = MockServer::start_one(sse_response(&[
            r#"{"choices":[{"index":0,"delta":{"content":"hello"},"finish_reason":"stop"}]}"#,
        ]))
        .unwrap();
        let config_path = config(&root, &server);
        if let Some(path) = key_file {
            let mut text = std::fs::read_to_string(&config_path).unwrap();
            text.push_str(&format!("api_key_file = {:?}\n", path.to_str().unwrap()));
            std::fs::write(&config_path, text).unwrap();
        }
        let mut command = Command::new(env!("CARGO_BIN_EXE_gears"));
        command
            .env("HOME", &root)
            .env_remove("OPENROUTER_API_KEY")
            .arg("--config")
            .arg(&config_path)
            .args(["ask", "hello"]);
        if let Some(key) = env_key {
            command.env("OPENROUTER_API_KEY", key);
        }
        let output = command.output().unwrap();
        if let Some(key) = expected {
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(server.requests().len(), 1);
            assert_eq!(
                server.requests()[0].header("Authorization"),
                Some(format!("Bearer {key}").as_str())
            );
            assert_eq!(output.stdout, b"hello\n");
        } else {
            assert!(!output.status.success());
            let error = String::from_utf8(output.stderr).unwrap();
            assert!(error.contains("implicit default key file"), "{error}");
            assert!(error.contains("provider.api_key_file"));
            assert!(error.contains("OPENROUTER_API_KEY"));
            assert!(server.requests().is_empty());
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}
