//! The agent, end to end: the built binary, a scripted endpoint, and a real
//! workspace on disk. Nothing here is mocked below the wire — the tools, the
//! session, the permission gate and the transport are all the real ones.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use gears::mock::{MockServer, Route, Script, provider_scenario, sse_response};

const KEY: &str = "sk-fake-agent-key";

struct Fixture {
    dir: PathBuf,
    workspace: PathBuf,
    config: PathBuf,
    server: MockServer,
}

impl Fixture {
    /// A workspace, a key, and a config pointing at `scripts`.
    fn new(name: &str, permissions: &str, scripts: Vec<Script>) -> Fixture {
        Fixture::routed(
            name,
            permissions,
            "",
            scripts.into_iter().map(any).collect(),
        )
    }

    /// The same, where which agent asked decides what it is answered — and
    /// with whatever else the run needs in the config.
    fn routed(name: &str, permissions: &str, extra: &str, routes: Vec<Route>) -> Fixture {
        let dir = std::env::temp_dir().join(format!("gears-agent-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let workspace = dir.join("work");
        std::fs::create_dir_all(&workspace).unwrap();
        let key_file = dir.join("openrouter.key");
        std::fs::write(&key_file, format!("{KEY}\n")).unwrap();

        let server = MockServer::start_routed(routes).unwrap();
        let config = dir.join("gears.toml");
        std::fs::write(
            &config,
            format!(
                "version = 1\n\
                 [net]\n\
                 egress_allowlist = [\"127.0.0.1\"]\n\
                 allow_plain_http_loopback = true\n\
                 [provider]\n\
                 base_url = \"{}/v1\"\n\
                 model = \"test/model\"\n\
                 key_file = \"{}\"\n\
                 [permissions]\n\
                 mode = \"{permissions}\"\n\
                 [trace]\n\
                 level = \"debug\"\n{extra}",
                server.base_url(),
                key_file.display()
            ),
        )
        .unwrap();

        Fixture {
            dir,
            workspace,
            config,
            server,
        }
    }

    fn gears(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gears"));
        command
            .arg("--config")
            .arg(&self.config)
            .arg("--workspace")
            .arg(&self.workspace)
            .arg("--log-file")
            .arg(self.dir.join("gears.log"))
            .env_remove("OPENROUTER_API_KEY");
        command
    }

    fn run(&self, extra: &[&str]) -> Output {
        self.gears().args(extra).output().unwrap()
    }

    /// Drive the interactive loop by typing at it.
    fn type_at(&self, input: &str) -> Output {
        let mut child = self
            .gears()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    /// Type some input, wait until the UI has printed `marker`, then finish.
    fn type_after(&self, first: &str, marker: &str, rest: &str) -> Output {
        self.type_steps(first, &[(marker, rest)])
    }

    /// Answer a sequence of questions only after each one is visible.
    fn type_steps(&self, first: &str, steps: &[(&str, &str)]) -> Output {
        let mut child = self
            .gears()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        input.write_all(first.as_bytes()).unwrap();

        let mut out = child.stdout.take().unwrap();
        let mut stdout = Vec::new();
        for (marker, response) in steps {
            let start = stdout.len();
            while !stdout[start..]
                .windows(marker.len())
                .any(|bytes| bytes == marker.as_bytes())
            {
                let mut byte = [0];
                assert!(
                    out.read(&mut byte).unwrap() > 0,
                    "output ended before {marker}"
                );
                stdout.push(byte[0]);
            }
            input.write_all(response.as_bytes()).unwrap();
        }
        drop(input);
        out.read_to_end(&mut stdout).unwrap();

        let mut stderr = Vec::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_end(&mut stderr)
            .unwrap();
        let status = child.wait().unwrap();
        Output {
            status,
            stdout,
            stderr,
        }
    }

    fn read(&self, path: &str) -> String {
        std::fs::read_to_string(self.workspace.join(path)).unwrap()
    }

    fn session_lines(&self, id: &str) -> Vec<serde_json::Value> {
        let path = self
            .workspace
            .join(gears::agent::session::SESSIONS_DIR)
            .join(format!("{id}.jsonl"));
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn request(&self, index: usize) -> serde_json::Value {
        serde_json::from_slice(&self.server.requests()[index].body).unwrap()
    }

    fn tool_result(&self, request: usize, call: &str) -> String {
        self.request(request)["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|message| message["tool_call_id"] == call)
            .and_then(|message| message["content"].as_str())
            .unwrap_or_else(|| panic!("request {request} has no result for {call}"))
            .to_string()
    }

    fn cleanup(self) {
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn read_until(reader: &mut impl Read, output: &mut Vec<u8>, marker: &str) {
    while !output
        .windows(marker.len())
        .any(|bytes| bytes == marker.as_bytes())
    {
        let mut byte = [0];
        assert!(
            reader.read(&mut byte).unwrap() > 0,
            "output ended before {marker}"
        );
        output.push(byte[0]);
    }
}

/// The session id gears announced on the way in.
fn session_id(out: &Output) -> String {
    stdout(out)
        .lines()
        .find_map(|line| line.strip_prefix("- session ").map(str::to_string))
        .unwrap_or_else(|| panic!("no session id in:\n{}", stdout(out)))
}

const USAGE: &str =
    r#"{"choices":[],"usage":{"prompt_tokens":9,"completion_tokens":4,"cost":0.0003}}"#;

/// The same, for a turn the endpoint says was expensive in *input*: what
/// gears' context management works from is this number and nothing else.
fn usage_of(prompt_tokens: u64) -> String {
    format!(r#"{{"choices":[],"usage":{{"prompt_tokens":{prompt_tokens},"completion_tokens":4}}}}"#)
}

/// A streamed turn that calls one tool, with the arguments split across two
/// deltas — which is how they really arrive.
fn calls(id: &str, name: &str, arguments: serde_json::Value) -> Script {
    calls_costing(id, name, arguments, USAGE)
}

fn calls_costing(id: &str, name: &str, arguments: serde_json::Value, usage: &str) -> Script {
    let text = arguments.to_string();
    let (head, tail) = text.split_at(text.len() / 2);
    let fragment = |piece: &str| {
        format!(
            r#"{{"choices":[{{"index":0,"delta":{{"tool_calls":[{{"index":0,"function":{{"arguments":{}}}}}]}}}}]}}"#,
            serde_json::Value::String(piece.to_string())
        )
    };
    sse_response(&[
        &format!(
            r#"{{"choices":[{{"index":0,"delta":{{"tool_calls":[{{"index":0,"id":"{id}","type":"function","function":{{"name":"{name}","arguments":""}}}}]}}}}]}}"#
        ),
        &fragment(head),
        &fragment(tail),
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
        usage,
    ])
}

fn calls_two(first: (&str, serde_json::Value), second: (&str, serde_json::Value)) -> Script {
    let calls = serde_json::json!({
        "choices": [{
            "index": 0,
            "delta": {"tool_calls": [
                {"index": 0, "id": "call_1", "type": "function", "function": {
                    "name": first.0, "arguments": first.1.to_string()
                }},
                {"index": 1, "id": "call_2", "type": "function", "function": {
                    "name": second.0, "arguments": second.1.to_string()
                }}
            ]}
        }]
    })
    .to_string();
    sse_response(&[
        &calls,
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
        USAGE,
    ])
}

/// A streamed turn that just answers.
fn says(text: &str) -> Script {
    sse_response(&[
        &format!(r#"{{"choices":[{{"index":0,"delta":{{"content":"{text}"}}}}]}}"#),
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
        USAGE,
    ])
}

/// A script for whoever asks next, which is what a single agent's run is.
fn any(script: Script) -> Route {
    Route::new("", script)
}

/// A script for one agent's traffic, picked out by the model it was given.
/// The needle is unescaped, so it matches the request's own model field and
/// not another agent's mention of it in a tool call.
fn asked_by(model: &str, script: Script) -> Route {
    Route::new(format!(r#""model":"{model}""#), script)
}

#[test]
fn a_line_prompt_attachment_is_visible_and_reaches_the_first_request() {
    let fixture = Fixture::new("attachment", "auto-approve", vec![says("received")]);
    std::fs::write(
        fixture.workspace.join("context.txt"),
        "attachment fixture bytes",
    )
    .unwrap();

    let out = fixture.run(&["--ui", "line", "-p", "inspect @context.txt"]);
    let shown = stdout(&out);
    assert!(
        out.status.success(),
        "{shown}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let notice = shown
        .find("- attached context.txt (file; 24 bytes")
        .unwrap();
    let answer = shown.find("received").unwrap();
    assert!(notice < answer, "{shown}");
    let request = fixture.request(0);
    let content = request["messages"]
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .find(|message| message["role"] == "user")
        .unwrap()["content"]
        .as_str()
        .unwrap();
    assert!(content.contains("Gears attachment \"context.txt\""));
    assert!(content.contains("attachment fixture bytes"));
    let records = fixture.session_lines(&session_id(&out));
    let user = records
        .iter()
        .find(|record| record["record"] == "message" && record["role"] == "user")
        .unwrap();
    assert!(
        user["display_content"]
            .as_str()
            .unwrap()
            .contains("Attachments:")
    );
    fixture.cleanup();
}

#[test]
fn one_prompt_creates_and_edits_files_and_the_session_records_it() {
    let fixture = Fixture::new(
        "work",
        "auto-approve",
        vec![
            calls(
                "call_1",
                "write_file",
                serde_json::json!({"path": "notes.txt", "content": "first line\n"}),
            ),
            calls(
                "call_2",
                "edit_file",
                serde_json::json!({"path": "notes.txt", "old": "first", "new": "second"}),
            ),
            says("Both done."),
        ],
    );

    let out = fixture.run(&["-p", "make some notes"]);
    let shown = stdout(&out);
    assert!(out.status.success(), "{shown}{:?}", out.status);
    assert!(
        shown.starts_with("Motor OS Gears - agentic coding harness\n\n- session "),
        "{shown}"
    );
    assert!(
        shown.contains(&format!(
            "\n- test/model in {}\n",
            fixture.workspace.display()
        )),
        "{shown}"
    );

    // The workspace really changed, both ways round.
    assert_eq!(fixture.read("notes.txt"), "second line\n");
    assert!(shown.contains("* write_file notes.txt"), "{shown}");
    assert!(shown.contains("* edit_file notes.txt"), "{shown}");
    assert!(shown.contains("Both done."), "{shown}");

    // The automatic initial checkpoint holds what it was before gears touched
    // it: nothing, since the file did not exist. Fresh sessions do not also
    // duplicate this state in the legacy undo store.
    let id = session_id(&out);
    let manifest = fixture.workspace.join(format!(
        ".gears/checkpoints/v1/{id}/1/files/1/metadata.json"
    ));
    let manifest = std::fs::read_to_string(&manifest).unwrap();
    assert!(manifest.contains(r#""path":"notes.txt""#), "{manifest}");
    assert!(!fixture.workspace.join(format!(".gears/undo/{id}")).exists());

    // And the session is a faithful transcript: each tool round retains its
    // exact prepared mutation, decision, and result before the model sees it.
    let records = fixture.session_lines(&id);
    let kinds: Vec<&str> = records
        .iter()
        .map(|r| r["record"].as_str().unwrap())
        .collect();
    assert_eq!(kinds.iter().filter(|kind| **kind == "task_v2").count(), 2);
    assert_eq!(records[0]["model"], serde_json::json!("test/model"));
    let messages: Vec<_> = records
        .iter()
        .filter(|record| record["record"] == "message")
        .collect();
    let mutations: Vec<_> = records
        .iter()
        .filter(|record| record["record"] == "mutation")
        .collect();
    assert_eq!(messages[0]["role"], serde_json::json!("system"));
    assert_eq!(messages[1]["content"], serde_json::json!("make some notes"));
    assert_eq!(
        messages[2]["tool_calls"][0]["function"]["name"],
        "write_file"
    );
    assert!(
        messages[3]["content"]
            .as_str()
            .unwrap()
            .contains("wrote 11 bytes")
    );
    assert_eq!(mutations[0]["phase"], "prepared");
    assert_eq!(mutations[0]["changes"][0]["before_identity"], "missing");
    assert_eq!(mutations[1]["detail"], "allow");
    assert_eq!(mutations[2]["phase"], "result");
    assert_eq!(mutations[0]["digest"], mutations[1]["digest"]);
    assert_eq!(mutations[1]["digest"], mutations[2]["digest"]);
    assert_eq!(mutations[3]["phase"], "prepared");
    assert_eq!(mutations[4]["detail"], "allow");
    assert_eq!(messages[6]["content"], serde_json::json!("Both done."));

    // The model was shown the tools, and the key went out on the wire.
    let sent: serde_json::Value =
        serde_json::from_slice(&fixture.server.requests()[0].body).unwrap();
    let names: Vec<&str> = sent["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["function"]["name"].as_str().unwrap())
        .collect();
    // A temporary directory is under no version control, so there are no git
    // tools in the list — the Motor OS v1 story, on the host. The three
    // self-hosting tools are there whether or not self-hosting is on; with it
    // off, as here, they refuse and say why, because a model that is told to
    // update itself and shown nothing improvises instead.
    assert_eq!(
        names,
        [
            "read_file",
            "write_file",
            "edit_file",
            "list_dir",
            "grep",
            "patch",
            "project_instructions",
            "repository_profile",
            "run",
            "artifacts",
            "checkpoints",
            "restore_checkpoint",
            "build",
            "test",
            "stage_candidate",
            "promote_candidate",
            "restart",
            "fetch",
            "spawn_agent",
            "wait_agents",
            "task",
            "completion"
        ]
    );
    assert!(!shown.contains(KEY), "{shown}");
    fixture.cleanup();
}

#[test]
fn the_p0_workflow_connects_plan_patch_native_test_review_and_completion() {
    let fixture = Fixture::new(
        "p0-workflow",
        "ask",
        provider_scenario("p0-workflow").unwrap(),
    );
    std::fs::create_dir_all(fixture.workspace.join("src")).unwrap();
    std::fs::create_dir_all(fixture.workspace.join("nested")).unwrap();
    std::fs::write(
        fixture.workspace.join("Cargo.toml"),
        "[package]\nname = \"p0-workflow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    std::fs::write(
        fixture.workspace.join("Cargo.lock"),
        "version = 4\n\n[[package]]\nname = \"p0-workflow\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    std::fs::write(
        fixture.workspace.join("src/lib.rs"),
        "pub const LABEL: &str = \"P0_WORKFLOW_OLD\";\n\n\
         #[test]\nfn label_is_updated() {\n    assert_eq!(LABEL, \"P0_WORKFLOW_NEW\");\n}\n",
    )
    .unwrap();
    std::fs::write(fixture.workspace.join("AGENTS.md"), "root workflow rules\n").unwrap();
    std::fs::write(
        fixture.workspace.join("nested/AGENTS.md"),
        "nested workflow rules\n",
    )
    .unwrap();
    std::fs::write(fixture.workspace.join("nested/lib.rs"), "// inspected\n").unwrap();

    let out = fixture.type_steps(
        "/mode plan\ncomplete the scripted P0 workflow\n",
        &[
            ("allow enter code mode from plan?", "y\n"),
            ("allow patch?", "y\n"),
            ("allow test?", "y\n/quit\n"),
        ],
    );
    let shown = stdout(&out);
    assert!(
        out.status.success(),
        "{shown}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for expected in [
        "next task mode: plan",
        "P0_WORKFLOW_OLD",
        "p0 workflow complete",
    ] {
        assert!(shown.contains(expected), "missing {expected:?}:\n{shown}");
    }
    assert!(
        fixture
            .tool_result(1, "instructions")
            .contains("nested workflow rules")
    );
    assert!(
        fixture
            .tool_result(1, "profile")
            .contains("selected Rust backend: cargo")
    );
    assert!(fixture.read("src/lib.rs").contains("P0_WORKFLOW_NEW"));
    assert_eq!(fixture.read("CHANGELOG.md"), "p0 workflow\n");

    let requests = fixture.server.requests();
    assert_eq!(requests.len(), 11, "{shown}");
    assert!(
        fixture
            .tool_result(10, "report")
            .starts_with("completion report v1")
    );
    let first: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    let system = first["messages"][0]["content"].as_str().unwrap();
    assert!(system.contains("Platform: linux"), "{system}");
    let first_tools = first["tools"].as_array().unwrap();
    assert!(
        first_tools
            .iter()
            .all(|tool| tool["function"]["name"] != "patch")
    );
    let code: serde_json::Value = serde_json::from_slice(&requests[2].body).unwrap();
    assert!(code["tools"].as_array().unwrap().iter().any(|tool| {
        tool["function"]["name"] == "test"
            && tool["function"]["description"]
                .as_str()
                .unwrap()
                .contains("Cargo")
    }));

    let records = fixture.session_lines(&session_id(&out));
    let patch: Vec<_> = records
        .iter()
        .filter(|record| record["record"] == "mutation" && record["tool"] == "patch")
        .collect();
    assert_eq!(patch.len(), 3, "{patch:?}");
    assert!(
        patch
            .iter()
            .all(|record| record["digest"] == patch[0]["digest"])
    );
    assert_eq!(patch[0]["changes"].as_array().unwrap().len(), 2);
    let evidence = records
        .iter()
        .find(|record| record["record"] == "verification_v1")
        .unwrap()["evidence"]
        .clone();
    assert_eq!(evidence["candidate"]["backend"], "cargo");
    assert_eq!(evidence["scope"]["checkpoint"], 2);
    assert_eq!(evidence["scope"]["mutation_generation"], 2);
    let task = records
        .iter()
        .rev()
        .find(|record| record["record"] == "task_v2")
        .unwrap()["task"]
        .clone();
    assert_eq!(task["mode"], "review");
    assert_eq!(task["verification_evidence"], serde_json::json!([1]));
    assert!(
        task["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["state"] == "completed")
    );
    fixture.cleanup();
}

#[cfg(target_os = "linux")]
#[test]
fn one_approved_patch_applies_every_file_operation_and_one_digest() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new(
        "atomic-patch",
        "auto-approve",
        vec![
            calls(
                "call_patch",
                "patch",
                serde_json::json!({"version": 1, "operations": [
                    {"kind": "create", "path": "created", "content": "new\n",
                        "executable": true},
                    {"kind": "edit", "path": "edited", "hunks": [
                        {"old": "old", "new": "changed"}]},
                    {"kind": "delete", "path": "deleted"},
                    {"kind": "rename", "path": "source", "to": "destination",
                        "hunks": [{"old": "move", "new": "moved"}]}
                ]}),
            ),
            says("Patch done."),
        ],
    );
    std::fs::write(fixture.workspace.join("edited"), "old text\n").unwrap();
    std::fs::write(fixture.workspace.join("deleted"), "gone\n").unwrap();
    std::fs::write(fixture.workspace.join("source"), "move me\n").unwrap();

    let out = fixture.run(&["-p", "apply one atomic patch"]);
    let shown = stdout(&out);
    assert!(out.status.success(), "{shown}");
    assert!(shown.contains("* patch"), "{shown}");
    assert_eq!(fixture.read("created"), "new\n");
    assert_eq!(fixture.read("edited"), "changed text\n");
    assert!(!fixture.workspace.join("deleted").exists());
    assert!(!fixture.workspace.join("source").exists());
    assert_eq!(fixture.read("destination"), "moved me\n");
    assert_eq!(
        std::fs::metadata(fixture.workspace.join("created"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );

    let records = fixture.session_lines(&session_id(&out));
    let mutations: Vec<&serde_json::Value> = records
        .iter()
        .filter(|record| record["record"] == "mutation")
        .collect();
    assert_eq!(mutations.len(), 3, "{mutations:?}");
    assert_eq!(mutations[0]["tool"], "patch");
    assert_eq!(mutations[0]["changes"].as_array().unwrap().len(), 5);
    assert!(
        mutations
            .iter()
            .all(|record| record["digest"] == mutations[0]["digest"])
    );
    fixture.cleanup();
}

#[test]
fn checkpoint_restore_is_diff_approved_atomic_and_audited() {
    let fixture = Fixture::new(
        "checkpoint-restore",
        "ask",
        vec![
            calls(
                "call_checkpoint",
                "checkpoints",
                serde_json::json!({"action": "create", "name": "initial"}),
            ),
            calls(
                "call_write",
                "write_file",
                serde_json::json!({"path": "notes.txt", "content": "hello\n"}),
            ),
            calls(
                "call_restore",
                "restore_checkpoint",
                serde_json::json!({"id": 2}),
            ),
            says("Restored."),
        ],
    );
    let out = fixture.type_steps(
        "restore my checkpoint\n",
        &[
            ("allow write_file notes.txt?", "y\n"),
            ("allow restore_checkpoint 2?", "y\n/quit\n"),
        ],
    );
    let shown = stdout(&out);
    assert!(out.status.success(), "{shown}");
    assert!(
        shown.contains("+++ /dev/null\n@@ -1,1 +1,0 @@\n-hello"),
        "{shown}"
    );
    assert!(!fixture.workspace.join("notes.txt").exists());

    let records = fixture.session_lines(&session_id(&out));
    let restore: Vec<_> = records
        .iter()
        .filter(|record| record["record"] == "mutation" && record["tool"] == "restore_checkpoint")
        .collect();
    assert_eq!(restore.len(), 3, "{restore:?}");
    assert_eq!(restore[0]["phase"], "prepared");
    assert_eq!(restore[1]["detail"], "allow");
    assert_eq!(restore[2]["phase"], "result");
    assert!(
        restore
            .iter()
            .all(|record| record["digest"] == restore[0]["digest"])
    );
    fixture.cleanup();
}

#[test]
fn undo_restores_the_initial_checkpoint_with_approval_and_audit() {
    let fixture = Fixture::new(
        "checkpoint-undo",
        "auto-approve",
        vec![
            calls(
                "call_write",
                "write_file",
                serde_json::json!({"path": "notes.txt", "content": "hello\n"}),
            ),
            says("Written."),
        ],
    );
    let out = fixture.type_at("write a note\n/undo\ny\n/quit\n");
    let shown = stdout(&out);
    assert!(out.status.success(), "{shown}");
    assert!(
        shown.contains("+++ /dev/null\n@@ -1,1 +1,0 @@\n-hello"),
        "{shown}"
    );
    assert!(shown.contains("restore checkpoint 1? [y/N]: "), "{shown}");
    assert!(shown.contains("- restored 1 file states"), "{shown}");
    assert!(!fixture.workspace.join("notes.txt").exists());

    let records = fixture.session_lines(&session_id(&out));
    let restore: Vec<_> = records
        .iter()
        .filter(|record| record["record"] == "mutation" && record["tool"] == "restore_checkpoint")
        .collect();
    assert_eq!(restore.len(), 3, "{restore:?}");
    assert_eq!(restore[0]["phase"], "prepared");
    assert_eq!(restore[1]["detail"], "allow");
    assert_eq!(restore[2]["phase"], "result");
    fixture.cleanup();
}

/// `run` is the escape hatch from everything the file tools confine, so the
/// question the user is asked has to name the whole command — and what is
/// remembered has to be that command, not "anything gears runs".
#[test]
fn a_command_is_asked_about_by_name_and_remembered_by_command() {
    let fixture = Fixture::new(
        "run",
        "ask",
        vec![
            calls(
                "call_1",
                "run",
                serde_json::json!({"command": "sh", "args": ["-c", "echo hello from a command"]}),
            ),
            says("It said hello."),
        ],
    );

    let out = fixture.type_after("run something\n", "[a]lways: ", "a\n/quit\n");
    let shown = stdout(&out);
    assert!(out.status.success(), "{shown}");
    assert!(
        shown.contains("allow run sh -c echo hello from a command?"),
        "{shown}"
    );

    // An "always" answer is about this command, and says so on disk.
    let allowed =
        std::fs::read_to_string(fixture.workspace.join(".gears/permissions.toml")).unwrap();
    assert!(allowed.contains("\"run:sh\""), "{allowed}");

    // What the command printed reached the model, under its exit status.
    let result = fixture.tool_result(1, "call_1");
    assert_eq!(result, "exit status 0\nhello from a command\n");
    fixture.cleanup();
}

#[test]
fn a_future_prompt_cannot_answer_a_permission_question() {
    let fixture = Fixture::new(
        "queued-prompt",
        "ask",
        vec![
            calls(
                "call_1",
                "run",
                serde_json::json!({"command": "sh", "args": ["-c", "true"]}),
            ),
            says("First done."),
            says("Second done."),
        ],
    );

    let out = fixture.type_after("first prompt\nsecond prompt\n", "[a]lways: ", "y\n/quit\n");
    let shown = stdout(&out);
    assert!(out.status.success(), "{shown}");
    assert!(shown.contains("First done."), "{shown}");
    assert!(shown.contains("Second done."), "{shown}");

    let requests = fixture.server.requests();
    assert_eq!(requests.len(), 3, "{shown}");
    let last: serde_json::Value = serde_json::from_slice(&requests[2].body).unwrap();
    assert_eq!(
        last["messages"].as_array().unwrap().last().unwrap()["content"],
        "second prompt"
    );
    fixture.cleanup();
}

#[test]
fn pause_waits_for_an_atomic_tool_then_resume_continues() {
    let fixture = Fixture::new(
        "pause",
        "auto-approve",
        vec![
            calls_two(
                (
                    "run",
                    serde_json::json!({"command": "sh", "args": ["-c", "sleep 0.2"]}),
                ),
                (
                    "write_file",
                    serde_json::json!({"path": "after.txt", "content": "resumed\n"}),
                ),
            ),
            says("Done after resume."),
        ],
    );
    let mut child = fixture
        .gears()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    input.write_all(b"do both things\n").unwrap();
    let mut out = child.stdout.take().unwrap();
    let mut shown = Vec::new();
    read_until(&mut out, &mut shown, "* run sh -c sleep 0.2");
    input.write_all(b"/pause\n").unwrap();
    read_until(&mut out, &mut shown, "- paused after current operation");
    read_until(&mut out, &mut shown, "exit status 0");
    assert!(!String::from_utf8_lossy(&shown).contains("* write_file"));

    input.write_all(b"/resume\n/quit\n").unwrap();
    drop(input);
    out.read_to_end(&mut shown).unwrap();
    let status = child.wait().unwrap();
    let shown = String::from_utf8_lossy(&shown);
    assert!(status.success(), "{shown}");
    assert!(shown.contains("- resumed"), "{shown}");
    assert!(shown.contains("Done after resume."), "{shown}");
    assert_eq!(fixture.read("after.txt"), "resumed\n");
    let records = fixture.session_lines(&session_id_in(&shown));
    let task_records: Vec<_> = records
        .iter()
        .filter(|record| record["record"] == "task_v2")
        .collect();
    let paused = task_records
        .iter()
        .position(|record| record["task"]["handoff"]["reason"] == "paused")
        .expect("pause was not journaled");
    assert!(task_records[paused + 1]["task"]["handoff"].is_null());
    fixture.cleanup();
}

/// `fetch` goes out over the same transport as everything else, and a host the
/// configuration already allows is not a question.
#[test]
fn a_fetch_of_an_allowed_host_goes_out_without_asking() {
    // A second server, so what the model fetches is plainly not the endpoint
    // it is talking to — both are loopback, which is what the config allows.
    let pages = MockServer::start(vec![Script::new().write(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nthe answer!",
    )])
    .unwrap();
    let url = format!("{}/page", pages.base_url());
    let fixture = Fixture::new(
        "fetch",
        "ask",
        vec![
            calls("call_1", "fetch", serde_json::json!({ "url": url })),
            says("It says: the answer!"),
        ],
    );

    let out = fixture.run(&["-p", "look it up"]);
    let shown = stdout(&out);
    assert!(out.status.success(), "{shown}");
    assert!(shown.contains(&format!("* fetch {url}")), "{shown}");
    assert!(!shown.contains("allow fetch"), "{shown}");

    // The GET really went out, and what came back reached the model.
    assert_eq!(pages.requests()[0].target, "/page");
    let result = fixture.tool_result(1, "call_1");
    assert_eq!(result, "HTTP 200 OK\nthe answer!");
    fixture.cleanup();
}

/// The step-5 bar: gears writes a crate, builds it and runs its tests with the
/// real toolchain. `--offline` keeps it hermetic — the crate has no
/// dependencies, so nothing here needs the network.
#[test]
fn a_crate_is_written_built_and_tested_with_the_real_toolchain() {
    const MANIFEST: &str = "[workspace]\n\
                            [package]\nname = \"hello\"\nversion = \"0.1.0\"\n\
                            edition = \"2021\"\n";
    const SOURCE: &str = "pub fn hello() -> &'static str { \"hello\" }\n\
                          #[test]\nfn it_says_hello() { assert_eq!(hello(), \"hello\"); }\n";

    let fixture = Fixture::new(
        "toolchain",
        "auto-approve",
        vec![
            calls(
                "call_1",
                "write_file",
                serde_json::json!({"path": "Cargo.toml", "content": MANIFEST}),
            ),
            calls(
                "call_2",
                "write_file",
                serde_json::json!({"path": "src/lib.rs", "content": SOURCE}),
            ),
            calls("call_3", "build", serde_json::json!({"offline": true})),
            calls("call_4", "test", serde_json::json!({"offline": true})),
            says("Built, and the test passes."),
        ],
    );

    let out = fixture.run(&["-p", "write a hello crate, build it and test it"]);
    let shown = stdout(&out);
    assert!(out.status.success(), "{shown}");
    assert!(shown.contains("* build"), "{shown}");
    assert!(shown.contains("* test"), "{shown}");
    assert!(fixture.workspace.join("target").is_dir(), "{shown}");

    // What cargo said reached the model, verbatim and successful.
    let built = fixture.tool_result(3, "call_3");
    assert!(built.starts_with("exit status 0"), "{built}");
    let tested = fixture.tool_result(4, "call_4");
    assert!(tested.starts_with("exit status 0"), "{tested}");
    assert!(tested.contains("test it_says_hello ... ok"), "{tested}");
    fixture.cleanup();
}

/// And the other half of that: a crate that does not compile comes back as the
/// compiler's own diagnostics rather than as a tool failure.
#[test]
fn a_broken_crate_comes_back_as_diagnostics() {
    let fixture = Fixture::new(
        "broken",
        "auto-approve",
        vec![
            calls(
                "call_1",
                "write_file",
                serde_json::json!({"path": "Cargo.toml",
                    "content": "[workspace]\n[package]\nname = \"broken\"\nversion = \"0.1.0\"\n"}),
            ),
            calls(
                "call_2",
                "write_file",
                serde_json::json!({"path": "src/lib.rs", "content": "pub fn f() -> u32 { \"no\" }\n"}),
            ),
            calls("call_3", "build", serde_json::json!({"offline": true})),
            says("It does not compile."),
        ],
    );

    let out = fixture.run(&["-p", "build it"]);
    let shown = stdout(&out);
    assert!(out.status.success(), "{shown}");

    let built = fixture.tool_result(3, "call_3");
    assert!(built.starts_with("exit status 101"), "{built}");
    assert!(built.contains("mismatched types"), "{built}");
    fixture.cleanup();
}

/// What the model was told and what the screen says are not the same thing: a
/// build log is a byte count on one line. `/+` is how the user gets at the rest
/// of it without opening the session file.
#[test]
fn a_summarized_result_is_marked_and_can_be_opened_up() {
    let fixture = Fixture::new(
        "expand",
        "auto-approve",
        vec![
            calls(
                "call_1",
                "write_file",
                serde_json::json!({"path": "Cargo.toml",
                    "content": "[workspace]\n[package]\nname = \"expand\"\nversion = \"0.1.0\"\n"}),
            ),
            calls(
                "call_2",
                "write_file",
                serde_json::json!({"path": "src/lib.rs", "content": "pub fn f() -> u32 { \"no\" }\n"}),
            ),
            calls("call_3", "build", serde_json::json!({"offline": true})),
            says("It does not compile."),
        ],
    );

    // `+` on its own does what `/+` does; `+ 9` asks for one that is not there.
    let out = fixture.type_at("build it\n/+\n+ 9\n/quit\n");
    let shown = stdout(&out);
    assert!(out.status.success(), "{shown}");

    // The build is summarized, and said to be more than what is on the line.
    let marked = shown
        .lines()
        .find(|line| line.starts_with("  [+] "))
        .unwrap_or_else(|| panic!("nothing marked expandable in:\n{shown}"));
    assert!(marked.ends_with(" bytes"), "{marked}");

    // And `/+` prints the compiler's own diagnostics, under a header naming
    // the call they came from.
    let (_, expanded) = shown.split_once("--- build (").unwrap();
    assert!(
        expanded.starts_with(&format!("{} bytes) ---\n", size(marked))),
        "{expanded}"
    );
    assert!(expanded.contains("exit status 101"), "{expanded}");
    assert!(expanded.contains("mismatched types"), "{expanded}");
    assert!(shown.contains("! no result 9; 1 kept"), "{shown}");
    fixture.cleanup();
}

/// The byte count out of a `  [+] 2144 bytes` line.
fn size(marked: &str) -> usize {
    marked
        .trim_start_matches("  [+] ")
        .trim_end_matches(" bytes")
        .parse()
        .unwrap()
}

/// Version control the model can see, on a real repository: it writes a file,
/// looks at what changed and commits it — and the commit is put to the user,
/// because gears making one uninvited is the thing D3 exists to prevent.
#[test]
fn a_change_is_committed_once_the_user_has_allowed_it() {
    let fixture = Fixture::new(
        "vcs",
        "ask",
        vec![
            calls(
                "call_1",
                "write_file",
                serde_json::json!({"path": "notes.txt", "content": "first line\n"}),
            ),
            calls("call_2", "git_status", serde_json::json!({})),
            calls(
                "call_3",
                "git_commit",
                serde_json::json!({"message": "add notes"}),
            ),
            says("Committed."),
        ],
    );
    git_init(&fixture.workspace);

    let out = fixture.type_steps(
        "write and commit some notes\n",
        &[
            ("allow write_file notes.txt?", "y\n"),
            ("allow git_commit add notes?", "y\n/quit\n"),
        ],
    );
    let shown = stdout(&out);
    assert!(out.status.success(), "{shown}");

    // The question named the message: "allow git_commit?" is not one anybody
    // could answer. Looking at what changed was not a question at all.
    assert!(shown.contains("allow git_commit add notes?"), "{shown}");
    assert!(!shown.contains("allow git_status"), "{shown}");

    // Exactly one commit, carrying the trailer under the repository's own
    // identity — and gears' own state is not in it.
    let log = git(&fixture.workspace, &["log", "--format=%s|%an"]);
    assert_eq!(log.trim(), "add notes|you");
    let message = git(&fixture.workspace, &["log", "-1", "--format=%B"]);
    assert!(
        message.trim_end().ends_with(gears::tools::vcs::TRAILER),
        "{message}"
    );
    assert_eq!(
        git(&fixture.workspace, &["ls-files"]).trim(),
        "notes.txt",
        "{shown}"
    );

    // And the model was shown the git tools, which is what made any of it
    // possible: it is in a repository this time.
    let sent: serde_json::Value =
        serde_json::from_slice(&fixture.server.requests()[0].body).unwrap();
    let names: Vec<&str> = sent["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["function"]["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"git_status"), "{names:?}");
    assert!(names.contains(&"git_commit"), "{names:?}");
    fixture.cleanup();
}

/// A repository with an identity of its own, so that what the host's git
/// configuration says — or does not say — is not part of what is under test.
fn git_init(dir: &PathBuf) {
    for args in [
        ["init", "--quiet"].as_slice(),
        &["config", "user.email", "you@invalid"],
        &["config", "user.name", "you"],
        &["config", "commit.gpgsign", "false"],
    ] {
        git(dir, args);
    }
}

fn git(dir: &PathBuf, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Two sub-agents, working at the same time on the same workspace: the whole
/// of step 7 in one run. Their streams are paced to overlap on purpose, and
/// what the screen must never show is one agent's half-line inside another's.
#[test]
fn two_sub_agents_work_at_once_and_both_answers_come_back() {
    let fixture = Fixture::routed(
        "agents",
        "ask",
        "",
        vec![
            // The root: one agent, then another, then it waits for both.
            asked_by(
                "test/model",
                calls(
                    "call_1",
                    "spawn_agent",
                    serde_json::json!({
                        "task": "count the crabs",
                        "model": "test/scout-a",
                        "read_only": true,
                    }),
                ),
            ),
            asked_by(
                "test/model",
                calls(
                    "call_2",
                    "spawn_agent",
                    serde_json::json!({"task": "count the whales", "model": "test/scout-b"}),
                ),
            ),
            asked_by(
                "test/model",
                calls("call_3", "wait_agents", serde_json::json!({})),
            ),
            asked_by("test/model", says("Both are back.")),
            // The first scout looks around before answering, slowly enough
            // that the second one is talking over it.
            asked_by(
                "test/scout-a",
                calls("call_a", "list_dir", serde_json::json!({"path": "."})),
            ),
            asked_by(
                "test/scout-a",
                says_slowly(&["crustaceans:", " three"], 0, 150),
            ),
            asked_by(
                "test/scout-b",
                says_slowly(&["cetaceans:", " two"], 75, 150),
            ),
        ],
    );

    let out = fixture.type_steps(
        "count the animals\n",
        &[
            ("allow spawn_agent count the crabs?", "y\n"),
            ("allow spawn_agent count the whales?", "y\n/quit\n"),
        ],
    );
    let shown = stdout(&out);
    assert!(out.status.success(), "{shown}");

    // Starting an agent is put to the user like any other change, and the
    // question says what the agent was asked to do.
    assert!(
        shown.contains("allow spawn_agent count the crabs?"),
        "{shown}"
    );
    assert!(shown.contains("  agent 1 started"), "{shown}");
    assert!(shown.contains("[1] * list_dir ."), "{shown}");

    // Every line is one agent's: what each said is marked as theirs, and no
    // line has both of them in it.
    for line in shown.lines() {
        if line.contains("crustaceans") || line.contains(" three") {
            assert!(line.starts_with("[1] "), "{line:?}\n{shown}");
        }
        if line.contains("cetaceans") || line.contains(" two") {
            assert!(line.starts_with("[2] "), "{line:?}\n{shown}");
        }
    }
    assert!(shown.contains("[1] - done"), "{shown}");
    assert!(shown.contains("[2] - done"), "{shown}");

    // Both answers reached the model as one tool result, labelled with who
    // said what — and the root's own output is unmarked throughout.
    let waited = sent_by(&fixture, "test/model")
        .into_iter()
        .find_map(|sent| {
            let last = sent["messages"].as_array()?.last()?;
            let text = last["content"].as_str()?.to_string();
            text.starts_with("agent 1 (").then_some(text)
        })
        .unwrap_or_else(|| panic!("no wait result in:\n{shown}"));
    assert!(
        waited.contains("agent 1 (count the crabs) answered:\ncrustaceans: three"),
        "{waited}"
    );
    assert!(
        waited.contains("agent 2 (count the whales) answered:\ncetaceans: two"),
        "{waited}"
    );
    assert!(shown.contains("Both are back."), "{shown}");

    // The read-only scout was given only the tools that change nothing, and
    // no way to start an agent that would.
    let scouted = sent_by(&fixture, "test/scout-a");
    let tools: Vec<&str> = scouted[0]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["function"]["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        tools,
        [
            "read_file",
            "list_dir",
            "grep",
            "project_instructions",
            "repository_profile",
            "artifacts",
            "checkpoints",
            "fetch"
        ]
    );
    fixture.cleanup();
}

/// Every request one agent made, in the order it made them.
fn sent_by(fixture: &Fixture, model: &str) -> Vec<serde_json::Value> {
    fixture
        .server
        .requests()
        .iter()
        .filter_map(|request| {
            let sent: serde_json::Value = serde_json::from_slice(&request.body).ok()?;
            (sent["model"] == serde_json::json!(model)).then_some(sent)
        })
        .collect()
}

/// A streamed answer that arrives in pieces `gap` milliseconds apart, after
/// `lead`: two of these overlap in a way a test can rely on, which sleeping
/// and hoping would not.
fn says_slowly(pieces: &[&str], lead: u64, gap: u64) -> Script {
    let pause = |ms: u64| std::time::Duration::from_millis(ms);
    let mut script = Script::new()
        .write("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
        .pause(pause(lead));
    for piece in pieces {
        script = script
            .write(format!(
                "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":{}}}}}]}}\n\n",
                serde_json::Value::String(piece.to_string())
            ))
            .pause(pause(gap));
    }
    script
        .write("data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n")
        .write(format!("data: {USAGE}\n\n"))
        .write("data: [DONE]\n\n")
}

/// A turn cut off mid-stream must leave something that can be picked up again:
/// no dangling tool call, and the prompt still the last thing said.
#[test]
fn a_broken_turn_leaves_a_resumable_session() {
    let cut = Script::new()
        .write("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
        .write("data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"half a sen\"}}]}\n\n")
        .close();
    let fixture = Fixture::new("cut", "auto-approve", vec![cut, says("All better.")]);

    let out = fixture.run(&["-p", "say something"]);
    let shown = stdout(&out);
    assert_eq!(out.status.code(), Some(1), "{shown}");
    assert!(shown.contains("half a sen"), "{shown}");
    assert!(shown.contains("! the response was cut short"), "{shown}");

    // The half-finished turn was not kept: what is on disk is the prompt.
    let id = session_id(&out);
    let records = fixture.session_lines(&id);
    let kinds: Vec<&str> = records
        .iter()
        .map(|r| r["record"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["meta", "message", "task_v2", "task_v2", "message"]);
    assert_eq!(records[4]["content"], serde_json::json!("say something"));

    // And a new run picks the session up and carries on in it.
    let out = fixture.run(&["--resume", &id, "-p", "try again"]);
    let shown = stdout(&out);
    assert!(out.status.success(), "{shown}");
    assert!(shown.contains(&format!("resumed session {id}")), "{shown}");
    assert!(shown.contains("All better."), "{shown}");

    let records = fixture.session_lines(&id);
    assert_eq!(records.len(), 8);
    // One system prompt in the whole file, and the second request carried the
    // first prompt back to the model.
    let systems = records
        .iter()
        .filter(|r| r["role"] == serde_json::json!("system"))
        .count();
    assert_eq!(systems, 1);
    let sent: serde_json::Value =
        serde_json::from_slice(&fixture.server.requests()[1].body).unwrap();
    let user_messages: Vec<_> = sent["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|message| message["role"] == "user")
        .map(|message| message["content"].clone())
        .collect();
    assert_eq!(
        user_messages,
        [
            serde_json::json!("say something"),
            serde_json::json!("try again")
        ]
    );
    fixture.cleanup();
}

/// With nobody at the keyboard and a gate that still asks, a mutating call is
/// refused — and the model is told so rather than being left to guess.
#[test]
fn a_one_shot_run_with_no_user_denies_what_it_cannot_ask_about() {
    let fixture = Fixture::new(
        "denied",
        "ask",
        vec![
            calls(
                "call_1",
                "write_file",
                serde_json::json!({"path": "notes.txt", "content": "nope\n"}),
            ),
            says("I could not write it."),
        ],
    );

    let out = fixture.run(&["-p", "write a file"]);
    let shown = stdout(&out);
    assert!(out.status.success(), "{shown}");
    assert!(shown.contains("nobody to ask"), "{shown}");
    assert!(!fixture.workspace.join("notes.txt").exists());

    // The refusal reached the model as a tool result it can act on.
    let result = fixture.tool_result(1, "call_1");
    assert!(result.contains("did not allow write_file"), "{result}");
    fixture.cleanup();
}

/// The gate's own state, and the fact that neither it nor the session is
/// visible to the model.
#[test]
fn gears_state_is_kept_out_of_the_models_reach() {
    let fixture = Fixture::new(
        "state",
        "auto-approve",
        vec![
            calls("call_1", "list_dir", serde_json::json!({"path": "."})),
            calls(
                "call_2",
                "read_file",
                serde_json::json!({"path": ".gears/permissions.toml"}),
            ),
            says("Nothing to see."),
        ],
    );
    // Something for it to find, if it could.
    std::fs::create_dir_all(fixture.workspace.join(".gears")).unwrap();
    std::fs::write(
        fixture.workspace.join(".gears/permissions.toml"),
        "version = 1\nallow = []\n",
    )
    .unwrap();

    let out = fixture.run(&["-p", "look around"]);
    let shown = stdout(&out);
    assert!(out.status.success(), "{shown}");
    assert!(shown.contains("error: read_file:"), "{shown}");

    let listing = fixture.tool_result(1, "call_1");
    assert!(!listing.contains("permissions.toml"), "{listing}");
    let refusal = fixture.tool_result(2, "call_2");
    assert!(refusal.contains("off limits"), "{refusal}");
    fixture.cleanup();
}

/// The interactive loop, driven by typing at it: a prompt, then the commands
/// that are about the session rather than about the model.
#[test]
fn the_repl_takes_prompts_and_slash_commands() {
    let fixture = Fixture::new(
        "repl",
        "auto-approve",
        vec![
            calls(
                "call_1",
                "write_file",
                serde_json::json!({"path": "notes.txt", "content": "typed\n"}),
            ),
            says("Written."),
        ],
    );

    let out = fixture.type_at(
        "/checkpoint create initial\n/checkpoint list\nmake some notes\n/checkpoint inspect 2\n/checkpoint restore 2\ny\n/status\n/undo\n/quit\n",
    );
    let shown = stdout(&out);
    assert!(out.status.success(), "{shown}");

    // Eight command prompts; the restore confirmation is its own prompt.
    assert_eq!(shown.matches("gears> ").count(), 8, "{shown}");
    assert!(shown.contains("- checkpoint 2 created: initial"), "{shown}");
    assert!(shown.contains("checkpoint 1: session start"), "{shown}");
    assert!(shown.contains("checkpoint 2: initial"), "{shown}");
    assert!(
        shown.contains("+++ /dev/null\n@@ -1,1 +1,0 @@\n-typed"),
        "{shown}"
    );
    assert!(shown.contains("restore checkpoint 2? [y/N]: "), "{shown}");
    assert!(shown.contains("- restored 1 file states"), "{shown}");
    assert!(shown.contains("* write_file notes.txt"), "{shown}");
    assert!(shown.contains("Written."), "{shown}");

    // /status reports the session, the model and what has been spent.
    let id = session_id(&out);
    assert!(
        shown.contains(&format!("session {id} | test/model")),
        "{shown}"
    );
    // Two completions in one turn: the tool round and the answer after it.
    assert!(
        shown.contains("2 completions, 18 + 8 tokens, $0.0006"),
        "{shown}"
    );
    assert!(shown.contains("1 files changed"), "{shown}");

    let records = fixture.session_lines(&id);
    let restore: Vec<_> = records
        .iter()
        .filter(|record| record["record"] == "mutation" && record["tool"] == "restore_checkpoint")
        .collect();
    assert_eq!(restore.len(), 3, "{restore:?}");
    assert_eq!(restore[1]["detail"], "allow");

    // The named restore already reached the session's initial state, so the
    // older whole-session undo has no remaining filesystem work.
    assert!(shown.contains("- nothing to undo"), "{shown}");
    assert!(!fixture.workspace.join("notes.txt").exists());
    fixture.cleanup();
}

/// ^C during a turn: the transfer is dropped, the user is told, and what is
/// left on disk is the prompt — not half an answer.
#[cfg(unix)]
#[test]
fn an_interrupt_cancels_the_turn_in_flight() {
    // Paced deliberately: the first delta is what the test waits for, and the
    // second is what the cancellation lands on.
    let slow = Script::new()
        .write("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
        .write("data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"half a sen\"}}]}\n\n")
        .pause(std::time::Duration::from_secs(2))
        .write("data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"tence\"}}]}\n\n")
        .write("data: [DONE]\n\n");
    let fixture = Fixture::new("interrupt", "auto-approve", vec![slow]);

    let mut child = fixture
        .gears()
        .args(["-p", "say something slowly"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    // Wait for the first token to really arrive rather than for a clock: the
    // interrupt has to land while the stream is open.
    let mut out = child.stdout.take().unwrap();
    let mut shown = String::new();
    let mut byte = [0u8; 1];
    while !shown.contains("half a sen") {
        assert!(
            out.read(&mut byte).unwrap() > 0,
            "the stream ended: {shown}"
        );
        shown.push(byte[0] as char);
    }
    assert_eq!(
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) },
        0
    );

    out.read_to_string(&mut shown).unwrap();
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(1), "{shown}");
    assert!(shown.contains("- cancelled"), "{shown}");
    assert!(!shown.contains("tence"), "{shown}");

    // The half-turn was dropped: the session is the prompt, and resumable.
    let records = fixture.session_lines(&session_id_in(&shown));
    let kinds: Vec<&str> = records
        .iter()
        .map(|r| r["record"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["meta", "message", "task_v2", "task_v2", "message"]);
    fixture.cleanup();
}

/// A foreground command takes the same cancellation path, but unlike a model
/// response it must leave a matched tool result in the resumable transcript.
#[cfg(unix)]
#[test]
fn an_interrupt_kills_a_foreground_command_and_leaves_the_session_resumable() {
    let fixture = Fixture::new(
        "interrupt-command",
        "auto-approve",
        vec![
            calls(
                "call_1",
                "run",
                serde_json::json!({
                    "command": "sh",
                    "args": ["-c", "printf 'tool ready\\n'; sleep 30"]
                }),
            ),
            says("Recovered after the cancelled command."),
        ],
    );
    let mut child = fixture
        .gears()
        .args(["-p", "run something slowly"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = child.stdout.take().unwrap();
    let mut bytes = Vec::new();
    read_until(&mut out, &mut bytes, "tool ready\n");

    let cancelled_at = std::time::Instant::now();
    assert_eq!(
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) },
        0
    );
    out.read_to_end(&mut bytes).unwrap();
    let status = child.wait().unwrap();
    let shown = String::from_utf8(bytes).unwrap();
    assert_eq!(status.code(), Some(1), "{shown}");
    assert!(cancelled_at.elapsed() < std::time::Duration::from_secs(1));
    assert!(shown.contains("- cancelled"), "{shown}");

    let id = session_id_in(&shown);
    let records = fixture.session_lines(&id);
    let tool_result = records
        .iter()
        .find(|record| record["record"] == "message" && record["role"] == "tool")
        .expect("the cancelled call has no result");
    let result = tool_result["content"].as_str().unwrap();
    assert!(
        result.contains("cancelled; killed the process group"),
        "{result}"
    );
    assert!(result.contains("tool ready"), "{result}");

    let resumed = fixture.run(&["--resume", &id, "-p", "continue after the cancellation"]);
    let shown = stdout(&resumed);
    assert!(resumed.status.success(), "{shown}");
    assert!(
        shown.contains("Recovered after the cancelled command."),
        "{shown}"
    );
    fixture.cleanup();
}

/// The interactive input owner notices host SIGINT during a turn, then owns
/// the next prompt as usual.
#[cfg(unix)]
#[test]
fn an_interactive_interrupt_returns_to_the_prompt() {
    let slow = Script::new()
        .write("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
        .write("data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"half a sen\"}}]}\n\n")
        .pause(std::time::Duration::from_secs(2))
        .write("data: [DONE]\n\n");
    let fixture = Fixture::new(
        "interactive-interrupt",
        "auto-approve",
        vec![slow, says("Recovered.")],
    );
    let mut child = fixture
        .gears()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    input.write_all(b"first prompt\n").unwrap();
    let mut out = child.stdout.take().unwrap();
    let mut shown = String::new();
    let mut byte = [0];
    while !shown.contains("half a sen") {
        assert!(out.read(&mut byte).unwrap() > 0, "{shown}");
        shown.push(byte[0] as char);
    }
    assert_eq!(
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) },
        0
    );
    while !shown
        .split_once("- cancelled")
        .is_some_and(|(_, after)| after.contains("gears> "))
    {
        assert!(out.read(&mut byte).unwrap() > 0, "{shown}");
        shown.push(byte[0] as char);
    }
    input.write_all(b"second prompt\n/quit\n").unwrap();
    drop(input);
    out.read_to_string(&mut shown).unwrap();
    let status = child.wait().unwrap();

    assert!(status.success(), "{shown}");
    assert!(shown.contains("- cancelled"), "{shown}");
    assert!(shown.contains("Recovered."), "{shown}");
    fixture.cleanup();
}

/// A ^C reaches the sub-agents too, and — the point of the test — a parent
/// waiting on one does not sit out the stream it has just been told to stop
/// caring about.
#[cfg(unix)]
#[test]
fn an_interrupt_stops_a_waiting_parent_and_its_agents() {
    use std::io::Read;

    let fixture = Fixture::routed(
        "cancel-agents",
        "auto-approve",
        "",
        vec![
            asked_by(
                "test/model",
                calls(
                    "call_1",
                    "spawn_agent",
                    serde_json::json!({"task": "watch the kettle", "model": "test/scout"}),
                ),
            ),
            asked_by(
                "test/model",
                calls("call_2", "wait_agents", serde_json::json!({})),
            ),
            asked_by("test/model", says("Recovered after the stopped agents.")),
            // One word, and then nothing for half a minute: the agent is
            // still working when the user gives up on it.
            asked_by("test/scout", says_slowly(&["watching"], 0, 30_000)),
        ],
    );

    let started = std::time::Instant::now();
    let mut child = fixture
        .gears()
        .args(["-p", "watch it"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    // Interrupt once the parent is really in the wait — the call is announced
    // after the round's last chance to cancel, so this is inside it — and the
    // sub-agent has said its one word and is blocked on a stream that will not
    // speak again. It cannot notice a ^C from there, which is the point: what
    // ends the wait has to be the parent.
    let mut out = child.stdout.take().unwrap();
    let mut shown = String::new();
    let mut byte = [0u8; 1];
    while !(shown.contains("* wait_agents") && shown.contains("[1] watching")) {
        assert!(
            out.read(&mut byte).unwrap() > 0,
            "the stream ended: {shown}"
        );
        shown.push(byte[0] as char);
    }
    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) };

    out.read_to_string(&mut shown).unwrap();
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(1), "{shown}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "it waited the sub-agent out: {shown}"
    );

    // The wait ended, the turn ended, and the agent that was still working
    // was stopped rather than left running into the next one.
    assert!(
        shown.contains("error: wait_agents: the agents were stopped"),
        "{shown}"
    );
    assert!(shown.contains("- cancelled"), "{shown}");
    assert!(
        shown.contains("- a sub-agent was still working and was stopped"),
        "{shown}"
    );

    let id = session_id_in(&shown);
    let records = fixture.session_lines(&id);
    assert!(
        records
            .iter()
            .any(|record| { record["role"] == "tool" && record["tool_call_id"] == "call_2" })
    );
    let resumed = fixture.run(&["--resume", &id, "-p", "continue"]);
    let shown = stdout(&resumed);
    assert!(resumed.status.success(), "{shown}");
    assert!(
        shown.contains("Recovered after the stopped agents."),
        "{shown}"
    );
    fixture.cleanup();
}

/// Context management through the built binary, config and all: the endpoint
/// says the window is nearly full, and the oldest result is dropped from what
/// is *sent* — but not from the session, which is the record of what happened.
#[test]
fn a_full_window_drops_the_oldest_result_from_what_is_sent() {
    let read_it = serde_json::json!({"path": "big.txt"});
    let fixture = Fixture::routed(
        "context",
        "auto-approve",
        "[context]\nbudget_tokens = 8000\n",
        vec![
            // Both rounds come back counted as far more than the window will
            // take, which is the only thing gears goes on.
            any(calls_costing(
                "call_1",
                "read_file",
                read_it.clone(),
                &usage_of(50_000),
            )),
            any(calls_costing(
                "call_2",
                "read_file",
                read_it,
                &usage_of(50_000),
            )),
            any(says("read it twice")),
        ],
    );
    std::fs::write(
        fixture.workspace.join("big.txt"),
        "lorem ipsum ".repeat(400),
    )
    .unwrap();

    let out = fixture.run(&["-p", "read big.txt twice"]);
    let shown = stdout(&out);
    assert!(out.status.success(), "{shown}");
    // The first result went before the third request; the second one is what
    // the model has just asked for and stayed.
    assert!(
        shown.contains("context: dropped 1 old tool result"),
        "{shown}"
    );

    let results: Vec<String> = fixture
        .session_lines(&session_id_in(&shown))
        .iter()
        .filter(|line| line["record"] == "message" && line["role"] == "tool")
        .map(|line| line["content"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(results.len(), 2);
    assert!(
        results.iter().all(|text| text.contains("lorem ipsum")),
        "the session lost a result: {results:?}"
    );
    fixture.cleanup();
}

fn session_id_in(shown: &str) -> String {
    shown
        .lines()
        .find_map(|line| line.strip_prefix("- session ").map(str::to_string))
        .unwrap_or_else(|| panic!("no session id in:\n{shown}"))
}
