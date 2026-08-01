//! The agent, end to end: the built binary, a scripted endpoint, and a real
//! workspace on disk. Nothing here is mocked below the wire — the tools, the
//! session, the permission gate and the transport are all the real ones.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use gears::mock::{MockServer, Script, sse_response};

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
        let dir = std::env::temp_dir().join(format!("gears-agent-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let workspace = dir.join("work");
        std::fs::create_dir_all(&workspace).unwrap();
        let key_file = dir.join("openrouter.key");
        std::fs::write(&key_file, format!("{KEY}\n")).unwrap();

        let server = MockServer::start(scripts).unwrap();
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
                 level = \"debug\"\n",
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

    fn cleanup(self) {
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
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

/// A streamed turn that calls one tool, with the arguments split across two
/// deltas — which is how they really arrive.
fn calls(id: &str, name: &str, arguments: serde_json::Value) -> Script {
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

    // The workspace really changed, both ways round.
    assert_eq!(fixture.read("notes.txt"), "second line\n");
    assert!(shown.contains("* write_file notes.txt"), "{shown}");
    assert!(shown.contains("* edit_file notes.txt"), "{shown}");
    assert!(shown.contains("Both done."), "{shown}");

    // The undo log holds what it was before gears touched it: nothing, since
    // the file did not exist.
    let id = session_id(&out);
    let manifest = fixture
        .workspace
        .join(format!(".gears/undo/{id}/manifest.jsonl"));
    let manifest = std::fs::read_to_string(&manifest).unwrap();
    assert_eq!(manifest.trim(), r#"{"existed":false,"path":"notes.txt"}"#);

    // And the session is a faithful transcript: meta, system prompt, prompt,
    // two tool rounds, the answer.
    let records = fixture.session_lines(&id);
    let kinds: Vec<&str> = records
        .iter()
        .map(|r| r["record"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        [
            "meta", "message", "message", "usage", "message", "message", "usage", "message",
            "message", "usage", "message"
        ]
    );
    assert_eq!(records[0]["model"], serde_json::json!("test/model"));
    assert_eq!(records[1]["role"], serde_json::json!("system"));
    assert_eq!(records[2]["content"], serde_json::json!("make some notes"));
    assert_eq!(
        records[4]["tool_calls"][0]["function"]["name"],
        "write_file"
    );
    assert!(
        records[5]["content"]
            .as_str()
            .unwrap()
            .contains("wrote 11 bytes")
    );
    assert_eq!(records[10]["content"], serde_json::json!("Both done."));

    // The model was shown the tools, and the key went out on the wire.
    let sent: serde_json::Value =
        serde_json::from_slice(&fixture.server.requests()[0].body).unwrap();
    let names: Vec<&str> = sent["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["function"]["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "read_file",
            "write_file",
            "edit_file",
            "list_dir",
            "grep",
            "run",
            "build",
            "test",
            "fetch"
        ]
    );
    assert!(!shown.contains(KEY), "{shown}");
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

    let out = fixture.type_at("run something\na\n/quit\n");
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
    let sent: serde_json::Value =
        serde_json::from_slice(&fixture.server.requests()[1].body).unwrap();
    let result = sent["messages"][3]["content"].as_str().unwrap();
    assert_eq!(result, "exit status 0\nhello from a command\n");
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
    let sent: serde_json::Value =
        serde_json::from_slice(&fixture.server.requests()[1].body).unwrap();
    let result = sent["messages"][3]["content"].as_str().unwrap();
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
    let result = |request: usize, message: usize| {
        let sent: serde_json::Value =
            serde_json::from_slice(&fixture.server.requests()[request].body).unwrap();
        sent["messages"][message]["content"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let built = result(3, 7);
    assert!(built.starts_with("exit status 0"), "{built}");
    let tested = result(4, 9);
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

    let sent: serde_json::Value =
        serde_json::from_slice(&fixture.server.requests()[3].body).unwrap();
    let built = sent["messages"][7]["content"].as_str().unwrap();
    assert!(built.starts_with("exit status 101"), "{built}");
    assert!(built.contains("mismatched types"), "{built}");
    fixture.cleanup();
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
    assert_eq!(kinds, ["meta", "message", "message"]);
    assert_eq!(records[2]["content"], serde_json::json!("say something"));

    // And a new run picks the session up and carries on in it.
    let out = fixture.run(&["--resume", &id, "-p", "try again"]);
    let shown = stdout(&out);
    assert!(out.status.success(), "{shown}");
    assert!(shown.contains(&format!("resumed session {id}")), "{shown}");
    assert!(shown.contains("All better."), "{shown}");

    let records = fixture.session_lines(&id);
    assert_eq!(records.len(), 6);
    // One system prompt in the whole file, and the second request carried the
    // first prompt back to the model.
    let systems = records
        .iter()
        .filter(|r| r["role"] == serde_json::json!("system"))
        .count();
    assert_eq!(systems, 1);
    let sent: serde_json::Value =
        serde_json::from_slice(&fixture.server.requests()[1].body).unwrap();
    assert_eq!(
        sent["messages"][1]["content"],
        serde_json::json!("say something")
    );
    assert_eq!(
        sent["messages"][2]["content"],
        serde_json::json!("try again")
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
    let sent: serde_json::Value =
        serde_json::from_slice(&fixture.server.requests()[1].body).unwrap();
    let result = sent["messages"][3]["content"].as_str().unwrap();
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

    let listing = {
        let sent: serde_json::Value =
            serde_json::from_slice(&fixture.server.requests()[1].body).unwrap();
        sent["messages"][3]["content"].as_str().unwrap().to_string()
    };
    assert!(!listing.contains("permissions.toml"), "{listing}");
    let refusal = {
        let sent: serde_json::Value =
            serde_json::from_slice(&fixture.server.requests()[2].body).unwrap();
        sent["messages"][5]["content"].as_str().unwrap().to_string()
    };
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

    let out = fixture.type_at("make some notes\n/status\n/undo\n/quit\n");
    let shown = stdout(&out);
    assert!(out.status.success(), "{shown}");

    // Four prompts: one per line typed.
    assert_eq!(shown.matches("gears> ").count(), 4, "{shown}");
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

    // /undo really puts the workspace back.
    assert!(shown.contains("- put back: notes.txt"), "{shown}");
    assert!(!fixture.workspace.join("notes.txt").exists());
    fixture.cleanup();
}

/// ^C during a turn: the transfer is dropped, the user is told, and what is
/// left on disk is the prompt — not half an answer.
#[cfg(unix)]
#[test]
fn an_interrupt_cancels_the_turn_in_flight() {
    use std::io::Read;

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
    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) };

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
    assert_eq!(kinds, ["meta", "message", "message"]);
    fixture.cleanup();
}

fn session_id_in(shown: &str) -> String {
    shown
        .lines()
        .find_map(|line| line.strip_prefix("- session ").map(str::to_string))
        .unwrap_or_else(|| panic!("no session id in:\n{shown}"))
}
