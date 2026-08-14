//! Self-hosting: gears working on its own source.
//!
//! The scenario at the bottom is the plan's step-9 gate — old gears edits its
//! own checkout, builds it, validates what it built, keeps it as a candidate
//! and restarts into it, with the *new* binary answering on the same session.
//! It is hermetic in the one place that matters: the model is scripted and the
//! endpoint is a mock. Everything else is real — real cargo, real binaries, a
//! real session file carried across a real process boundary.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use gears::mock::{MockServer, Script, sse_response};
use gears::tools::selfhost::Candidates;
use serde_json::json;

/// The version the scenario gives the gears it builds. Nothing but the marker
/// changes, and every assertion that the *new* binary is the one talking comes
/// back to it.
const MARKER: &str = "0.1.0-selfhost";

const USAGE: &str = r#"{"choices":[],"usage":{"prompt_tokens":40,"completion_tokens":8}}"#;

fn calls(id: &str, name: &str, arguments: serde_json::Value) -> Script {
    sse_response(&[
        &format!(
            r#"{{"choices":[{{"index":0,"delta":{{"tool_calls":[{{"index":0,"id":"{id}","type":"function","function":{{"name":"{name}","arguments":{}}}}}]}}}}]}}"#,
            serde_json::Value::String(arguments.to_string())
        ),
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
        USAGE,
    ])
}

fn says(text: &str) -> Script {
    sse_response(&[
        &format!(r#"{{"choices":[{{"index":0,"delta":{{"content":"{text}"}}}}]}}"#),
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
        USAGE,
    ])
}

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Staging *runs* the binary it is given, so both cases here use one this
/// process did not write: a file written and then executed by the same
/// multithreaded program races its own forks, and the exec comes back
/// `ETXTBSY`. In the scenario below the writer is cargo, which has exited.
#[test]
fn a_candidate_has_to_say_it_is_gears() {
    let dir = crate_dir().join("target/selfhost/identify");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let candidates = Candidates::new(&dir).unwrap();

    let staged = candidates
        .stage(Path::new(env!("CARGO_BIN_EXE_gears")))
        .unwrap();
    assert_eq!(staged.number, 1);
    assert!(staged.version.starts_with("gears "), "{}", staged.version);
    assert!(staged.path.is_file());

    // This test binary runs, and answers as something that is not gears.
    let error = candidates
        .stage(&std::env::current_exe().unwrap())
        .unwrap_err();
    assert!(error.contains("does not answer --version"), "{error}");

    // Something that cannot be run at all, and something that is not there.
    let text = dir.join("notes.txt");
    std::fs::write(&text, "not a binary").unwrap();
    assert!(candidates.stage(&text).is_err());
    assert!(candidates.stage(&dir.join("absent")).is_err());
    // None of those became a candidate.
    assert_eq!(candidates.list().unwrap(), [1]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A copy of gears' own source to work on, and an endpoint that answers from
/// a script.
struct SelfHost {
    work: PathBuf,
    config: PathBuf,
    log: PathBuf,
    _server: MockServer,
}

impl SelfHost {
    /// The scratch directory is deliberately *stable* rather than named after
    /// the process: the inner build's target directory lives in it, and cargo
    /// reuses nothing between two paths. The source is refreshed on every run;
    /// what is kept is the build cache, which is what makes the second run of
    /// this test a fraction of the first. It is named after the test, because
    /// two of them at once in one stable directory would be one directory.
    fn new(name: &str, scripts: Vec<Script>) -> SelfHost {
        let scratch = crate_dir().join("target/selfhost").join(name);
        let work = scratch.join("work");
        std::fs::create_dir_all(&work).unwrap();

        // Pristine sources, and none of the last run's state.
        let _ = std::fs::remove_dir_all(work.join("src"));
        let _ = std::fs::remove_dir_all(work.join(".gears"));
        copy_tree(&crate_dir().join("src"), &work.join("src"));
        for file in ["Cargo.toml", "Cargo.lock"] {
            std::fs::copy(crate_dir().join(file), work.join(file)).unwrap();
        }
        // The Motor-only moto-sys dependency: cargo reads every target's
        // manifest even building for the host, so the copy's relative path
        // has to resolve too. Point it back at the real tree rather than
        // copying half the OS in.
        let moto_sys = crate_dir().join("../../sys/lib/moto-sys");
        let manifest = std::fs::read_to_string(work.join("Cargo.toml")).unwrap();
        let manifest = manifest.replace(
            "../../sys/lib/moto-sys",
            moto_sys.canonicalize().unwrap().to_str().unwrap(),
        );
        std::fs::write(work.join("Cargo.toml"), manifest).unwrap();

        let key_file = scratch.join("openrouter.key");
        std::fs::write(&key_file, "sk-fake-selfhost-key\n").unwrap();
        let server = MockServer::start(scripts).unwrap();
        let config = scratch.join("gears.toml");
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
                 mode = \"auto-approve\"\n\
                 [selfhost]\n\
                 enabled = true\n\
                 [trace]\n\
                 level = \"debug\"\n",
                server.base_url(),
                key_file.display()
            ),
        )
        .unwrap();

        let log = scratch.join("gears.log");
        let _ = std::fs::remove_file(&log);
        SelfHost {
            work,
            config,
            log,
            _server: server,
        }
    }

    /// The *old* gears: the one this test suite was built with.
    fn gears(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gears"));
        command
            .arg("--config")
            .arg(&self.config)
            .arg("--workspace")
            .arg(&self.work)
            .arg("--log-file")
            .arg(&self.log)
            .env_remove("OPENROUTER_API_KEY");
        command
    }

    fn run(&self, prompt: &str) -> Output {
        self.gears().args(["-p", prompt]).output().unwrap()
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

    /// A candidate that is a gears, put there without building one: some of
    /// this is about the restart rather than about what it restarts into.
    fn candidate(&self) -> PathBuf {
        let path = Candidates::new(&self.work).unwrap().path(1).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::copy(env!("CARGO_BIN_EXE_gears"), &path).unwrap();
        path
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// The one session this run wrote, as records.
    fn session(&self) -> Vec<serde_json::Value> {
        let dir = self.work.join(gears::agent::session::SESSIONS_DIR);
        let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                (path.extension()? == "jsonl").then_some(path)
            })
            .collect();
        assert_eq!(files.len(), 1, "{files:?}");
        std::fs::read_to_string(files.remove(0))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        match entry.file_type().unwrap().is_dir() {
            true => copy_tree(&entry.path(), &target),
            false => {
                std::fs::copy(entry.path(), &target).unwrap();
            }
        }
    }
}

/// **The step-9 gate.** Edit, build, validate, keep, restart — and the binary
/// that answers afterwards is the one that was just built, on the session the
/// one before it was writing.
#[test]
fn gears_builds_a_new_gears_and_carries_on_as_it() {
    let build = json!({"target_dir": "target/self", "offline": true});
    let fixture = SelfHost::new(
        "build",
        vec![
            calls(
                "call_1",
                "edit_file",
                json!({
                    "path": "Cargo.toml",
                    "old": "version = \"0.1.0\"",
                    "new": format!("version = \"{MARKER}\""),
                }),
            ),
            calls("call_2", "build", build.clone()),
            // Validate before adopting, and the *old* binary is what runs it.
            // Bounded on purpose: the whole suite before a promotion is the
            // documented manual step, not this one.
            calls(
                "call_3",
                "test",
                json!({"target_dir": "target/self", "offline": true, "args": ["--lib", "config::"]}),
            ),
            calls(
                "call_4",
                "stage_candidate",
                json!({"path": "target/self/debug/gears"}),
            ),
            calls(
                "call_5",
                "restart",
                json!({"candidate": 1, "prompt": "say which gears you are"}),
            ),
            says("Built it, checked it, and restarting into it."),
            // From here on it is the new binary asking.
            says("I am the new gears."),
        ],
    );

    let out = fixture.run("make yourself a new version and carry on in it");
    let shown = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "{shown}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The candidate said what it was, and what it was is the edit.
    assert!(
        shown.contains(&format!("candidate 1 is gears {MARKER}")),
        "{shown}"
    );
    assert!(
        Candidates::new(&fixture.work)
            .unwrap()
            .path(1)
            .unwrap()
            .is_file()
    );
    // The new binary really ran: it says so on the way in, and only a gears
    // built from the edited source says this version.
    assert!(
        fixture.log().contains(&format!("gears {MARKER} starting")),
        "the candidate never started"
    );
    // And it answered, on the same session, with what it was asked at restart.
    assert!(shown.contains("I am the new gears."), "{shown}");

    let session = fixture.session();
    let meta = &session[0];
    assert_eq!(meta["record"], "meta");
    assert_eq!(
        meta["gears"], "0.1.0",
        "the session was not started by the old binary"
    );
    let said: Vec<&str> = session
        .iter()
        .filter(|record| record["record"] == "message")
        .filter_map(|record| record["content"].as_str())
        .collect();
    assert!(
        said.contains(&"say which gears you are"),
        "the continuation is not in the session: {said:?}"
    );
    assert_eq!(said.last(), Some(&"I am the new gears."));
}

/// The interactive loop hands the terminal over rather than going back to its
/// prompt: there is another gears about to take the session on, and two of
/// them reading the same keyboard is nobody's idea of a restart.
#[test]
fn an_interactive_restart_gives_up_the_prompt() {
    let fixture = SelfHost::new(
        "interactive",
        vec![
            calls(
                "call_1",
                "restart",
                json!({"candidate": 1, "prompt": "carry on"}),
            ),
            says("Restarting."),
            says("Carried on."),
        ],
    );
    fixture.candidate();

    // The second line would be answered by a loop that carried on reading.
    let out = fixture.type_at("start again\n/status\n");
    let shown = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "{shown}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(shown.contains("Carried on."), "{shown}");
    assert!(
        !shown.contains("files changed"),
        "the loop went back to the prompt: {shown}"
    );

    // One session, and the new process carried straight on in it.
    let session = fixture.session();
    let said: Vec<&str> = session
        .iter()
        .filter(|record| record["record"] == "message")
        .filter_map(|record| record["content"].as_str())
        .collect();
    assert!(said.contains(&"start again"), "{said:?}");
    assert_eq!(said.last(), Some(&"Carried on."));
}
