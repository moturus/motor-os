//! Running programs: the deliberate escape hatch from everything `fs.rs`
//! confines, and the reason every call goes through the permission gate under
//! a key naming the command rather than the tool.
//!
//! There is **no shell**. A command is a program and an argument vector, so
//! there is nothing to quote, nothing to expand, and no second interpreter
//! between what the user was asked about and what runs. Motor OS is the other
//! reason: a shell is not a thing gears may assume is there.
//!
//! [`execute`] is shared with `toolchain.rs`, which is the same machinery with
//! the argument vector built for it.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::{Tool, Workspace, opt_string, schema, string_arg, string_list, usize_arg};
use crate::provider::ToolSpec;

/// The longest any one call may ask to wait, whatever the config or the model
/// says. A command that has not finished in an hour is not going to.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(3600);

/// Defaults, overridable per call and in the config: a command is usually
/// quick, and a build usually is not.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
pub const DEFAULT_BUILD_TIMEOUT: Duration = Duration::from_secs(900);

/// Output kept from one command, at *each* end — so twice this, plus the
/// marker between them, has to stay under [`RunTool::cap`]. That is the point:
/// eliding then happens once, here, with an exact count, rather than twice
/// with the second count swallowing the first.
const KEPT: usize = 16 * 1024;

/// How long to wait for the pipes to drain after the command itself is gone.
/// A background process it left behind still holds them open, and gears was
/// not asked to wait for that one.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// One command, already checked: nothing here came straight from the model.
pub struct Job {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub timeout: Duration,
}

/// How a command ended and what it said, before either is made into a result.
/// `run` reports both to the model and calls neither a failure; `vcs.rs` reads
/// `ok`, because a commit that did not happen must not look like one that did.
pub struct Outcome {
    /// `exit status 0`, `killed by signal 9`, `timed out after 120s…`.
    pub status: String,
    pub ok: bool,
    pub output: String,
}

/// Run `job` to completion, or kill it and everything it started when the
/// timeout runs out, and return what the model reads: how it ended, then what
/// it said.
///
/// A non-zero exit status is *not* an `Err` — a failing build is the feedback
/// signal the agent works from, so `Err` keeps meaning "this could not be run
/// at all".
pub fn execute(job: &Job) -> Result<String, String> {
    let outcome = capture(job)?;
    Ok(match outcome.output.trim().is_empty() {
        true => outcome.status,
        false => format!("{}\n{}", outcome.status, outcome.output),
    })
}

/// The same run, with how it ended still a fact rather than a line of text.
pub fn capture(job: &Job) -> Result<Outcome, String> {
    let mut command = Command::new(&job.program);
    command
        .args(&job.args)
        .current_dir(&job.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = crate::platform::spawn(&mut command)
        .map_err(|e| format!("cannot run '{}': {e}", job.program))?;

    // Both pipes are drained as they fill: a command whose output nobody reads
    // blocks on a full pipe and never reaches its timeout.
    let buffer = Arc::new(Mutex::new(Capture::new(KEPT)));
    let readers = [
        drain(child.stdout.take(), buffer.clone()),
        drain(child.stderr.take(), buffer.clone()),
    ];
    let finished = wait(&mut child, job.timeout).map_err(|e| format!("{}: {e}", job.program))?;
    settle(readers);

    let (status, ok) = match finished {
        Some(status) => (crate::platform::status_text(status), status.success()),
        None => (
            format!(
                "timed out after {}s and was killed",
                job.timeout.as_secs_f64().round()
            ),
            false,
        ),
    };
    Ok(Outcome {
        status,
        ok,
        output: buffer.lock().unwrap().take_text(),
    })
}

/// Wait for `child`, killing everything it started once `timeout` is up.
/// `None` means it was killed rather than finished.
fn wait(child: &mut Child, timeout: Duration) -> std::io::Result<Option<ExitStatus>> {
    let start = Instant::now();
    let mut nap = Duration::from_millis(1);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let Some(left) = timeout.checked_sub(start.elapsed()) else {
            crate::platform::kill_tree(child);
            child.wait()?;
            return Ok(None);
        };
        std::thread::sleep(nap.min(left));
        nap = (nap * 2).min(Duration::from_millis(25));
    }
}

fn drain<R: Read + Send + 'static>(
    pipe: Option<R>,
    into: Arc<Mutex<Capture>>,
) -> Option<std::thread::JoinHandle<()>> {
    let mut pipe = pipe?;
    Some(std::thread::spawn(move || {
        let mut buffer = [0u8; 8192];
        while let Ok(read @ 1..) = pipe.read(&mut buffer) {
            into.lock().unwrap().push(&buffer[..read]);
        }
    }))
}

/// Give the readers a moment to finish, then leave them to it. Normally both
/// see the end of their pipe as the command exits and this returns at once;
/// what it refuses to do is block forever on a pipe some grandchild still
/// holds open.
fn settle(readers: [Option<std::thread::JoinHandle<()>>; 2]) {
    let deadline = Instant::now() + DRAIN_GRACE;
    for reader in readers.into_iter().flatten() {
        while !reader.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// A bounded copy of what a command said: the first `limit` bytes and the last
/// `limit`, with an exact count of what fell out between them. Both ends are
/// worth keeping — the head says what was attempted, the tail how it went —
/// and neither is worth an unbounded buffer.
struct Capture {
    head: Vec<u8>,
    tail: Vec<u8>,
    dropped: usize,
    limit: usize,
}

impl Capture {
    fn new(limit: usize) -> Capture {
        Capture {
            head: Vec::new(),
            tail: Vec::new(),
            dropped: 0,
            limit,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        let room = self.limit.saturating_sub(self.head.len()).min(bytes.len());
        self.head.extend_from_slice(&bytes[..room]);
        self.tail.extend_from_slice(&bytes[room..]);
        // Compacted in batches, so a chatty command does not move the whole
        // tail once per write.
        if self.tail.len() > self.limit * 2 {
            self.trim();
        }
    }

    fn trim(&mut self) {
        let over = self.tail.len().saturating_sub(self.limit);
        self.tail.drain(..over);
        self.dropped += over;
    }

    /// The captured text, leaving the buffer empty. Bytes are decoded lossily:
    /// a command may emit anything, and one bad byte must not lose the log.
    fn take_text(&mut self) -> String {
        self.trim();
        let head = String::from_utf8_lossy(&self.head).into_owned();
        let tail = String::from_utf8_lossy(&self.tail).into_owned();
        let dropped = self.dropped;
        *self = Capture::new(self.limit);
        match (tail.is_empty(), dropped) {
            (true, _) => head,
            (false, 0) => format!("{head}{tail}"),
            (false, n) => format!("{head}\n… [{n} bytes elided] …\n{tail}"),
        }
    }
}

/// The timeout a call asked for, bounded by what gears will wait for.
pub fn timeout_arg(args: &Value, default: Duration) -> Result<Duration, String> {
    let seconds = usize_arg(args, "timeout_seconds", default.as_secs() as usize)?;
    Ok(Duration::from_secs(seconds as u64).clamp(Duration::from_secs(1), MAX_TIMEOUT))
}

/// The `timeout_seconds` argument, described the same way wherever it appears.
pub fn timeout_property(default: Duration) -> Value {
    json!({
        "type": "integer",
        "description": format!(
            "Give up and kill the command after this long (default {}s, maximum {}s).",
            default.as_secs(), MAX_TIMEOUT.as_secs()),
    })
}

pub struct RunTool {
    workspace: Arc<Workspace>,
    timeout: Duration,
}

pub fn tool(workspace: Arc<Workspace>, timeout: Duration) -> Box<dyn Tool> {
    Box::new(RunTool { workspace, timeout })
}

impl Tool for RunTool {
    fn name(&self) -> &'static str {
        "run"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "run",
            "Run a program and return what it printed. There is no shell: pipes, \
             redirection, globbing, '&&' and variable expansion do not work, and \
             each argument goes in 'args' separately. stdout and stderr come back \
             merged, and the first line says how the command ended.",
            schema(
                json!({
                    "command": {"type": "string", "description": "The program to run."},
                    "args": {"type": "array", "items": {"type": "string"}},
                    "cwd": {"type": "string", "description":
                        "Directory to run in, relative to the workspace root (default: the root)."},
                    "timeout_seconds": timeout_property(self.timeout),
                }),
                &["command"],
            ),
        )
    }

    fn mutates(&self) -> bool {
        true
    }

    /// The command as written, not its file name: "always allow cargo" must
    /// not quietly cover a `cargo` somewhere else on the disk.
    fn permission_key(&self, args: &Value) -> String {
        match &args["command"] {
            Value::String(command) => format!("run:{command}"),
            _ => "run".to_string(),
        }
    }

    fn call(&self, args: &Value) -> Result<String, String> {
        let program = string_arg(args, "command")?;
        if program.is_empty() {
            return Err("'command' must not be empty".to_string());
        }
        let cwd = match opt_string(args, "cwd")? {
            Some(given) => {
                let path = self.workspace.resolve(&given)?;
                if !path.is_dir() {
                    return Err(format!("'{given}' is not a directory"));
                }
                path
            }
            None => self.workspace.root().to_path_buf(),
        };
        let job = Job {
            program,
            args: string_list(args, "args")?,
            cwd,
            timeout: timeout_arg(args, self.timeout)?,
        };
        execute(&job)
    }

    fn cap(&self) -> usize {
        // Above what `execute` keeps, so the capture's own eliding is the only
        // one that happens.
        64 * 1024
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace(name: &str) -> (PathBuf, Arc<Workspace>) {
        let dir = std::env::temp_dir().join(format!("gears-run-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("inside")).unwrap();
        let workspace = Arc::new(Workspace::new(&dir).unwrap());
        (dir, workspace)
    }

    fn call(tool: &dyn Tool, args: Value) -> Result<String, String> {
        tool.call(&args)
    }

    #[test]
    fn a_capture_keeps_both_ends_and_counts_the_middle() {
        let mut capture = Capture::new(4);
        capture.push(b"headXXXXXXXXtail");
        assert_eq!(capture.take_text(), "head\n… [8 bytes elided] …\ntail");
        // Nothing dropped: no marker, and the text is exactly what went in.
        let mut capture = Capture::new(4);
        capture.push(b"head");
        capture.push(b"tail");
        assert_eq!(capture.take_text(), "headtail");
        // And taking it leaves the buffer empty.
        assert_eq!(capture.take_text(), "");
    }

    #[cfg(unix)]
    #[test]
    fn a_command_runs_and_both_streams_come_back() {
        let (dir, workspace) = workspace("output");
        let tool = tool(workspace, DEFAULT_TIMEOUT);
        let out = call(
            &*tool,
            json!({"command": "sh", "args": ["-c", "echo out; echo err >&2"]}),
        )
        .unwrap();
        assert!(out.starts_with("exit status 0\n"), "{out}");
        assert!(out.contains("out"), "{out}");
        assert!(out.contains("err"), "{out}");

        // A failing command is not a tool error: the status is the answer.
        let out = call(&*tool, json!({"command": "sh", "args": ["-c", "exit 3"]})).unwrap();
        assert_eq!(out, "exit status 3");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A command can say more than a context window holds. What comes back
    /// keeps both ends, and says how much fell out — *once*: a second eliding
    /// pass by the registry's cap would report a byte count that is not the
    /// one that was really dropped.
    #[cfg(unix)]
    #[test]
    fn a_flood_of_output_is_elided_exactly_once() {
        let (dir, workspace) = workspace("flood");
        let tool = tool(workspace, DEFAULT_TIMEOUT);
        let out = call(
            &*tool,
            json!({"command": "sh", "args": ["-c", "seq 1 40000"]}),
        )
        .unwrap();
        assert!(out.len() < tool.cap(), "{} bytes", out.len());
        assert_eq!(out.matches("bytes elided").count(), 1, "{}", out.len());
        assert!(out.starts_with("exit status 0\n1\n2\n"), "{}", &out[..40]);
        assert!(out.ends_with("\n40000\n"), "{}", &out[out.len() - 40..]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_command_that_never_ends_is_killed() {
        let (dir, workspace) = workspace("timeout");
        let tool = tool(workspace, DEFAULT_TIMEOUT);
        let started = Instant::now();
        let out = call(
            &*tool,
            json!({"command": "sh", "args": ["-c", "echo starting; sleep 30"],
                   "timeout_seconds": 1}),
        )
        .unwrap();
        assert!(started.elapsed() < Duration::from_secs(10), "it waited");
        assert!(
            out.starts_with("timed out after 1s and was killed"),
            "{out}"
        );
        // What it managed to say before it was killed is still reported.
        assert!(out.contains("starting"), "{out}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The mechanism behind that kill: the child leads a group of its own, so
    /// the timeout reaches what the command started as well as the command.
    #[cfg(unix)]
    #[test]
    fn a_command_leads_its_own_process_group() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 5"]).stdout(Stdio::null());
        let child = crate::platform::spawn(&mut command).unwrap();
        let pid = child.id() as libc::pid_t;
        assert_eq!(unsafe { libc::getpgid(pid) }, pid);
        crate::platform::kill_tree(&child);
        let mut child = child;
        assert!(!child.wait().unwrap().success());
    }

    #[cfg(unix)]
    #[test]
    fn a_command_runs_where_it_was_told_to() {
        let (dir, workspace) = workspace("cwd");
        let root = workspace.root().to_path_buf();
        let tool = tool(workspace, DEFAULT_TIMEOUT);
        let out = call(&*tool, json!({"command": "pwd", "cwd": "inside"})).unwrap();
        assert!(
            out.contains(&root.join("inside").display().to_string()),
            "{out}"
        );

        // The workspace still bounds it, and a file is not a directory.
        let error = call(&*tool, json!({"command": "pwd", "cwd": "/etc"})).unwrap_err();
        assert!(error.contains("outside the workspace"), "{error}");
        std::fs::write(root.join("f.txt"), "x").unwrap();
        let error = call(&*tool, json!({"command": "pwd", "cwd": "f.txt"})).unwrap_err();
        assert!(error.contains("not a directory"), "{error}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_command_that_is_not_there_is_reported_not_run() {
        let (dir, workspace) = workspace("missing");
        let tool = tool(workspace, DEFAULT_TIMEOUT);
        let error = call(&*tool, json!({"command": "no-such-program-anywhere"})).unwrap_err();
        assert!(error.contains("cannot run"), "{error}");
        assert!(call(&*tool, json!({"command": ""})).is_err());
        assert!(call(&*tool, json!({"command": "sh", "args": "-c"})).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_call_is_remembered_by_its_command_and_bounded_by_the_maximum() {
        let (dir, workspace) = workspace("keys");
        let tool = tool(workspace, DEFAULT_TIMEOUT);
        assert_eq!(
            tool.permission_key(&json!({"command": "cargo", "args": ["build"]})),
            "run:cargo"
        );
        assert_eq!(
            tool.permission_key(&json!({"command": "/tmp/cargo"})),
            "run:/tmp/cargo"
        );
        assert_eq!(
            timeout_arg(&json!({"timeout_seconds": 99999}), DEFAULT_TIMEOUT).unwrap(),
            MAX_TIMEOUT
        );
        assert_eq!(
            timeout_arg(&json!({"timeout_seconds": 0}), DEFAULT_TIMEOUT).unwrap(),
            Duration::from_secs(1)
        );
        assert_eq!(
            timeout_arg(&json!({}), DEFAULT_TIMEOUT).unwrap(),
            DEFAULT_TIMEOUT
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
