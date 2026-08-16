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

use super::{
    Execution, Tool, ToolOutcome, ToolResult, Workspace, opt_string, schema, string_arg,
    string_list, usize_arg,
};
use crate::agent::ToolStream;
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
    /// Extra context for a program the platform could not start.
    pub spawn_context: Option<String>,
}

/// How a command ended and what it said, before either is made into a result.
/// A non-zero exit remains evidence for `run`; typed consumers distinguish a
/// timeout or cancellation.
pub struct Outcome {
    /// `exit status 0`, `killed by signal 9`, `timed out after 120s…`.
    pub status: String,
    pub ok: bool,
    pub output: String,
    pub(crate) end: ProcessEnd,
    full_output: FullOutput,
}

enum FullOutput {
    NotRequested,
    Complete(String),
    Exceeded { bytes: usize, limit: usize },
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcessEnd {
    Exited(ExitStatus),
    TimedOut { complete: bool },
    Cancelled { complete: bool },
}

enum ProcessError {
    Spawn(String),
    Failed(String),
}

impl ProcessError {
    fn message(self) -> String {
        match self {
            ProcessError::Spawn(message) | ProcessError::Failed(message) => message,
        }
    }
}

/// Run `job` to completion, or kill it and everything it started when the
/// timeout runs out, and return what the model reads: how it ended, then what
/// it said.
///
/// A non-zero exit status is *not* an `Err` — a failing build is the feedback
/// signal the agent works from, so `Err` keeps meaning "this could not be run
/// at all".
pub fn execute(job: &Job) -> Result<String, String> {
    Ok(rendered(capture(job)?))
}

/// Execute with live output, elapsed-time, and deadline state.
pub(crate) fn execute_with(job: &Job, execution: &Execution) -> Result<String, String> {
    capture_inner(job, Some(execution), None)
        .map(rendered)
        .map_err(ProcessError::message)
}

fn rendered(outcome: Outcome) -> String {
    match outcome.output.trim().is_empty() {
        true => outcome.status,
        false => format!("{}\n{}", outcome.status, outcome.output),
    }
}

/// The same run, with how it ended still a fact rather than a line of text.
pub fn capture(job: &Job) -> Result<Outcome, String> {
    capture_inner(job, None, None).map_err(ProcessError::message)
}

fn capture_inner(
    job: &Job,
    execution: Option<&Execution>,
    full_output_limit: Option<usize>,
) -> Result<Outcome, ProcessError> {
    let started = Instant::now();
    let execution = execution.map(|context| context.with_deadline(started + job.timeout));
    let mut command = Command::new(&job.program);
    command
        .args(&job.args)
        .current_dir(&job.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = crate::platform::spawn(&mut command).map_err(|error| {
        let mut message = format!("cannot run '{}': {error}", job.program);
        if let Some(context) = &job.spawn_context {
            message.push_str(&format!("; {context}"));
        }
        ProcessError::Spawn(message)
    })?;

    // Both pipes are drained as they fill: a command whose output nobody reads
    // blocks on a full pipe and never reaches its timeout.
    let buffer = Arc::new(Mutex::new(Capture::new(KEPT, full_output_limit)));
    let readers = [
        drain(
            child.stdout.take(),
            buffer.clone(),
            execution.clone(),
            ToolStream::Stdout,
        ),
        drain(
            child.stderr.take(),
            buffer.clone(),
            execution.clone(),
            ToolStream::Stderr,
        ),
    ];
    let finished = wait(&mut child, started, job.timeout, execution.as_ref())
        .map_err(|e| ProcessError::Failed(format!("{}: {e}", job.program)))?;
    if !settle(readers) {
        buffer.lock().unwrap().mark_incomplete();
    }

    let (status, ok) = match finished {
        ProcessEnd::Exited(status) => (crate::platform::status_text(status), status.success()),
        ProcessEnd::TimedOut { complete } => {
            let seconds = job.timeout.as_secs_f64().round();
            let status = if complete {
                format!("timed out after {seconds}s and was killed")
            } else {
                format!("timed out after {seconds}s; process-tree cleanup could not be confirmed")
            };
            (status, false)
        }
        ProcessEnd::Cancelled { complete } => (
            crate::platform::cancellation_text(complete).to_string(),
            false,
        ),
    };
    let (output, full_output) = buffer.lock().unwrap().take();
    Ok(Outcome {
        status,
        ok,
        output,
        end: finished,
        full_output,
    })
}

pub(crate) fn invoke(job: &Job, execution: &Execution, name: &str) -> ToolResult {
    invoked(capture_inner(job, Some(execution), None), name).0
}

pub(crate) fn invoke_recorded(
    job: &Job,
    execution: &Execution,
    name: &str,
    full_output_limit: usize,
) -> (
    ToolResult,
    crate::agent::verification::ProcessEnd,
    Result<String, String>,
) {
    let (result, end, full_output) = invoked(
        capture_inner(job, Some(execution), Some(full_output_limit)),
        name,
    );
    let raw_output = match full_output {
        FullOutput::Complete(output) => Ok(output),
        FullOutput::Exceeded { bytes, limit } => Err(format!(
            "complete output has {bytes} bytes; artifact limit is {limit}"
        )),
        FullOutput::Incomplete => {
            Err("output pipes remained open after the drain deadline".to_string())
        }
        FullOutput::NotRequested => Err("complete output capture was not requested".to_string()),
    };
    (result, end, raw_output)
}

fn invoked(
    captured: Result<Outcome, ProcessError>,
    name: &str,
) -> (
    ToolResult,
    crate::agent::verification::ProcessEnd,
    FullOutput,
) {
    match captured {
        Ok(mut outcome) => {
            let end = outcome.end;
            let full_output = std::mem::replace(&mut outcome.full_output, FullOutput::NotRequested);
            let verification_end = match &end {
                ProcessEnd::Exited(status) => crate::agent::verification::ProcessEnd::Exited {
                    status: crate::platform::status_text(*status),
                    success: status.success(),
                },
                ProcessEnd::TimedOut { .. } => crate::agent::verification::ProcessEnd::TimedOut,
                ProcessEnd::Cancelled { .. } => crate::agent::verification::ProcessEnd::Cancelled,
            };
            let content = rendered(outcome);
            let result = match end {
                ProcessEnd::Exited(_) => ToolResult::ok(content),
                ProcessEnd::TimedOut { .. } => ToolResult::failed(content, ToolOutcome::TimedOut),
                ProcessEnd::Cancelled { .. } => ToolResult::failed(content, ToolOutcome::Cancelled),
            };
            (result, verification_end, full_output)
        }
        Err(ProcessError::Spawn(message)) => (
            ToolResult::failed(format!("{name}: {message}"), ToolOutcome::SpawnFailed),
            crate::agent::verification::ProcessEnd::SpawnFailed,
            FullOutput::Complete(message),
        ),
        Err(ProcessError::Failed(message)) => (
            ToolResult::error(format!("{name}: {message}")),
            crate::agent::verification::ProcessEnd::ExecutionFailed,
            FullOutput::Complete(message),
        ),
    }
}

/// Wait for `child`, killing everything it started once `timeout` is up.
pub(crate) fn wait(
    child: &mut Child,
    started: Instant,
    timeout: Duration,
    execution: Option<&Execution>,
) -> std::io::Result<ProcessEnd> {
    let mut nap = Duration::from_millis(1);
    let mut next_progress = Duration::from_secs(1);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(ProcessEnd::Exited(status));
        }
        if execution.is_some_and(Execution::cancelled) {
            let complete = crate::platform::kill_tree(child);
            child.wait()?;
            return Ok(ProcessEnd::Cancelled { complete });
        }
        let elapsed = started.elapsed();
        if elapsed >= next_progress {
            if let Some(execution) = execution {
                let _ = execution.progress(elapsed);
            }
            next_progress += Duration::from_secs(1);
        }
        let left = match execution.and_then(Execution::deadline) {
            Some(deadline) => deadline.checked_duration_since(Instant::now()),
            None => timeout.checked_sub(elapsed),
        };
        let Some(left) = left else {
            let complete = crate::platform::kill_tree(child);
            child.wait()?;
            return Ok(ProcessEnd::TimedOut { complete });
        };
        std::thread::sleep(nap.min(left));
        nap = (nap * 2).min(Duration::from_millis(25));
    }
}

fn drain<R: Read + Send + 'static>(
    pipe: Option<R>,
    into: Arc<Mutex<Capture>>,
    execution: Option<Execution>,
    stream: ToolStream,
) -> Option<std::thread::JoinHandle<()>> {
    let mut pipe = pipe?;
    Some(std::thread::spawn(move || {
        let mut buffer = [0u8; 8192];
        while let Ok(read @ 1..) = pipe.read(&mut buffer) {
            let mut capture = into.lock().unwrap();
            capture.push(&buffer[..read]);
            if let Some(execution) = &execution {
                let text = String::from_utf8_lossy(&buffer[..read]);
                let _ = execution.output(stream, &text);
            }
        }
    }))
}

/// Give the readers a moment to finish, then leave them to it. Normally both
/// see the end of their pipe as the command exits and this returns at once;
/// what it refuses to do is block forever on a pipe some grandchild still
/// holds open.
fn settle(readers: [Option<std::thread::JoinHandle<()>>; 2]) -> bool {
    let deadline = Instant::now() + DRAIN_GRACE;
    let mut complete = true;
    for reader in readers.into_iter().flatten() {
        while !reader.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        complete &= reader.is_finished();
    }
    complete
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
    full: Option<CompleteCapture>,
}

struct CompleteCapture {
    bytes: Vec<u8>,
    total: usize,
    limit: usize,
    incomplete: bool,
}

impl Capture {
    fn new(limit: usize, full_limit: Option<usize>) -> Capture {
        Capture {
            head: Vec::new(),
            tail: Vec::new(),
            dropped: 0,
            limit,
            full: full_limit.map(|limit| CompleteCapture {
                bytes: Vec::new(),
                total: 0,
                limit,
                incomplete: false,
            }),
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        if let Some(full) = &mut self.full {
            full.total = full.total.saturating_add(bytes.len());
            let room = full.limit.saturating_sub(full.bytes.len()).min(bytes.len());
            full.bytes.extend_from_slice(&bytes[..room]);
        }
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

    fn mark_incomplete(&mut self) {
        if let Some(full) = &mut self.full {
            full.incomplete = true;
        }
    }

    /// The captured text, leaving the buffer empty. Bytes are decoded lossily:
    /// a command may emit anything, and one bad byte must not lose the log.
    fn take(&mut self) -> (String, FullOutput) {
        self.trim();
        let head = String::from_utf8_lossy(&self.head).into_owned();
        let tail = String::from_utf8_lossy(&self.tail).into_owned();
        let dropped = self.dropped;
        let full_limit = self.full.as_ref().map(|full| full.limit);
        let full = match self.full.take() {
            None => FullOutput::NotRequested,
            Some(full) if full.incomplete => FullOutput::Incomplete,
            Some(full) if full.total <= full.limit => {
                FullOutput::Complete(String::from_utf8_lossy(&full.bytes).into_owned())
            }
            Some(full) => FullOutput::Exceeded {
                bytes: full.total,
                limit: full.limit,
            },
        };
        *self = Capture::new(self.limit, full_limit);
        let shown = match (tail.is_empty(), dropped) {
            (true, _) => head,
            (false, 0) => format!("{head}{tail}"),
            (false, n) => format!("{head}\n… [{n} bytes elided] …\n{tail}"),
        };
        (shown, full)
    }

    #[cfg(test)]
    fn take_text(&mut self) -> String {
        self.take().0
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
        execute(&self.job(args)?)
    }

    fn execute(&self, args: &Value, execution: &Execution) -> Result<String, String> {
        execute_with(&self.job(args)?, execution)
    }

    fn invoke(&self, args: &Value, execution: &Execution) -> ToolResult {
        match self.job(args) {
            Ok(job) => invoke(&job, execution, self.name()),
            Err(message) => ToolResult::error(format!("{}: {message}", self.name())),
        }
    }

    fn cap(&self) -> usize {
        // Above what `execute` keeps, so the capture's own eliding is the only
        // one that happens.
        64 * 1024
    }
}

impl RunTool {
    fn job(&self, args: &Value) -> Result<Job, String> {
        let program = string_arg(args, "command")?;
        if program.is_empty() {
            return Err("'command' must not be empty".to_string());
        }
        refuse_motor_cargo(&program, cfg!(not(unix)))?;
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
        Ok(Job {
            program,
            args: string_list(args, "args")?,
            cwd,
            timeout: timeout_arg(args, self.timeout)?,
            spawn_context: None,
        })
    }
}

/// Motor has Lorry rather than Cargo. Refuse before permission or spawn so a
/// model gets one precise correction and no wrapper is implied.
fn refuse_motor_cargo(program: &str, motor: bool) -> Result<(), String> {
    if motor
        && PathBuf::from(program)
            .file_name()
            .and_then(|name| name.to_str())
            == Some("cargo")
    {
        return Err(
            "Motor OS does not provide Cargo; use the build or test tool, or run a supported lorry command"
                .to_string(),
        );
    }
    Ok(())
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
        let mut capture = Capture::new(4, None);
        capture.push(b"headXXXXXXXXtail");
        assert_eq!(capture.take_text(), "head\n… [8 bytes elided] …\ntail");
        // Nothing dropped: no marker, and the text is exactly what went in.
        let mut capture = Capture::new(4, None);
        capture.push(b"head");
        capture.push(b"tail");
        assert_eq!(capture.take_text(), "headtail");
        // And taking it leaves the buffer empty.
        assert_eq!(capture.take_text(), "");
    }

    #[test]
    fn a_bounded_view_can_keep_separate_complete_evidence() {
        let bytes = b"headXXXXXXXXXXXXXXXXtail";
        let mut capture = Capture::new(4, Some(bytes.len()));
        capture.push(bytes);
        let (shown, full) = capture.take();
        assert_eq!(shown, "head\n… [16 bytes elided] …\ntail");
        assert!(matches!(full, FullOutput::Complete(text) if text.as_bytes() == bytes));

        let mut capture = Capture::new(4, Some(bytes.len() - 1));
        capture.push(bytes);
        assert!(matches!(
            capture.take().1,
            FullOutput::Exceeded { bytes: actual, limit } if actual == bytes.len() && limit == bytes.len() - 1
        ));
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
        let (tx, _rx) = crate::agent::event_channel();
        let execution = crate::agent::Bus::new(crate::agent::ROOT, tx).execution();
        let out = tool.invoke(
            &json!({"command": "sh", "args": ["-c", "exit 3"]}),
            &execution,
        );
        assert_eq!(out.outcome, ToolOutcome::Completed);
        assert!(!out.is_error());
        assert_eq!(out.content, "exit status 3");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_live_command_streams_both_pipes_and_elapsed_time_before_it_ends() {
        let (dir, _) = workspace("live");
        let job = Job {
            program: "sh".to_string(),
            args: vec![
                "-c".to_string(),
                "printf 'out\\n'; sleep 1.1; printf 'err\\n' >&2".to_string(),
            ],
            cwd: dir.clone(),
            timeout: DEFAULT_TIMEOUT,
            spawn_context: None,
        };
        let (tx, rx) = crate::agent::event_channel();
        let execution = crate::agent::Bus::new(crate::agent::ROOT, tx).execution();
        let running = std::thread::spawn(move || invoke(&job, &execution, "run"));

        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            crate::agent::Event::ToolOutput {
                stream: ToolStream::Stdout,
                text,
                ..
            } if text == "out\n"
        ));
        let result = running.join().unwrap();
        let events: Vec<_> = rx.try_iter().collect();
        assert!(events.iter().any(|event| matches!(
            event,
            crate::agent::Event::ToolProgress { elapsed, .. }
                if *elapsed >= Duration::from_secs(1)
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            crate::agent::Event::ToolOutput {
                stream: ToolStream::Stderr,
                text,
                ..
            } if text == "err\n"
        )));
        assert_eq!(result.outcome, ToolOutcome::Completed);
        assert_eq!(result.content, "exit status 0\nout\nerr\n");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cancelling_a_live_command_kills_its_descendants_promptly() {
        let (dir, _) = workspace("cancel");
        let sentinel = dir.join("survived");
        let job = Job {
            program: "sh".to_string(),
            args: vec![
                "-c".to_string(),
                format!(
                    "printf 'ready\\n'; (sleep 0.2; printf survived > '{}') & wait",
                    sentinel.display()
                ),
            ],
            cwd: dir.clone(),
            timeout: Duration::from_secs(2),
            spawn_context: None,
        };
        let (tx, rx) = crate::agent::event_channel();
        let bus = crate::agent::Bus::new(crate::agent::ROOT, tx);
        let execution = bus.execution();
        let running = std::thread::spawn(move || invoke(&job, &execution, "run"));
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            crate::agent::Event::ToolOutput { text, .. } if text == "ready\n"
        ));

        let cancelled_at = Instant::now();
        bus.canceller().raise();
        let result = running.join().unwrap();
        assert!(cancelled_at.elapsed() < Duration::from_secs(1));
        assert_eq!(result.outcome, ToolOutcome::Cancelled);
        assert!(result.is_error());
        assert!(
            result
                .content
                .starts_with("cancelled; killed the process group\nready\n")
        );
        std::thread::sleep(Duration::from_millis(400));
        assert!(!sentinel.exists(), "a descendant survived cancellation");
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

    /// More output than the live queue can hold must apply backpressure while
    /// both pipes keep draining. The UI counts chunks instead of retaining
    /// them; only the bounded final head and tail survive the call.
    #[cfg(unix)]
    #[test]
    fn a_live_flood_drains_both_pipes_and_retains_one_bounded_result() {
        let (dir, _) = workspace("live-flood");
        let job = Job {
            program: "sh".to_string(),
            args: vec![
                "-c".to_string(),
                "printf 'BEGIN\\n'; sleep 0.05; i=0; \
                 while [ \"$i\" -lt 20000 ]; do \
                   printf 'stdout-%05d-xxxxxxxxxxxxxxxx\\n' \"$i\"; \
                   printf 'stderr-%05d-yyyyyyyyyyyyyyyy\\n' \"$i\" >&2; \
                   i=$((i+1)); \
                 done; \
                 sleep 0.05; printf 'END\\n' >&2"
                    .to_string(),
            ],
            cwd: dir.clone(),
            timeout: Duration::from_secs(10),
            spawn_context: None,
        };
        let (tx, rx) = crate::agent::event_channel();
        let execution = crate::agent::Bus::new(crate::agent::ROOT, tx).execution();
        let running = std::thread::spawn(move || invoke(&job, &execution, "run"));
        let mut stdout = 0;
        let mut stderr = 0;
        loop {
            match rx.recv_timeout(Duration::from_secs(2)) {
                Ok(crate::agent::Event::ToolOutput { stream, text, .. }) => {
                    assert!(text.len() <= crate::tools::LIVE_CHUNK_BYTES);
                    match stream {
                        ToolStream::Stdout => stdout += text.len(),
                        ToolStream::Stderr => stderr += text.len(),
                    }
                }
                Ok(crate::agent::Event::ToolProgress { .. }) => {}
                Ok(event) => panic!("unexpected live event: {event:?}"),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    assert!(running.is_finished(), "the live flood stopped draining");
                    break;
                }
            }
        }

        let result = running.join().unwrap();
        assert_eq!(result.outcome, ToolOutcome::Completed, "{result:?}");
        assert!(stdout > 500_000 && stderr > 500_000, "{stdout}, {stderr}");
        assert!(
            stdout + stderr > crate::agent::EVENT_QUEUE_CAPACITY * crate::tools::LIVE_CHUNK_BYTES
        );
        assert_eq!(result.content.matches("bytes elided").count(), 1);
        assert!(result.content.starts_with("exit status 0\nBEGIN\n"));
        assert!(result.content.ends_with("\nEND\n"), "{result:?}");
        assert!(result.content.len() < 64 * 1024);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_command_that_never_ends_is_killed() {
        let (dir, workspace) = workspace("timeout");
        let tool = tool(workspace, DEFAULT_TIMEOUT);
        let started = Instant::now();
        let (tx, _rx) = crate::agent::event_channel();
        let execution = crate::agent::Bus::new(crate::agent::ROOT, tx).execution();
        let out = tool.invoke(
            &json!({"command": "sh", "args": ["-c", "echo starting; sleep 30"],
                    "timeout_seconds": 1}),
            &execution,
        );
        assert!(started.elapsed() < Duration::from_secs(10), "it waited");
        assert_eq!(out.outcome, ToolOutcome::TimedOut);
        assert!(out.is_error());
        assert!(
            out.content.starts_with("timed out after 1s and was killed"),
            "{out:?}"
        );
        // What it managed to say before it was killed is still reported.
        assert!(out.content.contains("starting"), "{out:?}");
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
        let (tx, _rx) = crate::agent::event_channel();
        let execution = crate::agent::Bus::new(crate::agent::ROOT, tx).execution();
        let missing = tool.invoke(&json!({"command": "no-such-program-anywhere"}), &execution);
        assert_eq!(missing.outcome, ToolOutcome::SpawnFailed);
        assert!(missing.content.contains("cannot run"), "{missing:?}");
        assert!(call(&*tool, json!({"command": ""})).is_err());
        assert!(call(&*tool, json!({"command": "sh", "args": "-c"})).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn motor_refuses_raw_cargo_before_spawn() {
        for program in ["cargo", "/somewhere/cargo"] {
            let error = refuse_motor_cargo(program, true).unwrap_err();
            assert!(error.contains("Motor OS"), "{error}");
            assert!(error.contains("build or test"), "{error}");
            assert!(error.contains("lorry"), "{error}");
        }
        assert!(refuse_motor_cargo("lorry", true).is_ok());
        assert!(refuse_motor_cargo("rush", true).is_ok());
        assert!(refuse_motor_cargo("cargo", false).is_ok());
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
