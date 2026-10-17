//! Bounded, cancellable child-process execution shared by sh and hooks.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub use crate::cancellation::Cancellation;

const DRAIN_GRACE: Duration = Duration::from_secs(2);
static CLEANUP_FAILED: AtomicBool = AtomicBool::new(false);

/// A failed cleanup leaves ownership uncertain. Closing the current turn's
/// history is allowed, but no later work may start in this process.
pub fn ensure_cleanup() -> Result<(), String> {
    if CLEANUP_FAILED.load(Ordering::SeqCst) {
        Err(
            "previous child process-tree cleanup could not be confirmed; further work is blocked"
                .into(),
        )
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

pub struct Request {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub stdin: Option<Vec<u8>>,
    pub timeout: Duration,
    pub max_output_bytes: usize,
    pub env: Vec<(String, String)>,
    pub remove_env: Vec<String>,
}

#[derive(Debug)]
pub struct RunError {
    pub detail: String,
    pub started: bool,
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.detail.fmt(f)
    }
}

impl std::error::Error for RunError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub stdout: String,
    pub stderr: String,
    pub status: String,
    pub code: Option<i32>,
    pub timed_out: bool,
    pub cancelled: bool,
    pub stdout_dropped: usize,
    pub stderr_dropped: usize,
}

impl Output {
    pub fn success(&self) -> bool {
        self.code == Some(0) && !self.timed_out && !self.cancelled
    }

    pub fn model_text(&self, per_stream_bytes: usize) -> String {
        let stdout = bounded_view(&self.stdout, per_stream_bytes, self.stdout_dropped);
        let stderr = bounded_view(&self.stderr, per_stream_bytes, self.stderr_dropped);
        let mut result = self.status.clone();
        if !stdout.is_empty() {
            result.push_str("\nstdout:\n");
            result.push_str(&stdout);
        }
        if !stderr.is_empty() {
            result.push_str("\nstderr:\n");
            result.push_str(&stderr);
        }
        result
    }

    pub fn model_stdout(&self, max_bytes: usize) -> String {
        bounded_view(&self.stdout, max_bytes, self.stdout_dropped)
    }
}

pub fn sh(
    workspace: PathBuf,
    script: &str,
    timeout: Duration,
    max_output_bytes: usize,
    cancellation: &Cancellation,
    observer: &mut dyn FnMut(Stream, &str),
) -> Result<Output, RunError> {
    run(
        &Request {
            program: shell_program().to_string(),
            args: vec!["-c".to_string(), script.to_string()],
            cwd: workspace,
            stdin: None,
            timeout,
            max_output_bytes,
            env: Vec::new(),
            remove_env: vec![crate::provider::KEY_ENV.to_string()],
        },
        cancellation,
        observer,
    )
}

/// Manifests and hooks name `gears-batteries` bare; it is installed beside Gears.
pub fn program_path(program: &str) -> Result<PathBuf, String> {
    if program != "gears-batteries" {
        return Ok(PathBuf::from(program));
    }
    std::env::current_exe()
        .map(|gears| gears.with_file_name(program))
        .map_err(|error| format!("cannot locate Gears executable: {error}"))
}

pub fn run(
    request: &Request,
    cancellation: &Cancellation,
    observer: &mut dyn FnMut(Stream, &str),
) -> Result<Output, RunError> {
    ensure_cleanup().map_err(|detail| RunError {
        detail,
        started: false,
    })?;
    let program = program_path(&request.program).map_err(|detail| RunError {
        detail,
        started: false,
    })?;
    let mut command = Command::new(program);
    command
        .args(&request.args)
        .current_dir(&request.cwd)
        .stdin(if request.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in &request.env {
        command.env(name, value);
    }
    for name in &request.remove_env {
        command.env_remove(name);
    }
    if cancellation.cancelled() {
        return Err(RunError {
            detail: "cancelled before starting the child process".into(),
            started: false,
        });
    }
    let mut child = crate::platform::spawn(&mut command).map_err(|error| RunError {
        detail: format!("cannot run {}: {error}", request.program),
        started: false,
    })?;
    let (sender, receiver) = mpsc::channel();
    let readers = [
        drain(child.stdout.take(), Stream::Stdout, sender.clone()),
        drain(child.stderr.take(), Stream::Stderr, sender),
    ];
    let input = request.stdin.clone().and_then(|bytes| {
        let mut stdin = child.stdin.take()?;
        Some(std::thread::spawn(move || {
            let result = stdin.write_all(&bytes);
            drop(stdin);
            result
        }))
    });

    let started = Instant::now();
    let mut stdout = Capture::new(request.max_output_bytes);
    let mut stderr = Capture::new(request.max_output_bytes);
    let mut timed_out = false;
    let mut was_cancelled = false;
    let (status, mut cleanup_complete) = loop {
        while let Ok((stream, bytes)) = receiver.try_recv() {
            receive(stream, &bytes, &mut stdout, &mut stderr, observer);
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                // A wrapper can exit while its descendants still hold our pipes.
                break (status, crate::platform::cleanup_after_exit(&child));
            }
            Ok(None) => {}
            Err(error) => {
                let cleaned = crate::platform::kill_tree(&child);
                if child.wait().is_err() || !cleaned {
                    CLEANUP_FAILED.store(true, Ordering::SeqCst);
                }
                return Err(RunError {
                    detail: format!(
                        "cannot wait for {}: {error}; process-tree cleanup {}",
                        request.program,
                        if cleaned {
                            "completed"
                        } else {
                            "could not be confirmed"
                        }
                    ),
                    started: true,
                });
            }
        }
        if cancellation.cancelled() {
            was_cancelled = true;
        } else if started.elapsed() >= request.timeout {
            timed_out = true;
        }
        if was_cancelled || timed_out {
            let cleanup_complete = crate::platform::kill_tree(&child);
            let status = child.wait().map_err(|error| RunError {
                detail: {
                    CLEANUP_FAILED.store(true, Ordering::SeqCst);
                    format!("cannot reap {}: {error}", request.program)
                },
                started: true,
            })?;
            if !cleanup_complete {
                crate::trace::log(
                    crate::trace::Level::Warn,
                    "child process-tree cleanup could not be confirmed",
                );
            }
            break (status, cleanup_complete);
        }
        match receiver.recv_timeout(Duration::from_millis(10)) {
            Ok((stream, bytes)) => receive(stream, &bytes, &mut stdout, &mut stderr, observer),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                std::thread::yield_now();
            }
        }
    };

    // A surviving descendant can hold a pipe open; the stdin writer then
    // blocks too. Neither may keep this runner waiting past the grace.
    let unfinished = |input: &Option<std::thread::JoinHandle<std::io::Result<()>>>| {
        readers.iter().flatten().any(|reader| !reader.is_finished())
            || input.as_ref().is_some_and(|input| !input.is_finished())
    };
    let deadline = Instant::now() + DRAIN_GRACE;
    while unfinished(&input) && Instant::now() < deadline {
        if let Ok((stream, bytes)) = receiver.recv_timeout(Duration::from_millis(5)) {
            receive(stream, &bytes, &mut stdout, &mut stderr, observer);
        }
    }
    while let Ok((stream, bytes)) = receiver.try_recv() {
        receive(stream, &bytes, &mut stdout, &mut stderr, observer);
    }
    if unfinished(&input) {
        cleanup_complete = false;
    }
    if !cleanup_complete {
        CLEANUP_FAILED.store(true, Ordering::SeqCst);
        return Err(RunError {
            detail: format!(
                "{}: process-tree cleanup could not be confirmed",
                request.program
            ),
            started: true,
        });
    }
    if let Some(input) = input {
        let result = input.join().map_err(|_| RunError {
            detail: format!("{} stdin writer panicked", request.program),
            started: true,
        })?;
        if let Err(error) = result
            && !((was_cancelled || timed_out) && error.kind() == std::io::ErrorKind::BrokenPipe)
        {
            return Err(RunError {
                detail: format!("{} stdin: {error}", request.program),
                started: true,
            });
        }
    }
    let (stdout_text, stdout_dropped) = stdout.finish();
    let (stderr_text, stderr_dropped) = stderr.finish();
    let status_text = if was_cancelled {
        crate::platform::cancellation_text(cleanup_complete).to_string()
    } else if timed_out {
        if cleanup_complete {
            format!(
                "timed out after {}s and was killed",
                request.timeout.as_secs()
            )
        } else {
            format!(
                "timed out after {}s; process-tree cleanup could not be confirmed",
                request.timeout.as_secs()
            )
        }
    } else {
        crate::platform::status_text(status)
    };
    Ok(Output {
        stdout: stdout_text,
        stderr: stderr_text,
        status: status_text,
        code: status.code(),
        timed_out,
        cancelled: was_cancelled,
        stdout_dropped,
        stderr_dropped,
    })
}

fn shell_program() -> &'static str {
    #[cfg(unix)]
    {
        "sh"
    }
    #[cfg(not(unix))]
    {
        "/system/bin/rush"
    }
}

fn drain<R: Read + Send + 'static>(
    pipe: Option<R>,
    stream: Stream,
    sender: mpsc::Sender<(Stream, Vec<u8>)>,
) -> Option<std::thread::JoinHandle<()>> {
    let mut pipe = pipe?;
    Some(std::thread::spawn(move || {
        let mut buffer = [0_u8; 8192];
        while let Ok(read @ 1..) = pipe.read(&mut buffer) {
            if sender.send((stream, buffer[..read].to_vec())).is_err() {
                break;
            }
        }
    }))
}

fn receive(
    stream: Stream,
    bytes: &[u8],
    stdout: &mut Capture,
    stderr: &mut Capture,
    observer: &mut dyn FnMut(Stream, &str),
) {
    let text = String::from_utf8_lossy(bytes);
    observer(stream, &text);
    match stream {
        Stream::Stdout => stdout.push(bytes),
        Stream::Stderr => stderr.push(bytes),
    }
}

struct Capture {
    head: Vec<u8>,
    tail: Vec<u8>,
    total: usize,
    half: usize,
}

impl Capture {
    fn new(limit: usize) -> Self {
        Self {
            head: Vec::new(),
            tail: Vec::new(),
            total: 0,
            half: limit / 2,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        self.total = self.total.saturating_add(bytes.len());
        let head_room = self.half.saturating_sub(self.head.len()).min(bytes.len());
        self.head.extend_from_slice(&bytes[..head_room]);
        self.tail.extend_from_slice(&bytes[head_room..]);
        if self.tail.len() > self.half {
            self.tail.drain(..self.tail.len() - self.half);
        }
    }

    fn finish(self) -> (String, usize) {
        let kept = self.head.len() + self.tail.len();
        let dropped = self.total.saturating_sub(kept);
        let head = String::from_utf8_lossy(&self.head);
        let tail = String::from_utf8_lossy(&self.tail);
        let text = if dropped == 0 {
            format!("{head}{tail}")
        } else {
            format!("{head}\n… [{dropped} bytes elided] …\n{tail}")
        };
        (text, dropped)
    }
}

fn bounded_view(text: &str, limit: usize, already_dropped: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }
    let half = limit / 2;
    let head_end = floor_boundary(text, half);
    let tail_start = ceil_boundary(text, text.len().saturating_sub(half));
    let dropped = text.len() - head_end - (text.len() - tail_start) + already_dropped;
    format!(
        "{}\n… [{dropped} bytes elided for model] …\n{}",
        &text[..head_end],
        &text[tail_start..]
    )
}

fn floor_boundary(text: &str, mut at: usize) -> usize {
    at = at.min(text.len());
    while at > 0 && !text.is_char_boundary(at) {
        at -= 1;
    }
    at
}

fn ceil_boundary(text: &str, mut at: usize) -> usize {
    at = at.min(text.len());
    while at < text.len() && !text.is_char_boundary(at) {
        at += 1;
    }
    at
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_failure_is_identified_as_not_started() {
        let error = run(
            &Request {
                program: "/no-such-gears-test-program".to_string(),
                args: Vec::new(),
                cwd: std::env::temp_dir(),
                stdin: None,
                timeout: Duration::from_secs(1),
                max_output_bytes: 4096,
                env: Vec::new(),
                remove_env: Vec::new(),
            },
            &Cancellation::new(),
            &mut |_, _| {},
        )
        .unwrap_err();
        assert!(!error.started);
        assert!(error.to_string().contains("cannot run"));
    }

    #[test]
    fn a_cancelled_request_does_not_spawn_a_child() {
        let marker = std::env::temp_dir().join(format!("gears-pre-cancel-{}", std::process::id()));
        if marker.exists() {
            std::fs::remove_file(&marker).unwrap();
        }
        let cancellation = Cancellation::new();
        cancellation.cancel();
        let error = run(
            &Request {
                program: shell_program().into(),
                args: vec!["-c".into(), "printf started > \"$MARKER\"".into()],
                cwd: std::env::temp_dir(),
                stdin: None,
                timeout: Duration::from_secs(2),
                max_output_bytes: 4096,
                env: vec![("MARKER".into(), marker.display().to_string())],
                remove_env: Vec::new(),
            },
            &cancellation,
            &mut |_, _| {},
        )
        .unwrap_err();
        assert!(!error.started);
        assert!(error.detail.contains("cancelled before starting"));
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn sh_keeps_streams_and_status_separate() {
        let cancellation = Cancellation::new();
        let mut seen = Vec::new();
        let output = sh(
            std::env::temp_dir(),
            "printf out; printf err >&2; exit 7",
            Duration::from_secs(2),
            4096,
            &cancellation,
            &mut |stream, text| seen.push((stream, text.to_string())),
        )
        .unwrap();
        assert_eq!(output.code, Some(7));
        assert_eq!(output.stdout, "out");
        assert_eq!(output.stderr, "err");
        assert!(seen.iter().any(|(stream, _)| *stream == Stream::Stdout));
        assert!(seen.iter().any(|(stream, _)| *stream == Stream::Stderr));
    }

    #[cfg(unix)]
    #[test]
    fn cancellation_kills_the_process_group() {
        let cancellation = Cancellation::new();
        let mut saw_output = false;
        let output = sh(
            std::env::temp_dir(),
            "printf started; sleep 5",
            Duration::from_secs(10),
            4096,
            &cancellation,
            &mut |_, _| {
                saw_output = true;
                cancellation.cancel();
            },
        )
        .unwrap();
        assert!(saw_output);
        assert!(output.cancelled);
    }

    #[cfg(unix)]
    #[test]
    fn cancellation_does_not_report_the_killed_childs_broken_stdin() {
        let cancellation = Cancellation::new();
        let mut saw_output = false;
        let output = run(
            &Request {
                program: "sh".into(),
                args: vec!["-c".into(), "printf started; sleep 5".into()],
                cwd: std::env::temp_dir(),
                stdin: Some(vec![b'x'; 1024 * 1024]),
                timeout: Duration::from_secs(10),
                max_output_bytes: 4096,
                env: Vec::new(),
                remove_env: Vec::new(),
            },
            &cancellation,
            &mut |_, _| {
                saw_output = true;
                cancellation.cancel();
            },
        )
        .unwrap();
        assert!(saw_output);
        assert!(output.cancelled);
    }

    #[cfg(unix)]
    #[test]
    fn timeout_kills_the_process_group() {
        let output = sh(
            std::env::temp_dir(),
            "sleep 5",
            Duration::from_millis(30),
            4096,
            &Cancellation::new(),
            &mut |_, _| {},
        )
        .unwrap();
        assert!(output.timed_out);
        assert!(output.status.contains("timed out"));
    }

    #[cfg(unix)]
    #[test]
    fn normal_exit_stops_background_descendants() {
        let output = sh(
            std::env::temp_dir(),
            "sleep 10 & echo $!",
            Duration::from_secs(3),
            4096,
            &Cancellation::new(),
            &mut |_, _| {},
        )
        .unwrap();
        assert_eq!(output.code, Some(0));
        let pid: u32 = output.stdout.trim().parse().unwrap();
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"));
        if let Ok(stat) = stat {
            let state = stat.rsplit_once(") ").unwrap().1.chars().next().unwrap();
            assert_eq!(state, 'Z', "background child {pid} is still running");
        }
    }

    #[cfg(unix)]
    #[test]
    fn capture_keeps_bounded_head_and_tail() {
        let output = sh(
            std::env::temp_dir(),
            "printf 0123456789abcdef",
            Duration::from_secs(2),
            8,
            &Cancellation::new(),
            &mut |_, _| {},
        )
        .unwrap();
        assert_eq!(output.stdout_dropped, 8);
        assert!(output.stdout.starts_with("0123"));
        assert!(output.stdout.ends_with("cdef"));
        assert!(output.stdout.contains("bytes elided"));
    }

    #[cfg(unix)]
    #[test]
    fn provider_key_is_removed_from_children() {
        let output = run(
            &Request {
                program: "sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "test -z \"$OPENROUTER_API_KEY\"".to_string(),
                ],
                cwd: std::env::temp_dir(),
                stdin: None,
                timeout: Duration::from_secs(2),
                max_output_bytes: 4096,
                env: vec![(
                    crate::provider::KEY_ENV.to_string(),
                    "must-not-leak".to_string(),
                )],
                remove_env: vec![crate::provider::KEY_ENV.to_string()],
            },
            &Cancellation::new(),
            &mut |_, _| {},
        )
        .unwrap();
        assert!(output.success(), "{}", output.model_text(4096));
    }
}
