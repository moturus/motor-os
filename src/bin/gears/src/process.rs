//! Bounded, cancellable child-process execution shared by sh and hooks.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub use crate::cancellation::Cancellation;

const DRAIN_GRACE: Duration = Duration::from_secs(2);

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
}

pub fn sh(
    workspace: PathBuf,
    script: &str,
    timeout: Duration,
    max_output_bytes: usize,
    cancellation: &Cancellation,
    observer: &mut dyn FnMut(Stream, &str),
) -> Result<Output, String> {
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

pub fn run(
    request: &Request,
    cancellation: &Cancellation,
    observer: &mut dyn FnMut(Stream, &str),
) -> Result<Output, String> {
    let mut command = Command::new(&request.program);
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
    let mut child = crate::platform::spawn(&mut command)
        .map_err(|error| format!("cannot run {}: {error}", request.program))?;
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
    let mut cleanup_complete = true;
    let status = loop {
        while let Ok((stream, bytes)) = receiver.try_recv() {
            receive(stream, &bytes, &mut stdout, &mut stderr, observer);
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("cannot wait for {}: {error}", request.program))?
        {
            break status;
        }
        if cancellation.cancelled() {
            was_cancelled = true;
        } else if started.elapsed() >= request.timeout {
            timed_out = true;
        }
        if was_cancelled || timed_out {
            cleanup_complete = crate::platform::kill_tree(&child);
            let status = child
                .wait()
                .map_err(|error| format!("cannot reap {}: {error}", request.program))?;
            if !cleanup_complete {
                crate::trace::log(
                    crate::trace::Level::Warn,
                    "child process-tree cleanup could not be confirmed",
                );
            }
            break status;
        }
        match receiver.recv_timeout(Duration::from_millis(10)) {
            Ok((stream, bytes)) => receive(stream, &bytes, &mut stdout, &mut stderr, observer),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                std::thread::yield_now();
            }
        }
    };

    let deadline = Instant::now() + DRAIN_GRACE;
    while readers.iter().flatten().any(|reader| !reader.is_finished()) && Instant::now() < deadline
    {
        if let Ok((stream, bytes)) = receiver.recv_timeout(Duration::from_millis(5)) {
            receive(stream, &bytes, &mut stdout, &mut stderr, observer);
        }
    }
    while let Ok((stream, bytes)) = receiver.try_recv() {
        receive(stream, &bytes, &mut stdout, &mut stderr, observer);
    }
    if let Some(input) = input {
        input
            .join()
            .map_err(|_| format!("{} stdin writer panicked", request.program))?
            .map_err(|error| format!("{} stdin: {error}", request.program))?;
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
        let cancel = cancellation.clone();
        let thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            cancel.cancel();
        });
        let output = sh(
            std::env::temp_dir(),
            "sleep 5",
            Duration::from_secs(10),
            4096,
            &cancellation,
            &mut |_, _| {},
        )
        .unwrap();
        thread.join().unwrap();
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
