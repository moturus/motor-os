use std::{
    error::Error,
    io::{self, Read},
    process::{Child, ChildStdin, ChildStdout, Command, ExitStatus},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, SyncSender, TrySendError, sync_channel},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::cancellation::Cancellation;

const STDERR_LIMIT: usize = 64 * 1024;
const SESSION_TIMEOUT: Duration = Duration::from_secs(300);
const POLL_INTERVAL: Duration = Duration::from_millis(2);
const MAX_FAILURES: usize = 8;

type BoxError = Box<dyn Error + Send + Sync>;

pub struct Session {
    worker: Option<JoinHandle<Outcome>>,
    stop: Arc<AtomicBool>,
    input_closed: InputClosed,
}

pub struct Startup(Receiver<(ChildStdout, ChildStdin)>);

#[derive(Clone)]
pub struct InputClosed(Arc<AtomicBool>);

impl Session {
    pub fn launch(
        mut command: Command,
        cancellation: &Cancellation,
    ) -> io::Result<(Self, Startup)> {
        cancellation.check().map_err(io::Error::other)?;
        let mut stderr = Vec::new();
        stderr
            .try_reserve_exact(STDERR_LIMIT)
            .map_err(io::Error::other)?;
        let failures = reserve_failures()?;
        let (startup_tx, startup_rx) = sync_channel(0);
        let stop = Arc::new(AtomicBool::new(false));
        let input_closed = InputClosed(Arc::new(AtomicBool::new(false)));
        let worker = {
            let stop = Arc::clone(&stop);
            let cancellation = cancellation.clone();
            thread::Builder::new()
                .name("gix-ssh-supervisor".into())
                .spawn(move || {
                    supervise(
                        &mut command,
                        startup_tx,
                        stop,
                        cancellation,
                        stderr,
                        failures,
                    )
                })?
        };
        Ok((
            Self {
                worker: Some(worker),
                stop,
                input_closed,
            },
            Startup(startup_rx),
        ))
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }

    pub fn input_closed(&self) -> InputClosed {
        self.input_closed.clone()
    }

    pub fn is_closed(&self) -> bool {
        self.input_closed.0.load(Ordering::Acquire)
    }

    pub fn join(mut self, expected_stop: bool) -> crate::Result<Vec<u8>> {
        let worker = self
            .worker
            .take()
            .ok_or_else(|| io::Error::other("SSH session was already joined"))?;
        worker
            .join()
            .map_err(|_| io::Error::other("SSH supervisor thread panicked"))?
            .into_result(expected_stop)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Startup {
    pub fn wait(self) -> io::Result<(ChildStdout, ChildStdin)> {
        self.0
            .recv()
            .map_err(|_| io::Error::other("SSH supervisor stopped during startup"))
    }
}

impl InputClosed {
    pub fn mark(&self) {
        self.0.store(true, Ordering::Release);
    }
}

fn supervise(
    command: &mut Command,
    startup: SyncSender<(ChildStdout, ChildStdin)>,
    stop: Arc<AtomicBool>,
    cancellation: Cancellation,
    stderr_buffer: Vec<u8>,
    mut failures: Vec<BoxError>,
) -> Outcome {
    if let Err(error) = cancellation.check() {
        failures.push(error);
        return Outcome::failed(failures);
    }
    let started = Instant::now();
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            context(&mut failures, "failed to start SSH", error);
            return Outcome::failed(failures);
        }
    };
    let mut child = ChildGuard::new(child, cancellation.clone(), failures);
    let mut stdout = child.child.stdout.take();
    let mut stdin = child.child.stdin.take();
    let mut stderr = child.child.stderr.take();
    if stdout.is_none() || stdin.is_none() || stderr.is_none() {
        drop(stdin.take());
        drop(stdout.take());
        drop(stderr.take());
        child.failures.push(Box::new(io::Error::other(
            "SSH child did not provide all configured pipes",
        )));
        return child.finish(false, false);
    }
    let stdout = stdout.expect("checked above");
    let stdin = stdin.expect("checked above");
    let stderr = stderr.expect("checked above");
    let reader_failed = Arc::new(AtomicBool::new(false));
    let stderr_worker = {
        let reader_failed = Arc::clone(&reader_failed);
        thread::Builder::new()
            .name("gix-ssh-stderr".into())
            .spawn(move || {
                let capture = capture_stderr(stderr, stderr_buffer);
                reader_failed.store(capture.error.is_some(), Ordering::Release);
                capture
            })
    };
    child.stderr_worker = match stderr_worker {
        Ok(worker) => Some(worker),
        Err(error) => {
            drop(stdin);
            drop(stdout);
            context(
                &mut child.failures,
                "failed to start the SSH stderr reader",
                error,
            );
            return child.finish(false, false);
        }
    };
    let mut pipes = Some((stdout, stdin));
    let (status, requested_stop) = loop {
        if let Some(pending) = pipes.take() {
            match startup.try_send(pending) {
                Ok(()) => {}
                Err(TrySendError::Full(returned)) => pipes = Some(returned),
                Err(TrySendError::Disconnected((stdout, stdin))) => {
                    drop(stdin);
                    drop(stdout);
                    child
                        .failures
                        .push(Box::new(io::Error::other("SSH startup receiver stopped")));
                    break (None, false);
                }
            }
        }
        match child.child.try_wait() {
            Ok(Some(status)) => break (Some(status), false),
            Ok(None) => {}
            Err(error) => {
                context(
                    &mut child.failures,
                    "failed to query SSH child status",
                    error,
                );
                break (None, false);
            }
        }
        if reader_failed.load(Ordering::Acquire) {
            child.join_stderr();
            break (None, false);
        }
        if let Err(error) = cancellation.check() {
            child.failures.push(error);
            break (None, false);
        }
        let elapsed = started.elapsed();
        if elapsed >= SESSION_TIMEOUT {
            child.failures.push(Box::new(io::Error::new(
                io::ErrorKind::TimedOut,
                "SSH session exceeded 300 seconds",
            )));
            break (None, false);
        }
        if stop.load(Ordering::Acquire) {
            break (None, true);
        }
        thread::sleep(POLL_INTERVAL.min(SESSION_TIMEOUT - elapsed));
    };
    let input_closed_for_stop = requested_stop && pipes.is_some();
    // Startup can end before the caller receives its pipes. Close input first.
    if let Some((stdout, stdin)) = pipes {
        drop(stdin);
        drop(stdout);
    }
    match status {
        Some(status) => child.reaped(status),
        None => child.finish(requested_stop, input_closed_for_stop),
    }
}

struct ChildGuard {
    child: Child,
    cancellation: Cancellation,
    stderr_worker: Option<JoinHandle<StderrCapture>>,
    stderr: Vec<u8>,
    failures: Vec<BoxError>,
    reaped: bool,
}

impl ChildGuard {
    fn new(child: Child, cancellation: Cancellation, failures: Vec<BoxError>) -> Self {
        Self {
            child,
            cancellation,
            stderr_worker: None,
            stderr: Vec::new(),
            failures,
            reaped: false,
        }
    }

    fn reaped(mut self, status: ExitStatus) -> Outcome {
        self.reaped = true;
        self.outcome(Some(status), false)
    }

    fn finish(mut self, requested_stop: bool, input_closed_for_stop: bool) -> Outcome {
        let mut local = requested_stop;
        let status = match self.child.try_wait() {
            Ok(Some(status)) => {
                local = input_closed_for_stop;
                Some(status)
            }
            Ok(None) => self.kill_and_wait(),
            Err(error) => {
                context(
                    &mut self.failures,
                    "failed to query SSH child status during cleanup",
                    error,
                );
                self.kill_and_wait()
            }
        };
        self.reaped = status.is_some();
        self.outcome(status, local)
    }

    fn kill_and_wait(&mut self) -> Option<ExitStatus> {
        if let Err(error) = self.child.kill() {
            context(&mut self.failures, "failed to kill SSH", error);
        }
        match self.child.wait() {
            Ok(status) => Some(status),
            Err(error) => {
                context(&mut self.failures, "failed to wait for SSH", error);
                None
            }
        }
    }

    fn join_stderr(&mut self) {
        let Some(worker) = self.stderr_worker.take() else {
            return;
        };
        let capture = worker.join().unwrap_or_else(|_| StderrCapture {
            bytes: Vec::new(),
            error: Some(io::Error::other("SSH stderr reader thread panicked")),
        });
        self.stderr = capture.bytes;
        if let Some(error) = capture.error {
            context(&mut self.failures, "failed to capture SSH stderr", error);
        }
    }

    fn outcome(mut self, status: Option<ExitStatus>, locally_stopped: bool) -> Outcome {
        if status.as_ref().and_then(ExitStatus::code) == Some(130) {
            self.cancellation.cancel();
        }
        self.join_stderr();
        Outcome {
            status,
            stderr: std::mem::take(&mut self.stderr),
            failures: std::mem::take(&mut self.failures),
            locally_stopped,
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(worker) = self.stderr_worker.take() {
            let _ = worker.join();
        }
    }
}

struct Outcome {
    status: Option<ExitStatus>,
    stderr: Vec<u8>,
    failures: Vec<BoxError>,
    locally_stopped: bool,
}

impl Outcome {
    fn failed(failures: Vec<BoxError>) -> Self {
        Self {
            status: None,
            stderr: Vec::new(),
            failures,
            locally_stopped: false,
        }
    }

    fn into_result(mut self, expected_stop: bool) -> crate::Result<Vec<u8>> {
        let suppress_stop_status = self.locally_stopped && expected_stop;
        if self.locally_stopped && !expected_stop {
            self.failures.push(Box::new(io::Error::other(
                "SSH session was stopped locally",
            )));
        }
        match self.status {
            Some(status) if status.success() || suppress_stop_status => {}
            Some(status) => self.failures.push(Box::new(io::Error::other(format!(
                "SSH exited with status {status}"
            )))),
            None => {}
        }
        if self.failures.is_empty() {
            Ok(self.stderr)
        } else {
            Err(finish_error(self.failures, &self.stderr))
        }
    }
}

#[derive(Default)]
struct StderrCapture {
    bytes: Vec<u8>,
    error: Option<io::Error>,
}

fn capture_stderr(mut stderr: impl Read, mut bytes: Vec<u8>) -> StderrCapture {
    let mut buffer = [0u8; 8192];
    loop {
        let count = match stderr.read(&mut buffer) {
            Ok(0) => return StderrCapture { bytes, error: None },
            Ok(count) => count,
            Err(error) => {
                return StderrCapture {
                    bytes,
                    error: Some(error),
                };
            }
        };
        let remaining = STDERR_LIMIT - bytes.len();
        bytes.extend_from_slice(&buffer[..count.min(remaining)]);
        if count > remaining {
            return StderrCapture {
                bytes,
                error: Some(io::Error::other(format!(
                    "SSH stderr exceeded the {STDERR_LIMIT}-byte limit"
                ))),
            };
        }
    }
}

fn reserve_failures() -> io::Result<Vec<BoxError>> {
    let mut failures = Vec::new();
    failures
        .try_reserve_exact(MAX_FAILURES)
        .map_err(io::Error::other)?;
    Ok(failures)
}

fn context(
    failures: &mut Vec<BoxError>,
    message: &str,
    source: impl Error + Send + Sync + 'static,
) {
    debug_assert!(failures.len() < MAX_FAILURES);
    failures.push(Box::new(crate::network::Failure::new(
        format!("{message}: {source}"),
        Box::new(source),
    )));
}

fn finish_error(mut failures: Vec<BoxError>, stderr: &[u8]) -> BoxError {
    let mut message = String::from("SSH session failed");
    for error in &failures {
        message.push_str("; ");
        message.push_str(&error.to_string());
        let mut cause = error.source();
        while let Some(error) = cause {
            message.push_str(": ");
            message.push_str(&error.to_string());
            cause = error.source();
        }
    }
    if !stderr.is_empty() {
        message.push_str("; stderr: ");
        message.push_str(&String::from_utf8_lossy(stderr));
    }
    let source = failures.remove(0);
    Box::new(crate::network::Failure::new(message, source))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stderr_accepts_the_limit_and_retains_the_prefix_on_overflow() {
        for length in [STDERR_LIMIT, STDERR_LIMIT + 1] {
            let input = vec![b'x'; length];
            let captured = capture_stderr(input.as_slice(), Vec::with_capacity(STDERR_LIMIT));
            assert_eq!(captured.bytes, input[..STDERR_LIMIT]);
            assert_eq!(captured.error.is_some(), length > STDERR_LIMIT);
        }
    }
}
