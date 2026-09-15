use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::cancellation::Cancellation;

const STDERR_LIMIT: usize = 64 * 1024;
const OUTER_DEADLINE: Duration = Duration::from_secs(305);
const POLL_INTERVAL: Duration = Duration::from_millis(2);

type Error = Box<dyn std::error::Error + Send + Sync>;

pub struct Captured {
    pub response: File,
    pub body_size: u64,
    pub stderr: Vec<u8>,
    pub status: ExitStatus,
}

/// Run one prepared curl command while bounding and fully joining its output readers.
pub fn capture(
    mut command: Command,
    mut response: File,
    mut input: Option<File>,
    body_limit: u64,
    cancellation: &Cancellation,
) -> crate::Result<Captured> {
    cancellation.check()?;
    if body_limit == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "curl body limit must be nonzero",
        )
        .into());
    }
    response.set_len(0)?;
    response.seek(SeekFrom::Start(0))?;
    if let Some(input) = input.as_mut() {
        input.seek(SeekFrom::Start(0))?;
    }
    let mut stderr_bytes = Vec::new();
    stderr_bytes
        .try_reserve_exact(STDERR_LIMIT)
        .map_err(|error| {
            io::Error::other(format!("failed to reserve curl stderr capture: {error}"))
        })?;

    command
        .stdin(input.map_or_else(Stdio::null, Stdio::from))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let program = command.get_program().to_string_lossy().into_owned();
    let child = command.spawn().map_err(|error| {
        io::Error::new(error.kind(), format!("failed to start {program}: {error}"))
    })?;
    let failed = Arc::new(AtomicBool::new(false));
    let mut guard = Guard::new(child, cancellation);

    let stdout = match guard.child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            return guard.abort(Some(
                io::Error::other("curl stdout pipe was not created").into(),
            ));
        }
    };
    let stdout_failed = failed.clone();
    guard.body = match thread::Builder::new()
        .name("gix-curl-stdout".into())
        .spawn(move || {
            let result = copy_body(stdout, response, body_limit);
            if result.is_err() {
                stdout_failed.store(true, Ordering::Release);
            }
            result
        }) {
        Ok(worker) => Some(worker),
        Err(error) => {
            return guard.abort(Some(
                io::Error::new(
                    error.kind(),
                    format!("failed to start curl stdout reader: {error}"),
                )
                .into(),
            ));
        }
    };

    let stderr = match guard.child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            return guard.abort(Some(
                io::Error::other("curl stderr pipe was not created").into(),
            ));
        }
    };
    let stderr_failed = failed.clone();
    guard.stderr = match thread::Builder::new()
        .name("gix-curl-stderr".into())
        .spawn(move || {
            let result = copy_stderr(stderr, stderr_bytes);
            if result.is_err() {
                stderr_failed.store(true, Ordering::Release);
            }
            result
        }) {
        Ok(worker) => Some(worker),
        Err(error) => {
            return guard.abort(Some(
                io::Error::new(
                    error.kind(),
                    format!("failed to start curl stderr reader: {error}"),
                )
                .into(),
            ));
        }
    };

    let started = Instant::now();
    let status = loop {
        if let Err(error) = cancellation.check() {
            return guard.abort(Some(error));
        }
        if failed.load(Ordering::Acquire) {
            return guard.abort(None);
        }
        if started.elapsed() >= OUTER_DEADLINE {
            return guard.abort(Some(
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "curl did not exit within 305 seconds",
                )
                .into(),
            ));
        }
        match guard.child.try_wait() {
            Ok(Some(status)) => {
                guard.reaped = true;
                break status;
            }
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(error) => {
                return guard.abort(Some(
                    io::Error::new(
                        error.kind(),
                        format!("failed while waiting for curl: {error}"),
                    )
                    .into(),
                ));
            }
        }
    };

    if status.code() == Some(130) {
        cancellation.cancel();
    }
    let body = join(guard.body.take(), "curl stdout reader");
    let stderr = join(guard.stderr.take(), "curl stderr reader");
    cancellation.check()?;
    let (response, body_size) = body?;
    let stderr = stderr?;
    Ok(Captured {
        response,
        body_size,
        stderr,
        status,
    })
}

fn copy_body(mut source: impl Read, mut response: File, limit: u64) -> io::Result<(File, u64)> {
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            response.flush()?;
            response.seek(SeekFrom::Start(0))?;
            return Ok((response, total));
        }
        let next = total
            .checked_add(count as u64)
            .filter(|next| *next <= limit)
            .ok_or_else(|| {
                io::Error::other(format!("curl response exceeded the {limit}-byte limit"))
            })?;
        response.write_all(&buffer[..count])?;
        total = next;
    }
}

fn copy_stderr(mut source: impl Read, mut bytes: Vec<u8>) -> io::Result<Vec<u8>> {
    let mut buffer = [0_u8; 8192];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            return Ok(bytes);
        }
        if bytes
            .len()
            .checked_add(count)
            .is_none_or(|next| next > STDERR_LIMIT)
        {
            return Err(io::Error::other(format!(
                "curl stderr exceeded the {STDERR_LIMIT}-byte limit"
            )));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
}

type BodyWorker = JoinHandle<io::Result<(File, u64)>>;
type StderrWorker = JoinHandle<io::Result<Vec<u8>>>;

struct Guard<'a> {
    child: Child,
    body: Option<BodyWorker>,
    stderr: Option<StderrWorker>,
    reaped: bool,
    cancellation: &'a Cancellation,
}

impl<'a> Guard<'a> {
    fn new(child: Child, cancellation: &'a Cancellation) -> Self {
        Self {
            child,
            body: None,
            stderr: None,
            reaped: false,
            cancellation,
        }
    }

    fn abort<T>(mut self, primary: Option<Error>) -> crate::Result<T> {
        let child_error = self.stop_child().err().map(Into::into);
        let body_error = self
            .body
            .take()
            .and_then(|worker| join(Some(worker), "curl stdout reader").err())
            .map(Into::into);
        let stderr_error = self
            .stderr
            .take()
            .and_then(|worker| join(Some(worker), "curl stderr reader").err())
            .map(Into::into);
        self.cancellation.check()?;
        Err(primary
            .or(body_error)
            .or(stderr_error)
            .or(child_error)
            .unwrap_or_else(|| io::Error::other("curl capture worker stopped").into()))
    }

    fn stop_child(&mut self) -> io::Result<()> {
        if self.reaped {
            return Ok(());
        }
        let kill = self.child.kill();
        let wait = self.child.wait();
        if let Ok(status) = &wait {
            self.reaped = true;
            if status.code() == Some(130) {
                self.cancellation.cancel();
            }
        }
        kill.and(wait).map(|_| ())
    }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        _ = self.stop_child();
        if let Some(worker) = self.body.take() {
            _ = worker.join();
        }
        if let Some(worker) = self.stderr.take() {
            _ = worker.join();
        }
    }
}

fn join<T>(worker: Option<JoinHandle<io::Result<T>>>, name: &str) -> io::Result<T> {
    worker
        .ok_or_else(|| io::Error::other(format!("{name} was not started")))?
        .join()
        .map_err(|_| io::Error::other(format!("{name} panicked")))?
}
