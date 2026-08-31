use std::collections::VecDeque;
use std::io::{self, Read};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::transport::{FrameReader, write_frame};

pub const MAX_STDERR_LEN: usize = 64 * 1024;
const MESSAGE_QUEUE_LEN: usize = 16;

pub struct ServerProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    messages: Option<Receiver<io::Result<Option<Value>>>>,
    stderr: Arc<Mutex<StderrTail>>,
    readers: Vec<JoinHandle<()>>,
    status: Option<ExitStatus>,
}

impl ServerProcess {
    pub fn spawn(command: &mut Command) -> io::Result<Self> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("server stdin was not piped"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("server stdout was not piped"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("server stderr was not piped"))?;

        let (sender, receiver) = mpsc::sync_channel(MESSAGE_QUEUE_LEN);
        let stdout_reader = thread::spawn(move || {
            let mut reader = FrameReader::new(stdout);
            loop {
                let message = reader.read();
                let finished = !matches!(message, Ok(Some(_)));
                if sender.send(message).is_err() || finished {
                    break;
                }
            }
        });
        let stderr_tail = Arc::new(Mutex::new(StderrTail::default()));
        let shared_tail = Arc::clone(&stderr_tail);
        let stderr_reader = thread::spawn(move || {
            let mut stderr = stderr;
            let mut chunk = [0; 8192];
            while let Ok(read) = stderr.read(&mut chunk) {
                if read == 0 {
                    break;
                }
                shared_tail.lock().unwrap().extend(&chunk[..read]);
            }
        });

        Ok(Self {
            child,
            stdin: Some(stdin),
            messages: Some(receiver),
            stderr: stderr_tail,
            readers: vec![stdout_reader, stderr_reader],
            status: None,
        })
    }

    pub fn write(&mut self, message: &Value) -> io::Result<()> {
        write_frame(
            self.stdin
                .as_mut()
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "server stdin closed"))?,
            message,
        )
    }

    pub(crate) fn stdin(&mut self) -> io::Result<&mut ChildStdin> {
        self.stdin
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "server stdin closed"))
    }

    pub(crate) fn close_stdin(&mut self) {
        self.stdin.take();
    }

    pub fn read_until(&mut self, deadline: Instant) -> io::Result<Value> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| self.timeout_error())?;
        let received = self
            .messages
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "server stdout closed"))?
            .recv_timeout(remaining);
        match received {
            Ok(Ok(Some(message))) => Ok(message),
            Ok(Ok(None)) | Err(RecvTimeoutError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "server stdout closed",
            )),
            Ok(Err(error)) => Err(error),
            Err(RecvTimeoutError::Timeout) => Err(self.timeout_error()),
        }
    }

    pub fn wait_until(&mut self, deadline: Instant) -> io::Result<ExitStatus> {
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.status = Some(status);
                if !self.finish_readers_until(deadline) {
                    return Err(self.timeout_error());
                }
                return Ok(status);
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(self.timeout_error());
            };
            thread::sleep(remaining.min(Duration::from_millis(10)));
        }
    }

    pub fn stderr_tail(&self) -> String {
        let bytes: Vec<_> = self.stderr.lock().unwrap().bytes.iter().copied().collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn timeout_error(&mut self) -> io::Error {
        let _ = self.terminate();
        io::Error::new(io::ErrorKind::TimedOut, "rust-analyzer deadline expired")
    }

    fn terminate(&mut self) -> io::Result<ExitStatus> {
        self.stdin.take();
        self.messages.take();
        let status = match self.status {
            Some(status) => status,
            None => match self.child.try_wait()? {
                Some(status) => status,
                None => {
                    self.child.kill()?;
                    self.child.wait()?
                }
            },
        };
        self.status = Some(status);
        // A descendant may have inherited a pipe. Detach readers here so
        // timeout and Drop cleanup cannot wait beyond their contract.
        self.readers.clear();
        Ok(status)
    }

    fn finish_readers_until(&mut self, deadline: Instant) -> bool {
        self.stdin.take();
        self.messages.take();
        while self.readers.iter().any(|reader| !reader.is_finished()) {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            thread::sleep(remaining.min(Duration::from_millis(10)));
        }
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
        true
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

#[derive(Default)]
struct StderrTail {
    bytes: VecDeque<u8>,
}

impl StderrTail {
    fn extend(&mut self, bytes: &[u8]) {
        let bytes = if bytes.len() > MAX_STDERR_LEN {
            &bytes[bytes.len() - MAX_STDERR_LEN..]
        } else {
            bytes
        };
        let overflow = self
            .bytes
            .len()
            .saturating_add(bytes.len())
            .saturating_sub(MAX_STDERR_LEN);
        self.bytes.drain(..overflow);
        self.bytes.extend(bytes);
    }
}
