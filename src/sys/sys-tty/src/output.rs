use std::collections::VecDeque;
use std::fmt;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const SCREEN_COUNT: usize = 2;
/// Covers the entire 2 KiB console pipe, including a wrapped read. The pipe
/// self-test holds a real, full pipe to this.
const SCREEN_CHUNK: usize = 4 * 1024;
const QUIET_WINDOW: Duration = Duration::from_millis(30);
const HOLD_TIME: Duration = Duration::from_millis(500);
const HOLD_SIZE: usize = 16 * 1024;
const ANSI_GRACE: Duration = Duration::from_millis(100);
const LOG_CAPACITY: usize = 256 * 1024;

#[path = "output_tests.rs"]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Source {
    Stdout,
    Stderr,
}

impl Source {
    fn index(self) -> usize {
        match self {
            Self::Stdout => 0,
            Self::Stderr => 1,
        }
    }

    fn other(self) -> Self {
        match self {
            Self::Stdout => Self::Stderr,
            Self::Stderr => Self::Stdout,
        }
    }
}

struct State {
    /// Ordered screen batches, with stderr sampled after stdout but emitted first.
    screens: VecDeque<(Source, Vec<u8>)>,
    kernel: Option<Vec<u8>>,
    pipes: Option<Pipes>,
    writing: bool,
}

impl State {
    fn new() -> Self {
        Self {
            screens: VecDeque::new(),
            kernel: None,
            pipes: None,
            writing: false,
        }
    }

    fn has_screen(&self, source: Source) -> bool {
        self.screens.iter().any(|(queued, _)| *queued == source)
    }

    fn push_screen(&mut self, source: Source, data: Vec<u8>) {
        self.screens.push_back((source, data));
    }

    /// The oldest chunk of `source`, which owns an unfinished sequence.
    fn take_screen(&mut self, source: Source) -> Option<Vec<u8>> {
        let index = self
            .screens
            .iter()
            .position(|(queued, _)| *queued == source)?;
        self.screens.remove(index).map(|(_, data)| data)
    }

    fn take_next_screen(&mut self) -> Option<(Source, Vec<u8>)> {
        self.screens.pop_front()
    }

    fn fill_screens(
        &mut self,
        owner: Option<Source>,
        mut read: impl FnMut(Source) -> Option<Vec<u8>>,
    ) {
        if self.screens.is_empty() {
            // A foreground child's stderr is published before the next prompt.
            // Read it AFTER capturing stdout so this snapshot includes its tail.
            let stdout = read(Source::Stdout);
            if let Some(stderr) = read(Source::Stderr) {
                self.push_screen(Source::Stderr, stderr);
            }
            if let Some(stdout) = stdout {
                self.push_screen(Source::Stdout, stdout);
            }
        } else if let Some(owner) = owner
            && !self.has_screen(owner)
            && let Some(data) = read(owner)
        {
            // An unfinished sequence may need a continuation ahead of the
            // waiting batch; never read more of the other stream here.
            self.push_screen(owner, data);
        }
    }

    fn drained(&self) -> bool {
        !self.writing
            && self.screens.is_empty()
            && self.pipes.as_ref().is_none_or(|pipes| pipes.closed())
    }
}

struct Pipes {
    files: [Option<std::fs::File>; SCREEN_COUNT],
    /// One buffer for every read: most wakes find both pipes empty.
    buf: Vec<u8>,
}

impl Pipes {
    fn new(
        stdout: std::process::ChildStdout,
        stderr: std::process::ChildStderr,
        poll: i32,
    ) -> Self {
        let files = [stdout.into_raw_fd(), stderr.into_raw_fd()].map(|fd| {
            // Ownership moves from ChildStdout/ChildStderr into the writer.
            let pipe = unsafe { std::fs::File::from_raw_fd(fd) };
            moto_rt::net::set_nonblocking(fd, true).unwrap();
            moto_rt::poll::add(poll, fd, fd as u64, moto_rt::poll::POLL_READABLE).unwrap();
            Some(pipe)
        });
        Self {
            files,
            buf: vec![0; SCREEN_CHUNK],
        }
    }

    fn read(&mut self, source: Source, poll: i32) -> Option<Vec<u8>> {
        let slot = &mut self.files[source.index()];
        let pipe = slot.as_mut()?;
        match pipe.read(&mut self.buf) {
            Ok(len) if len != 0 => Some(self.buf[..len].to_vec()),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => None,
            _ => {
                // ChildStdio delivers the remote's unread tail before EOF.
                moto_rt::poll::del(poll, pipe.as_raw_fd()).unwrap();
                *slot = None;
                None
            }
        }
    }

    fn closed(&self) -> bool {
        self.files.iter().all(Option::is_none)
    }
}

struct Arbiter {
    scanner: crate::ansi::Scanner,
    owner: Option<Source>,
    grace_started: Option<Instant>,
    held_logs: VecDeque<Vec<u8>>,
    held_bytes: usize,
    held_since: Option<Instant>,
    dropped_logs: u64,
    last_screen: Option<Instant>,
    last_screen_line_end: bool,
}

impl Arbiter {
    fn new() -> Self {
        Self {
            scanner: crate::ansi::Scanner::new(),
            owner: None,
            grace_started: None,
            held_logs: VecDeque::new(),
            held_bytes: 0,
            held_since: None,
            dropped_logs: 0,
            last_screen: None,
            last_screen_line_end: true,
        }
    }

    fn hold_log(&mut self, record: Vec<u8>, now: Instant) {
        let record = crate::sanitize::for_console(&record);
        if record.len() > LOG_CAPACITY {
            self.dropped_logs = self.dropped_logs.saturating_add(1);
            return;
        }
        while self.held_bytes + record.len() > LOG_CAPACITY {
            let dropped = self.held_logs.pop_front().unwrap();
            self.held_bytes -= dropped.len();
            self.dropped_logs = self.dropped_logs.saturating_add(1);
        }
        if self.held_logs.is_empty() {
            self.held_since = Some(now);
        }
        self.held_bytes += record.len();
        self.held_logs.push_back(record);
    }

    fn logs_ready(&self, now: Instant) -> bool {
        if self.held_logs.is_empty() {
            return false;
        }
        self.held_bytes >= HOLD_SIZE
            || now.duration_since(self.held_since.unwrap()) >= HOLD_TIME
            || self
                .last_screen
                .is_none_or(|last| now.duration_since(last) >= QUIET_WINDOW)
    }

    fn waiting_screen(&self, state: &State) -> Option<Source> {
        let source = self.owner?.other();
        state.has_screen(source).then_some(source)
    }

    fn take_ready(&mut self, state: &mut State, now: Instant) -> Option<Vec<u8>> {
        if self.scanner.is_safe() {
            self.owner = None;
            self.grace_started = None;
            if self.logs_ready(now) {
                return Some(self.take_logs(true));
            }
            let (source, data) = state.take_next_screen()?;
            return Some(self.finish_screen(source, data, now));
        }

        let logs_waiting = self.logs_ready(now);
        let screen_waiting = self.waiting_screen(state);
        if logs_waiting || screen_waiting.is_some() {
            let started = *self.grace_started.get_or_insert(now);
            if now.duration_since(started) >= ANSI_GRACE {
                self.scanner.cancel();
                debug_assert!(self.scanner.is_safe());
                self.grace_started = None;
                let mut output = b"\x18\r\n".to_vec();
                if let Some(source) = screen_waiting {
                    let data = state.take_screen(source).unwrap();
                    output.extend_from_slice(&self.finish_screen(source, data, now));
                } else {
                    output.extend_from_slice(&self.take_logs(false));
                }
                return Some(output);
            }
        } else {
            self.grace_started = None;
        }

        let owner = self.owner.expect("an unsafe screen sequence has an owner");
        let data = state.take_screen(owner)?;
        Some(self.finish_screen(owner, data, now))
    }

    fn finish_screen(&mut self, source: Source, data: Vec<u8>, now: Instant) -> Vec<u8> {
        let was_safe = self.scanner.is_safe();
        self.scanner.advance(&data);
        self.owner = if self.scanner.is_safe() {
            None
        } else if was_safe {
            Some(source)
        } else {
            self.owner
        };
        self.last_screen = Some(now);
        self.last_screen_line_end = data.last().is_none_or(|byte| matches!(byte, b'\r' | b'\n'));
        data
    }

    fn take_logs(&mut self, prefix_line: bool) -> Vec<u8> {
        let mut output = Vec::with_capacity(self.held_bytes + 80);
        if prefix_line && !self.last_screen_line_end {
            output.extend_from_slice(b"\r\n");
        }
        if self.dropped_logs != 0 {
            output.extend_from_slice(
                format!(
                    "[kernel log: {} records dropped: console backlog]\n",
                    self.dropped_logs
                )
                .as_bytes(),
            );
            self.dropped_logs = 0;
        }
        while let Some(record) = self.held_logs.pop_front() {
            output.extend_from_slice(&record);
        }
        self.held_bytes = 0;
        self.held_since = None;
        self.scanner.advance(&output);
        debug_assert!(self.scanner.is_safe());
        output
    }

    fn wait_duration(&self, now: Instant) -> Option<Duration> {
        let mut deadline = self.grace_started.map(|start| start + ANSI_GRACE);
        if !self.held_logs.is_empty() && !self.logs_ready(now) {
            let quiet = self.last_screen.map(|last| last + QUIET_WINDOW).unwrap();
            let hold = self.held_since.unwrap() + HOLD_TIME;
            let log_deadline = quiet.min(hold);
            deadline = Some(deadline.map_or(log_deadline, |current| current.min(log_deadline)));
        }
        deadline.map(|deadline| deadline.saturating_duration_since(now))
    }
}

struct Shared {
    state: Mutex<State>,
    changed: Condvar,
    poll: OwnedFd,
    waker: OwnedFd,
}

/// The sole pipe reader and UART writer, plus its message handoffs.
#[derive(Clone)]
pub(crate) struct Output {
    shared: Arc<Shared>,
}

impl Output {
    fn new() -> Self {
        // Poll registries also serve as wake sources when registered in a poll.
        let poll = unsafe { OwnedFd::from_raw_fd(moto_rt::poll::new().unwrap()) };
        let waker = unsafe { OwnedFd::from_raw_fd(moto_rt::poll::new().unwrap()) };
        moto_rt::poll::add(
            poll.as_raw_fd(),
            waker.as_raw_fd(),
            0,
            moto_rt::poll::POLL_READABLE,
        )
        .unwrap();
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State::new()),
                changed: Condvar::new(),
                poll,
                waker,
            }),
        }
    }

    pub(crate) fn start_serial_writer() -> Self {
        let output = Self::new();
        let reader = output.clone();
        std::thread::Builder::new()
            .name("tty-writer".to_owned())
            .spawn(move || {
                let mut arbiter = Arbiter::new();
                loop {
                    let data = reader.take(&mut arbiter);
                    crate::serial::write_serial_raw(&data);
                    reader.shared.state.lock().unwrap().writing = false;
                    reader.shared.changed.notify_all();
                }
            })
            .unwrap();
        output
    }

    pub(crate) fn attach(
        &self,
        stdout: std::process::ChildStdout,
        stderr: std::process::ChildStderr,
    ) {
        let mut state = self.shared.state.lock().unwrap();
        assert!(state.pipes.is_none());
        state.pipes = Some(Pipes::new(stdout, stderr, self.shared.poll.as_raw_fd()));
        self.wake();
    }

    pub(crate) fn drain(&self) {
        let mut state = self.shared.state.lock().unwrap();
        while !state.drained() {
            state = self.shared.changed.wait(state).unwrap();
        }
    }

    fn wake(&self) {
        moto_rt::poll::wake(self.shared.waker.as_raw_fd()).unwrap();
    }

    pub(crate) fn send(&self, source: Source, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        // Sys-tty's own messages are a few short lines, so nothing bounds them.
        self.shared.state.lock().unwrap().push_screen(source, data);
        self.wake();
    }

    pub(crate) fn send_fmt(&self, source: Source, args: fmt::Arguments<'_>) {
        use fmt::Write as _;
        let mut message = String::new();
        message.write_fmt(args).unwrap();
        self.send(source, message.into_bytes());
    }

    /// Kernel logging is best-effort: a full handoff drops this complete batch.
    pub(crate) fn try_send_kernel(&self, data: Vec<u8>) -> bool {
        if data.is_empty() {
            return true;
        }
        let mut state = self.shared.state.lock().unwrap();
        if state.kernel.is_some() {
            return false;
        }
        state.kernel = Some(data);
        self.wake();
        true
    }

    fn take(&self, arbiter: &mut Arbiter) -> Vec<u8> {
        loop {
            let mut state = self.shared.state.lock().unwrap();
            if let Some(mut pipes) = state.pipes.take() {
                let owner = arbiter.owner.filter(|_| !arbiter.scanner.is_safe());
                state.fill_screens(owner, |source| {
                    pipes.read(source, self.shared.poll.as_raw_fd())
                });
                state.pipes = Some(pipes);
                // The pipes may have closed, which drain() waits for.
                self.shared.changed.notify_all();
            }
            let now = Instant::now();
            if let Some(record) = state.kernel.take() {
                arbiter.hold_log(record, now);
            }
            if let Some(data) = arbiter.take_ready(&mut state, now) {
                state.writing = true;
                return data;
            }
            let deadline = arbiter
                .wait_duration(now)
                .map(|duration| moto_rt::time::Instant::now() + duration);
            drop(state);
            let mut events = [moto_rt::poll::Event::default(); 3];
            moto_rt::poll::wait(
                self.shared.poll.as_raw_fd(),
                events.as_mut_ptr(),
                events.len(),
                deadline,
            )
            .unwrap();
        }
    }
}

pub(crate) fn run_pipe_self_test() {
    tests::closed_pipes_keep_their_tail();
    println!("sys-tty pipe self-test PASS");
}

pub(crate) fn run_pipe_self_test_child() {
    tests::child();
}

pub(crate) fn run_self_tests() {
    tests::run();
    let output = Output::new();

    assert!(output.try_send_kernel(b"kernel".to_vec()));
    assert!(!output.try_send_kernel(b"dropped".to_vec()));
    output.send(Source::Stdout, b"stdout".to_vec());
    output.send(Source::Stderr, b"stderr".to_vec());

    let base = Instant::now();
    let mut arbiter = Arbiter::new();
    let mut state = output.shared.state.lock().unwrap();
    arbiter.hold_log(state.kernel.take().unwrap(), base);
    assert_eq!(
        arbiter.take_ready(&mut state, base),
        Some(b"kernel".to_vec())
    );
    assert_eq!(
        arbiter.take_ready(&mut state, base),
        Some(b"stdout".to_vec())
    );
    assert_eq!(
        arbiter.take_ready(&mut state, base),
        Some(b"stderr".to_vec())
    );

    // Already queued batches retain their order.
    state.push_screen(Source::Stdout, b"echo".to_vec());
    state.push_screen(Source::Stderr, b"error 1, ".to_vec());
    state.push_screen(Source::Stderr, b"error 2".to_vec());
    state.push_screen(Source::Stdout, b"prompt".to_vec());
    for expected in [b"echo".as_slice(), b"error 1, ", b"error 2", b"prompt"] {
        assert_eq!(
            arbiter.take_ready(&mut state, base).as_deref(),
            Some(expected)
        );
    }

    state.push_screen(Source::Stdout, b"\x1b[".to_vec());
    assert_eq!(
        arbiter.take_ready(&mut state, base),
        Some(b"\x1b[".to_vec())
    );
    state.push_screen(Source::Stderr, b"other".to_vec());
    assert_eq!(arbiter.take_ready(&mut state, base), None);
    state.push_screen(Source::Stdout, b"31m".to_vec());
    assert_eq!(
        arbiter.take_ready(&mut state, base + Duration::from_millis(99)),
        Some(b"31m".to_vec())
    );
    assert_eq!(
        arbiter.take_ready(&mut state, base + Duration::from_millis(99)),
        Some(b"other".to_vec())
    );

    let mut arbiter = Arbiter::new();
    let mut state = State::new();
    state.push_screen(Source::Stdout, b"\x1b]".to_vec());
    assert_eq!(
        arbiter.take_ready(&mut state, base),
        Some(b"\x1b]".to_vec())
    );
    state.push_screen(Source::Stderr, b"timeout".to_vec());
    assert_eq!(arbiter.take_ready(&mut state, base), None);
    assert_eq!(
        arbiter.take_ready(&mut state, base + ANSI_GRACE + Duration::from_millis(1)),
        Some(b"\x18\r\ntimeout".to_vec())
    );

    let mut arbiter = Arbiter::new();
    let mut state = State::new();
    state.push_screen(Source::Stdout, vec![0xc3]);
    assert_eq!(arbiter.take_ready(&mut state, base), Some(vec![0xc3]));
    state.push_screen(Source::Stderr, b"other".to_vec());
    assert_eq!(arbiter.take_ready(&mut state, base), None);
    state.push_screen(Source::Stdout, vec![0xa9]);
    assert_eq!(
        arbiter.take_ready(&mut state, base + Duration::from_millis(1)),
        Some(vec![0xa9])
    );
    assert_eq!(
        arbiter.take_ready(&mut state, base + Duration::from_millis(1)),
        Some(b"other".to_vec())
    );

    let mut arbiter = Arbiter::new();
    let mut state = State::new();
    assert_eq!(
        arbiter.finish_screen(Source::Stdout, b"prompt".to_vec(), base),
        b"prompt"
    );
    arbiter.hold_log(b"\x1b unsafe \xc2\x9b".to_vec(), base);
    assert_eq!(
        arbiter.take_ready(&mut state, base + Duration::from_millis(29)),
        None
    );
    assert_eq!(
        arbiter.take_ready(&mut state, base + Duration::from_millis(31)),
        Some(
            b"\r\n[UNSAFE ASCII ESCAPE SEQUENCE DETECTED] unsafe [UNSAFE C1 CONTROL CHARACTER DETECTED]"
                .to_vec()
        )
    );

    let mut arbiter = Arbiter::new();
    let mut state = State::new();
    arbiter.finish_screen(Source::Stdout, b"screen".to_vec(), base);
    arbiter.hold_log(b"held".to_vec(), base);
    arbiter.finish_screen(
        Source::Stdout,
        b"activity".to_vec(),
        base + Duration::from_millis(490),
    );
    assert_eq!(
        arbiter.take_ready(&mut state, base + Duration::from_millis(499)),
        None
    );
    assert_eq!(
        arbiter.take_ready(&mut state, base + Duration::from_millis(501)),
        Some(b"\r\nheld".to_vec())
    );

    let mut arbiter = Arbiter::new();
    let mut state = State::new();
    arbiter.finish_screen(Source::Stdout, b"screen".to_vec(), base);
    let sized = vec![b'x'; HOLD_SIZE];
    arbiter.hold_log(sized.clone(), base);
    let mut expected = b"\r\n".to_vec();
    expected.extend_from_slice(&sized);
    assert_eq!(arbiter.take_ready(&mut state, base), Some(expected));

    let mut arbiter = Arbiter::new();
    let mut state = State::new();
    arbiter.hold_log(vec![b'a'; LOG_CAPACITY * 3 / 4], base);
    let kept = vec![b'b'; LOG_CAPACITY / 2];
    arbiter.hold_log(kept.clone(), base);
    let mut expected = b"[kernel log: 1 records dropped: console backlog]\n".to_vec();
    expected.extend_from_slice(&kept);
    assert_eq!(arbiter.take_ready(&mut state, base), Some(expected));

    println!("sys-tty writer self-test PASS");
}
