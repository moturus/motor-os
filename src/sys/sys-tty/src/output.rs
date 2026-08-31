use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const SOURCE_COUNT: usize = 3;
const SCREEN_COUNT: usize = 2;
const QUIET_WINDOW: Duration = Duration::from_millis(30);
const HOLD_TIME: Duration = Duration::from_millis(500);
const HOLD_SIZE: usize = 16 * 1024;
const ANSI_GRACE: Duration = Duration::from_millis(100);
const LOG_CAPACITY: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Source {
    Stdout,
    Stderr,
    Kernel,
}

impl Source {
    fn index(self) -> usize {
        match self {
            Self::Stdout => 0,
            Self::Stderr => 1,
            Self::Kernel => 2,
        }
    }

    fn other(self) -> Self {
        match self {
            Self::Stdout => Self::Stderr,
            Self::Stderr => Self::Stdout,
            Self::Kernel => unreachable!(),
        }
    }
}

struct State {
    slots: [Option<Vec<u8>>; SOURCE_COUNT],
    next_screen: usize,
}

impl State {
    fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| None),
            next_screen: 0,
        }
    }

    fn take_screen(&mut self, source: Source) -> Option<Vec<u8>> {
        let index = source.index();
        debug_assert!(index < SCREEN_COUNT);
        let data = self.slots[index].take()?;
        self.next_screen = (index + 1) % SCREEN_COUNT;
        Some(data)
    }

    fn take_next_screen(&mut self) -> Option<(Source, Vec<u8>)> {
        for offset in 0..SCREEN_COUNT {
            let index = (self.next_screen + offset) % SCREEN_COUNT;
            let Some(data) = self.slots[index].take() else {
                continue;
            };
            self.next_screen = (index + 1) % SCREEN_COUNT;
            let source = match index {
                0 => Source::Stdout,
                1 => Source::Stderr,
                _ => unreachable!(),
            };
            return Some((source, data));
        }
        None
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
        state.slots[source.index()].as_ref().map(|_| source)
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
}

/// The three bounded handoffs feeding sys-tty's sole UART writer.
#[derive(Clone)]
pub(crate) struct Output {
    shared: Arc<Shared>,
}

impl Output {
    fn new() -> Self {
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State::new()),
                changed: Condvar::new(),
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
                }
            })
            .unwrap();
        output
    }

    fn try_send(&self, source: Source, data: Vec<u8>) -> Result<(), Vec<u8>> {
        if data.is_empty() {
            return Ok(());
        }
        let mut state = self.shared.state.lock().unwrap();
        let slot = &mut state.slots[source.index()];
        if slot.is_some() {
            return Err(data);
        }
        *slot = Some(data);
        self.shared.changed.notify_all();
        Ok(())
    }

    pub(crate) fn send(&self, source: Source, data: Vec<u8>) {
        debug_assert!(source != Source::Kernel);
        if data.is_empty() {
            return;
        }
        let mut state = self.shared.state.lock().unwrap();
        let index = source.index();
        while state.slots[index].is_some() {
            state = self.shared.changed.wait(state).unwrap();
        }
        state.slots[index] = Some(data);
        self.shared.changed.notify_all();
    }

    pub(crate) fn send_fmt(&self, source: Source, args: fmt::Arguments<'_>) {
        use fmt::Write as _;
        let mut message = String::new();
        message.write_fmt(args).unwrap();
        self.send(source, message.into_bytes());
    }

    /// Kernel logging is best-effort: a full handoff drops this complete batch.
    pub(crate) fn try_send_kernel(&self, data: Vec<u8>) -> bool {
        self.try_send(Source::Kernel, data).is_ok()
    }

    fn take(&self, arbiter: &mut Arbiter) -> Vec<u8> {
        let mut state = self.shared.state.lock().unwrap();
        loop {
            let now = Instant::now();
            if let Some(record) = state.slots[Source::Kernel.index()].take() {
                arbiter.hold_log(record, now);
                self.shared.changed.notify_all();
            }
            if let Some(data) = arbiter.take_ready(&mut state, now) {
                self.shared.changed.notify_all();
                return data;
            }
            state = match arbiter.wait_duration(now) {
                Some(duration) => self.shared.changed.wait_timeout(state, duration).unwrap().0,
                None => self.shared.changed.wait(state).unwrap(),
            };
        }
    }
}

pub(crate) fn run_self_tests() {
    let output = Output::new();

    assert!(output.try_send(Source::Kernel, b"kernel".to_vec()).is_ok());
    assert!(output.try_send(Source::Stdout, b"stdout".to_vec()).is_ok());
    assert!(output.try_send(Source::Stderr, b"stderr".to_vec()).is_ok());
    assert_eq!(
        output.try_send(Source::Stdout, b"blocked".to_vec()),
        Err(b"blocked".to_vec())
    );

    let base = Instant::now();
    let mut arbiter = Arbiter::new();
    let mut state = output.shared.state.lock().unwrap();
    arbiter.hold_log(state.slots[Source::Kernel.index()].take().unwrap(), base);
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

    state.slots[Source::Stdout.index()] = Some(b"\x1b[".to_vec());
    assert_eq!(
        arbiter.take_ready(&mut state, base),
        Some(b"\x1b[".to_vec())
    );
    state.slots[Source::Stderr.index()] = Some(b"other".to_vec());
    assert_eq!(arbiter.take_ready(&mut state, base), None);
    state.slots[Source::Stdout.index()] = Some(b"31m".to_vec());
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
    state.slots[Source::Stdout.index()] = Some(b"\x1b]".to_vec());
    assert_eq!(
        arbiter.take_ready(&mut state, base),
        Some(b"\x1b]".to_vec())
    );
    state.slots[Source::Stderr.index()] = Some(b"timeout".to_vec());
    assert_eq!(arbiter.take_ready(&mut state, base), None);
    assert_eq!(
        arbiter.take_ready(&mut state, base + ANSI_GRACE + Duration::from_millis(1)),
        Some(b"\x18\r\ntimeout".to_vec())
    );

    println!("sys-tty writer self-test PASS");
}
