use std::fmt;
use std::sync::{Arc, Condvar, Mutex};

const SOURCE_COUNT: usize = 3;

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
}

struct State {
    slots: [Option<Vec<u8>>; SOURCE_COUNT],
    next: usize,
}

impl State {
    fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| None),
            next: 0,
        }
    }

    fn take(&mut self) -> Option<(Source, Vec<u8>)> {
        for offset in 0..SOURCE_COUNT {
            let index = (self.next + offset) % SOURCE_COUNT;
            let Some(data) = self.slots[index].take() else {
                continue;
            };
            self.next = (index + 1) % SOURCE_COUNT;
            let source = match index {
                0 => Source::Stdout,
                1 => Source::Stderr,
                2 => Source::Kernel,
                _ => unreachable!(),
            };
            return Some((source, data));
        }
        None
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
                loop {
                    let (_, data) = reader.take();
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

    fn take(&self) -> (Source, Vec<u8>) {
        let mut state = self.shared.state.lock().unwrap();
        loop {
            if let Some(item) = state.take() {
                self.shared.changed.notify_all();
                return item;
            }
            state = self.shared.changed.wait(state).unwrap();
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

    assert_eq!(output.take(), (Source::Stdout, b"stdout".to_vec()));
    assert_eq!(output.take(), (Source::Stderr, b"stderr".to_vec()));
    assert_eq!(output.take(), (Source::Kernel, b"kernel".to_vec()));

    assert!(output.try_send_kernel(b"first".to_vec()));
    assert!(!output.try_send_kernel(b"dropped".to_vec()));
    assert_eq!(output.take(), (Source::Kernel, b"first".to_vec()));

    println!("sys-tty writer self-test PASS");
}
