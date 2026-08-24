//! Motor OS backend: native process control and terminal Ctrl+C handling.
//!
//! Line mode explicitly handles Ctrl+C and wakes its one input owner; TUI mode
//! uses crossterm's adapter instead and never constructs this reader. The
//! process side is real: spawn, kill and liveness all work. Motor OS has no
//! process groups, so descendant cleanup walks the process tree one generation
//! at a time.

use std::io;
use std::sync::Arc;
use std::time::Duration;

const STDIN_TOKEN: u64 = 0;
const CTRL_C_TOKEN: u64 = 1;

struct Registry(moto_rt::RtFd);

impl Drop for Registry {
    fn drop(&mut self) {
        let _ = moto_rt::fs::close(self.0);
    }
}

#[derive(Clone)]
struct InputWaker(Arc<Registry>);

impl InputWaker {
    fn new() -> io::Result<Self> {
        moto_rt::poll::new()
            .map(Registry)
            .map(Arc::new)
            .map(InputWaker)
            .map_err(io_error)
    }

    fn wake(&self) {
        let _ = moto_rt::poll::wake(self.0.0);
    }
}

/// A native readiness registry for stdin and line mode's Ctrl+C callback.
pub struct TerminalInput {
    registry: Registry,
}

impl TerminalInput {
    pub fn new() -> io::Result<TerminalInput> {
        let registry = Registry(moto_rt::poll::new().map_err(io_error)?);
        moto_rt::poll::add(
            registry.0,
            moto_rt::FD_STDIN,
            STDIN_TOKEN,
            moto_rt::poll::POLL_READABLE,
        )
        .map_err(io_error)?;

        let waker = InputWaker::new()?;
        moto_rt::poll::add(
            registry.0,
            waker.0.0,
            CTRL_C_TOKEN,
            moto_rt::poll::POLL_READABLE,
        )
        .map_err(io_error)?;
        ctrlc::set_handler(move || {
            super::note_interrupt();
            waker.wake();
        })
        .map_err(io::Error::other)?;

        Ok(TerminalInput { registry })
    }

    pub fn read(
        &mut self,
        buffer: &mut [u8],
        timeout: Option<Duration>,
    ) -> io::Result<Option<usize>> {
        let deadline = timeout.map(|left| moto_rt::time::Instant::now() + left);
        let mut event = moto_rt::poll::Event::default();
        let ready =
            moto_rt::poll::wait(self.registry.0, &mut event, 1, deadline).map_err(io_error)?;
        if ready == 0 {
            return Ok(None);
        }
        if event.token == CTRL_C_TOKEN {
            return Err(io::ErrorKind::Interrupted.into());
        }
        moto_rt::fs::read(moto_rt::FD_STDIN, buffer)
            .map(Some)
            .map_err(io_error)
    }
}

fn io_error(error: moto_rt::Error) -> io::Error {
    io::Error::from_raw_os_error(moto_rt::ErrorCode::from(error).into())
}

/// The selected UI installs its handler with its own input wake path.
pub fn install_interrupt_handler() -> bool {
    true
}

/// Whether the console needs gears to do its own echo and line editing.
/// Whenever stdin is a terminal at all: Motor OS has no termios and no
/// cooked mode, so a console here is raw by construction (the rush contract,
/// `rush/src/sys/mod.rs`) and nothing echoes a keystroke unless the program
/// does. A pipe is not a terminal and gets neither echo nor editing.
pub fn raw_console() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdin())
}

/// Whether a process still exists. There is no per-pid query, but the process
/// list is ordered by pid, so one entry starting at `pid` decides it (the
/// rush idiom, `sys/motor.rs`). A zombie (`active == 0`) is gone; a list this
/// process may not read is "alive", the way `EPERM` is on the host — a lock
/// that cannot be checked must not be broken.
pub fn process_alive(pid: u32) -> bool {
    // Pid 0 in a lockfile is junk rather than an owner (see the unix backend).
    if pid == 0 {
        return false;
    }
    process_active(u64::from(pid))
}

fn process_active(pid: u64) -> bool {
    let mut buf = [moto_sys::stats::ProcessInfoV1::default(); 1];
    match moto_sys::stats::ProcessInfoV1::list(pid, &mut buf) {
        Ok(n) => n >= 1 && buf[0].pid == pid && buf[0].active != 0,
        Err(_) => true,
    }
}

/// A plain spawn. Motor OS has no process groups; [`kill_tree`] follows the
/// process relationships exposed by the kernel instead.
pub fn spawn(command: &mut std::process::Command) -> std::io::Result<std::process::Child> {
    command.spawn()
}

/// Kill `child`, then its children, grandchildren, and so on.
///
/// Killing a parent first prevents it from adding more descendants. Process
/// statistics retain the relationship while a descendant remains, so each
/// next generation can then be discovered. A failed kill is harmless only if
/// a fresh query says the victim has already stopped.
pub fn kill_tree(child: &std::process::Child) -> bool {
    let mut generation = vec![u64::from(child.id())];
    let mut complete = true;
    while !generation.is_empty() {
        let mut next = Vec::new();
        for pid in generation {
            if moto_sys::SysCpu::kill_pid(pid).is_err() && process_active(pid) {
                complete = false;
            }
            match child_pids(pid) {
                Ok(children) => next.extend(children),
                Err(()) => complete = false,
            }
        }
        generation = next;
    }
    complete
}

fn child_pids(parent: u64) -> Result<Vec<u64>, ()> {
    const FIRST_CAPACITY: usize = 16;
    const MAX_CAPACITY: usize = 65_536;

    let mut capacity = FIRST_CAPACITY;
    loop {
        let mut children = vec![moto_sys::stats::ProcessInfoV1::default(); capacity];
        let count =
            moto_sys::stats::ProcessInfoV1::list_children(parent, &mut children).map_err(|_| ())?;
        children.truncate(count);
        if count < capacity {
            return Ok(children.into_iter().map(|child| child.pid).collect());
        }
        if capacity == MAX_CAPACITY {
            return Err(());
        }
        capacity = (capacity * 2).min(MAX_CAPACITY);
    }
}

pub fn cancellation_text(complete: bool) -> &'static str {
    if complete {
        "cancelled; killed the process tree"
    } else {
        "cancelled; process-tree cleanup could not be confirmed"
    }
}

/// No signal can kill a process here, so unlike the unix backend there is no
/// "killed by" case to report (the rush precedent, `sys/motor.rs`).
pub fn status_text(status: std::process::ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("exit status {code}"),
        None => "stopped".to_string(),
    }
}
