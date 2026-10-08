//! Unix host backend: real signals, used for development and testing.

use std::collections::BTreeMap;
use std::io;
use std::time::Duration;

/// Read stdin only after the OS says doing so will not block.
pub struct TerminalInput;

impl TerminalInput {
    pub fn new() -> io::Result<TerminalInput> {
        Ok(TerminalInput)
    }

    pub fn read(
        &mut self,
        buffer: &mut [u8],
        timeout: Option<Duration>,
    ) -> io::Result<Option<usize>> {
        let mut fd = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = timeout.map_or(-1, |duration| {
            let rounded = if duration.is_zero() {
                0
            } else {
                duration.as_millis().max(1)
            };
            i32::try_from(rounded).unwrap_or(i32::MAX)
        });
        let ready = unsafe { libc::poll(&mut fd, 1, millis) };
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        if ready == 0 {
            return Ok(None);
        }
        let read =
            unsafe { libc::read(libc::STDIN_FILENO, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(read as usize))
    }
}

/// The SIGINT handler: records delivery and nothing else (a handler may only
/// touch async-signal-safe state).
extern "C" fn note_handler(_signo: libc::c_int) {
    super::note_interrupt();
}

/// Point SIGINT at the interrupt flag; false if the platform refused.
///
/// `sa_flags` omits `SA_RESTART` so a ^C interrupts a blocking read promptly
/// instead of whenever the read happens to return (the rush idiom).
pub fn install_interrupt_handler() -> bool {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = note_handler as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut()) == 0
    }
}

/// Every runner, nested or not, gives each child a new process group, so a
/// tool's background jobs can be stopped without touching the runner itself.
pub fn spawn(command: &mut std::process::Command) -> std::io::Result<std::process::Child> {
    use std::os::unix::process::CommandExt;
    command.process_group(0).spawn()
}

/// After a normal exit the child's descendants have lost their parent link;
/// its process group still identifies the jobs it left behind.
pub fn cleanup_after_exit(child: &std::process::Child) -> bool {
    match libc::pid_t::try_from(child.id()) {
        Ok(group @ 1..) => kill_groups(&[group]),
        _ => false,
    }
}

/// Stop a running child and everything below it, nested Gears runs included.
///
/// The tree is frozen first: a stopped process cannot fork, and killing a
/// parent first would re-parent its children before they were found. Every
/// group seen in the frozen tree is then killed, which also reaches jobs
/// already orphaned from those groups.
pub fn kill_tree(child: &std::process::Child) -> bool {
    let Ok(root @ 1..) = libc::pid_t::try_from(child.id()) else {
        return false;
    };
    let own_group = unsafe { libc::getpgrp() };
    let mut frozen = BTreeMap::new();
    let mut complete = false;
    for _ in 0..64 {
        let Ok(table) = process_table() else {
            break;
        };
        let mut added = false;
        for process in descendants(root, &table) {
            if frozen.insert(process.pid, process.group).is_none() {
                unsafe { libc::kill(process.pid, libc::SIGSTOP) };
                added = true;
            }
        }
        if !added {
            complete = true;
            break;
        }
    }
    for pid in frozen.keys() {
        unsafe { libc::kill(*pid, libc::SIGKILL) };
    }
    let mut groups: Vec<_> = frozen
        .into_values()
        .chain([root])
        .filter(|group| *group > 1 && *group != own_group)
        .collect();
    groups.sort_unstable();
    groups.dedup();
    kill_groups(&groups) && complete
}

fn kill_groups(groups: &[libc::pid_t]) -> bool {
    let mut complete = true;
    for group in groups {
        if unsafe { libc::killpg(*group, libc::SIGKILL) } != 0
            && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
        {
            complete = false;
        }
    }
    // Signal delivery is asynchronous. A successful killpg does not yet
    // mean a grandchild has stopped before the next tool starts.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match process_table() {
            Ok(table)
                if !table
                    .iter()
                    .any(|process| process.live && groups.contains(&process.group)) =>
            {
                return complete;
            }
            Ok(_) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            _ => return false,
        }
    }
}

struct Process {
    pid: libc::pid_t,
    parent: libc::pid_t,
    group: libc::pid_t,
    live: bool,
}

/// `root` and every process whose parent chain reaches it, zombies included.
fn descendants(root: libc::pid_t, table: &[Process]) -> Vec<&Process> {
    let mut found: Vec<&Process> = table.iter().filter(|p| p.pid == root).collect();
    let mut next = 0;
    while next < found.len() {
        let parent = found[next].pid;
        found.extend(table.iter().filter(|p| p.parent == parent && p.pid != root));
        next += 1;
    }
    found
}

fn process_table() -> Result<Vec<Process>, ()> {
    let mut table = Vec::new();
    for entry in std::fs::read_dir("/proc").map_err(|_| ())? {
        let entry = entry.map_err(|_| ())?;
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<libc::pid_t>() else {
            continue;
        };
        let stat = match std::fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(error) if vanished_process(&error) => continue,
            Err(_) => return Err(()),
        };
        // The command field is parenthesized and may itself contain spaces.
        let Some((_, fields)) = stat.rsplit_once(") ") else {
            return Err(());
        };
        let mut fields = fields.split_whitespace();
        let (Some(state), Some(Ok(parent)), Some(Ok(group))) = (
            fields.next(),
            fields.next().map(str::parse),
            fields.next().map(str::parse),
        ) else {
            return Err(());
        };
        table.push(Process {
            pid,
            parent,
            group,
            live: !matches!(state, "Z" | "X" | "x"),
        });
    }
    Ok(table)
}

fn vanished_process(error: &io::Error) -> bool {
    // An exiting /proc entry can report ESRCH even after read_dir found it.
    error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}

pub fn cancellation_text(complete: bool) -> &'static str {
    if complete {
        "cancelled; killed the process group"
    } else {
        "cancelled; process-group cleanup could not be confirmed"
    }
}

/// Whether the console needs gears to do its own echo and line editing.
/// Never on the host: for a terminal the driver's cooked mode does both, and
/// a piped stdin has no keystrokes to edit.
pub fn raw_console() -> bool {
    false
}

/// How a finished child is described. A signalled death has no exit code, and
/// saying which signal is the difference between "the test failed" and "the
/// test was killed".
pub fn status_text(status: std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => format!("exit status {code}"),
        (None, Some(signal)) => format!("killed by signal {signal}"),
        (None, None) => "stopped".to_string(),
    }
}

/// Whether a process still exists — signal 0 checks without delivering.
/// `EPERM` means it exists and belongs to somebody else, which is still
/// "alive"; only `ESRCH` says the pid is free.
pub fn process_alive(pid: u32) -> bool {
    // `kill` reads 0 as "my whole process group", never as a process, so a
    // lockfile naming it is junk rather than an owner — and answering "alive"
    // to it would make every such lock permanent.
    let Ok(pid @ 1..) = libc::pid_t::try_from(pid) else {
        return false;
    };
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// A live non-Gears PID cannot keep a stale Gears directory lock.
pub fn process_is_gears(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/comm")) {
        Ok(name) => name.trim() == "gears",
        Err(_) => process_alive(pid), // Unknown identity must not break a live lock.
    }
}

/// Only a Gears process started by the lock holder may share its lock.
pub fn process_is_descendant_of(ancestor: u32) -> bool {
    let mut current = std::process::id();
    for _ in 0..1024 {
        let Some(parent) = parent_pid(current) else {
            return false;
        };
        if parent == ancestor {
            return true;
        }
        if parent == 0 || parent == current {
            return false;
        }
        current = parent;
    }
    false
}

fn parent_pid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command field is parenthesized and may itself contain spaces.
    stat.rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

#[cfg(test)]
mod lock_tests {
    use super::*;

    #[test]
    fn exiting_proc_entries_are_skipped_without_hiding_other_errors() {
        assert!(vanished_process(&io::Error::from_raw_os_error(
            libc::ENOENT
        )));
        assert!(vanished_process(&io::Error::from_raw_os_error(libc::ESRCH)));
        assert!(!vanished_process(&io::Error::from_raw_os_error(
            libc::EACCES
        )));
    }

    #[test]
    fn ancestry_excludes_self_and_includes_parent() {
        assert!(!process_is_descendant_of(std::process::id()));
        assert!(process_is_descendant_of(unsafe { libc::getppid() } as u32));
        assert!(!process_is_gears(std::process::id()));
    }
}
