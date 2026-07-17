//! Child processes and the background job table (Phase 7).
//!
//! This module owns every child process rush runs: spawning it with the stdio
//! Motor OS allows, pumping what that platform cannot wire directly, waiting for
//! it, and — for a background job — remembering it until `wait`/`jobs` asks.
//! [`crate::exec`] decides *what* to run; this decides how a running process is
//! held. Both foreground commands and background jobs go through
//! [`PumpedChild`], so there is one implementation of the awkward parts.
//!
//! # Job identity: why `$!` is not always a pid
//!
//! On the Unix host a job's `pid` is the real one. On Motor OS there is no pid
//! to be had: its `std` pal returns 0 from `Child::id()` and holds the child as
//! an opaque handle, and the kernel offers no handle→pid mapping. So a job's
//! identity is assigned by *this table*, and `wait`, `kill`, `fg` and `jobs`
//! resolve their arguments through it before falling back to the OS. That makes
//! `sleep 5 & kill $!` work identically on both platforms; what does not work on
//! Motor OS is handing `$!` to something *outside* rush (`/bin/kill $!`, or
//! matching it against `ps`), because the number is rush's, not the kernel's.
//! Synthetic ids are therefore deliberately implausible as pids (see
//! [`Jobs::next_pid`]) so such a mistake fails to find a process rather than
//! finding the wrong one.

use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::OnceLock;
use std::thread::JoinHandle;

use crate::sys::{self, WaitOutcome};

// ---- detached-spawn policy --------------------------------------------------

/// Which programs the shell will hand `CAP_SPAWN_DETACHED` to, and the env
/// assignment that does it.
///
/// A program named here is granted the capability to spawn detached children —
/// daemons that outlive this shell — when it is run. The list comes from
/// `/user/cfg/rush.toml`'s `spawn-detached` key; the grant itself is `None`
/// unless the shell holds the capability to pass on (off Motor, always). This is
/// how a program like `rmux` gets to run a server that survives logout without
/// every program being able to.
struct DetachPolicy {
    grant: Option<(&'static str, String)>,
    programs: HashSet<String>,
}

static DETACH_POLICY: OnceLock<DetachPolicy> = OnceLock::new();

/// Install the detached-spawn pass-list (from `rush.toml`). Called once at
/// startup; a second call is ignored.
pub fn init_detach_policy(programs: HashSet<String>) {
    let _ = DETACH_POLICY.set(DetachPolicy {
        grant: sys::detach_cap_grant(),
        programs,
    });
}

/// If `program` is on the pass-list and the shell can grant it, the env
/// assignment that hands it `CAP_SPAWN_DETACHED`.
fn detach_grant_for(program: &str) -> Option<(&'static str, String)> {
    let policy = DETACH_POLICY.get()?;
    let (key, val) = policy.grant.as_ref()?;
    let base = program.rsplit('/').next().unwrap_or(program);
    if policy.programs.contains(base) {
        Some((key, val.clone()))
    } else {
        None
    }
}

// ---- child stdio ------------------------------------------------------------

/// A child's standard input: inherited, empty, or piped and fed by us.
///
/// Motor OS's spawn accepts only inherit/null/pipe for a child's stdio — a real
/// file descriptor cannot be handed over — so file-backed input is read here and
/// pushed through a pipe instead.
pub enum ChildIn {
    Inherit,
    /// Nothing to read: an immediate EOF. A background job's stdin, so it cannot
    /// steal input from the terminal (POSIX §2.9.3).
    Null,
    File(Arc<File>),
    Heredoc(Arc<String>),
}

/// A child's standard output/error: inherited, or pumped into a file (a captured
/// pipeline stage's output is a temp file, so it is `File` too).
pub enum ChildOut {
    Inherit,
    File(Arc<File>),
}

// ---- a running child --------------------------------------------------------

/// A spawned child, plus the threads pumping any stdio the platform could not
/// wire directly.
///
/// Motor OS's sys-io is not reentrant under concurrent filesystem access from
/// one process, so rush keeps all of its own FS I/O on the main thread: input
/// files are read *before* the child starts, captured output is written *after*
/// it exits ([`finish`](Self::finish)), and the pump threads in between touch
/// only pipes. For a background job that means its redirected output lands in
/// the file when it is reaped rather than as it is produced — see
/// `rush-to-sh-plan.md` §7.
pub struct PumpedChild {
    child: Option<Child>,
    feed: Option<JoinHandle<()>>,
    out: Option<(JoinHandle<Vec<u8>>, Arc<File>)>,
    err: Option<(JoinHandle<Vec<u8>>, Arc<File>)>,
    status: Option<i32>,
}

/// Spawn `program`, returning the running child, or the error that stopped it.
///
/// The *caller* reports a failure, because only it knows where the failing
/// command's stderr was pointed: `nosuchcommand 2>/dev/null` must say nothing,
/// and a diagnostic printed from here would go to the shell's own stderr
/// regardless. See `exec::report_spawn_error`.
pub fn spawn(
    program: &str,
    args: &[String],
    env: &[(String, String)],
    stdin: ChildIn,
    stdout: ChildOut,
    stderr: ChildOut,
) -> Result<PumpedChild, std::io::Error> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }

    // Trusted programs (rush.toml's `spawn-detached`) get CAP_SPAWN_DETACHED.
    // Set after the env loop so a stray MOTURUS_CAPS in the shell environment
    // cannot override the grant.
    if let Some((key, val)) = detach_grant_for(program) {
        cmd.env(key, val);
    }

    // Read file-backed input up front: FS access must stay on this thread.
    let feed: Option<Vec<u8>> = match &stdin {
        ChildIn::Inherit | ChildIn::Null => None,
        ChildIn::Heredoc(b) => Some(b.as_bytes().to_vec()),
        ChildIn::File(f) => Some(read_all(f)),
    };
    let out_file = match stdout {
        ChildOut::Inherit => None,
        ChildOut::File(f) => Some(f),
    };
    let err_file = match stderr {
        ChildOut::Inherit => None,
        ChildOut::File(f) => Some(f),
    };

    cmd.stdin(match (&stdin, feed.is_some()) {
        (_, true) => Stdio::piped(),
        (ChildIn::Null, _) => Stdio::null(),
        _ => Stdio::inherit(),
    });
    cmd.stdout(if out_file.is_some() {
        Stdio::piped()
    } else {
        Stdio::inherit()
    });
    cmd.stderr(if err_file.is_some() {
        Stdio::piped()
    } else {
        Stdio::inherit()
    });

    let mut child = cmd.spawn()?;

    // Pipe-only work from here on, so it is safe to hand to threads.
    let feed = match (feed, child.stdin.take()) {
        (Some(bytes), Some(mut sink)) => Some(std::thread::spawn(move || {
            let _ = sink.write_all(&bytes);
        })),
        _ => None,
    };
    let out = out_file.and_then(|f| {
        child
            .stdout
            .take()
            .map(|mut o| (std::thread::spawn(move || read_stream(&mut o)), f))
    });
    let err = err_file.and_then(|f| {
        child
            .stderr
            .take()
            .map(|mut e| (std::thread::spawn(move || read_stream(&mut e)), f))
    });

    Ok(PumpedChild {
        child: Some(child),
        feed,
        out,
        err,
        status: None,
    })
}

impl PumpedChild {
    /// The child's pid, where the platform has one to give (see the module docs).
    pub fn pid(&self) -> Option<u64> {
        #[cfg(unix)]
        return self.child.as_ref().map(|c| c.id() as u64);
        #[cfg(not(unix))]
        return None;
    }

    /// Block until the child exits, or until a signal arrives first.
    ///
    /// `Interrupted` leaves the child running: the caller runs its pending traps
    /// and calls again. (The Unix backend is what makes this possible; on Motor
    /// OS nothing can arrive while we block, so this only ever returns `Exited`.)
    pub fn wait(&mut self) -> WaitOutcome {
        if let Some(status) = self.status {
            return WaitOutcome::Exited(status);
        }
        let Some(child) = self.child.as_mut() else {
            return WaitOutcome::Exited(0);
        };
        match sys::wait_child(child) {
            Ok(WaitOutcome::Exited(status)) => {
                self.status = Some(status);
                WaitOutcome::Exited(status)
            }
            Ok(WaitOutcome::Interrupted) => WaitOutcome::Interrupted,
            Err(err) => {
                eprintln!("rush: {err}");
                self.status = Some(126);
                WaitOutcome::Exited(126)
            }
        }
    }

    /// The child's status if it has already exited, without blocking.
    pub fn try_reap(&mut self) -> Option<i32> {
        if let Some(status) = self.status {
            return Some(status);
        }
        let child = self.child.as_mut()?;
        match child.try_wait() {
            Ok(Some(s)) => {
                let status = sys::exit_status_code(s);
                self.status = Some(status);
                Some(status)
            }
            Ok(None) => None,
            Err(err) => {
                eprintln!("rush: {err}");
                self.status = Some(126);
                Some(126)
            }
        }
    }

    /// Terminate the child through its handle.
    ///
    /// Motor OS only: it has no pid to aim a kill at, so this is the sole way to
    /// stop a job there. The Unix host signals by pid instead, so that
    /// `kill -USR1 %1` can mean what it says (see [`Jobs::signal`]).
    #[cfg(not(unix))]
    pub fn kill(&mut self) -> std::io::Result<()> {
        match self.child.as_mut() {
            Some(child) => child.kill(),
            None => Ok(()),
        }
    }

    /// Join the pump threads and flush any captured output to its file.
    ///
    /// Must be called on the main thread, and only once the child has exited:
    /// this is the FS access that had to wait (see the struct docs).
    pub fn finish(&mut self) {
        if let Some(t) = self.feed.take() {
            let _ = t.join();
        }
        if let Some((t, file)) = self.out.take() {
            write_all(&file, &t.join().unwrap_or_default());
        }
        if let Some((t, file)) = self.err.take() {
            write_all(&file, &t.join().unwrap_or_default());
        }
        self.child = None;
    }
}

/// Read an entire file into memory (single-threaded FS access).
fn read_all(f: &Arc<File>) -> Vec<u8> {
    let mut buf = Vec::new();
    if let Ok(mut c) = f.try_clone() {
        let _ = c.read_to_end(&mut buf);
    }
    buf
}

/// Read a pipe to end (no FS).
fn read_stream(r: &mut dyn Read) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = r.read_to_end(&mut buf);
    buf
}

/// Append `bytes` to a file (single-threaded FS access).
fn write_all(f: &Arc<File>, bytes: &[u8]) {
    if let Ok(mut c) = f.try_clone() {
        let _ = c.write_all(bytes);
    }
}

// ---- the job table ----------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum JobState {
    Running,
    Done(i32),
}

/// The result of one [`Jobs::wait_step`].
pub enum JobWait {
    Done(i32),
    /// A signal arrived first: run the traps and step again.
    Interrupted,
    /// No such job.
    Gone,
}

pub struct Job {
    /// The job number, as `%n` names it.
    pub id: u32,
    /// What `$!` reported for this job, and what `wait`/`kill` match against.
    /// A real pid on the Unix host; rush's own number on Motor OS (module docs).
    pub pid: u64,
    /// The command text, for `jobs`.
    pub cmd: String,
    pub state: JobState,
    /// The live process, while there is one. `None` for a job that never was its
    /// own process — a builtin, compound command or function backgrounded on a
    /// platform with no `fork`, which rush runs to completion in place (§7).
    child: Option<PumpedChild>,
}

impl Job {
    /// Whether this job has finished.
    pub fn done(&self) -> Option<i32> {
        match self.state {
            JobState::Done(status) => Some(status),
            JobState::Running => None,
        }
    }
}

/// The background jobs of one shell.
///
/// Deliberately *not* part of [`crate::shell::Snapshot`]: a job is a property of
/// the process, not of the variable scope a subshell rolls back, and a live
/// `Child` cannot be cloned anyway. A consequence is that a job started inside an
/// emulated subshell stays visible to the parent, where a real `fork` would have
/// kept it private — one more item on the no-`fork` list in §3.4.
#[derive(Default)]
pub struct Jobs {
    jobs: Vec<Job>,
    next_id: u32,
    /// `$!`: the pid of the most recent background job.
    last_pid: Option<u64>,
    /// Counter behind [`Jobs::next_pid`].
    synthetic: u64,
    /// Jobs ever started, which unlike `next_id` never resets.
    started: u64,
}

impl Jobs {
    pub fn new() -> Self {
        Self {
            jobs: Vec::new(),
            next_id: 1,
            last_pid: None,
            synthetic: 0,
            started: 0,
        }
    }

    /// How many jobs this shell has ever started. Monotonic, so a caller can
    /// tell whether an attempt to background something actually started a job.
    pub fn started(&self) -> u64 {
        self.started
    }

    /// An identity for a job whose platform gives us no pid (Motor OS).
    ///
    /// Based well above any plausible pid so that passing `$!` to something
    /// outside rush — which cannot work there, see the module docs — fails to
    /// find a process rather than finding an unrelated one.
    fn next_pid(&mut self) -> u64 {
        const SYNTHETIC_BASE: u64 = 1 << 40;
        self.synthetic += 1;
        SYNTHETIC_BASE + self.synthetic
    }

    /// Record a newly started background job and return its `$!`.
    pub fn add(&mut self, cmd: String, child: Option<PumpedChild>, state: JobState) -> u64 {
        let pid = match child.as_ref().and_then(PumpedChild::pid) {
            Some(pid) => pid,
            None => self.next_pid(),
        };
        let id = self.next_id;
        self.next_id += 1;
        self.started += 1;
        self.jobs.push(Job {
            id,
            pid,
            cmd,
            state,
            child,
        });
        self.last_pid = Some(pid);
        pid
    }

    /// `$!` — the most recent background job's pid, or `None` if there has been
    /// none (POSIX leaves `$!` unset then, and dash expands it to nothing).
    pub fn last_pid(&self) -> Option<u64> {
        self.last_pid
    }

    pub fn iter(&self) -> impl Iterator<Item = &Job> {
        self.jobs.iter()
    }

    /// Collect the status of any job that has exited since the last look, so
    /// `jobs` and `wait` report it. Flushes each finished job's captured output
    /// (main-thread FS access — see [`PumpedChild::finish`]).
    pub fn poll(&mut self) {
        for job in &mut self.jobs {
            if job.state != JobState::Running {
                continue;
            }
            let Some(child) = job.child.as_mut() else {
                continue;
            };
            if let Some(status) = child.try_reap() {
                child.finish();
                job.state = JobState::Done(status);
            }
        }
    }

    /// Find a job by the `%n`/`%%`/`%+`/`%-` job control notation, or by pid.
    pub fn find(&self, spec: &str) -> Option<usize> {
        if let Some(rest) = spec.strip_prefix('%') {
            return match rest {
                // `%%`/`%+` name the current job, `%-` the previous one. With no
                // suspend/resume there is no user-visible "current job" to move,
                // so they mean the most recent (and next-most-recent) job.
                "%" | "+" | "" => self.jobs.len().checked_sub(1),
                "-" => self.jobs.len().checked_sub(2),
                _ => {
                    let id: u32 = rest.parse().ok()?;
                    self.jobs.iter().position(|j| j.id == id)
                }
            };
        }
        let pid: u64 = spec.parse().ok()?;
        self.jobs.iter().position(|j| j.pid == pid)
    }

    pub fn get(&self, idx: usize) -> Option<&Job> {
        self.jobs.get(idx)
    }

    /// One attempt to wait for a job.
    ///
    /// Step-wise rather than a loop with a callback because handling
    /// `Interrupted` means running a trap, which is a whole shell's worth of
    /// execution over the very `Shell` that owns this table — so the caller must
    /// have the borrow back before it can happen.
    pub fn wait_step(&mut self, idx: usize) -> JobWait {
        let Some(job) = self.jobs.get_mut(idx) else {
            return JobWait::Gone;
        };
        if let Some(status) = job.done() {
            return JobWait::Done(status);
        }
        let Some(child) = job.child.as_mut() else {
            // A job with no process of its own has already run to completion.
            job.state = JobState::Done(0);
            return JobWait::Done(0);
        };
        match child.wait() {
            WaitOutcome::Exited(status) => {
                child.finish();
                job.state = JobState::Done(status);
                JobWait::Done(status)
            }
            WaitOutcome::Interrupted => JobWait::Interrupted,
        }
    }

    /// Send a signal to a job's process. `None` if the job has no process (see
    /// [`Job::child`]) or has already finished.
    pub fn signal(&mut self, idx: usize, signo: i32) -> Option<Result<(), sys::KillError>> {
        let job = self.jobs.get_mut(idx)?;
        if job.done().is_some() {
            return Some(Err(sys::KillError::NoSuchProcess));
        }
        let pid = job.pid;
        let child = job.child.as_mut()?;
        Some(Self::signal_child(child, pid, signo))
    }

    /// Deliver a signal to one running child.
    ///
    /// Split per platform because the two have nothing in common: the Unix host
    /// signals by pid, so `kill -USR1 %1` means what it says, while Motor OS has
    /// no pid to aim at and exactly one thing it can do to a child — so a
    /// KILL/TERM goes through the handle and anything else is refused rather
    /// than quietly turned into a kill.
    #[cfg(unix)]
    fn signal_child(_child: &mut PumpedChild, pid: u64, signo: i32) -> Result<(), sys::KillError> {
        sys::kill(pid, signo)
    }

    #[cfg(not(unix))]
    fn signal_child(child: &mut PumpedChild, _pid: u64, signo: i32) -> Result<(), sys::KillError> {
        const SIGKILL: i32 = 9;
        const SIGTERM: i32 = 15;
        if signo != SIGKILL && signo != SIGTERM {
            return Err(sys::KillError::Unsupported);
        }
        child.kill().map_err(|_| sys::KillError::NoSuchProcess)
    }

    /// Forget finished jobs. POSIX has the shell report and then discard a
    /// completed job; rush does it after `jobs`/`wait` has had a chance to see
    /// it, so a status is never dropped before it is asked for.
    pub fn retain_unfinished(&mut self) {
        self.jobs.retain(|j| j.done().is_none());
        if self.jobs.is_empty() {
            self.next_id = 1;
        }
    }

    /// Every unfinished job, for `wait` with no arguments.
    pub fn running_indices(&self) -> Vec<usize> {
        (0..self.jobs.len())
            .filter(|&i| self.jobs[i].done().is_none())
            .collect()
    }
}
