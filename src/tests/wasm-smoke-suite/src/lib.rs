//! Harness shared by the installed wasm tool checks on Motor: each case runs one
//! rush command with a deadline and an expected exit status while sampling
//! whole-VM memory, and a suite fails if any memory admission was refused
//! outside its deliberate exhaustion cases.
#![cfg(target_os = "motor")]

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

use moto_sdk::stats::Collector;
use moto_sdk::sys::stats::{MemoryStats, ProcessInfoV1};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const DEADLINE: Duration = Duration::from_secs(120);
/// The status of a process the kernel killed.
const KILLED: i32 = -1;

pub struct Suite {
    name: &'static str,
    output: Box<dyn Write>,
    pub root: PathBuf,
    cases: usize,
    refusals: u64,
    expected_refusals: u64,
}

impl Suite {
    /// Prints the installed provenance in `sources` and creates a scratch
    /// directory writable by role None.
    pub fn new(name: &'static str, sources: &str) -> Result<Self> {
        Self::new_in(
            name,
            sources,
            Path::new("/none/wasm-tests"),
            std::io::stdout(),
        )
    }

    /// Creates a suite beneath an existing test directory and reports to `output`.
    pub fn new_in(
        name: &'static str,
        sources: &str,
        parent: &Path,
        output: impl Write + 'static,
    ) -> Result<Self> {
        // Retained outputs stay on disk so the small-VM memory measurements
        // exclude fixture storage. Children keep their role-specific TMPDIR.
        let root = parent.join(format!("{name}-{}", std::process::id()));
        create_writable_dir(&root)?;
        let mut output = Box::new(output);
        writeln!(
            output,
            "{name}: installed-tool checks; scratch={}",
            root.display()
        )?;
        writeln!(output, "{}", fs::read_to_string(sources)?)?;
        let available = MemoryStats::get().map_err(|e| format!("{e:?}"))?.available;
        writeln!(output, "usable_memory_bytes={available}")?;
        Ok(Self {
            name,
            output,
            root,
            cases: 0,
            refusals: admission_refusals()?,
            expected_refusals: 0,
        })
    }

    /// A new directory under the scratch root that role None can write.
    pub fn writable_dir(&self, name: &str) -> Result<PathBuf> {
        let dir = self.root.join(name);
        create_writable_dir(&dir)?;
        Ok(dir)
    }

    pub fn command(&mut self, label: &str, command: &str, code: i32) -> Result<(String, String)> {
        self.command_with_input(label, command, code, None)
    }

    /// With `input`, stdin is a pipe holding those bytes that stays open until
    /// the command exits; otherwise stdin is at EOF.
    pub fn command_with_input(
        &mut self,
        label: &str,
        command: &str,
        code: i32,
        input: Option<&[u8]>,
    ) -> Result<(String, String)> {
        let mut job = self.spawn(label, command, input.is_some(), false)?;
        if let Some(bytes) = input {
            job.stdin
                .as_mut()
                .ok_or("missing stdin pipe")?
                .write_all(bytes)?;
        }
        self.wait(&mut job, code)
    }

    /// Starts `command` for a case that interacts with it before `wait`. With
    /// `terminal`, its stdin is an open pipe marked as a terminal, as an
    /// interactive session's is, so `Job::ctrl_c` reaches its foreground job.
    pub fn start(&self, label: &str, command: &str, terminal: bool) -> Result<Job> {
        self.spawn(label, command, terminal, terminal)
    }

    fn spawn(&self, label: &str, command: &str, piped: bool, terminal: bool) -> Result<Job> {
        let stdout_path = self.root.join(format!("{label}.stdout"));
        let stderr_path = self.root.join(format!("{label}.stderr"));
        let mut rush = Command::new("/system/bin/rush");
        preserve_system_role(&mut rush);
        rush.args(["-c", command])
            .current_dir(&self.root)
            .stdin(if piped { Stdio::piped() } else { Stdio::null() })
            .stdout(fs::File::create(&stdout_path)?)
            .stderr(fs::File::create(&stderr_path)?);
        if terminal {
            rush.env(moto_sdk::rt::process::STDIO_IS_TERMINAL_ENV_KEY, "true");
        }
        let mut child = rush.spawn()?;
        Ok(Job {
            label: label.to_owned(),
            stdin: child.stdin.take(),
            child,
            stdout_path,
            stderr_path,
            started: Instant::now(),
        })
    }

    /// Waits for `job` to exit with `code` while sampling whole-VM memory.
    pub fn wait(&mut self, job: &mut Job, code: i32) -> Result<(String, String)> {
        let label = &job.label;
        let mut last = Instant::now();
        let mut gap = Duration::ZERO;
        let mut peak = 0;
        // Sampled whole-VM peaks include this driver; they are not RSS.
        let status = loop {
            let sample = MemoryStats::get().map_err(|e| format!("memory stats: {e:?}"))?;
            peak = peak.max(sample.used());
            let now = Instant::now();
            gap = gap.max(now - last);
            last = now;
            if let Some(status) = job.child.try_wait()? {
                break status;
            }
            if job.started.elapsed() >= DEADLINE {
                job.child.kill()?;
                job.child.wait()?;
                let (stdout, stderr) = job.logs()?;
                return Err(format!("{label}: exceeded {DEADLINE:?}\n{stdout}\n{stderr}").into());
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let (stdout, stderr) = job.logs()?;
        if status.code() != Some(code) {
            return Err(
                format!("{label}: expected exit {code}, got {status}\n{stdout}\n{stderr}").into(),
            );
        }
        writeln!(
            self.output,
            "PASS {label}: exit={code} elapsed_ms={} sampled_vm_peak_bytes={peak} max_gap_us={}",
            job.started.elapsed().as_millis(),
            gap.as_micros()
        )?;
        self.cases += 1;
        Ok((stdout, stderr))
    }

    /// A command that must fail with exit 1 and name `diagnostic` on stderr.
    pub fn refusal(&mut self, label: &str, command: &str, diagnostic: &str) -> Result<()> {
        let (_, stderr) = self.command(label, command, 1)?;
        if !stderr.contains(diagnostic) {
            return Err(format!("{label}: missing diagnostic {diagnostic:?}: {stderr}").into());
        }
        Ok(())
    }

    /// Runs `command`, which the kernel must kill when one of its page faults
    /// is refused, while this driver holds all usable memory but `free` bytes.
    /// That single refusal is expected; any other still fails the suite.
    pub fn refused_fault(&mut self, label: &str, command: &str, free: u64) -> Result<()> {
        let stats = MemoryStats::get().map_err(|e| format!("memory stats: {e:?}"))?;
        let hold = (stats.available - stats.used()).saturating_sub(free) as usize;
        let mut held = Vec::new();
        held.try_reserve_exact(hold)?;
        held.resize(hold, 1_u8);
        let before = admission_refusals()?;
        let result = self.command(label, command, KILLED);
        drop(held);
        result?;
        let refused = admission_refusals()? - before;
        if refused != 1 {
            return Err(format!("{label}: {refused} admission refusals, not one").into());
        }
        writeln!(
            self.output,
            "{label}: held={hold} expected_admission_refusals=1"
        )?;
        self.refusals += 1;
        self.expected_refusals += 1;
        Ok(())
    }

    pub fn same_bytes(&self, first: &str, second: &str) -> Result<()> {
        let mut first = fs::File::open(self.root.join(first))?;
        let mut second = fs::File::open(self.root.join(second))?;
        if first.metadata()?.len() != second.metadata()?.len() {
            return Err("output lengths differ".into());
        }
        let mut a = [0; 4096];
        let mut b = [0; 4096];
        loop {
            let count = first.read(&mut a)?;
            if count == 0 {
                return Ok(());
            }
            second.read_exact(&mut b[..count])?;
            if a[..count] != b[..count] {
                return Err("output bytes differ".into());
            }
        }
    }

    /// Fails on any memory admission refusal since `new` and removes the
    /// scratch directory.
    pub fn finish(mut self) -> Result<()> {
        if admission_refusals()? != self.refusals {
            return Err("unexpected memory admission refusals".into());
        }
        fs::remove_dir_all(&self.root)?;
        writeln!(
            self.output,
            "{}: {} commands PASS; admission_refusal_delta=0 expected_refusals={}",
            self.name, self.cases, self.expected_refusals
        )?;
        Ok(())
    }
}

/// A rush command started by `Suite::start`.
pub struct Job {
    label: String,
    child: Child,
    stdin: Option<ChildStdin>,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    started: Instant,
}

impl Job {
    /// Waits until the command's stdout contains `text`.
    pub fn wait_stdout(&mut self, text: &str) -> Result<()> {
        self.wait_output(text, false).map(|_| ())
    }

    /// Waits for a diagnostic and returns stderr, including reported addresses.
    pub fn wait_stderr(&mut self, text: &str) -> Result<String> {
        self.wait_output(text, true)
    }

    fn wait_output(&mut self, text: &str, use_stderr: bool) -> Result<String> {
        loop {
            let (stdout, stderr) = self.logs()?;
            let output = if use_stderr { &stderr } else { &stdout };
            if output.contains(text) {
                return Ok(output.clone());
            }
            if let Some(status) = self.child.try_wait()? {
                return Err(
                    format!("{}: exited {status} before {text:?}\n{stderr}", self.label).into(),
                );
            }
            if self.started.elapsed() >= DEADLINE {
                return Err(format!("{}: no {text:?} within {DEADLINE:?}", self.label).into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Types Ctrl+C on the terminal of a job started with `terminal`.
    pub fn ctrl_c(&mut self) -> Result<()> {
        let stdin = self.stdin.as_mut().ok_or("not a terminal job")?;
        stdin.write_all(b"\x03")?;
        Ok(())
    }

    pub fn kill(&mut self) -> Result<()> {
        Ok(self.child.kill()?)
    }

    /// Active direct children of the job's rush, as (pid, name).
    pub fn children(&self) -> Result<Vec<(u64, String)>> {
        let mut list = [ProcessInfoV1::default(); 16];
        let count = ProcessInfoV1::list_children(self.child.id().into(), &mut list)
            .map_err(|e| format!("process list: {e:?}"))?;
        Ok(list[..count]
            .iter()
            .filter(|info| info.active != 0)
            .map(|info| (info.pid, info.debug_name().to_owned()))
            .collect())
    }

    /// Reads bounded stdout/stderr snapshots for an interactive case's failure.
    pub fn logs(&self) -> Result<(String, String)> {
        let read = |path: &Path| -> Result<String> {
            if fs::metadata(path)?.len() > 256 * 1024 {
                return Err(format!("oversized command log: {path:?}").into());
            }
            Ok(fs::read_to_string(path)?)
        };
        Ok((read(&self.stdout_path)?, read(&self.stderr_path)?))
    }
}

/// Whether `pid` names a process that has not exited.
pub fn process_active(pid: u64) -> Result<bool> {
    let mut list = [ProcessInfoV1::default(); 1];
    let count = ProcessInfoV1::list(pid, &mut list).map_err(|e| format!("process list: {e:?}"))?;
    Ok(count == 1 && list[0].pid == pid && list[0].active != 0)
}

/// Whole-VM used memory, as the cases sample it.
pub fn used_memory() -> Result<u64> {
    Ok(MemoryStats::get()
        .map_err(|e| format!("memory stats: {e:?}"))?
        .used())
}

/// Directories are created readable but not writable for lower roles.
fn create_writable_dir(dir: &Path) -> Result<()> {
    fs::create_dir(dir)?;
    let mut chmod = Command::new("/system/bin/chmod");
    preserve_system_role(&mut chmod);
    if !chmod.arg("rwxrwxrwx").arg(dir).status()?.success() {
        return Err(format!("could not make {dir:?} writable to role None").into());
    }
    Ok(())
}

/// System does not propagate on ordinary spawns. Keep the launcher's authority
/// for its shell and for chmod of directories it created as System.
fn preserve_system_role(command: &mut Command) {
    let caps = moto_sdk::sys::ProcessStaticPage::get().capabilities;
    if caps & moto_sdk::sys::caps::CAP_SYS != 0 {
        command.env(
            moto_sdk::sys::caps::MOTOR_OS_CAPS_ENV_KEY,
            format!("0x{caps:x}"),
        );
    }
}

fn admission_refusals() -> Result<u64> {
    let kernel = Collector::kernel();
    let catalog = Collector::describe(&kernel).map_err(|e| format!("metric catalog: {e:?}"))?;
    // Refusals are counted on the kernel's own process stats.
    let values = Collector::query_scoped(&kernel, moto_sdk::sys::stats::PID_KERNEL)
        .map_err(|e| format!("kernel metrics: {e:?}"))?;
    let mut total = 0;
    for name in ["mem.admission_refused_user", "mem.admission_refused_sys_io"] {
        let id = catalog
            .iter()
            .find(|m| m.name == name)
            .ok_or("missing refusal metric")?
            .id;
        total += values
            .iter()
            .find(|m| m.metric == id)
            .ok_or("missing refusal counter")?
            .value;
    }
    Ok(total)
}
