//! Harness shared by the installed wasm tool checks on Motor: each case runs one
//! rush command with a deadline and an expected exit status while sampling
//! whole-VM memory, and a suite fails if any memory admission was refused.
#![cfg(target_os = "motor")]

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use moto_stats::Collector;
use moto_sys::stats::MemoryStats;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const DEADLINE: Duration = Duration::from_secs(120);

pub struct Suite {
    name: &'static str,
    pub root: PathBuf,
    cases: usize,
    refusals: u64,
}

impl Suite {
    /// Prints the installed provenance in `sources` and creates a scratch
    /// directory writable by role None.
    pub fn new(name: &'static str, sources: &str) -> Result<Self> {
        let root = PathBuf::from(format!("/user/tmp/{name}-{}", std::process::id()));
        fs::create_dir(&root)?;
        if !Command::new("/system/bin/chmod")
            .arg("rwxrwxrwx")
            .arg(&root)
            .status()?
            .success()
        {
            return Err("could not make scratch directory writable to role None".into());
        }
        println!("{name}: installed-tool checks; scratch={}", root.display());
        println!("{}", fs::read_to_string(sources)?);
        let available = MemoryStats::get().map_err(|e| format!("{e:?}"))?.available;
        println!("usable_memory_bytes={available}");
        Ok(Self {
            name,
            root,
            cases: 0,
            refusals: admission_refusals()?,
        })
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
        let stdout_path = self.root.join(format!("{label}.stdout"));
        let stderr_path = self.root.join(format!("{label}.stderr"));
        let mut child = Command::new("/system/bin/rush")
            .args(["-c", command])
            .current_dir(&self.root)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(fs::File::create(&stdout_path)?)
            .stderr(fs::File::create(&stderr_path)?)
            .spawn()?;
        let _stdin = match input {
            Some(bytes) => {
                let mut pipe = child.stdin.take().ok_or("missing stdin pipe")?;
                pipe.write_all(bytes)?;
                Some(pipe)
            }
            None => None,
        };
        let started = Instant::now();
        let mut last = started;
        let mut gap = Duration::ZERO;
        let mut peak = 0;
        let read_log = |path: &Path| -> Result<String> {
            if fs::metadata(path)?.len() > 256 * 1024 {
                return Err(format!("oversized command log: {path:?}").into());
            }
            Ok(fs::read_to_string(path)?)
        };
        // Sampled whole-VM peaks include this driver; they are not RSS.
        let status = loop {
            let sample = MemoryStats::get().map_err(|e| format!("memory stats: {e:?}"))?;
            peak = peak.max(sample.used());
            let now = Instant::now();
            gap = gap.max(now - last);
            last = now;
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if started.elapsed() >= DEADLINE {
                child.kill()?;
                child.wait()?;
                let (stdout, stderr) = (read_log(&stdout_path)?, read_log(&stderr_path)?);
                return Err(format!("{label}: exceeded {DEADLINE:?}\n{stdout}\n{stderr}").into());
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let stdout = read_log(&stdout_path)?;
        let stderr = read_log(&stderr_path)?;
        if status.code() != Some(code) {
            return Err(
                format!("{label}: expected exit {code}, got {status}\n{stdout}\n{stderr}").into(),
            );
        }
        println!(
            "PASS {label}: exit={code} elapsed_ms={} sampled_vm_peak_bytes={peak} max_gap_us={}",
            started.elapsed().as_millis(),
            gap.as_micros()
        );
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
    pub fn finish(self) -> Result<()> {
        if admission_refusals()? != self.refusals {
            return Err("unexpected memory admission refusals".into());
        }
        fs::remove_dir_all(&self.root)?;
        println!(
            "{}: {} commands PASS; admission_refusal_delta=0",
            self.name, self.cases
        );
        Ok(())
    }
}

fn admission_refusals() -> Result<u64> {
    let kernel = Collector::kernel();
    let catalog = Collector::describe(&kernel).map_err(|e| format!("metric catalog: {e:?}"))?;
    let values = Collector::query(&kernel).map_err(|e| format!("kernel metrics: {e:?}"))?;
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
