use std::env;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::atomic::AtomicDirectory;
use crate::config::PolicyLimits;
use crate::diagnostic::{Error, Result};
use crate::hash::hex;
use crate::source_tree::{Exclusions, Limits, Tree};

use super::{GitPatch, Materialized};

const GIT_SECONDS: u64 = 300;
const GIT_OUTPUT_BYTES: u64 = 8 * 1024 * 1024;
const GIT_FETCH_RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(3),
    Duration::from_secs(5),
];

pub(super) fn materialize_one(
    root: &Path,
    patch: &GitPatch,
    git: &Path,
    limits: Limits,
    accept_all: bool,
    verbose: bool,
) -> Result<Materialized> {
    let relative = format!(".lorry/vendor/{}/source", patch.alias);
    let destination = root.join(".lorry/vendor").join(&patch.alias);
    if destination.exists() {
        return Err(Error::failure(format!(
            "Git patch destination `{}` already exists while Cargo.toml still declares Git",
            destination.display()
        ))
        .with_help(
            "remove the incomplete destination after review, or restore its matching local path patch",
        ));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| Error::failure("Git patch destination has no parent"))?;
    let staging = AtomicDirectory::new(parent, &format!("git-{}", patch.alias))?;
    let repository = staging.path().join("repository.git");
    let source = staging.path().join("source");
    fs::create_dir(&source).map_err(|error| {
        Error::failure(format!(
            "failed to create private Git source staging: {error}"
        ))
    })?;
    let mut runner = GitRunner::new(git, staging.path(), verbose);
    runner.run(&["init", "--bare", path_text(&repository)?])?;
    runner.run(&[
        "--git-dir",
        path_text(&repository)?,
        "remote",
        "add",
        "origin",
        &patch.url,
    ])?;
    let requested = patch.selector.fetch_spec();
    runner.fetch(&[
        "--git-dir",
        path_text(&repository)?,
        "fetch",
        "--depth=1",
        "--no-tags",
        "origin",
        &requested,
    ])?;
    let fetched = runner.text(&[
        "--git-dir",
        path_text(&repository)?,
        "rev-parse",
        "--verify",
        "FETCH_HEAD^{commit}",
    ])?;
    let commit = if let Some(locked) = &patch.locked_commit {
        if &fetched != locked {
            runner.fetch(&[
                "--git-dir",
                path_text(&repository)?,
                "fetch",
                "--depth=1",
                "--no-tags",
                "origin",
                locked,
            ])?;
        }
        locked.clone()
    } else {
        fetched
    };
    let tree = runner.text(&[
        "--git-dir",
        path_text(&repository)?,
        "rev-parse",
        "--verify",
        &format!("{commit}^{{tree}}"),
    ])?;
    runner.run(&[
        "--git-dir",
        path_text(&repository)?,
        "--work-tree",
        path_text(&source)?,
        "checkout",
        "--force",
        &commit,
        "--",
        ".",
    ])?;
    fs::remove_dir_all(&repository).map_err(|error| {
        Error::failure(format!(
            "failed to remove private Git object staging: {error}"
        ))
    })?;
    let source_tree = Tree::scan(&source, limits, Exclusions::None)?;
    approve(patch, &commit, &tree, &source_tree, accept_all)?;
    let provenance = format!(
        "format-version = 1\nalias = {:?}\ngit-url = {:?}\nrequested-revision = {:?}\nresolved-commit = {:?}\ngit-tree = {:?}\nsource-tree-sha256 = {:?}\n",
        patch.alias,
        patch.url,
        patch.selector.requested(),
        commit,
        tree,
        hex(&source_tree.sha256),
    );
    fs::write(staging.path().join("git.toml"), provenance).map_err(|error| {
        Error::failure(format!("failed to write Git provenance staging: {error}"))
    })?;
    staging.commit(&destination)?;
    Ok(Materialized { path: relative })
}

fn approve(
    patch: &GitPatch,
    commit: &str,
    tree: &str,
    source: &Tree,
    accept_all: bool,
) -> Result<()> {
    eprintln!(
        "Git patch {}\n  URL: {}\n  requested: {}\n  commit: {}\n  tree: {}\n  source SHA-256: {}\n  files: {}; bytes: {}",
        patch.alias,
        patch.url,
        patch.selector.requested(),
        commit,
        tree,
        hex(&source.sha256),
        source.file_count,
        source.total_bytes,
    );
    if accept_all {
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        return Err(Error::failure(format!(
            "Git patch `{}` requires approval on non-interactive input",
            patch.alias
        ))
        .with_help("review the evidence, then rerun `lorry vendor --accept-all`"));
    }
    eprint!("Materialize this Git patch? [y/N] ");
    io::stderr()
        .flush()
        .map_err(|error| Error::failure(format!("failed to flush Git approval prompt: {error}")))?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|error| Error::failure(format!("failed to read Git approval: {error}")))?;
    if answer.trim().eq_ignore_ascii_case("y") || answer.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        Err(Error::failure(format!(
            "Git patch `{}` was not approved",
            patch.alias
        )))
    }
}

pub(super) fn tree_limits(policy: &PolicyLimits) -> Result<Limits> {
    Ok(Limits {
        max_entries: usize::try_from(policy.max_package_files)
            .map_err(|_| Error::failure("Git source file limit does not fit this platform"))?,
        max_path_bytes: 4096,
        max_file_bytes: policy.max_extracted_package_bytes,
        max_tree_bytes: policy.max_extracted_package_bytes,
    })
}

pub(super) fn find_git() -> Result<PathBuf> {
    let path = env::var_os("PATH").ok_or_else(|| {
        Error::failure("local Git is required to materialize `[patch.crates-io]` Git entries")
    })?;
    for directory in env::split_paths(&path) {
        let candidate = directory.join("git");
        if candidate.is_file() {
            return fs::canonicalize(&candidate).map_err(|error| {
                Error::failure(format!(
                    "failed to canonicalize local Git `{}`: {error}",
                    candidate.display()
                ))
            });
        }
    }
    Err(
        Error::failure("local Git is required to materialize `[patch.crates-io]` Git entries")
            .with_help("install Git on Linux, or vendor the project on another Linux host"),
    )
}

struct GitRunner<'a> {
    program: &'a Path,
    current_dir: &'a Path,
    home: PathBuf,
    verbose: bool,
}

impl<'a> GitRunner<'a> {
    fn new(program: &'a Path, current_dir: &'a Path, verbose: bool) -> Self {
        Self {
            program,
            current_dir,
            home: current_dir.join("home"),
            verbose,
        }
    }

    fn run(&mut self, arguments: &[&str]) -> Result<Vec<u8>> {
        fs::create_dir_all(&self.home).map_err(|error| {
            Error::failure(format!("failed to create private Git home: {error}"))
        })?;
        let template = self.current_dir.join("empty-template");
        fs::create_dir_all(&template).map_err(|error| {
            Error::failure(format!("failed to create empty Git template: {error}"))
        })?;
        if self.verbose {
            eprintln!("Running {} {}", self.program.display(), arguments.join(" "));
        }
        let mut command = Command::new(self.program);
        command
            .args(arguments)
            .env_clear()
            .env("HOME", &self.home)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_TEMPLATE_DIR", template)
            .env("LC_ALL", "C")
            .current_dir(self.current_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let captured = capture(&mut command)?;
        if !captured.status.success() {
            let diagnostic = String::from_utf8_lossy(&captured.stderr);
            return Err(Error::failure(format!(
                "local Git failed{}{}",
                captured
                    .status
                    .code()
                    .map_or_else(String::new, |code| format!(" with status {code}")),
                if diagnostic.trim().is_empty() {
                    String::new()
                } else {
                    format!(": {}", diagnostic.trim())
                }
            )));
        }
        Ok(captured.stdout)
    }

    fn text(&mut self, arguments: &[&str]) -> Result<String> {
        let output = self.run(arguments)?;
        let value = std::str::from_utf8(&output)
            .map_err(|_| Error::failure("local Git returned non-UTF-8 identity output"))?
            .trim();
        if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Error::failure(format!(
                "local Git returned invalid object identity `{value}`"
            )));
        }
        Ok(value.to_ascii_lowercase())
    }

    fn fetch(&mut self, arguments: &[&str]) -> Result<Vec<u8>> {
        run_with_retries(
            &GIT_FETCH_RETRY_DELAYS,
            || self.run(arguments),
            std::thread::sleep,
        )
    }
}

fn run_with_retries<T>(
    delays: &[Duration],
    mut operation: impl FnMut() -> Result<T>,
    mut wait: impl FnMut(Duration),
) -> Result<T> {
    for (attempt, delay) in delays.iter().enumerate() {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) => {
                eprintln!(
                    "local Git fetch attempt {} failed: {error}; retrying in {} second(s)",
                    attempt + 1,
                    delay.as_secs()
                );
                wait(*delay);
            }
        }
    }
    operation()
}

struct Captured {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn capture(command: &mut Command) -> Result<Captured> {
    let mut child = command
        .spawn()
        .map_err(|error| Error::failure(format!("failed to execute local Git: {error}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::failure("local Git stdout pipe was not created"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| Error::failure("local Git stderr pipe was not created"))?;
    let total = Arc::new(AtomicU64::new(0));
    let exceeded = Arc::new(AtomicBool::new(false));
    let stdout_thread = capture_pipe(stdout, total.clone(), exceeded.clone());
    let stderr_thread = capture_pipe(stderr, total, exceeded.clone());
    let started = Instant::now();
    let status = loop {
        if exceeded.load(Ordering::Acquire) || started.elapsed() >= Duration::from_secs(GIT_SECONDS)
        {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err(if exceeded.load(Ordering::Acquire) {
                Error::failure(format!(
                    "local Git output exceeded the {GIT_OUTPUT_BYTES}-byte limit"
                ))
            } else {
                Error::failure(format!("local Git timed out after {GIT_SECONDS} seconds"))
            });
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(Error::failure(format!(
                    "failed while waiting for local Git: {error}"
                )));
            }
        }
    };
    let stdout = stdout_thread
        .join()
        .map_err(|_| Error::failure("local Git stdout capture thread panicked"))??;
    let stderr = stderr_thread
        .join()
        .map_err(|_| Error::failure("local Git stderr capture thread panicked"))??;
    Ok(Captured {
        status,
        stdout,
        stderr,
    })
}

fn capture_pipe(
    mut pipe: impl Read + Send + 'static,
    total: Arc<AtomicU64>,
    exceeded: Arc<AtomicBool>,
) -> std::thread::JoinHandle<io::Result<Vec<u8>>> {
    std::thread::spawn(move || {
        let mut captured = Vec::new();
        let mut buffer = [0_u8; 8192];
        loop {
            let read = pipe.read(&mut buffer)?;
            if read == 0 {
                return Ok(captured);
            }
            let previous = total.fetch_add(read as u64, Ordering::AcqRel);
            let available = GIT_OUTPUT_BYTES.saturating_sub(previous) as usize;
            captured.extend_from_slice(&buffer[..read.min(available)]);
            if read > available {
                exceeded.store(true, Ordering::Release);
            }
        }
    })
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| Error::failure(format!("Git path `{}` is not UTF-8", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_retries_three_times_with_the_reviewed_schedule() {
        let mut attempts = 0;
        let mut waits = Vec::new();
        let result = run_with_retries(
            &GIT_FETCH_RETRY_DELAYS,
            || {
                attempts += 1;
                if attempts < 4 {
                    Err(Error::failure(format!("failure {attempts}")))
                } else {
                    Ok("fetched")
                }
            },
            |delay| waits.push(delay),
        );

        assert_eq!(result.unwrap(), "fetched");
        assert_eq!(attempts, 4);
        assert_eq!(
            waits,
            [
                Duration::from_secs(1),
                Duration::from_secs(3),
                Duration::from_secs(5)
            ]
        );
    }
}
