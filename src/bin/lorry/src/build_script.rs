#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::diagnostic::{Error, Result};
use crate::sandbox::{Executable, NetworkAccess, Policy, Sandbox};
use crate::source_tree::{Exclusions, Limits as TreeLimits, Tree};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Output {
    pub directives: Vec<Directive>,
    pub diagnostics: Vec<String>,
    pub stderr: String,
    pub out_dir: Tree,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Directive {
    RustcCfg(String),
    RustcCheckCfg(String),
    RustcEnv { name: String, value: String },
    RustcLinkLib(String),
    RustcLinkSearch { kind: Option<String>, path: PathBuf },
    RerunIfChanged(PathBuf),
    RerunIfEnvChanged(String),
    Warning(String),
}

pub struct ParseOptions<'a> {
    pub package_root: &'a Path,
    pub out_dir: &'a Path,
    pub approved_environment: &'a BTreeSet<String>,
    pub max_bytes: u64,
    pub out_dir_limits: TreeLimits,
}

pub struct RunOptions<'a> {
    pub executable: &'a Path,
    pub arguments: &'a [OsString],
    pub environment: &'a BTreeMap<String, OsString>,
    pub package_root: &'a Path,
    pub out_dir: &'a Path,
    pub temp_dir: &'a Path,
    pub read_only: &'a [PathBuf],
    pub executables: &'a [Executable],
    pub timeout: Duration,
    pub max_output_bytes: u64,
    pub out_dir_limits: TreeLimits,
    pub verbose: bool,
}

pub fn run(options: &RunOptions<'_>) -> Result<Output> {
    if options.timeout.is_zero() {
        return Err(Error::failure("build-script timeout must be nonzero"));
    }
    if options.max_output_bytes == 0 {
        return Err(Error::failure("build-script output limit must be nonzero"));
    }
    let package_root = canonical_directory(options.package_root, "package root")?;
    let out_dir = canonical_directory(options.out_dir, "OUT_DIR")?;
    let temp_dir = canonical_directory(options.temp_dir, "temporary directory")?;
    if package_root.starts_with(&out_dir) || package_root.starts_with(&temp_dir) {
        return Err(Error::failure(
            "build-script package root may not be nested inside a writable sandbox directory",
        ));
    }
    if out_dir.starts_with(&temp_dir) || temp_dir.starts_with(&out_dir) {
        return Err(Error::failure(format!(
            "build-script OUT_DIR `{}` and temporary directory `{}` overlap",
            out_dir.display(),
            temp_dir.display()
        )));
    }

    let mut read_only = options.read_only.to_vec();
    read_only.push(package_root.clone());
    let policy = Policy {
        read_only,
        writable: vec![out_dir.clone(), temp_dir],
        executables: options.executables.to_vec(),
        network: NetworkAccess::Deny,
    };
    let mut command = Command::new(options.executable);
    command
        .args(options.arguments)
        .env_clear()
        .envs(options.environment)
        .current_dir(&package_root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    crate::sandbox::platform().apply(&mut command, &policy)?;
    if options.verbose {
        eprintln!(
            "Running sandboxed {}",
            crate::process::display_command(options.executable.as_os_str(), options.arguments)
        );
    }
    let captured = capture(&mut command, options.timeout, options.max_output_bytes)?;
    if !captured.status.success() {
        let stderr = String::from_utf8_lossy(&captured.stderr);
        return Err(Error::failure(format!(
            "build script `{}` failed{}{}",
            options.executable.display(),
            captured.status.code().map_or_else(
                || " after being terminated by a signal".to_owned(),
                |code| { format!(" with status {code}") }
            ),
            if stderr.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", stderr.trim())
            }
        )));
    }

    let approved_environment = options.environment.keys().cloned().collect();
    let mut output = parse(
        &captured.stdout,
        &ParseOptions {
            package_root: &package_root,
            out_dir: &out_dir,
            approved_environment: &approved_environment,
            max_bytes: options.max_output_bytes,
            out_dir_limits: options.out_dir_limits,
        },
    )?;
    output.stderr = String::from_utf8_lossy(&captured.stderr).into_owned();
    Ok(output)
}

struct Captured {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn capture(command: &mut Command, timeout: Duration, max_bytes: u64) -> Result<Captured> {
    let mut child = command.spawn().map_err(|error| {
        Error::failure(format!(
            "failed to start sandboxed build script `{}`: {error}",
            Path::new(command.get_program()).display()
        ))
    })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::failure("build-script stdout pipe was not created"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| Error::failure("build-script stderr pipe was not created"))?;
    let total = Arc::new(AtomicU64::new(0));
    let exceeded = Arc::new(AtomicBool::new(false));
    let stdout_thread = capture_pipe(stdout, total.clone(), exceeded.clone(), max_bytes);
    let stderr_thread = capture_pipe(stderr, total, exceeded.clone(), max_bytes);
    let started = Instant::now();
    let status = loop {
        if exceeded.load(Ordering::Acquire) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err(Error::failure(format!(
                "build-script output exceeded the {max_bytes}-byte combined limit"
            )));
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err(Error::failure(format!(
                "build script timed out after {} ms",
                timeout.as_millis()
            )));
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
                    "failed while waiting for build script: {error}"
                )));
            }
        }
    };
    let stdout = stdout_thread
        .join()
        .map_err(|_| Error::failure("build-script stdout capture thread panicked"))??;
    let stderr = stderr_thread
        .join()
        .map_err(|_| Error::failure("build-script stderr capture thread panicked"))??;
    if exceeded.load(Ordering::Acquire) {
        return Err(Error::failure(format!(
            "build-script output exceeded the {max_bytes}-byte combined limit"
        )));
    }
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
    max_bytes: u64,
) -> std::thread::JoinHandle<std::io::Result<Vec<u8>>> {
    std::thread::spawn(move || {
        let mut captured = Vec::new();
        let mut buffer = [0_u8; 8192];
        loop {
            let read = pipe.read(&mut buffer)?;
            if read == 0 {
                return Ok(captured);
            }
            let previous = total.fetch_add(read as u64, Ordering::AcqRel);
            let available = max_bytes.saturating_sub(previous) as usize;
            captured.extend_from_slice(&buffer[..read.min(available)]);
            if read > available {
                exceeded.store(true, Ordering::Release);
            }
        }
    })
}

pub fn parse(stdout: &[u8], options: &ParseOptions<'_>) -> Result<Output> {
    if stdout.len() as u64 > options.max_bytes {
        return Err(Error::failure(format!(
            "build-script stdout is {} bytes, exceeding the {}-byte limit",
            stdout.len(),
            options.max_bytes
        )));
    }
    let stdout = std::str::from_utf8(stdout)
        .map_err(|_| Error::failure("build-script stdout is not valid UTF-8"))?;
    let package_root = canonical_directory(options.package_root, "package root")?;
    let out_dir = canonical_directory(options.out_dir, "OUT_DIR")?;
    if !out_dir.starts_with(&package_root) && package_root.starts_with(&out_dir) {
        return Err(Error::failure(
            "build-script package root may not be nested inside OUT_DIR",
        ));
    }

    let mut output = Output {
        directives: Vec::new(),
        diagnostics: Vec::new(),
        stderr: String::new(),
        out_dir: Tree::scan(&out_dir, options.out_dir_limits, Exclusions::None)?,
    };
    for (index, raw_line) in stdout.split('\n').enumerate() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let directive = line
            .strip_prefix("cargo::")
            .or_else(|| line.strip_prefix("cargo:"));
        let Some(directive) = directive else {
            if !line.is_empty() {
                output.diagnostics.push(line.to_owned());
            }
            continue;
        };
        let (name, value) = directive.split_once('=').ok_or_else(|| {
            Error::failure(format!(
                "build-script directive on line {} has no `=` value",
                index + 1
            ))
        })?;
        validate_directive_value(name, value, index + 1)?;
        let parsed = match name {
            "rustc-cfg" => Directive::RustcCfg(value.to_owned()),
            "rustc-check-cfg" => Directive::RustcCheckCfg(value.to_owned()),
            "rustc-env" => {
                let (name, value) = value.split_once('=').ok_or_else(|| {
                    Error::failure(format!(
                        "build-script rustc-env directive on line {} must be NAME=VALUE",
                        index + 1
                    ))
                })?;
                validate_environment_name(name, "rustc-env")?;
                Directive::RustcEnv {
                    name: name.to_owned(),
                    value: value.to_owned(),
                }
            }
            "rustc-link-lib" => Directive::RustcLinkLib(value.to_owned()),
            "rustc-link-search" => {
                let (kind, path) = split_link_search(value)?;
                Directive::RustcLinkSearch {
                    kind: kind.map(str::to_owned),
                    path: resolve_existing(path, &package_root, &[&out_dir], "rustc-link-search")?,
                }
            }
            "rerun-if-changed" => Directive::RerunIfChanged(resolve_existing(
                value,
                &package_root,
                &[&package_root, &out_dir],
                "rerun-if-changed",
            )?),
            "rerun-if-env-changed" => {
                validate_environment_name(value, "rerun-if-env-changed")?;
                if !options.approved_environment.contains(value) {
                    return Err(Error::failure(format!(
                        "build-script rerun-if-env-changed names unapproved environment variable `{value}`"
                    )));
                }
                Directive::RerunIfEnvChanged(value.to_owned())
            }
            "warning" => Directive::Warning(value.to_owned()),
            "error" => {
                return Err(Error::failure(format!(
                    "build script reported an error: {value}"
                )));
            }
            _ => {
                return Err(Error::failure(format!(
                    "unsupported build-script directive `{name}` on line {}",
                    index + 1
                ))
                .with_help("use only the Stage-2 cargo directive subset documented in plan.md"));
            }
        };
        output.directives.push(parsed);
    }
    Ok(output)
}

fn canonical_directory(path: &Path, description: &str) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        Error::failure(format!(
            "failed to canonicalize build-script {description} `{}`: {error}",
            path.display()
        ))
    })?;
    if !canonical.is_dir() {
        return Err(Error::failure(format!(
            "build-script {description} `{}` is not a directory",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn resolve_existing(
    value: &str,
    package_root: &Path,
    allowed_roots: &[&Path],
    directive: &str,
) -> Result<PathBuf> {
    let declared = Path::new(value);
    let path = if declared.is_absolute() {
        declared.to_owned()
    } else {
        package_root.join(declared)
    };
    let canonical = fs::canonicalize(&path).map_err(|error| {
        Error::failure(format!(
            "build-script {directive} path `{}` cannot be resolved: {error}",
            path.display()
        ))
    })?;
    if !allowed_roots.iter().any(|root| canonical.starts_with(root)) {
        return Err(Error::failure(format!(
            "build-script {directive} path `{}` escapes its permitted roots",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn split_link_search(value: &str) -> Result<(Option<&str>, &str)> {
    let Some((kind, path)) = value.split_once('=') else {
        return Ok((None, value));
    };
    if !matches!(
        kind,
        "dependency" | "crate" | "native" | "framework" | "all"
    ) {
        return Err(Error::failure(format!(
            "unsupported rustc-link-search kind `{kind}`"
        )));
    }
    if path.is_empty() {
        return Err(Error::failure(
            "build-script rustc-link-search path is empty",
        ));
    }
    Ok((Some(kind), path))
}

fn validate_directive_value(name: &str, value: &str, line: usize) -> Result<()> {
    if name.is_empty() || value.is_empty() {
        return Err(Error::failure(format!(
            "build-script directive on line {line} has an empty name or value"
        )));
    }
    if name
        .bytes()
        .any(|byte| !(byte.is_ascii_lowercase() || byte == b'-'))
        || value
            .chars()
            .any(|character| character == '\0' || character.is_control())
    {
        return Err(Error::failure(format!(
            "build-script directive on line {line} contains invalid control or name characters"
        )));
    }
    Ok(())
}

fn validate_environment_name(name: &str, directive: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
        && !name.as_bytes()[0].is_ascii_digit();
    if !valid {
        return Err(Error::failure(format!(
            "build-script {directive} has invalid environment name `{name}`"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        out: PathBuf,
        environment: BTreeSet<String>,
    }

    impl Fixture {
        fn new() -> Self {
            let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("lorry-build-output-{}-{id}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            let out = root.join("target/out");
            fs::create_dir_all(&out).unwrap();
            fs::write(root.join("build.rs"), "fn main() {}\n").unwrap();
            fs::write(out.join("libnative.a"), b"archive").unwrap();
            Self {
                root,
                out,
                environment: BTreeSet::from(["TARGET".to_owned(), "RUSTC".to_owned()]),
            }
        }

        fn options(&self) -> ParseOptions<'_> {
            ParseOptions {
                package_root: &self.root,
                out_dir: &self.out,
                approved_environment: &self.environment,
                max_bytes: 1024,
                out_dir_limits: crate::source_tree::DEFAULT_LIMITS,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn parses_the_approved_ordered_protocol() {
        let fixture = Fixture::new();
        let source = format!(
            "diagnostic text\n\
             cargo:rerun-if-changed=build.rs\n\
             cargo::rerun-if-env-changed=TARGET\n\
             cargo:rustc-cfg=portable_atomic_no_atomic_64\n\
             cargo::rustc-check-cfg=cfg(portable_atomic_no_atomic_64)\n\
             cargo:rustc-env=GENERATED=value=with=equals\n\
             cargo:rustc-link-search=native={}\n\
             cargo:rustc-link-lib=static=native\n\
             cargo::warning=reviewed warning\n",
            fixture.out.display()
        );
        let output = parse(source.as_bytes(), &fixture.options()).unwrap();
        assert_eq!(output.diagnostics, ["diagnostic text"]);
        assert_eq!(output.out_dir.file_count, 1);
        assert_eq!(output.out_dir.entries[0].path, "libnative.a");
        assert_eq!(
            output.directives,
            [
                Directive::RerunIfChanged(fixture.root.join("build.rs")),
                Directive::RerunIfEnvChanged("TARGET".to_owned()),
                Directive::RustcCfg("portable_atomic_no_atomic_64".to_owned()),
                Directive::RustcCheckCfg("cfg(portable_atomic_no_atomic_64)".to_owned()),
                Directive::RustcEnv {
                    name: "GENERATED".to_owned(),
                    value: "value=with=equals".to_owned(),
                },
                Directive::RustcLinkSearch {
                    kind: Some("native".to_owned()),
                    path: fixture.out.clone(),
                },
                Directive::RustcLinkLib("static=native".to_owned()),
                Directive::Warning("reviewed warning".to_owned()),
            ]
        );
    }

    #[test]
    fn rejects_unknown_errors_limits_and_unapproved_environment() {
        let fixture = Fixture::new();
        for (source, expected) in [
            ("cargo:metadata=value\n", "unsupported"),
            ("cargo::error=bad input\n", "reported an error"),
            (
                "cargo:rerun-if-env-changed=SECRET\n",
                "unapproved environment",
            ),
            ("cargo:rustc-env=9BAD=value\n", "invalid environment"),
            ("cargo:warning\n", "no `=`"),
        ] {
            assert!(
                parse(source.as_bytes(), &fixture.options())
                    .unwrap_err()
                    .to_string()
                    .contains(expected),
                "{source:?}"
            );
        }
        let mut options = fixture.options();
        options.max_bytes = 3;
        assert!(
            parse(b"four", &options)
                .unwrap_err()
                .to_string()
                .contains("limit")
        );
        assert!(parse(&[0xff], &fixture.options()).is_err());
    }

    #[test]
    fn rejects_paths_outside_the_package_or_out_dir() {
        let fixture = Fixture::new();
        let outside = fixture.root.parent().unwrap().join("outside-build-input");
        fs::write(&outside, b"outside").unwrap();
        for source in [
            format!("cargo:rerun-if-changed={}\n", outside.display()),
            format!(
                "cargo:rustc-link-search=native={}\n",
                fixture.root.display()
            ),
            "cargo:rerun-if-changed=missing\n".to_owned(),
        ] {
            assert!(parse(source.as_bytes(), &fixture.options()).is_err());
        }
        fs::remove_file(outside).unwrap();
    }

    #[cfg(target_os = "linux")]
    struct RunFixture {
        root: PathBuf,
        package: PathBuf,
        out: PathBuf,
        temp: PathBuf,
        outside: PathBuf,
        executable: PathBuf,
        arguments: Vec<OsString>,
        environment: BTreeMap<String, OsString>,
        read_only: Vec<PathBuf>,
    }

    #[cfg(target_os = "linux")]
    impl RunFixture {
        fn new(action: &str) -> Self {
            let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root =
                std::env::temp_dir().join(format!("lorry-build-run-{}-{id}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            let package = root.join("package");
            let out = root.join("output");
            let temp = root.join("temp");
            let outside = root.join("outside");
            for path in [&package, &out, &temp, &outside] {
                fs::create_dir_all(path).unwrap();
            }
            fs::write(package.join("build.rs"), b"input").unwrap();
            fs::write(outside.join("secret"), b"secret").unwrap();
            let executable = std::env::current_exe().unwrap();
            let arguments = [
                "--exact",
                "build_script::tests::sandboxed_build_script_child",
                "--nocapture",
            ]
            .into_iter()
            .map(OsString::from)
            .collect();
            let environment = BTreeMap::from([
                ("LORRY_BUILD_SCRIPT_CHILD".to_owned(), action.into()),
                ("OUT_DIR".to_owned(), out.clone().into_os_string()),
                ("TARGET".to_owned(), "x86_64-unknown-linux-gnu".into()),
                ("TMPDIR".to_owned(), temp.clone().into_os_string()),
            ]);
            let mut read_only = Vec::new();
            for path in ["/lib", "/lib64", "/usr/lib", "/etc/ld.so.cache"] {
                if Path::new(path).exists() {
                    read_only.push(PathBuf::from(path));
                }
            }
            Self {
                root,
                package,
                out,
                temp,
                outside,
                executable,
                arguments,
                environment,
                read_only,
            }
        }

        fn options(&self, timeout: Duration, max_output_bytes: u64) -> RunOptions<'_> {
            RunOptions {
                executable: &self.executable,
                arguments: &self.arguments,
                environment: &self.environment,
                package_root: &self.package,
                out_dir: &self.out,
                temp_dir: &self.temp,
                read_only: &self.read_only,
                executables: &[],
                timeout,
                max_output_bytes,
                out_dir_limits: crate::source_tree::DEFAULT_LIMITS,
                verbose: false,
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for RunFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn runs_with_a_clean_environment_and_enforced_sandbox() {
        let fixture = RunFixture::new("success");
        let output = run(&fixture.options(Duration::from_secs(5), 64 * 1024)).unwrap();
        assert_eq!(fs::read(fixture.out.join("generated")).unwrap(), b"output");
        assert_eq!(fs::read(fixture.temp.join("temporary")).unwrap(), b"temp");
        assert_eq!(
            fs::read(fixture.package.join("build.rs")).unwrap(),
            b"input"
        );
        assert_eq!(output.out_dir.file_count, 1);
        assert!(output.stderr.contains("sandbox stderr"));
        assert!(
            output.directives.iter().any(|directive| {
                *directive == Directive::RerunIfEnvChanged("TARGET".to_owned())
            })
        );
        assert!(output.directives.iter().any(|directive| {
            *directive
                == Directive::RustcEnv {
                    name: "GENERATED".to_owned(),
                    value: "yes".to_owned(),
                }
        }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kills_timeouts_and_rejects_combined_output_and_failures() {
        let timeout = RunFixture::new("timeout");
        assert!(
            run(&timeout.options(Duration::from_millis(20), 64 * 1024))
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );

        let excess = RunFixture::new("excess-output");
        assert!(
            run(&excess.options(Duration::from_secs(5), 128))
                .unwrap_err()
                .to_string()
                .contains("combined limit")
        );

        let failure = RunFixture::new("failure");
        assert!(
            run(&failure.options(Duration::from_secs(5), 64 * 1024))
                .unwrap_err()
                .to_string()
                .contains("failed with status")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sandboxed_build_script_child() {
        let Ok(action) = std::env::var("LORRY_BUILD_SCRIPT_CHILD") else {
            return;
        };
        match action.as_str() {
            "success" => {
                let package = std::env::current_dir().unwrap();
                let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
                let temp = PathBuf::from(std::env::var_os("TMPDIR").unwrap());
                let outside = package.parent().unwrap().join("outside/secret");
                assert!(std::env::var_os("HOME").is_none());
                assert_eq!(fs::read(package.join("build.rs")).unwrap(), b"input");
                fs::write(out.join("generated"), b"output").unwrap();
                fs::write(temp.join("temporary"), b"temp").unwrap();
                assert!(fs::write(package.join("build.rs"), b"bad").is_err());
                assert!(fs::read(outside).is_err());
                assert!(
                    std::net::TcpStream::connect("127.0.0.1:9").is_err_and(|error| {
                        error.kind() == std::io::ErrorKind::PermissionDenied
                    })
                );
                assert!(Command::new("/bin/true").status().is_err());
                println!("cargo:rerun-if-changed=build.rs");
                println!("cargo:rerun-if-env-changed=TARGET");
                println!("cargo:rustc-env=GENERATED=yes");
                println!("cargo:rustc-link-search=native={}", out.display());
                eprintln!("sandbox stderr");
            }
            "timeout" => std::thread::sleep(Duration::from_secs(5)),
            "excess-output" => println!("{}", "x".repeat(4096)),
            "failure" => panic!("requested build-script failure"),
            _ => panic!("unknown build-script child action {action}"),
        }
    }
}
