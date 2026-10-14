use crate::diagnostic::{Error, Result};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::{Command, Output, Stdio};

pub fn query(program: &Path, arguments: &[&str], description: &str) -> Result<Output> {
    let output = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            Error::failure(format!(
                "failed to execute {description} `{}`: {error}",
                program.display()
            ))
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(command_failure(
            output.status,
            format!(
                "{description} `{}` failed{}{}",
                program.display(),
                output
                    .status
                    .code()
                    .map_or_else(String::new, |code| format!(" with status {code}")),
                if stderr.trim().is_empty() {
                    String::new()
                } else {
                    format!(": {}", stderr.trim())
                }
            ),
        ));
    }
    Ok(output)
}

pub fn query_rustc(program: &Path, arguments: &[&str], description: &str) -> Result<Output> {
    let mut command = Command::new(program);
    remove_cargo_client_environment(&mut command);
    let output = command
        .args(arguments)
        .env_remove("RUSTC_BOOTSTRAP")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            Error::failure(format!(
                "failed to execute {description} `{}`: {error}",
                program.display()
            ))
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(command_failure(
            output.status,
            format!(
                "{description} `{}` failed: {}",
                program.display(),
                stderr.trim()
            ),
        ));
    }
    Ok(output)
}

pub fn remove_cargo_client_environment(command: &mut Command) {
    for name in REMOVED_CARGO_CLIENT_ENVIRONMENT {
        command.env_remove(name);
    }
}

const REMOVED_CARGO_CLIENT_ENVIRONMENT: [&str; 3] = [
    "__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS",
    "RUSTUP_TOOLCHAIN",
    "CARGO_LOG",
];

pub fn is_removed_cargo_client_environment(name: &OsStr) -> bool {
    REMOVED_CARGO_CLIENT_ENVIRONMENT
        .iter()
        .any(|removed| name == OsStr::new(removed))
}

pub struct RustcCommand<'a> {
    pub child_lease_fd: Option<i32>,
    pub program: &'a Path,
    pub arguments: &'a [OsString],
    pub environment: &'a BTreeMap<String, OsString>,
    pub current_dir: &'a Path,
    pub verbose: bool,
    pub color: bool,
}

impl RustcCommand<'_> {
    pub fn run(&self) -> Result<()> {
        let output = self.execute()?;
        Self::finish(&output, self.color)
    }

    /// Runs rustc and captures its output without rendering it, so callers
    /// executing units concurrently can print each unit's diagnostics as one
    /// uninterrupted block via `finish`.
    pub fn execute(&self) -> Result<Output> {
        self.execute_observed(&mut |_| {})
    }

    /// Like `execute`, and passes each stderr line to `observe` as rustc
    /// writes it, so a caller can act on an artifact notification early.
    pub fn execute_observed(&self, observe: &mut dyn FnMut(&[u8])) -> Result<Output> {
        if self.verbose {
            eprintln!(
                "Running {}",
                display_command(self.program.as_os_str(), self.arguments)
            );
        }
        let failure = |error: std::io::Error| {
            Error::failure(format!(
                "failed to execute rustc `{}`: {error}",
                self.program.display()
            ))
        };
        let mut command = Command::new(self.program);
        command
            .args(self.arguments)
            .env_remove("CARGO_PRIMARY_PACKAGE")
            .envs(self.environment)
            .current_dir(self.current_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        crate::artifact_lock::configure_child_lease(&mut command, self.child_lease_fd);
        remove_cargo_client_environment(&mut command);
        let mut child = command.spawn().map_err(failure)?;
        let mut stdout = child.stdout.take().unwrap();
        let reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut stdout, &mut bytes).map(|_| bytes)
        });
        let mut stderr = Vec::new();
        let mut lines = std::io::BufReader::new(child.stderr.take().unwrap());
        let read = loop {
            let start = stderr.len();
            match std::io::BufRead::read_until(&mut lines, b'\n', &mut stderr) {
                Ok(0) => break Ok(()),
                Ok(_) => observe(&stderr[start..]),
                Err(error) => {
                    let _ = child.kill();
                    break Err(error);
                }
            }
        };
        let stdout = reader
            .join()
            .map_err(|_| Error::failure("rustc stdout reader panicked"))?;
        let status = child.wait().map_err(failure)?;
        read.map_err(failure)?;
        let stdout = stdout.map_err(failure)?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }

    pub fn finish(output: &Output, color: bool) -> Result<()> {
        Self::render_messages(&output.stdout, &output.stderr, color);
        Self::require_success(output)
    }

    pub fn render_messages(stdout: &[u8], stderr: &[u8], color: bool) {
        render_rustc_output(stdout, color);
        render_rustc_output(stderr, color);
    }

    pub fn diagnostic_messages(bytes: &[u8]) -> Vec<u8> {
        let mut diagnostics = Vec::new();
        for line in bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let message = serde_json::from_slice::<serde_json::Value>(line).ok();
            // Artifact notifications contain temporary output paths, and are
            // reported from the validated outputs rather than replayed.
            if message.as_ref().is_none_or(|message| {
                message.get("artifact").is_none() && message.get("unused_extern_names").is_none()
            }) {
                diagnostics.extend_from_slice(line);
                diagnostics.push(b'\n');
            }
        }
        diagnostics
    }

    pub fn require_success(output: &Output) -> Result<()> {
        if output.status.success() {
            Ok(())
        } else {
            Err(command_failure(
                output.status,
                match output.status.code() {
                    Some(code) => format!("rustc failed with status {code}"),
                    None => "rustc was terminated by a signal".to_owned(),
                },
            ))
        }
    }
}

pub fn command_failure(status: std::process::ExitStatus, message: impl Into<String>) -> Error {
    if exit_status_code(status) == 130 {
        Error::interrupted(message)
    } else {
        Error::failure(message)
    }
}

#[derive(Clone, Copy)]
pub enum ChildKind {
    Program,
    Test,
}

pub fn run_child(
    program: &OsStr,
    arguments: &[OsString],
    current_dir: &Path,
    environment: &BTreeMap<String, OsString>,
    kind: ChildKind,
    verbose: bool,
) -> Result<i32> {
    if verbose {
        eprintln!("Running {}", display_command(program, arguments));
    }
    let status = Command::new(program)
        .args(arguments)
        .envs(environment)
        .current_dir(current_dir)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|error| {
            Error::failure(format!(
                "failed to execute `{}`: {error}",
                Path::new(program).display()
            ))
        })?;
    Ok(match kind {
        ChildKind::Program => exit_status_code(status),
        ChildKind::Test => status.code().unwrap_or(101),
    })
}

pub fn exit_status_code(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    130
}

fn render_rustc_output(bytes: &[u8], color: bool) {
    let text = String::from_utf8_lossy(bytes);
    for line in text.lines() {
        match json_string_field(line, "rendered") {
            Some(rendered) if color => eprint!("{rendered}"),
            Some(rendered) => eprint!("{}", strip_ansi(&rendered)),
            None if line.trim_start().starts_with('{') => {}
            None if !line.trim().is_empty() => eprintln!("{line}"),
            None => {}
        }
    }
}

pub(crate) fn strip_ansi(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    let mut plain = 0;
    while index < bytes.len() {
        if bytes[index] == 0x1b && bytes.get(index + 1) == Some(&b'[') {
            output.push_str(&text[plain..index]);
            index += 2;
            while index < bytes.len() {
                let byte = bytes[index];
                index += 1;
                if (0x40..=0x7e).contains(&byte) {
                    break;
                }
            }
            plain = index;
        } else {
            index += 1;
        }
    }
    output.push_str(&text[plain..]);
    output
}

fn json_string_field(document: &str, wanted: &str) -> Option<String> {
    let bytes = document.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() || bytes[index] != b'"' {
            index += 1;
            continue;
        }
        let (key, next) = decode_json_string(document, index)?;
        index = next;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() || bytes[index] != b':' {
            continue;
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if key == wanted && index < bytes.len() && bytes[index] == b'"' {
            return decode_json_string(document, index).map(|(value, _)| value);
        }
    }
    None
}

fn decode_json_string(document: &str, start: usize) -> Option<(String, usize)> {
    let bytes = document.as_bytes();
    if bytes.get(start) != Some(&b'"') {
        return None;
    }
    let mut result = String::new();
    let mut index = start + 1;
    let mut plain_start = index;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                result.push_str(std::str::from_utf8(&bytes[plain_start..index]).ok()?);
                return Some((result, index + 1));
            }
            b'\\' => {
                result.push_str(std::str::from_utf8(&bytes[plain_start..index]).ok()?);
                index += 1;
                match *bytes.get(index)? {
                    b'"' => result.push('"'),
                    b'\\' => result.push('\\'),
                    b'/' => result.push('/'),
                    b'b' => result.push('\u{8}'),
                    b'f' => result.push('\u{c}'),
                    b'n' => result.push('\n'),
                    b'r' => result.push('\r'),
                    b't' => result.push('\t'),
                    b'u' => {
                        let end = index + 5;
                        let value = u16::from_str_radix(
                            std::str::from_utf8(bytes.get(index + 1..end)?).ok()?,
                            16,
                        )
                        .ok()?;
                        index = end - 1;
                        if (0xd800..=0xdbff).contains(&value) {
                            if bytes.get(index + 1..index + 3) != Some(b"\\u") {
                                return None;
                            }
                            let low_end = index + 7;
                            let low = u16::from_str_radix(
                                std::str::from_utf8(bytes.get(index + 3..low_end)?).ok()?,
                                16,
                            )
                            .ok()?;
                            if !(0xdc00..=0xdfff).contains(&low) {
                                return None;
                            }
                            let scalar =
                                0x10000 + (((value as u32 - 0xd800) << 10) | (low as u32 - 0xdc00));
                            result.push(char::from_u32(scalar)?);
                            index = low_end - 1;
                        } else {
                            result.push(char::from_u32(value as u32)?);
                        }
                    }
                    _ => return None,
                }
                index += 1;
                plain_start = index;
                continue;
            }
            0..=0x1f => return None,
            _ => {}
        }
        index += 1;
    }
    None
}

pub fn display_command(program: &OsStr, arguments: &[OsString]) -> String {
    std::iter::once(program)
        .chain(arguments.iter().map(OsString::as_os_str))
        .map(|argument| quote_display(&redact(argument.to_string_lossy().as_ref())))
        .collect::<Vec<_>>()
        .join(" ")
}

fn redact(argument: &str) -> String {
    let lower = argument.to_ascii_lowercase();
    if let Some(scheme) = argument.find("://") {
        let authority = scheme + 3;
        let end = argument[authority..]
            .find('/')
            .map_or(argument.len(), |offset| authority + offset);
        let mut result = argument.to_owned();
        if let Some(at) = argument[authority..end].rfind('@') {
            result.replace_range(authority..authority + at + 1, "[REDACTED]@");
        }
        if let Some(query) = result.find('?') {
            result.truncate(query);
            result.push_str("?[REDACTED]");
        }
        return result;
    }
    if ["token=", "password=", "secret=", "credential="]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        let prefix = argument
            .split_once('=')
            .map_or(argument, |(prefix, _)| prefix);
        return format!("{prefix}=[REDACTED]");
    }
    argument.to_owned()
}

fn quote_display(argument: &str) -> String {
    if !argument.is_empty()
        && argument
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_./:=,+@".contains(&byte))
    {
        argument.to_owned()
    } else {
        format!("'{}'", argument.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn interrupted_children_keep_exit_130_and_other_failures_keep_101() {
        use std::os::unix::process::ExitStatusExt;
        for (status, expected) in [
            (130 << 8, 130),
            (libc::SIGINT, 130),
            (9 << 8, 101),
            (libc::SIGKILL, 101),
        ] {
            let output = Output {
                status: std::process::ExitStatus::from_raw(status),
                stdout: Vec::new(),
                stderr: Vec::new(),
            };
            let error = RustcCommand::require_success(&output).unwrap_err();
            assert_eq!(error.exit_code(), expected);
        }
    }

    #[test]
    fn stored_diagnostics_omit_temporary_artifact_notifications() {
        let captured = b"{\"artifact\":\"/staging/library.rlib\"}\n{\"message\":\"warning\",\"rendered\":\"warning\\n\"}\n";
        assert_eq!(
            RustcCommand::diagnostic_messages(captured),
            b"{\"message\":\"warning\",\"rendered\":\"warning\\n\"}\n"
        );
        assert_eq!(
            RustcCommand::diagnostic_messages(b"not JSON\n"),
            b"not JSON\n"
        );
        assert_eq!(RustcCommand::diagnostic_messages(b"42\n"), b"42\n");
    }

    #[test]
    fn extracts_and_decodes_rendered_json_diagnostic() {
        let line = r#"{"message":"x","rendered":"error: bad \u{1f4a5}\n  --> a.rs:1\n"}"#
            .replace("\\u{1f4a5}", "\\ud83d\\udca5");
        assert_eq!(
            json_string_field(&line, "rendered").unwrap(),
            "error: bad 💥\n  --> a.rs:1\n"
        );
    }

    #[test]
    fn redacts_verbose_command_secrets() {
        let args = [
            OsString::from("https://user:pass@example.test/file?token=x"),
            OsString::from("--token=secret"),
            OsString::from("two words"),
        ];
        let display = display_command(OsStr::new("tool"), &args);
        assert!(!display.contains("pass"));
        assert!(!display.contains("secret"));
        assert!(display.contains("[REDACTED]"));
        assert!(display.contains("'two words'"));
    }

    #[test]
    fn removes_ansi_control_sequences() {
        assert_eq!(strip_ansi("\x1b[1;31merror\x1b[0m: bad"), "error: bad");
    }
}
