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
        return Err(Error::failure(format!(
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
        )));
    }
    Ok(output)
}

#[allow(dead_code)] // Consumed by the build engine in the next implementation slice.
pub struct RustcCommand<'a> {
    pub program: &'a Path,
    pub arguments: &'a [OsString],
    pub environment: &'a BTreeMap<String, OsString>,
    pub current_dir: &'a Path,
    pub verbose: bool,
}

#[allow(dead_code)] // Consumed by the build engine in the next implementation slice.
impl RustcCommand<'_> {
    pub fn run(&self) -> Result<()> {
        if self.verbose {
            eprintln!(
                "Running {}",
                display_command(self.program.as_os_str(), self.arguments)
            );
        }
        let output = Command::new(self.program)
            .args(self.arguments)
            .envs(self.environment)
            .current_dir(self.current_dir)
            .stdin(Stdio::null())
            .output()
            .map_err(|error| {
                Error::failure(format!(
                    "failed to execute rustc `{}`: {error}",
                    self.program.display()
                ))
            })?;
        render_rustc_output(&output.stdout);
        render_rustc_output(&output.stderr);
        if output.status.success() {
            Ok(())
        } else {
            Err(Error::failure(match output.status.code() {
                Some(code) => format!("rustc failed with status {code}"),
                None => "rustc was terminated by a signal".to_owned(),
            }))
        }
    }
}

#[allow(dead_code)] // Consumed by run/test in the next implementation slice.
pub fn run_child(
    program: &OsStr,
    arguments: &[OsString],
    current_dir: &Path,
    verbose: bool,
) -> Result<i32> {
    if verbose {
        eprintln!("Running {}", display_command(program, arguments));
    }
    let status = Command::new(program)
        .args(arguments)
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
    Ok(status.code().unwrap_or(130))
}

#[allow(dead_code)] // Reached through RustcCommand once the build engine is installed.
fn render_rustc_output(bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    for line in text.lines() {
        match json_string_field(line, "rendered") {
            Some(rendered) => eprint!("{rendered}"),
            None if !line.trim().is_empty() => eprintln!("{line}"),
            None => {}
        }
    }
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
                            if bytes.get(index + 1..index + 3) != Some(&[b'\\', b'u']) {
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
}
