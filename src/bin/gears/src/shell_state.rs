//! Commit shell snapshots after filtering variables that must not be restored.

use std::io::Read;
use std::path::Path;

use crate::state::StateRoot;

const PENDING_CWD: &str = "cwd.pending";
const PENDING_ENV: &str = "env.pending";
const MAX_CWD_BYTES: usize = 16 * 1024;
const MAX_ENV_BYTES: usize = 16 * 1024 * 1024;

pub fn prepare(directory: &Path) -> Result<(), String> {
    let state = StateRoot::new(directory.to_path_buf())?;
    for name in ["cwd", "env.sh"] {
        state.existing_file(Path::new(name))?;
    }
    clear_pending(&state)
}

pub fn finish(directory: &Path, interrupted: bool) -> Result<(), String> {
    let state = StateRoot::new(directory.to_path_buf())?;
    if interrupted {
        return clear_pending(&state);
    }
    let cwd = state.existing_file(Path::new(PENDING_CWD))?;
    let env = state.existing_file(Path::new(PENDING_ENV))?;
    let result = (|| match (cwd, env) {
        (None, None) => Ok(()), // `exit` or `exec` bypassed the wrapper's save step.
        (Some(cwd), Some(env)) => {
            let cwd = read_snapshot(&cwd, MAX_CWD_BYTES)?;
            let env = read_snapshot(&env, MAX_ENV_BYTES)?;
            let cwd = cwd.strip_suffix('\n').unwrap_or(&cwd);
            if !Path::new(cwd).is_absolute() {
                Err("shell returned a non-absolute working directory".to_string())
            } else {
                let filtered = filter_exports(&env)?;
                state.replace_file(Path::new("env.sh"), filtered.as_bytes())?;
                state.replace_file(Path::new("cwd"), format!("{cwd}\n").as_bytes())
            }
        }
        _ => Err("shell returned an incomplete state snapshot".to_string()),
    })();
    let cleanup = clear_pending(&state);
    result.and(cleanup)
}

fn read_snapshot(path: &Path, limit: usize) -> Result<String, String> {
    let file = std::fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if bytes.len() > limit {
        return Err(format!(
            "{}: shell snapshot exceeds {limit} bytes",
            path.display()
        ));
    }
    String::from_utf8(bytes).map_err(|error| format!("{}: {error}", path.display()))
}

fn clear_pending(state: &StateRoot) -> Result<(), String> {
    for name in [PENDING_CWD, PENDING_ENV] {
        if let Some(path) = state.existing_file(Path::new(name))? {
            std::fs::remove_file(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        }
    }
    Ok(())
}

fn filter_exports(raw: &str) -> Result<String, String> {
    let mut filtered = String::new();
    let mut record = String::new();
    for line in raw.split_inclusive('\n') {
        record.push_str(line);
        if !complete_record(&record) {
            continue;
        }
        let assignment = record
            .strip_prefix("export ")
            .or_else(|| record.strip_prefix("declare -x "))
            .ok_or("unexpected shell export format")?;
        let name = assignment.split(['=', '\n']).next().unwrap_or("");
        if name.is_empty()
            || !name.bytes().enumerate().all(|(index, byte)| {
                byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
            })
        {
            return Err("invalid exported variable name".to_string());
        }
        if name != "PATH" && !name.starts_with("GEARS_") {
            filtered.push_str(&record);
        }
        record.clear();
    }
    if !record.is_empty() {
        return Err("incomplete shell export snapshot".to_string());
    }
    Ok(filtered)
}

fn complete_record(record: &str) -> bool {
    let mut quote = b' ';
    let mut escaped = false;
    let mut previous = b' ';
    for byte in record.bytes() {
        if escaped {
            escaped = false;
        } else if byte == b'\\' && quote != b'\'' {
            escaped = true;
        } else if quote == b' ' && (byte == b'\'' || byte == b'"') {
            quote = if byte == b'\'' && previous == b'$' {
                b'$'
            } else {
                byte
            };
        } else if (quote == b'\'' && byte == b'\'')
            || (quote == b'"' && byte == b'"')
            || (quote == b'$' && byte == b'\'')
        {
            quote = b' ';
        }
        previous = byte;
    }
    quote == b' ' && !escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_bash_and_rush_exports_without_breaking_multiline_values() {
        let raw = "export KEEP='one\ntwo'\nexport PATH='/bad'\nexport GEARS_SESSION_ID='old'\ndeclare -x ALSO=$'a\\nb'\n";
        assert_eq!(
            filter_exports(raw).unwrap(),
            "export KEEP='one\ntwo'\ndeclare -x ALSO=$'a\\nb'\n"
        );
        let long = format!("export LONG='{}'\n", "x".repeat(9800));
        assert_eq!(filter_exports(&long).unwrap(), long);
    }

    #[test]
    fn rejects_an_incomplete_or_invalid_snapshot() {
        assert!(filter_exports("export ONE='unfinished\n").is_err());
        assert!(filter_exports("export 1BAD='x'\n").is_err());
    }

    #[test]
    fn snapshot_read_is_bounded() {
        let path =
            std::env::temp_dir().join(format!("gears-snapshot-limit-{}", std::process::id()));
        std::fs::write(&path, "123456789").unwrap();
        assert!(
            read_snapshot(&path, 8)
                .unwrap_err()
                .contains("exceeds 8 bytes")
        );
        assert_eq!(read_snapshot(&path, 9).unwrap(), "123456789");
        std::fs::remove_file(path).unwrap();
    }
}
