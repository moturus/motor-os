//! Edits scalar fields in the bare-table layout used by the shipped sshd.toml.
//! Unsupported layouts fail instead of guessing which account a field belongs to.

use super::invalid;
use std::collections::BTreeSet;
use std::io;
use std::ops::Range;

pub(super) fn replace(config: &str, table: &str, changes: &[(&str, &str)]) -> io::Result<Vec<u8>> {
    let mut section = "";
    let mut version = false;
    let mut seen = BTreeSet::new();
    let mut edits = Vec::new();
    let mut offset = 0;
    while offset < config.len() {
        let rest = &config[offset..];
        let trimmed = rest.trim_start_matches([' ', '\t', '\r', '\n']);
        offset += rest.len() - trimmed.len();
        if trimmed.is_empty() {
            break;
        }
        let line_end = config[offset..]
            .find('\n')
            .map_or(config.len(), |end| offset + end);
        if trimmed.starts_with('#') {
            offset = line_end;
            continue;
        }
        if trimmed.starts_with('[') {
            let header = config[offset..line_end].split('#').next().unwrap().trim();
            section = header
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .filter(|s| s.split('.').all(bare_key))
                .ok_or_else(|| invalid("unsupported SSH configuration table layout"))?;
            if !seen.insert((section, "")) {
                return Err(invalid("duplicate SSH configuration table"));
            }
            offset = line_end;
            continue;
        }
        let (key, _) = config[offset..line_end]
            .split_once('=')
            .ok_or_else(|| invalid("expected an SSH configuration assignment"))?;
        let name = key.trim();
        if !bare_key(name) || !seen.insert((section, name)) {
            return Err(invalid("unsupported or duplicate SSH configuration field"));
        }
        let start = offset + key.len() + 1;
        let start =
            start + config[start..].len() - config[start..].trim_start_matches([' ', '\t']).len();
        let range = value_range(config, start)?;
        let end = config[range.end..]
            .find('\n')
            .map_or(config.len(), |end| range.end + end);
        let suffix = config[range.end..end].trim();
        if !suffix.is_empty() && !suffix.starts_with('#') {
            return Err(invalid("unsupported SSH configuration value suffix"));
        }
        if section.is_empty() && name == "version" {
            version = &config[range.clone()] == "1";
        }
        if section == table {
            if let Some((_, value)) = changes.iter().find(|(field, _)| *field == name) {
                edits.push((range, quote(value)));
            }
        }
        offset = end;
    }
    if !version || edits.len() != changes.len() {
        return Err(invalid(
            "expected SSH configuration version 1 and existing target fields",
        ));
    }
    let mut result = config.to_owned();
    for (range, value) in edits.into_iter().rev() {
        result.replace_range(range, &value);
    }
    Ok(result.into_bytes())
}

fn bare_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
}

fn value_range(config: &str, start: usize) -> io::Result<Range<usize>> {
    let bytes = config.as_bytes();
    let Some(&quote) = bytes.get(start) else {
        return Err(invalid("missing SSH configuration value"));
    };
    if !matches!(quote, b'\'' | b'"') {
        let end = config[start..]
            .find(['#', '\n', '\r'])
            .map_or(config.len(), |end| start + end);
        let value = config[start..end].trim_end();
        // Other shipped fields are scalar strings, integers, or booleans.
        if value.is_empty()
            || !value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'+' | b'-' | b':'))
        {
            return Err(invalid("unsupported SSH configuration value layout"));
        }
        return Ok(start..start + value.len());
    }
    let width = if bytes.get(start..start + 3) == Some(&[quote; 3]) {
        3
    } else {
        1
    };
    let mut cursor = start + width;
    while cursor < bytes.len() {
        if quote == b'"' && bytes[cursor] == b'\\' {
            cursor += 2;
        } else if bytes[cursor] == quote {
            let run = bytes[cursor..].iter().take_while(|&&c| c == quote).count();
            if width == 1 {
                return Ok(start..cursor + 1);
            }
            if run >= 3 {
                if run > 5 {
                    return Err(invalid("invalid SSH configuration string delimiter"));
                }
                return Ok(start..cursor + run);
            }
            cursor += run;
        } else {
            if width == 1 && matches!(bytes[cursor], b'\n' | b'\r') {
                return Err(invalid("unterminated SSH configuration string"));
            }
            cursor += 1;
        }
    }
    Err(invalid("unterminated SSH configuration string"))
}

fn quote(value: &str) -> String {
    use std::fmt::Write;
    let mut result = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => write!(&mut result, "\\u{:04X}", c as u32).unwrap(),
            c => result.push(c),
        }
    }
    result.push('"');
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_only_selected_fields_and_escapes_input() {
        let config = "version = 1\nhost_key = '''[users.motor]\nauthorized_key = 'fake'\n'''\n[users.motor]\n  authorized_key = 'old' # keep\n[users.other]\nauthorized_key = 'other'\n";
        let updated = replace(config, "users.motor", &[("authorized_key", "key\"\\\n雪")]).unwrap();
        assert_eq!(
            String::from_utf8(updated).unwrap(),
            config.replace("'old'", "\"key\\\"\\\\\\n雪\"")
        );
        assert_eq!(quote("\u{0001}"), "\"\\u0001\"");
    }

    #[test]
    fn refuses_ambiguous_or_missing_fields() {
        for config in [
            "version = 2\n[users.motor]\nauthorized_key = 'old'",
            "version = 1\n[users.motor]\n",
            "version = 1\n[users.motor]\nauthorized_key = 'old'\nauthorized_key = 'second'",
            "version = 1\n[users.motor]\nauthorized_key = '''unterminated",
            "version = 1\nusers = { motor = { authorized_key = 'old' } }",
        ] {
            assert!(replace(config, "users.motor", &[("authorized_key", "new")]).is_err());
        }
    }
}
