//! Reads and edits the bare-table TOML layout of the shipped SSH files.
//! Unsupported layouts fail instead of guessing which account a field belongs
//! to, and a user name is matched against parsed headers, not searched for.

use super::credentials::{Login, UserSecret, KEYS_DIR, USERS_FILE};
use super::invalid;
use std::collections::BTreeSet;
use std::io;
use std::ops::Range;

const SERVICE_VERSION: &str = "2";
const REGISTRY_VERSION: &str = "1";
const MAX_USER_NAME_BYTES: usize = 64;
// russhd refuses a whole registry past this, which denies every login.
const MAX_USERS: usize = 1024;
const SERVICE_FIELDS: [&str; 8] = [
    "version",
    "listen_on",
    "path",
    "host_key",
    "users_file",
    "authorized_keys_dir",
    "allow_tcp_forwarding",
    "gateway_ports",
];

struct Table<'a> {
    name: &'a str,
    /// Where the table's first line would go.
    body: usize,
}

struct Field<'a> {
    table: &'a str,
    name: &'a str,
    value: Range<usize>,
}

struct Document<'a> {
    text: &'a str,
    tables: Vec<Table<'a>>,
    fields: Vec<Field<'a>>,
}

impl<'a> Document<'a> {
    fn parse(text: &'a str, version: &str) -> io::Result<Self> {
        let mut table = "";
        let mut seen = BTreeSet::new();
        let (mut tables, mut fields) = (Vec::new(), Vec::new());
        let mut offset = 0;
        while offset < text.len() {
            let rest = &text[offset..];
            let trimmed = rest.trim_start_matches([' ', '\t', '\r', '\n']);
            offset += rest.len() - trimmed.len();
            if trimmed.is_empty() {
                break;
            }
            let line_end = text[offset..]
                .find('\n')
                .map_or(text.len(), |end| offset + end);
            if trimmed.starts_with('#') {
                offset = line_end;
                continue;
            }
            if trimmed.starts_with('[') {
                let header = text[offset..line_end].split('#').next().unwrap().trim();
                table = header
                    .strip_prefix('[')
                    .and_then(|s| s.strip_suffix(']'))
                    .filter(|s| s.split('.').all(bare_key))
                    .ok_or_else(|| invalid("unsupported SSH configuration table layout"))?;
                if !seen.insert((table, "")) {
                    return Err(invalid("duplicate SSH configuration table"));
                }
                tables.push(Table {
                    name: table,
                    body: (line_end + 1).min(text.len()),
                });
                offset = line_end;
                continue;
            }
            let (key, _) = text[offset..line_end]
                .split_once('=')
                .ok_or_else(|| invalid("expected an SSH configuration assignment"))?;
            let name = key.trim();
            if !bare_key(name) || !seen.insert((table, name)) {
                return Err(invalid("unsupported or duplicate SSH configuration field"));
            }
            let start = offset + key.len() + 1;
            let start =
                start + text[start..].len() - text[start..].trim_start_matches([' ', '\t']).len();
            let value = value_range(text, start)?;
            let end = text[value.end..]
                .find('\n')
                .map_or(text.len(), |end| value.end + end);
            let suffix = text[value.end..end].trim();
            if !suffix.is_empty() && !suffix.starts_with('#') {
                return Err(invalid("unsupported SSH configuration value suffix"));
            }
            fields.push(Field { table, name, value });
            offset = end;
        }
        let document = Self {
            text,
            tables,
            fields,
        };
        match document.field("", "version") {
            Some(field) if &text[field.value.clone()] == version => Ok(document),
            _ => Err(invalid("unsupported SSH configuration version")),
        }
    }

    fn field(&self, table: &str, name: &str) -> Option<&Field<'a>> {
        self.fields
            .iter()
            .find(|field| field.table == table && field.name == name)
    }

    fn table(&self, name: &str) -> Option<&Table<'a>> {
        self.tables.iter().find(|table| table.name == name)
    }

    /// A top-level string with nothing to unescape.
    fn literal(&self, name: &str) -> Option<&'a str> {
        let value = &self.text[self.field("", name)?.value.clone()];
        let inner = value
            .strip_prefix('\'')
            .and_then(|value| value.strip_suffix('\''))
            .or_else(|| {
                value
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
            })?;
        (!inner.contains(['\\', '\'', '"'])).then_some(inner)
    }

    fn apply(&self, mut edits: Vec<(Range<usize>, String)>) -> Vec<u8> {
        edits.sort_by_key(|(range, _)| range.start);
        let mut result = self.text.to_owned();
        for (range, value) in edits.into_iter().rev() {
            result.replace_range(range, &value);
        }
        result.into_bytes()
    }
}

/// Parses the version 2 `sshd.toml`, whose credential paths must be the
/// standard ones: paths read from inside an image are never followed.
fn service(text: &str) -> io::Result<Document<'_>> {
    let document = Document::parse(text, SERVICE_VERSION)?;
    if !document.tables.is_empty()
        || document
            .fields
            .iter()
            .any(|field| !SERVICE_FIELDS.contains(&field.name))
    {
        return Err(invalid("unsupported SSH service configuration schema"));
    }
    if document.field("", "listen_on").is_none()
        || document.field("", "host_key").is_none()
        || document.literal("users_file") != Some(USERS_FILE)
        || document.literal("authorized_keys_dir") != Some(KEYS_DIR)
    {
        return Err(invalid("unsupported SSH service configuration values"));
    }
    Ok(document)
}

/// Accepts a service configuration, which by its schema holds no user credentials.
pub(super) fn check_service(text: &str) -> io::Result<()> {
    service(text).map(|_| ())
}

pub(super) fn set_host_key(text: &str, key: &str) -> io::Result<Vec<u8>> {
    let document = service(text)?;
    let field = document
        .field("", "host_key")
        .ok_or_else(|| invalid("missing SSH host key field"))?;
    Ok(document.apply(vec![(field.value.clone(), quote(key))]))
}

fn registry(text: &str) -> io::Result<Document<'_>> {
    let document = Document::parse(text, REGISTRY_VERSION)?;
    if document.tables.len() > MAX_USERS {
        return Err(invalid("more than 1024 SSH users"));
    }
    for table in &document.tables {
        if !table
            .name
            .strip_prefix("users.")
            .is_some_and(valid_user_name)
        {
            return Err(invalid("unsupported SSH user table"));
        }
    }
    for field in &document.fields {
        let known = match field.table {
            "" => field.name == "version",
            _ => matches!(field.name, "salt" | "password_hash"),
        };
        if !known {
            return Err(invalid("unsupported SSH user field"));
        }
    }
    Ok(document)
}

/// Selects `login`, whose name passed `valid_user_name`, and applies `secret`
/// to its record, adding whichever verifier fields are missing. `None` means
/// the registry stays as it is. One parse decides all of it, so what gets
/// edited is what passed the checks.
pub(super) fn update_user(
    text: &str,
    login: &Login,
    secret: &UserSecret,
) -> io::Result<Option<Vec<u8>>> {
    let document = registry(text)?;
    let name = format!("users.{}", login.name());
    let verifier = match secret {
        UserSecret::Password { salt, hash } => Some([("salt", salt), ("password_hash", hash)]),
        UserSecret::PublicKey(_) => None,
    };
    match (login, document.table(&name)) {
        (Login::New(_), Some(_)) => Err(invalid("SSH user already exists")),
        (Login::Existing(_), None) => Err(invalid("no such SSH user")),
        (Login::New(_), None) if document.tables.len() == MAX_USERS => {
            Err(invalid("already 1024 SSH users"))
        }
        (Login::New(_), None) => {
            let mut result = text.to_owned();
            if !result.ends_with('\n') {
                result.push('\n');
            }
            result.push_str(&format!("\n[{name}]\n"));
            for (field, value) in verifier.into_iter().flatten() {
                result.push_str(&format!("{field} = {}\n", quote(value)));
            }
            Ok(Some(result.into_bytes()))
        }
        (Login::Existing(_), Some(table)) => {
            let Some(verifier) = verifier else {
                return Ok(None);
            };
            let mut edits = Vec::new();
            let mut missing = String::new();
            for (field, value) in verifier {
                match document.field(&name, field) {
                    Some(field) => edits.push((field.value.clone(), quote(value))),
                    None => missing.push_str(&format!("{field} = {}\n", quote(value))),
                }
            }
            if !missing.is_empty() {
                if !text[..table.body].ends_with('\n') {
                    missing.insert(0, '\n');
                }
                edits.push((table.body..table.body, missing));
            }
            Ok(Some(document.apply(edits)))
        }
    }
}

pub(crate) fn valid_user_name(name: &str) -> bool {
    name.len() <= MAX_USER_NAME_BYTES && bare_key(name)
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

    const SERVICE: &str =
        "version = 2\nlisten_on = '0.0.0.0:2222'\nhost_key = \"\"\"old\"\"\" # keep\n\
        users_file = '/user/cfg/russhd/users.toml'\nauthorized_keys_dir = '/user/cfg/ssh'\n";
    const REGISTRY: &str =
        "# a comment\nversion = 1\n\n[users.motor] # keep\n  salt = 'old' # keep\n\
        password_hash = 'oldhash'\n[users.other]\nsalt = 'other'\npassword_hash = 'otherhash'\n";

    fn text(bytes: Vec<u8>) -> String {
        String::from_utf8(bytes).unwrap()
    }

    fn new(name: &str) -> Login {
        Login::New(name.to_owned())
    }

    fn existing(name: &str) -> Login {
        Login::Existing(name.to_owned())
    }

    fn password() -> UserSecret {
        UserSecret::Password {
            salt: "s".to_owned(),
            hash: "h".to_owned(),
        }
    }

    fn key() -> UserSecret {
        UserSecret::PublicKey("key".to_owned())
    }

    /// The registry after an update that has to change it.
    fn updated(source: &str, login: Login, secret: UserSecret) -> String {
        text(update_user(source, &login, &secret).unwrap().unwrap())
    }

    #[test]
    fn replaces_only_selected_fields_and_escapes_input() {
        let updated_key = text(set_host_key(SERVICE, "key\"\\\n雪").unwrap());
        assert_eq!(
            updated_key,
            SERVICE.replace("\"\"\"old\"\"\"", "\"key\\\"\\\\\\n雪\"")
        );
        assert_eq!(quote("\u{0001}"), "\"\\u0001\"");

        assert_eq!(
            updated(REGISTRY, existing("motor"), password()),
            REGISTRY
                .replace("'old'", "\"s\"")
                .replace("'oldhash'", "\"h\"")
        );
    }

    #[test]
    fn a_name_in_a_string_is_not_a_table() {
        let fake = "version = 1\n[users.real]\nsalt = '''\n[users.fake]\n'''\n";
        assert_eq!(update_user(fake, &existing("real"), &key()).unwrap(), None);
        assert!(update_user(fake, &existing("fake"), &key()).is_err());
        assert!(update_user(fake, &existing("fake"), &password()).is_err());
        assert!(update_user(fake, &new("fake"), &key()).unwrap().is_some());
    }

    #[test]
    fn inserts_a_missing_verifier_without_touching_other_records() {
        for (source, expected) in [
            (
                "version = 1\n[users.a]\n[users.b]\nsalt = 'x'\n",
                "version = 1\n[users.a]\nsalt = \"s\"\npassword_hash = \"h\"\n[users.b]\nsalt = 'x'\n",
            ),
            (
                "version = 1\n[users.a]",
                "version = 1\n[users.a]\nsalt = \"s\"\npassword_hash = \"h\"\n",
            ),
            (
                "version = 1\n[users.a]\nsalt = 'x'\n",
                "version = 1\n[users.a]\npassword_hash = \"h\"\nsalt = \"s\"\n",
            ),
        ] {
            assert_eq!(updated(source, existing("a"), password()), expected);
        }
    }

    #[test]
    fn adds_a_user_as_a_new_table() {
        for source in ["version = 1", "version = 1\n", REGISTRY] {
            let added = updated(source, new("alice"), key());
            assert!(added.starts_with(source));
            assert_eq!(
                update_user(&added, &existing("alice"), &key()).unwrap(),
                None
            );
            assert_eq!(
                updated(source, new("alice"), password()),
                updated(&added, existing("alice"), password())
            );
        }
        assert!(update_user(REGISTRY, &new("motor"), &key()).is_err());
    }

    #[test]
    fn user_names_have_the_registry_shape() {
        for name in ["a", "A-b_9", "-", &"n".repeat(64)] {
            assert!(valid_user_name(name), "{name}");
        }
        for name in ["", " a", "a b", "a.b", "a/b", "é", &"n".repeat(65)] {
            assert!(!valid_user_name(name), "{name}");
        }
    }

    #[test]
    fn preserves_forwarding_policy_when_replacing_the_host_key() {
        for (policy, gateway) in [
            ("true", "false"),
            ("false", "true"),
            ("true", "true"),
            ("false", "false"),
        ] {
            let source =
                format!("{SERVICE}allow_tcp_forwarding = {policy}\ngateway_ports = {gateway}\n");
            check_service(&source).unwrap();
            assert_eq!(
                text(set_host_key(&source, "new").unwrap()),
                source.replace("\"\"\"old\"\"\"", "\"new\"")
            );
        }
    }

    #[test]
    fn refuses_other_service_schemas() {
        check_service(SERVICE).unwrap();
        for config in [
            SERVICE.replace("version = 2", "version = 1"),
            SERVICE.replace("version = 2\n", ""),
            format!("{SERVICE}[users.motor]\n"),
            format!("{SERVICE}authorized_key = 'k'\n"),
            format!("{SERVICE}[extra]\nvalue = 1\n"),
            SERVICE.replace("/user/cfg/russhd/users.toml", "/user/cfg/elsewhere"),
            SERVICE.replace("/user/cfg/ssh", "/none/cfg"),
            SERVICE.replace("users_file = '/user/cfg/russhd/users.toml'\n", ""),
            SERVICE.replace("authorized_keys_dir = '/user/cfg/ssh'\n", ""),
            SERVICE.replace("listen_on = '0.0.0.0:2222'\n", ""),
            SERVICE.replace("host_key = \"\"\"old\"\"\" # keep\n", ""),
            SERVICE.replace("'/user/cfg/ssh'", "'''/user/cfg/ssh'''"),
            SERVICE.replace("'/user/cfg/ssh'", "\"/user/cfg\\u002fssh\""),
        ] {
            assert!(check_service(&config).is_err(), "{config}");
            assert!(set_host_key(&config, "new").is_err(), "{config}");
        }
    }

    #[test]
    fn refuses_ambiguous_or_unknown_registry_layouts() {
        for config in [
            "version = 2\n[users.motor]\n",
            "[users.motor]\n",
            "version = 1\n[users.motor]\nsalt = 'a'\nsalt = 'b'\n",
            "version = 1\n[users.motor]\n[users.motor]\n",
            "version = 1\n[users.motor]\nsalt = '''unterminated",
            "version = 1\nusers = { motor = { salt = 'a' } }\n",
            "version = 1\n[users]\n",
            "version = 1\n[other.motor]\n",
            "version = 1\n[users.motor.deep]\n",
            "version = 1\n[users.\"motor\"]\n",
            "version = 1\n[[users.motor]]\n",
            "version = 1\n[users.motor]\nauthorized_key = 'legacy'\n",
            "version = 1\nextra = 'x'\n[users.motor]\n",
        ] {
            assert!(
                update_user(config, &existing("motor"), &key()).is_err(),
                "{config}"
            );
            assert!(
                update_user(config, &existing("motor"), &password()).is_err(),
                "{config}"
            );
            assert!(
                update_user(config, &new("new"), &key()).is_err(),
                "{config}"
            );
        }
    }
}
