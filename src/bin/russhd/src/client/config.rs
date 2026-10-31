use std::path::{Path, PathBuf};

use super::args::{ConnectionOptions, Destination, ParseError};

const MAX_HOPS: usize = 16;

#[derive(Debug, Default)]
pub struct Config {
    directives: Vec<(String, Vec<String>)>,
}

#[derive(Debug)]
pub struct ResolvedHost {
    pub alias: String,
    pub destination: Destination,
    pub options: ConnectionOptions,
}

impl Config {
    pub fn parse(text: &str, filename: &Path) -> Result<Self, ParseError> {
        let mut directives = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let parsed = (|| {
                let Some((key, values)) = option(line)? else {
                    return Ok(None);
                };
                if key.eq_ignore_ascii_case("Host") {
                    if values.is_empty()
                        || values.iter().any(|value| value.is_empty() || value == "!")
                    {
                        return Err(ParseError::new("Host requires nonempty patterns"));
                    }
                } else {
                    if values.len() != 1 {
                        return Err(ParseError::new(format!("{key} requires one argument")));
                    }
                    ConnectionOptions::default().apply(&key, &values[0])?;
                }
                Ok(Some((key, values)))
            })()
            .map_err(|error: ParseError| {
                ParseError::new(format!("{}:{}: {error}", filename.display(), index + 1))
            })?;
            if let Some(directive) = parsed {
                directives.push(directive);
            }
        }
        Ok(Self { directives })
    }

    pub fn load(selected: Option<&Path>) -> Result<Self, ParseError> {
        if selected.is_some_and(|path| path == Path::new("none") || path == Path::new("/dev/null"))
        {
            return Ok(Self::default());
        }
        let default = default_path();
        let path = selected.unwrap_or(&default);
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text, path),
            Err(error) if selected.is_none() && error.kind() == std::io::ErrorKind::NotFound => {
                Ok(Self::default())
            }
            Err(error) => Err(ParseError::new(format!("{}: {error}", path.display()))),
        }
    }

    pub fn resolve(
        &self,
        options: &ConnectionOptions,
        destination: &Destination,
    ) -> Result<Vec<ResolvedHost>, ParseError> {
        let target = self.host(options.clone(), destination)?;
        let mut route = Vec::new();
        self.expand(target, &mut Vec::new(), &mut route)?;
        Ok(route)
    }

    fn host(
        &self,
        mut options: ConnectionOptions,
        destination: &Destination,
    ) -> Result<ResolvedHost, ParseError> {
        if destination.user_explicit && options.user.is_none() {
            options.user = Some(destination.user.clone());
        }
        let mut active = true;
        for (key, values) in &self.directives {
            if key.eq_ignore_ascii_case("Host") {
                active = matches_host(&destination.host, values);
            } else if active {
                options.apply(key, &values[0])?;
            }
        }
        let host = options.hostname.as_deref().unwrap_or(&destination.host);
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        if host.is_empty() || host.contains(['[', ']']) {
            return Err(ParseError::new("invalid HostName"));
        }
        let resolved = Destination {
            host: host.to_owned(),
            user: options
                .user
                .clone()
                .unwrap_or_else(|| destination.user.clone()),
            user_explicit: true,
        };
        #[cfg(target_os = "motor")]
        if !options.identity_files_set {
            options
                .identities
                .push(PathBuf::from("/user/cfg/ssh/id_ed25519"));
        }
        Ok(ResolvedHost {
            alias: destination.host.clone(),
            destination: resolved,
            options,
        })
    }

    fn expand(
        &self,
        host: ResolvedHost,
        ancestors: &mut Vec<(String, String, u16)>,
        route: &mut Vec<ResolvedHost>,
    ) -> Result<(), ParseError> {
        let endpoint = (
            host.destination.user.clone(),
            host.destination.host.clone(),
            host.options.port,
        );
        if ancestors.contains(&endpoint)
            || route.iter().any(|hop| {
                (
                    hop.destination.user.clone(),
                    hop.destination.host.clone(),
                    hop.options.port,
                ) == endpoint
            })
        {
            return Err(ParseError::new(format!(
                "ProxyJump cycle at '{}'",
                host.alias
            )));
        }
        if ancestors.len() + route.len() >= MAX_HOPS {
            return Err(ParseError::new("ProxyJump route exceeds 16 hosts"));
        }
        ancestors.push(endpoint);
        let jumps = host
            .options
            .proxy_jump
            .as_deref()
            .map(jump_hosts)
            .transpose()?
            .unwrap_or_default();
        for (index, jump) in jumps.iter().enumerate() {
            let mut options = ConnectionOptions::default();
            if let Some(port) = jump.port {
                options.set_port(&port.to_string())?;
            }
            // An explicit comma-separated chain supplies the preceding hops of
            // every entry after the first, overriding that entry's ProxyJump.
            if index != 0 {
                options.proxy_jump = Some("none".to_owned());
            }
            let jump = self.host(options, &jump.destination)?;
            self.expand(jump, ancestors, route)?;
        }
        ancestors.pop();
        route.push(host);
        Ok(())
    }
}

#[cfg(target_os = "motor")]
fn default_path() -> PathBuf {
    PathBuf::from("/user/cfg/ssh/config")
}

#[cfg(not(target_os = "motor"))]
fn default_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
        .join(".ssh/config")
}

pub(crate) fn literal_path(value: &str) -> Result<(), ParseError> {
    if value.starts_with('~') || value.contains('%') || value.contains("${") {
        return Err(ParseError::new(
            "config token, environment and tilde expansion are unsupported; use literal values",
        ));
    }
    Ok(())
}

// Split the keyword before lexing arguments: '=' is a separator only here,
// and remains an ordinary character in paths and other argument values.
pub(crate) fn option(line: &str) -> Result<Option<(String, Vec<String>)>, ParseError> {
    let line = line.trim_start();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let split = line
        .find(|ch: char| ch.is_ascii_whitespace() || ch == '=')
        .unwrap_or(line.len());
    let key = &line[..split];
    if key.is_empty() || !key.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return Err(ParseError::new("invalid config keyword"));
    }
    let rest = line[split..].trim_start();
    let rest = rest.strip_prefix('=').unwrap_or(rest).trim_start();
    let mut values = Vec::new();
    let mut value = String::new();
    let mut quote = None;
    let mut started = false;
    let mut chars = rest.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' | '\'' if quote.is_none() || quote == Some(ch) => {
                quote = if quote.is_none() { Some(ch) } else { None };
                started = true;
            }
            '\\' => {
                // Other backslashes stay literal, including quoted spaces.
                let escaped = chars.peek().copied().is_some_and(|next| {
                    matches!(next, '"' | '\'' | '\\') || (quote.is_none() && next == ' ')
                });
                value.push(if escaped { chars.next().unwrap() } else { ch });
                started = true;
            }
            '#' if quote.is_none() && !started => break,
            ch if ch.is_ascii_whitespace() && quote.is_none() => {
                if started {
                    values.push(std::mem::take(&mut value));
                    started = false;
                }
            }
            ch => {
                value.push(ch);
                started = true;
            }
        }
    }
    if quote.is_some() {
        return Err(ParseError::new("unterminated quoted value"));
    }
    if started {
        values.push(value);
    }
    Ok(Some((key.to_owned(), values)))
}

fn wildcard(pattern: &[u8], host: &[u8]) -> bool {
    let (mut p, mut h, mut star) = (0, 0, None);
    while h < host.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == host[h]) {
            p += 1;
            h += 1;
        } else if pattern.get(p) == Some(&b'*') {
            star = Some((p, h));
            p += 1;
        } else if let Some((s, matched)) = star {
            h = matched + 1;
            p = s + 1;
            star = Some((s, h));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|byte| *byte == b'*')
}

fn matches_host(host: &str, patterns: &[String]) -> bool {
    let mut positive = false;
    for pattern in patterns {
        let (negated, pattern) = match pattern.strip_prefix('!') {
            Some(pattern) => (true, pattern),
            None => (false, pattern.as_str()),
        };
        if wildcard(pattern.as_bytes(), host.as_bytes()) {
            if negated {
                return false;
            }
            positive = true;
        }
    }
    positive
}

pub(crate) struct JumpHost {
    destination: Destination,
    port: Option<u16>,
}

pub(crate) fn jump_hosts(value: &str) -> Result<Vec<JumpHost>, ParseError> {
    literal_path(value)?;
    if value == "none" {
        return Ok(Vec::new());
    }
    let mut jumps = Vec::new();
    for value in value.split(',') {
        if jumps.len() >= MAX_HOPS
            || value.is_empty()
            || value.contains("://")
            || value.chars().any(char::is_whitespace)
        {
            return Err(ParseError::new("invalid or excessive ProxyJump hosts"));
        }
        let host_start = value.rfind('@').map_or(0, |index| index + 1);
        let host = &value[host_start..];
        let colon = if host.starts_with('[') {
            let end = host
                .find(']')
                .ok_or_else(|| ParseError::new("invalid bracketed ProxyJump host"))?;
            if host[end + 1..].is_empty() {
                None
            } else if host.as_bytes().get(end + 1) == Some(&b':') {
                Some(host_start + end + 1)
            } else {
                return Err(ParseError::new("invalid ProxyJump port"));
            }
        } else {
            value.rfind(':')
        };
        let (name, port) = if let Some(colon) = colon {
            let mut options = ConnectionOptions::default();
            options.set_port(&value[colon + 1..])?;
            (&value[..colon], Some(options.port))
        } else {
            (value, None)
        };
        jumps.push(JumpHost {
            destination: Destination::parse(name)?,
            port,
        });
    }
    Ok(jumps)
}

#[cfg(test)]
mod tests {
    use super::option;
    use crate::client::args::ConnectionOptions;

    #[test]
    fn option_syntax_accepts_separators_patterns_and_comments() {
        for line in [
            "BatchMode yes",
            " BatchMode=yes",
            "\tBatchMode = yes # comment",
        ] {
            assert_eq!(
                option(line).unwrap(),
                Some(("BatchMode".into(), vec!["yes".into()]))
            );
        }
        assert_eq!(
            option("Host db? *.example !blocked.example # comment").unwrap(),
            Some((
                "Host".into(),
                vec!["db?".into(), "*.example".into(), "!blocked.example".into()]
            ))
        );
        for line in ["", " \t", " # comment"] {
            assert_eq!(option(line).unwrap(), None);
        }
    }

    #[test]
    fn option_syntax_rejects_bad_keywords_and_unclosed_quotes() {
        for line in [
            "=value",
            "123 value",
            "Bad-Key value",
            "User \"unterminated",
            "User 'unterminated",
        ] {
            assert!(option(line).is_err(), "{line}");
        }
    }

    #[test]
    fn option_literals_preserve_hashes_quotes_and_backslashes() {
        #[cfg(unix)]
        let root = {
            let root = std::env::temp_dir()
                .join(format!("motor-ssh-option-oracle-{}", std::process::id()));
            std::fs::create_dir(&root).unwrap();
            root
        };
        for (line, expected) in [
            ("User abc#def", "abc#def"),
            ("User abc #comment", "abc"),
            ("User \"abc\"#def", "abc#def"),
            (r#"User "abc def#ghi""#, "abc def#ghi"),
            (r#"User abc"def ghi""#, "abcdef ghi"),
            (r#"User 'abc def'"#, "abc def"),
            (r"User abc\q", r"abc\q"),
            (r"User abc\#def", r"abc\#def"),
            (r"User abc\\def", r"abc\def"),
            (r"User abc\ def", "abc def"),
            (r"User abc\", r"abc\"),
            ("User abc\\\t#comment", r"abc\"),
            (r#"User "abc\ def""#, r"abc\ def"),
            (r#"User "abc\"def""#, "abc\"def"),
            (r#"User "abc\'def""#, "abc'def"),
            (r#"User 'abc\"def'"#, "abc\"def"),
            (r"IdentityFile /tmp/a\q", r"/tmp/a\q"),
            ("UserKnownHostsFile /tmp/known#hosts", "/tmp/known#hosts"),
            (
                r#"UserKnownHostsFile "/tmp/a b#c=hosts""#,
                "/tmp/a b#c=hosts",
            ),
        ] {
            let (key, values) = option(line).unwrap().unwrap();
            assert_eq!(values, [expected], "{line}");
            // -G dumps effective options without connecting to any host.
            #[cfg(unix)]
            {
                let path = root.join("config");
                std::fs::write(&path, format!("{line}\n")).unwrap();
                let output = std::process::Command::new("ssh")
                    .args(["-G", "-F"])
                    .arg(&path)
                    .arg("127.0.0.1")
                    .output()
                    .unwrap();
                assert!(output.status.success(), "{line}: {output:?}");
                let effective = String::from_utf8(output.stdout).unwrap();
                let expected = format!("{} {expected}", key.to_ascii_lowercase());
                assert!(
                    effective.lines().any(|line| line == expected),
                    "{line}: {effective}"
                );
            }
            #[cfg(not(unix))]
            let _ = key;
        }
        #[cfg(unix)]
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn command_line_options_use_shared_syntax_and_keep_first_value() {
        let mut options = ConnectionOptions::default();
        options.apply_o("bAtChMoDe yes # comment").unwrap();
        options.apply_o("BatchMode=no").unwrap();
        options.apply_o("ConnectTimeout = 7").unwrap();
        options
            .apply_o(r#"UserKnownHostsFile "/tmp/a b#c=hosts""#)
            .unwrap();
        options.apply_o("UserKnownHostsFile=/ignored").unwrap();
        assert!(options.batch_mode);
        assert_eq!(
            options.connect_timeout,
            Some(std::time::Duration::from_secs(7))
        );
        assert_eq!(
            options.known_hosts,
            Some(std::path::PathBuf::from("/tmp/a b#c=hosts"))
        );
        for bad in [
            "",
            "# comment",
            "BatchMode",
            "BatchMode yes no",
            "BatchMode \"",
            "BatchMode \"\"",
            "Compression=yes",
        ] {
            assert!(options.apply_o(bad).is_err(), "{bad}");
        }
    }
}
