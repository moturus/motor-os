use super::args::ParseError;

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
