use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use crate::{CurlError, CurlResult};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Help,
    Version,
    Transfer(Options),
}

/// Where a request body comes from. The transfer layer needs the bytes (it
/// sends a Content-Length), so `main` resolves `Stdin` before connecting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataSource {
    Stdin,
    Literal(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Options {
    pub silent: bool,
    pub show_error: bool,
    pub include: bool,
    pub connect_timeout: Duration,
    pub max_time: Duration,
    pub speed_limit: u64,
    pub speed_time: Duration,
    pub user_agent: String,
    /// Request headers as given, in order. Validated at parse time: token
    /// names, printable values, and never a header the transfer layer itself
    /// manages (Host, Connection, Content-Length).
    pub headers: Vec<(String, String)>,
    /// Lowercase names from the `--header 'Name:'` removal form: send no
    /// such header, not even the built-in default.
    pub suppressed: Vec<String>,
    /// A body makes the request a POST.
    pub data: Option<DataSource>,
    pub write_out: Option<String>,
    pub ca_cert: Option<PathBuf>,
    pub url: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            silent: false,
            show_error: false,
            include: false,
            connect_timeout: Duration::from_secs(30),
            max_time: Duration::from_secs(300),
            speed_limit: 1,
            speed_time: Duration::from_secs(30),
            user_agent: format!("curl/{}", crate::VERSION),
            headers: Vec::new(),
            suppressed: Vec::new(),
            data: None,
            write_out: None,
            ca_cert: None,
            url: String::new(),
        }
    }
}

impl Options {
    pub fn parse<I, S>(arguments: I) -> CurlResult<Action>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut arguments = arguments.into_iter().map(Into::into).peekable();
        let mut options = Self::default();
        let mut url = None;
        // `--variable` imports, for `--expand-header`. Expansion happens as
        // the argument list is walked, the way upstream curl does it, so a
        // reference to a variable defined later is an error either way.
        let mut variables: BTreeMap<String, String> = BTreeMap::new();

        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--help" => return exclusive_action(arguments, Action::Help),
                "--version" => return exclusive_action(arguments, Action::Version),
                "--disable"
                | "--globoff"
                | "--http1.1"
                | "--disallow-username-in-url"
                | "--no-buffer" // Output is unbuffered already.
                | "--tlsv1.2" => {}
                "--silent" => options.silent = true,
                "--show-error" => options.show_error = true,
                "--include" => options.include = true,
                "--proto" => require_value(&mut arguments, "--proto", "=https")?,
                "--noproxy" => require_value(&mut arguments, "--noproxy", "*")?,
                "--tls-max" => require_value(&mut arguments, "--tls-max", "1.3")?,
                "--connect-timeout" => {
                    options.connect_timeout =
                        parse_duration(take_value(&mut arguments, "--connect-timeout")?)?;
                }
                "--max-time" => {
                    options.max_time = parse_duration(take_value(&mut arguments, "--max-time")?)?;
                }
                "--speed-limit" => {
                    options.speed_limit =
                        parse_positive_u64(take_value(&mut arguments, "--speed-limit")?)?;
                }
                "--speed-time" => {
                    options.speed_time =
                        parse_duration(take_value(&mut arguments, "--speed-time")?)?;
                }
                "--user-agent" => {
                    options.user_agent = take_value(&mut arguments, "--user-agent")?;
                    reject_header_bytes(&options.user_agent, "--user-agent")?;
                }
                "--header" => {
                    let value = take_value(&mut arguments, "--header")?;
                    options.add_header(&value)?;
                }
                // The pair that keeps a secret off the command line: the
                // value comes in through the environment, and the argument
                // vector carries only the variable's name.
                "--variable" => {
                    let value = take_value(&mut arguments, "--variable")?;
                    let name = value.strip_prefix('%').ok_or_else(|| {
                        CurlError::usage(
                            "only environment imports (--variable %NAME) are supported",
                        )
                    })?;
                    if name.is_empty()
                        || !name
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                    {
                        return Err(CurlError::usage(format!("bad variable name `{name}`")));
                    }
                    let value = std::env::var(name).map_err(|_| {
                        CurlError::usage(format!("environment variable {name} is not set"))
                    })?;
                    variables.insert(name.to_owned(), value);
                }
                "--expand-header" => {
                    let value = take_value(&mut arguments, "--expand-header")?;
                    options.add_header(&expand(&value, &variables)?)?;
                }
                "--data-binary" => {
                    let value = take_value(&mut arguments, "--data-binary")?;
                    let data = match value.strip_prefix('@') {
                        Some("-") => DataSource::Stdin,
                        Some(_) => {
                            return Err(CurlError::usage(
                                "only `--data-binary @-` reads from a file (stdin)",
                            ));
                        }
                        None => DataSource::Literal(value),
                    };
                    if options.data.replace(data).is_some() {
                        return Err(CurlError::usage("only one --data-binary is supported"));
                    }
                }
                "--output" => require_value(&mut arguments, "--output", "-")?,
                "--write-out" => {
                    options.write_out = Some(take_value(&mut arguments, "--write-out")?);
                }
                "--cacert" => {
                    let value = PathBuf::from(take_value(&mut arguments, "--cacert")?);
                    if !value.is_absolute() {
                        return Err(CurlError::usage("--cacert requires an absolute path"));
                    }
                    options.ca_cert = Some(value);
                }
                "--url" => set_url(&mut url, take_value(&mut arguments, "--url")?)?,
                _ if argument.starts_with('-') => {
                    return Err(CurlError::usage(format!("unsupported option: {argument}")));
                }
                _ => set_url(&mut url, argument)?,
            }
        }

        options.url = url.ok_or_else(|| CurlError::usage("no URL specified"))?;
        Ok(Action::Transfer(options))
    }

    /// Record one `--header` argument: `Name: value` sets, `Name:` (empty
    /// value) suppresses. Diagnostics name the header but never repeat its
    /// value — an expanded value may be a secret.
    fn add_header(&mut self, argument: &str) -> CurlResult<()> {
        let Some((name, value)) = argument.split_once(':') else {
            return Err(CurlError::usage("a header must be `Name: value`"));
        };
        if name.is_empty() || !name.bytes().all(crate::http::is_token) {
            return Err(CurlError::usage(format!("bad header name `{name}`")));
        }
        let value = value.trim_matches([' ', '\t']);
        if value.is_empty() {
            self.suppressed.push(name.to_ascii_lowercase());
            return Ok(());
        }
        // Headers the transfer layer computes itself: accepting a caller's
        // value would silently break framing, so it is refused instead.
        for managed in ["host", "connection", "content-length", "transfer-encoding", "expect"] {
            if name.eq_ignore_ascii_case(managed) {
                return Err(CurlError::usage(format!(
                    "the {name} header is set by curl and cannot be overridden"
                )));
            }
        }
        if !value
            .bytes()
            .all(|byte| byte == b'\t' || (0x20..0x7f).contains(&byte))
        {
            return Err(CurlError::usage(format!(
                "the value of the {name} header contains invalid bytes"
            )));
        }
        self.headers.push((name.to_owned(), value.to_owned()));
        Ok(())
    }
}

/// Replace each `{{NAME}}` with the imported variable's value. Anything else
/// passes through verbatim; a `{{` that does not reference a known variable
/// is an error rather than a guess.
fn expand(text: &str, variables: &BTreeMap<String, String>) -> CurlResult<String> {
    let mut result = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        result.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find("}}")
            .ok_or_else(|| CurlError::usage("unterminated {{ in --expand-header"))?;
        let name = &after[..end];
        let value = variables.get(name).ok_or_else(|| {
            CurlError::usage(format!("unknown variable `{name}` in --expand-header"))
        })?;
        result.push_str(value);
        rest = &after[end + 2..];
    }
    result.push_str(rest);
    Ok(result)
}

fn exclusive_action(
    mut remaining: impl Iterator<Item = String>,
    action: Action,
) -> CurlResult<Action> {
    if remaining.next().is_some() {
        return Err(CurlError::usage(
            "--help and --version must be used on their own",
        ));
    }
    Ok(action)
}

fn take_value(arguments: &mut impl Iterator<Item = String>, option: &str) -> CurlResult<String> {
    arguments
        .next()
        .ok_or_else(|| CurlError::usage(format!("option {option} requires a value")))
}

fn require_value(
    arguments: &mut impl Iterator<Item = String>,
    option: &str,
    expected: &str,
) -> CurlResult<()> {
    let value = take_value(arguments, option)?;
    if value != expected {
        return Err(CurlError::usage(format!(
            "unsupported value for {option}: {value}"
        )));
    }
    Ok(())
}

fn parse_duration(value: String) -> CurlResult<Duration> {
    Ok(Duration::from_secs(parse_positive_u64(value)?))
}

fn parse_positive_u64(value: String) -> CurlResult<u64> {
    match value.parse::<u64>() {
        Ok(value) if value != 0 => Ok(value),
        _ => Err(CurlError::usage(format!(
            "expected a positive integer, got `{value}`"
        ))),
    }
}

fn reject_header_bytes(value: &str, option: &str) -> CurlResult<()> {
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(CurlError::usage(format!(
            "{option} contains invalid header bytes"
        )));
    }
    Ok(())
}

fn set_url(url: &mut Option<String>, value: String) -> CurlResult<()> {
    if url.replace(value).is_some() {
        return Err(CurlError::usage("only one URL is supported"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lorry_argument_vector() {
        let action = Options::parse([
            "--disable",
            "--silent",
            "--show-error",
            "--globoff",
            "--http1.1",
            "--proto",
            "=https",
            "--noproxy",
            "*",
            "--disallow-username-in-url",
            "--tlsv1.2",
            "--tls-max",
            "1.3",
            "--connect-timeout",
            "30",
            "--max-time",
            "300",
            "--speed-limit",
            "1",
            "--speed-time",
            "30",
            "--user-agent",
            "lorry/0.1.0",
            "--header",
            "Accept-Encoding: identity",
            "--output",
            "-",
            "--write-out",
            "%{stderr}%{response_code}",
            "--cacert",
            "/tmp/ca.pem",
            "--url",
            "https://example.test/a",
        ])
        .unwrap();

        let Action::Transfer(options) = action else {
            panic!("expected a transfer");
        };
        assert!(options.silent);
        assert!(options.show_error);
        assert_eq!(options.user_agent, "lorry/0.1.0");
        assert_eq!(options.ca_cert, Some(PathBuf::from("/tmp/ca.pem")));
        assert_eq!(options.url, "https://example.test/a");
        assert_eq!(
            options.headers,
            [("Accept-Encoding".to_owned(), "identity".to_owned())]
        );
    }

    /// The argument vector gears sends (long forms of the same options its
    /// host transport passes to upstream curl).
    #[test]
    fn parses_gears_argument_vector() {
        // SAFETY: this test's variable name is unique to it.
        unsafe { std::env::set_var("CURL_TEST_GEARS_KEY", "sk-secret") };
        let action = Options::parse([
            "--disable",
            "--silent",
            "--show-error",
            "--no-buffer",
            "--include",
            "--http1.1",
            "--noproxy",
            "*",
            "--header",
            "Expect:",
            "--header",
            "Accept-Encoding: identity",
            "--connect-timeout",
            "30",
            "--max-time",
            "900",
            "--speed-limit",
            "1",
            "--speed-time",
            "90",
            "--header",
            "Content-Type: application/json",
            "--variable",
            "%CURL_TEST_GEARS_KEY",
            "--expand-header",
            "Authorization: Bearer {{CURL_TEST_GEARS_KEY}}",
            "--data-binary",
            "@-",
            "https://openrouter.ai/api/v1/chat/completions",
        ])
        .unwrap();

        let Action::Transfer(options) = action else {
            panic!("expected a transfer");
        };
        assert!(options.include);
        assert_eq!(options.data, Some(DataSource::Stdin));
        assert_eq!(options.suppressed, ["expect"]);
        assert_eq!(
            options.headers,
            [
                ("Accept-Encoding".to_owned(), "identity".to_owned()),
                ("Content-Type".to_owned(), "application/json".to_owned()),
                ("Authorization".to_owned(), "Bearer sk-secret".to_owned()),
            ]
        );
        assert_eq!(options.url, "https://openrouter.ai/api/v1/chat/completions");
    }

    #[test]
    fn header_arguments_are_validated_and_secrets_never_echoed() {
        let mut options = Options::default();
        options.add_header("X-One: 1").unwrap();
        options.add_header("Accept:").unwrap();
        assert_eq!(options.headers, [("X-One".to_owned(), "1".to_owned())]);
        assert_eq!(options.suppressed, ["accept"]);

        for (bad, mentions) in [
            ("no colon", "Name: value"),
            ("Bad Name: x", "bad header name"),
            (": empty", "bad header name"),
            ("Host: evil.test", "set by curl"),
            ("Content-Length: 4", "set by curl"),
            ("Connection: keep-alive", "set by curl"),
            ("Expect: 100-continue", "set by curl"),
            ("X-Secret: bad\u{7f}byte", "invalid bytes"),
        ] {
            let error = Options::default().add_header(bad).unwrap_err();
            assert_eq!(error.code(), CurlError::USAGE, "{bad}");
            assert!(error.message().contains(mentions), "{bad}: {error}");
            // The value may be a secret: diagnostics must not repeat it.
            let value = bad.split_once(':').map(|(_, v)| v.trim()).unwrap_or("");
            if !value.is_empty() {
                assert!(!error.message().contains(value), "{bad}: {error}");
            }
        }
    }

    #[test]
    fn variables_expand_strictly() {
        // SAFETY: this test's variable name is unique to it.
        unsafe { std::env::set_var("CURL_TEST_EXPAND", "value-7") };
        let mut variables = BTreeMap::new();
        variables.insert("CURL_TEST_EXPAND".to_owned(), "value-7".to_owned());
        assert_eq!(
            expand("Authorization: Bearer {{CURL_TEST_EXPAND}}", &variables).unwrap(),
            "Authorization: Bearer value-7"
        );
        assert_eq!(expand("plain text }} intact", &variables).unwrap(), "plain text }} intact");
        for bad in ["x {{MISSING}}", "x {{CURL_TEST_EXPAND"] {
            assert_eq!(
                expand(bad, &variables).unwrap_err().code(),
                CurlError::USAGE,
                "{bad}"
            );
        }

        for arguments in [
            // An import of a variable the environment does not have.
            vec!["--variable", "%CURL_TEST_NOT_SET_ANYWHERE", "https://a.test"],
            // Not the import form.
            vec!["--variable", "NAME=x", "https://a.test"],
            vec!["--variable", "%bad name", "https://a.test"],
            // Expansion of a variable that was never imported.
            vec![
                "--expand-header",
                "Authorization: {{CURL_TEST_NOT_SET_ANYWHERE}}",
                "https://a.test",
            ],
        ] {
            let error = Options::parse(arguments.clone()).unwrap_err();
            assert_eq!(error.code(), CurlError::USAGE, "{arguments:?}");
        }
    }

    #[test]
    fn data_binary_sources() {
        let Action::Transfer(options) =
            Options::parse(["--data-binary", "@-", "https://a.test"]).unwrap()
        else {
            panic!("expected a transfer");
        };
        assert_eq!(options.data, Some(DataSource::Stdin));

        let Action::Transfer(options) =
            Options::parse(["--data-binary", "a=b", "https://a.test"]).unwrap()
        else {
            panic!("expected a transfer");
        };
        assert_eq!(options.data, Some(DataSource::Literal("a=b".to_owned())));

        for arguments in [
            vec!["--data-binary", "@/etc/passwd", "https://a.test"],
            vec!["--data-binary", "x", "--data-binary", "y", "https://a.test"],
        ] {
            assert!(Options::parse(arguments).is_err());
        }
    }

    #[test]
    fn accepts_a_single_positional_url() {
        let Action::Transfer(options) = Options::parse(["https://example.test"]).unwrap() else {
            panic!("expected a transfer");
        };
        assert_eq!(options.url, "https://example.test");
    }

    #[test]
    fn rejects_unsupported_or_ambiguous_arguments() {
        for arguments in [
            vec!["--location"],
            vec!["--proto", "http", "--url", "https://example.test"],
            vec!["--header", "Host: other.test", "https://example.test"],
            vec!["--cacert", "relative.pem", "https://example.test"],
            vec!["https://one.test", "https://two.test"],
        ] {
            assert!(Options::parse(arguments).is_err());
        }
    }

    #[test]
    fn rejects_missing_and_invalid_values() {
        for arguments in [
            vec!["--url"],
            vec!["--max-time", "0", "https://example.test"],
            vec!["--speed-time", "seconds", "https://example.test"],
            vec!["--user-agent", "bad\nvalue", "https://example.test"],
        ] {
            let error = Options::parse(arguments).unwrap_err();
            assert_eq!(error.code(), CurlError::USAGE);
        }
    }
}
