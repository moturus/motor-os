use std::path::PathBuf;
use std::time::Duration;

use crate::{CurlError, CurlResult};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Help,
    Version,
    Transfer(Options),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Options {
    pub silent: bool,
    pub show_error: bool,
    pub connect_timeout: Duration,
    pub max_time: Duration,
    pub speed_limit: u64,
    pub speed_time: Duration,
    pub user_agent: String,
    pub write_out: Option<String>,
    pub ca_cert: Option<PathBuf>,
    pub url: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            silent: false,
            show_error: false,
            connect_timeout: Duration::from_secs(30),
            max_time: Duration::from_secs(300),
            speed_limit: 1,
            speed_time: Duration::from_secs(30),
            user_agent: format!("curl/{}", crate::VERSION),
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

        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--help" => return exclusive_action(arguments, Action::Help),
                "--version" => return exclusive_action(arguments, Action::Version),
                "--disable"
                | "--globoff"
                | "--http1.1"
                | "--disallow-username-in-url"
                | "--tlsv1.2" => {}
                "--silent" => options.silent = true,
                "--show-error" => options.show_error = true,
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
                    if !value.eq_ignore_ascii_case("Accept-Encoding: identity") {
                        return Err(CurlError::usage(
                            "only `Accept-Encoding: identity` is supported",
                        ));
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
            vec!["--header", "Authorization: secret", "https://example.test"],
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
