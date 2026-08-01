//! Command-line argument parsing, hand-rolled (no clap — the red/rmux
//! dependency posture).

use std::path::PathBuf;

pub const USAGE: &str = "\
gears - an agentic coding harness

Usage: gears [OPTIONS]

Options:
  --config PATH     Read configuration from PATH instead of the default
  --workspace DIR   Operate on DIR (default: the current directory)
  --log-file PATH   Append a debug/wire trace to PATH
  --version         Print the version and exit
  --help            Print this help and exit
";

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Run,
    Version,
    Help,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Args {
    pub action: Action,
    pub config: Option<PathBuf>,
    pub workspace: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
}

impl Args {
    /// Parse `argv` (without the program name). Both `--flag value` and
    /// `--flag=value` are accepted. `--version`/`--help` win immediately,
    /// without validating the rest of the line.
    pub fn parse<S: AsRef<str>>(argv: &[S]) -> Result<Args, String> {
        let mut args = Args {
            action: Action::Run,
            config: None,
            workspace: None,
            log_file: None,
        };
        let mut it = argv.iter().map(AsRef::as_ref);
        while let Some(arg) = it.next() {
            let (flag, inline) = match arg.split_once('=') {
                Some((flag, value)) => (flag, Some(value)),
                None => (arg, None),
            };
            match flag {
                "--version" => {
                    args.action = Action::Version;
                    return Ok(args);
                }
                "--help" => {
                    args.action = Action::Help;
                    return Ok(args);
                }
                "--config" => args.config = Some(take_value(flag, inline, &mut it)?.into()),
                "--workspace" => args.workspace = Some(take_value(flag, inline, &mut it)?.into()),
                "--log-file" => args.log_file = Some(take_value(flag, inline, &mut it)?.into()),
                _ => return Err(format!("unrecognized argument '{arg}'")),
            }
        }
        Ok(args)
    }
}

fn take_value<'a>(
    flag: &str,
    inline: Option<&'a str>,
    it: &mut impl Iterator<Item = &'a str>,
) -> Result<&'a str, String> {
    inline
        .or_else(|| it.next())
        .ok_or_else(|| format!("{flag} requires a value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_argv_runs() {
        let args = Args::parse::<&str>(&[]).unwrap();
        assert_eq!(args.action, Action::Run);
        assert_eq!(args.config, None);
        assert_eq!(args.workspace, None);
        assert_eq!(args.log_file, None);
    }

    #[test]
    fn version_and_help_short_circuit() {
        let args = Args::parse(&["--version", "--bogus"]).unwrap();
        assert_eq!(args.action, Action::Version);
        let args = Args::parse(&["--help"]).unwrap();
        assert_eq!(args.action, Action::Help);
    }

    #[test]
    fn values_in_both_forms() {
        let args = Args::parse(&["--config", "/a/b.toml", "--workspace=/w"]).unwrap();
        assert_eq!(args.config, Some(PathBuf::from("/a/b.toml")));
        assert_eq!(args.workspace, Some(PathBuf::from("/w")));

        let args = Args::parse(&["--log-file=/tmp/t.log"]).unwrap();
        assert_eq!(args.log_file, Some(PathBuf::from("/tmp/t.log")));
    }

    #[test]
    fn missing_value_is_an_error() {
        let err = Args::parse(&["--config"]).unwrap_err();
        assert!(err.contains("--config"), "{err}");
    }

    #[test]
    fn unknown_arguments_are_errors() {
        assert!(Args::parse(&["--frobnicate"]).is_err());
        assert!(Args::parse(&["positional"]).is_err());
    }
}
