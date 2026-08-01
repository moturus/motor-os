//! Command-line argument parsing, hand-rolled (no clap — the red/rmux
//! dependency posture).

use std::path::PathBuf;

pub const USAGE: &str = "\
gears - an agentic coding harness

Usage: gears [OPTIONS]
       gears ask [-m MODEL] PROMPT

Options:
  --config PATH     Read configuration from PATH instead of the default
  --workspace DIR   Operate on DIR (default: the current directory)
  --log-file PATH   Append a debug/wire trace to PATH
  -m, --model ID    Model id for 'ask' (default: provider.model in the config)
  --version         Print the version and exit
  --help            Print this help and exit

'ask' sends one prompt and prints the answer: a spot check of the endpoint,
the key and a model, with none of the agent loop in the way.
";

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Run,
    /// One prompt, one answer.
    Ask,
    Version,
    Help,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Args {
    pub action: Action,
    pub config: Option<PathBuf>,
    pub workspace: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
    pub model: Option<String>,
    pub prompt: Option<String>,
}

impl Args {
    /// Parse `argv` (without the program name). Both `--flag value` and
    /// `--flag=value` are accepted, `--` ends the flags, and
    /// `--version`/`--help` win immediately without validating the rest.
    pub fn parse<S: AsRef<str>>(argv: &[S]) -> Result<Args, String> {
        let mut args = Args {
            action: Action::Run,
            config: None,
            workspace: None,
            log_file: None,
            model: None,
            prompt: None,
        };
        let mut it = argv.iter().map(AsRef::as_ref);
        let mut only_positional = false;
        while let Some(arg) = it.next() {
            if only_positional || !arg.starts_with('-') {
                args.take_positional(arg)?;
                continue;
            }
            let (flag, inline) = match arg.split_once('=') {
                Some((flag, value)) => (flag, Some(value)),
                None => (arg, None),
            };
            match flag {
                "--" => only_positional = true,
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
                "-m" | "--model" => {
                    args.model = Some(take_value(flag, inline, &mut it)?.to_string())
                }
                _ => return Err(format!("unrecognized argument '{arg}'")),
            }
        }
        if args.action == Action::Ask && args.prompt.is_none() {
            return Err("ask requires a prompt".to_string());
        }
        Ok(args)
    }

    /// The subcommand, then its one argument.
    fn take_positional(&mut self, arg: &str) -> Result<(), String> {
        match (&self.action, &self.prompt) {
            (Action::Run, _) if arg == "ask" => self.action = Action::Ask,
            (Action::Ask, None) => self.prompt = Some(arg.to_string()),
            _ => return Err(format!("unexpected argument '{arg}'")),
        }
        Ok(())
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
        assert!(Args::parse(&["ask", "one", "two"]).is_err());
    }

    #[test]
    fn ask_takes_a_model_and_a_prompt() {
        let args = Args::parse(&["ask", "-m", "openai/gpt-5", "what is 2+2?"]).unwrap();
        assert_eq!(args.action, Action::Ask);
        assert_eq!(args.model.as_deref(), Some("openai/gpt-5"));
        assert_eq!(args.prompt.as_deref(), Some("what is 2+2?"));

        // Flags may follow the prompt, and the model may come from config.
        let args = Args::parse(&["ask", "hello", "--log-file=/tmp/t.log"]).unwrap();
        assert_eq!(args.model, None);
        assert_eq!(args.prompt.as_deref(), Some("hello"));
        assert_eq!(args.log_file, Some(PathBuf::from("/tmp/t.log")));

        assert!(Args::parse(&["ask"]).unwrap_err().contains("prompt"));
    }

    #[test]
    fn a_prompt_may_start_with_a_dash() {
        let args = Args::parse(&["ask", "--", "--not-a-flag"]).unwrap();
        assert_eq!(args.prompt.as_deref(), Some("--not-a-flag"));
    }
}
