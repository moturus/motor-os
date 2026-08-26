//! Dependency-free command-line parsing.

use std::path::PathBuf;

pub const USAGE: &str = "\
gears - a small extensible agent harness

Usage: gears [OPTIONS]
       gears -p PROMPT [OPTIONS]
       gears ask [-m MODEL] PROMPT

Options:
  --config PATH       Read configuration from PATH
  --workspace DIR     Use DIR as the working directory
  --log-file PATH     Append a diagnostic trace to PATH
  -m, --model ID      Select a model
  --ui UI             Use auto, tui, or line
  -p, --prompt TEXT   Run one prompt
  -c, --continue      Continue the most recent workspace session
  -r, --resume ID     Resume a session by path or partial id
  --session ID        Alias for --resume
  --fork ID           Clone the active branch of a saved session
  --ephemeral         Do not save the session
  -n, --name NAME     Name a new session
  -v, -vv, -vvv       Increase transport diagnostics
  --version           Print the version
  --help              Print this help

Interactive commands include /new, /resume, /name, /session, /tree, /label,
/fork, /clone, /compact, /model, /status, /help, and /quit.
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Run,
    Ask,
    Version,
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SessionStart {
    #[default]
    New,
    Continue,
    Resume(String),
    Fork(String),
    Ephemeral,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub action: Action,
    pub config: Option<PathBuf>,
    pub workspace: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
    pub model: Option<String>,
    pub prompt: Option<String>,
    pub ui: crate::ui::select::Requested,
    pub verbosity: u8,
    pub session: SessionStart,
    pub name: Option<String>,
}

impl Args {
    pub fn parse<S: AsRef<str>>(argv: &[S]) -> Result<Self, String> {
        let mut args = Self {
            action: Action::Run,
            config: None,
            workspace: None,
            log_file: None,
            model: None,
            prompt: None,
            ui: crate::ui::select::Requested::Auto,
            verbosity: 0,
            session: SessionStart::New,
            name: None,
        };
        let mut iterator = argv.iter().map(AsRef::as_ref);
        let mut positional = false;
        let mut ui_set = false;
        while let Some(argument) = iterator.next() {
            if positional || !argument.starts_with('-') {
                args.positional(argument)?;
                continue;
            }
            if let Some(count) = verbosity(argument) {
                args.verbosity = args
                    .verbosity
                    .checked_add(count)
                    .filter(|level| *level <= 3)
                    .ok_or("verbosity cannot exceed -vvv")?;
                continue;
            }
            let (flag, inline) = argument
                .split_once('=')
                .map_or((argument, None), |(flag, value)| (flag, Some(value)));
            match flag {
                "--" => positional = true,
                "--version" => {
                    args.action = Action::Version;
                    return Ok(args);
                }
                "--help" => {
                    args.action = Action::Help;
                    return Ok(args);
                }
                "--config" => args.config = Some(value(flag, inline, &mut iterator)?.into()),
                "--workspace" => args.workspace = Some(value(flag, inline, &mut iterator)?.into()),
                "--log-file" => args.log_file = Some(value(flag, inline, &mut iterator)?.into()),
                "-m" | "--model" => {
                    args.model = Some(value(flag, inline, &mut iterator)?.to_string())
                }
                "-p" | "--prompt" => {
                    if args.prompt.is_some() {
                        return Err("only one prompt may be supplied".to_string());
                    }
                    args.prompt = Some(value(flag, inline, &mut iterator)?.to_string());
                }
                "--ui" => {
                    args.ui =
                        crate::ui::select::Requested::parse(value(flag, inline, &mut iterator)?)?;
                    ui_set = true;
                }
                "-c" | "--continue" => args.set_session(SessionStart::Continue)?,
                "-r" | "--resume" | "--session" => args.set_session(SessionStart::Resume(
                    value(flag, inline, &mut iterator)?.to_string(),
                ))?,
                "--fork" => args.set_session(SessionStart::Fork(
                    value(flag, inline, &mut iterator)?.to_string(),
                ))?,
                "--ephemeral" | "--no-session" => args.set_session(SessionStart::Ephemeral)?,
                "-n" | "--name" => {
                    args.name = Some(value(flag, inline, &mut iterator)?.to_string())
                }
                _ => return Err(format!("unrecognized argument {argument:?}")),
            }
        }
        if args.action == Action::Ask {
            if args.prompt.is_none() {
                return Err("ask requires a prompt".to_string());
            }
            if ui_set {
                return Err("--ui applies to the agent, not gears ask".to_string());
            }
            if args.session != SessionStart::New || args.name.is_some() {
                return Err("session options do not apply to gears ask".to_string());
            }
        }
        if args.name.is_some()
            && !matches!(args.session, SessionStart::New | SessionStart::Ephemeral)
        {
            return Err("--name applies only to a new session".to_string());
        }
        Ok(args)
    }

    fn positional(&mut self, argument: &str) -> Result<(), String> {
        match (&self.action, &self.prompt) {
            (Action::Run, _) if argument == "ask" => self.action = Action::Ask,
            (Action::Ask, None) => self.prompt = Some(argument.to_string()),
            _ => return Err(format!("unexpected argument {argument:?}")),
        }
        Ok(())
    }

    fn set_session(&mut self, session: SessionStart) -> Result<(), String> {
        if self.session != SessionStart::New {
            return Err("session options are mutually exclusive".to_string());
        }
        self.session = session;
        Ok(())
    }
}

fn verbosity(argument: &str) -> Option<u8> {
    let suffix = argument.strip_prefix('-')?;
    if suffix.is_empty() || !suffix.bytes().all(|byte| byte == b'v') {
        return None;
    }
    u8::try_from(suffix.len()).ok()
}

fn value<'a>(
    flag: &str,
    inline: Option<&'a str>,
    iterator: &mut impl Iterator<Item = &'a str>,
) -> Result<&'a str, String> {
    inline
        .or_else(|| iterator.next())
        .ok_or_else(|| format!("{flag} requires a value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_starts_are_explicit_and_exclusive() {
        assert_eq!(
            Args::parse(&["-c"]).unwrap().session,
            SessionStart::Continue
        );
        assert_eq!(
            Args::parse(&["--session=abc"]).unwrap().session,
            SessionStart::Resume("abc".to_string())
        );
        assert!(Args::parse(&["-c", "--ephemeral"]).is_err());
    }

    #[test]
    fn ask_stays_outside_sessions_and_ui() {
        let args = Args::parse(&["ask", "-m", "model", "hello"]).unwrap();
        assert_eq!(args.action, Action::Ask);
        assert_eq!(args.prompt.as_deref(), Some("hello"));
        assert!(Args::parse(&["ask", "hello", "--ui", "line"]).is_err());
        assert!(Args::parse(&["ask", "hello", "-c"]).is_err());
    }

    #[test]
    fn help_and_version_short_circuit() {
        assert_eq!(
            Args::parse(&["--help", "--bad"]).unwrap().action,
            Action::Help
        );
        assert_eq!(Args::parse(&["--version"]).unwrap().action, Action::Version);
    }
}
