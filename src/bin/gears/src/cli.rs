//! Dependency-free command-line parsing.

use std::path::PathBuf;

pub const COMMAND_NAMES: &[&str] = &[
    "quit",
    "exit",
    "help",
    "status",
    "tools",
    "tool",
    "permissions",
    "permission",
    "session",
    "name",
    "new",
    "resume",
    "label",
    "tree",
    "fork",
    "clone",
    "compact",
    "model",
    "provider",
    "reset",
    "setup",
];

pub const USAGE: &str = "\
gears - a small extensible agent harness

Usage: gears [OPTIONS]
       gears -p PROMPT [OPTIONS]
       gears ask [-m MODEL] PROMPT
       gears reset [--workspace DIR]

Options:
  --config PATH       Read configuration from PATH
  --workspace DIR     Use DIR as the working directory
  --log-file PATH     Append a diagnostic trace to PATH
  --provider NAME     Select a configured provider
  -m, --model ID      Select a model
  --ui UI             Use auto, tui, or line
  -p, --prompt TEXT   Run one prompt
  --output FORMAT     Use text or jsonl output for a -p run
  -c, --continue      Continue the most recent workspace session
  -r, --resume ID     Resume a session by path or partial id
  --session ID        Alias for --resume
  --fork ID           Clone a saved session; may combine with --ephemeral
  --fork-entry ID     End that clone at this saved entry; requires --fork
  --ephemeral         Do not save the session
  -n, --name NAME     Name a new session
  -v, -vv, -vvv       Increase transport diagnostics
  --version           Print the version
  --help              Print this help

Interactive commands include /new, /resume, /name, /session, /tree, /label,
/fork, /clone, /compact, /provider, /model, /tools, /tool, /permissions,
/permission, /status, /setup, /reset, /help, and /quit.
Without a chosen model, an interactive start asks for the provider, model and
key; /setup asks again at any time.
`gears reset` and /reset ask, then remove keys, saved settings, memory, skills
and sessions from the Gears directory, keeping gears.toml, gears-batteries.toml
and tools/, and remove .gears/ from the current directory.
Use /tool enable|disable|reset NAME [--global] to change directory tools.
Use /permission revoke NAME [--global] to remove saved grants.
Use /provider NAME --default or /model ID --default to save both defaults.
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Run,
    Ask,
    Reset,
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
    ForkEphemeral(String),
    Ephemeral,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Output {
    #[default]
    Text,
    Jsonl,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub action: Action,
    pub config: Option<PathBuf>,
    pub workspace: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub prompt: Option<String>,
    pub output: Output,
    pub ui: crate::ui::select::Requested,
    pub verbosity: u8,
    pub session: SessionStart,
    pub fork_entry: Option<String>,
    pub name: Option<String>,
}

impl Args {
    pub fn parse<S: AsRef<str>>(argv: &[S]) -> Result<Self, String> {
        let mut args = Self {
            action: Action::Run,
            config: None,
            workspace: None,
            log_file: None,
            provider: None,
            model: None,
            prompt: None,
            output: Output::Text,
            ui: crate::ui::select::Requested::Auto,
            verbosity: 0,
            session: SessionStart::New,
            fork_entry: None,
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
                "--provider" => {
                    args.provider = Some(value(flag, inline, &mut iterator)?.to_string())
                }
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
                "--output" => {
                    args.output = match value(flag, inline, &mut iterator)? {
                        "text" => Output::Text,
                        "jsonl" => Output::Jsonl,
                        other => {
                            return Err(format!(
                                "unknown output format {other:?}; use text or jsonl"
                            ));
                        }
                    };
                }
                "-c" | "--continue" => args.set_session(SessionStart::Continue)?,
                "-r" | "--resume" | "--session" => args.set_session(SessionStart::Resume(
                    value(flag, inline, &mut iterator)?.to_string(),
                ))?,
                "--fork" => args.set_session(SessionStart::Fork(
                    value(flag, inline, &mut iterator)?.to_string(),
                ))?,
                "--fork-entry" => {
                    if args.fork_entry.is_some() {
                        return Err("only one --fork-entry may be supplied".into());
                    }
                    let entry = value(flag, inline, &mut iterator)?;
                    if entry.is_empty() || entry.len() > 128 || entry.chars().any(char::is_control)
                    {
                        return Err("--fork-entry needs a saved entry id".into());
                    }
                    args.fork_entry = Some(entry.into());
                }
                "--ephemeral" | "--no-session" => args.set_session(SessionStart::Ephemeral)?,
                "-n" | "--name" => {
                    args.name = Some(value(flag, inline, &mut iterator)?.to_string())
                }
                _ => return Err(format!("unrecognized argument {argument:?}")),
            }
        }
        if args.fork_entry.is_some()
            && !matches!(
                args.session,
                SessionStart::Fork(_) | SessionStart::ForkEphemeral(_)
            )
        {
            return Err("--fork-entry requires --fork".into());
        }
        if args.output == Output::Jsonl {
            if args.action != Action::Run || args.prompt.is_none() {
                return Err("--output jsonl requires a -p run".into());
            }
            if args.ui == crate::ui::select::Requested::Tui {
                return Err("--output jsonl cannot use --ui tui".into());
            }
        }
        if args.action == Action::Reset
            && (args.config.is_some()
                || args.log_file.is_some()
                || args.provider.is_some()
                || args.model.is_some()
                || args.prompt.is_some()
                || args.output != Output::Text
                || ui_set
                || args.verbosity > 0
                || args.session != SessionStart::New
                || args.fork_entry.is_some()
                || args.name.is_some())
        {
            return Err("gears reset takes only --workspace".into());
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
            (Action::Run, None) if argument == "reset" => self.action = Action::Reset,
            (Action::Ask, None) => self.prompt = Some(argument.to_string()),
            _ => return Err(format!("unexpected argument {argument:?}")),
        }
        Ok(())
    }

    fn set_session(&mut self, session: SessionStart) -> Result<(), String> {
        match (&self.session, &session) {
            (SessionStart::Fork(selector), SessionStart::Ephemeral)
            | (SessionStart::Ephemeral, SessionStart::Fork(selector)) => {
                self.session = SessionStart::ForkEphemeral(selector.clone());
                return Ok(());
            }
            _ => {}
        }
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
    fn saved_entry_selection_requires_a_fork_and_accepts_either_option_order() {
        for argv in [
            vec!["--fork", "parent", "--fork-entry", "e1"],
            vec!["--fork-entry=e1", "--ephemeral", "--fork", "parent"],
        ] {
            assert_eq!(
                Args::parse(&argv).unwrap().fork_entry.as_deref(),
                Some("e1")
            );
        }
        for argv in [
            vec!["--fork-entry", "e1"],
            vec!["--resume", "parent", "--fork-entry", "e1"],
            vec!["--fork", "parent", "--fork-entry="],
            vec!["--fork", "parent", "--fork-entry", "e1", "--fork-entry=e2"],
            vec!["--fork", "parent", "--fork-entry", "bad\nentry"],
        ] {
            assert!(Args::parse(&argv).is_err(), "{argv:?}");
        }
    }

    #[test]
    fn ephemeral_forks_accept_either_option_order() {
        for argv in [
            vec!["--fork", "parent", "--ephemeral", "-p", "review"],
            vec!["--ephemeral", "--fork=parent", "-p", "review"],
            vec!["--no-session", "--fork", "parent", "-p", "review"],
        ] {
            let args = Args::parse(&argv).unwrap();
            assert_eq!(args.session, SessionStart::ForkEphemeral("parent".into()));
            assert_eq!(args.prompt.as_deref(), Some("review"));
        }
        for argv in [
            vec!["--resume", "parent", "--ephemeral"],
            vec!["--fork", "parent", "--ephemeral", "--ephemeral"],
            vec!["--fork", "parent", "--ephemeral", "--fork", "other"],
            vec!["ask", "review", "--fork", "parent", "--ephemeral"],
        ] {
            assert!(Args::parse(&argv).is_err(), "{argv:?}");
        }
    }

    #[test]
    fn reset_takes_only_a_workspace() {
        assert_eq!(Args::parse(&["reset"]).unwrap().action, Action::Reset);
        let args = Args::parse(&["reset", "--workspace", "/work"]).unwrap();
        assert_eq!(args.workspace, Some(PathBuf::from("/work")));
        for argv in [
            vec!["reset", "now"],
            vec!["reset", "-p", "work"],
            vec!["reset", "--config", "/c.toml"],
            vec!["reset", "--ephemeral"],
            vec!["-p", "work", "reset"],
        ] {
            assert!(Args::parse(&argv).is_err(), "{argv:?}");
        }
    }

    #[test]
    fn jsonl_output_is_explicit_and_only_for_one_shot_agent_runs() {
        assert_eq!(
            Args::parse(&["-p", "work", "--output=jsonl"])
                .unwrap()
                .output,
            Output::Jsonl
        );
        assert_eq!(Args::parse(&["-p", "work"]).unwrap().output, Output::Text);
        for argv in [
            vec!["--output", "jsonl"],
            vec!["ask", "work", "--output", "jsonl"],
            vec!["-p", "work", "--output", "unknown"],
            vec!["-p", "work", "--output", "jsonl", "--ui", "tui"],
        ] {
            assert!(Args::parse(&argv).is_err(), "{argv:?}");
        }
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
    fn named_provider_can_be_selected_for_agent_and_ask() {
        assert_eq!(
            Args::parse(&["--provider=local", "-p", "hello"])
                .unwrap()
                .provider
                .as_deref(),
            Some("local")
        );
        assert_eq!(
            Args::parse(&["ask", "--provider", "remote", "hello"])
                .unwrap()
                .provider
                .as_deref(),
            Some("remote")
        );
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
