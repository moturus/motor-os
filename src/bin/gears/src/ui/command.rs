//! The small command language shared by the line and full-screen interfaces.

use crate::agent::task::Mode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    Prompt(String),
    Command(Command),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Quit,
    Help,
    Status,
    Model,
    Pause,
    Resume,
    Mode(Mode),
    Expand(usize),
    Undo,
    Compact(Option<String>),
}

/// Classify one complete input before it can become a model prompt.
pub fn parse(input: &str) -> Result<Input, String> {
    let input = input.trim();
    let Some(command) = input
        .strip_prefix('/')
        .or_else(|| input.starts_with('+').then_some(input))
    else {
        return Ok(Input::Prompt(input.to_string()));
    };
    Ok(Input::Command(parse_command(command.trim())?))
}

fn parse_command(command: &str) -> Result<Command, String> {
    let name = command.split_whitespace().next().unwrap_or_default();
    match name {
        "quit" | "exit" | "q" => no_arguments(command, Command::Quit, "/quit"),
        "help" | "?" => no_arguments(command, Command::Help, "/help"),
        "status" => no_arguments(command, Command::Status, "/status"),
        "model" => no_arguments(command, Command::Model, "/model"),
        "pause" => no_arguments(command, Command::Pause, "/pause"),
        "resume" => no_arguments(command, Command::Resume, "/resume"),
        "undo" => no_arguments(command, Command::Undo, "/undo"),
        "mode" => parse_mode(command),
        "compact" => Ok(Command::Compact(
            command
                .strip_prefix("compact")
                .map(str::trim)
                .filter(|focus| !focus.is_empty())
                .map(str::to_string),
        )),
        word if word.starts_with('+') => parse_expand(command),
        other => Err(format!("no such command '/{other}'; try /help")),
    }
}

fn no_arguments(command: &str, parsed: Command, usage: &str) -> Result<Command, String> {
    match command.split_whitespace().count() {
        1 => Ok(parsed),
        _ => Err(format!("usage: {usage}")),
    }
}

fn parse_mode(command: &str) -> Result<Command, String> {
    let usage = "usage: /mode ask|plan|code|review";
    let mut words = command.split_whitespace();
    let _ = words.next();
    let name = words
        .next()
        .filter(|_| words.next().is_none())
        .ok_or(usage)?;
    crate::agent::mode::from_name(name)
        .map(Command::Mode)
        .ok_or_else(|| usage.to_string())
}

fn parse_expand(command: &str) -> Result<Command, String> {
    let argument = command.strip_prefix('+').unwrap_or_default().trim();
    let nth = match argument {
        "" => 1,
        value => value
            .parse::<usize>()
            .ok()
            .filter(|nth| *nth > 0)
            .ok_or_else(|| format!("'{value}' is not a positive number"))?,
    };
    Ok(Command::Expand(nth))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_text_is_a_prompt() {
        assert_eq!(
            parse("  explain this  "),
            Ok(Input::Prompt("explain this".into()))
        );
        assert_eq!(parse(""), Ok(Input::Prompt(String::new())));
    }

    #[test]
    fn simple_commands_and_aliases_are_recognized() {
        for (text, command) in [
            ("/quit", Command::Quit),
            ("/exit", Command::Quit),
            ("/q", Command::Quit),
            ("/help", Command::Help),
            ("/?", Command::Help),
            ("/status", Command::Status),
            ("/model", Command::Model),
            ("/pause", Command::Pause),
            ("/resume", Command::Resume),
            ("/undo", Command::Undo),
        ] {
            assert_eq!(parse(text), Ok(Input::Command(command)), "{text}");
        }
    }

    #[test]
    fn parameterized_commands_are_recognized() {
        assert_eq!(parse("/+"), Ok(Input::Command(Command::Expand(1))));
        assert_eq!(parse("+2"), Ok(Input::Command(Command::Expand(2))));
        assert_eq!(parse("/+ 3"), Ok(Input::Command(Command::Expand(3))));
        assert_eq!(
            parse("/mode code"),
            Ok(Input::Command(Command::Mode(Mode::Code)))
        );
        assert_eq!(
            parse("/compact"),
            Ok(Input::Command(Command::Compact(None)))
        );
        assert_eq!(
            parse("/compact focus on tests"),
            Ok(Input::Command(Command::Compact(Some(
                "focus on tests".into()
            ))))
        );
    }

    #[test]
    fn slash_prefixes_unknown_names_and_bad_syntax_are_rejected() {
        for text in [
            "/",
            "/wat",
            "/compactor",
            "/status now",
            "/model now",
            "/mode",
            "/mode code now",
            "/mode unknown",
            "/+0",
            "/+ nope",
            "/checkpoint",
            "/checkpoint list",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
    }
}
