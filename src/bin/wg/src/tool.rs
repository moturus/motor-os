//! Command syntax and display helpers shared with the native tool.
use crate::config::Result;

pub const HELP: &str = "Usage: wg-tool new\n       wg-tool add-peer [FILE]\n       wg-tool up FILE\n       wg-tool down INTERFACE\n       wg-tool status\n\nUse -- before an operand beginning with '-'. Peer edits affect the saved file;\napply them with down/up. Commands require the Interactive role.\nUse wg-tool COMMAND --help for command help.";

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Help(String),
    New,
    AddPeer(Option<String>),
    Up(String),
    Down(String),
    Status,
}

pub fn parse(args: &[String]) -> Result<Command> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err(HELP);
    };
    if args == ["--help"] {
        return Ok(Command::Help(HELP.into()));
    }
    if !["new", "add-peer", "up", "down", "status"].contains(&command) {
        return Err("unknown command; use wg-tool --help");
    }
    if args.len() == 2 && args[1] == "--help" {
        return Ok(Command::Help(match command {
            "new" => "wg-tool new\nPrompt for interface settings and create a protected config with new inline keys.",
            "add-peer" => "wg-tool add-peer [FILE]\nAppend one peer to a saved config, preserving comments. Apply with down/up.",
            "up" => "wg-tool up FILE\nStart an Interactive detached daemon and wait for activation. Requires CAP_NET, CAP_SPAWN and CAP_SPAWN_DETACHED.",
            "down" => "wg-tool down INTERFACE\nGracefully stop the running interface and wait for cleanup.",
            _ => "wg-tool status\nShow loaded interface and peer state, without reading config files.",
        }.into()));
    }
    let operands = if args.get(1).is_some_and(|arg| arg == "--") {
        &args[2..]
    } else {
        if args[1..].iter().any(|arg| arg.starts_with('-')) {
            return Err("unknown option; use -- before operands beginning with '-'");
        }
        &args[1..]
    };
    match (command, operands) {
        ("new", []) => Ok(Command::New),
        ("status", []) => Ok(Command::Status),
        ("add-peer", []) => Ok(Command::AddPeer(None)),
        ("add-peer", [file]) => Ok(Command::AddPeer(Some(file.clone()))),
        ("up", [file]) => Ok(Command::Up(file.clone())),
        ("down", [name]) => {
            crate::config::validate_name(name)?;
            Ok(Command::Down(name.clone()))
        }
        _ => Err("incorrect operands; use wg-tool COMMAND --help"),
    }
}

pub fn escaped(text: &str) -> String {
    text.chars()
        .flat_map(|ch| {
            if ch.is_control() {
                ch.escape_default().collect::<Vec<_>>()
            } else {
                vec![ch]
            }
        })
        .collect()
}

pub fn quoted(text: &str) -> String {
    if text.chars().any(char::is_control) {
        let value: String = text
            .chars()
            .map(|ch| {
                if ch.is_control() {
                    format!("\\x{:02x}", ch as u32)
                } else if ch == '\\' || ch == '\'' {
                    format!("\\{ch}")
                } else {
                    ch.to_string()
                }
            })
            .collect();
        format!("$'{value}'")
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

pub fn unused_name(names: impl IntoIterator<Item = String>) -> String {
    let names: std::collections::HashSet<_> = names.into_iter().collect();
    (0u64..)
        .map(|index| format!("wg{index}"))
        .find(|name| !names.contains(name))
        .unwrap()
}

pub fn list<T: std::str::FromStr>(input: &str) -> Result<Vec<T>> {
    input
        .split(',')
        .map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return Err("list entries must not be empty");
            }
            part.parse().map_err(|_| "invalid address or CIDR in list")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(text: &[&str]) -> Vec<String> {
        text.iter().map(|s| s.to_string()).collect()
    }
    #[test]
    fn syntax_and_defaults() {
        assert_eq!(
            parse(&args(&["up", "--", "-office.toml"])),
            Ok(Command::Up("-office.toml".into()))
        );
        assert_eq!(parse(&args(&["add-peer"])), Ok(Command::AddPeer(None)));
        for bad in [
            &[][..],
            &["up"][..],
            &["status", "extra"][..],
            &["new", "--bogus"][..],
        ] {
            assert!(parse(&args(bad)).is_err());
        }
        assert_eq!(unused_name([]), "wg0");
        assert_eq!(unused_name(args(&["wg0", "wg2", "office"])), "wg1");
        assert_eq!(quoted("my ' config.toml"), "'my '\\'' config.toml'");
        assert_eq!(escaped("a\n\u{1b}"), "a\\n\\u{1b}");
    }
}
