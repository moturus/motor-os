//! Options of the user-facing batteries commands.

use std::path::PathBuf;

pub const USAGE: &str = "usage: gears-batteries hook | tool NAME
       gears-batteries history [--offset N] [--limit N]
       gears-batteries status
Both commands accept --workspace PATH and --root PATH (the Gears directory).";

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    History { offset: usize, limit: usize },
    Status,
}

#[derive(Debug)]
pub struct Options {
    pub command: Command,
    pub workspace: PathBuf,
    pub root: PathBuf,
}

impl Options {
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let role = args.first().map(String::as_str).ok_or(USAGE)?;
        if !matches!(role, "history" | "status") {
            return Err(USAGE.into());
        }
        let mut workspace = None;
        let mut root = None;
        let mut offset = None;
        let mut limit = None;
        let mut rest = args.iter().skip(1);
        while let Some(flag) = rest.next() {
            match (role, flag.as_str()) {
                (_, "--workspace" | "--root") | ("history", "--offset" | "--limit") => {}
                _ => return Err(format!("unknown {role} option: {flag}")),
            }
            let value = rest
                .next()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("{flag} needs a value"))?;
            match flag.as_str() {
                "--workspace" => set(&mut workspace, PathBuf::from(value), flag)?,
                "--root" => set(&mut root, PathBuf::from(value), flag)?,
                "--offset" => set(&mut offset, number(value, flag)?, flag)?,
                _ => set(&mut limit, number(value, flag)?, flag)?,
            }
        }
        let command = if role == "history" {
            let limit = limit.unwrap_or(20);
            if !(1..=100).contains(&limit) {
                return Err("history limit must be 1–100".into());
            }
            Command::History {
                offset: offset.unwrap_or(0),
                limit,
            }
        } else {
            Command::Status
        };
        let current = std::env::current_dir().map_err(|error| error.to_string())?;
        let absolute = |path: PathBuf| {
            if path.is_absolute() {
                path
            } else {
                current.join(path)
            }
        };
        Ok(Self {
            command,
            workspace: absolute(workspace.unwrap_or_else(|| current.clone())),
            root: absolute(
                root.map(Ok)
                    .unwrap_or_else(crate::batteries::default_root)?,
            ),
        })
    }
}

fn set<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("{flag} was repeated"));
    }
    Ok(())
}

fn number(value: &str, flag: &str) -> Result<usize, String> {
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{flag} needs a nonnegative integer"));
    }
    value.parse().map_err(|_| format!("{flag} is out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(values: &[&str]) -> Result<Options, String> {
        Options::parse(
            &values
                .iter()
                .map(|value| (*value).to_string())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn commands_take_their_own_options_once() {
        let options = parse(&[
            "history",
            "--offset",
            "3",
            "--limit",
            "5",
            "--root",
            "/tmp/state",
        ])
        .unwrap();
        assert_eq!(
            options.command,
            Command::History {
                offset: 3,
                limit: 5
            }
        );
        assert_eq!(options.root, PathBuf::from("/tmp/state"));
        assert_eq!(
            parse(&["history"]).unwrap().command,
            Command::History {
                offset: 0,
                limit: 20
            }
        );
        assert_eq!(
            parse(&["status", "--workspace", "/tmp/w"]).unwrap().command,
            Command::Status
        );
        for bad in [
            vec!["pending"],
            vec!["cleanup", "--since", "2026-01-01"],
            vec!["status", "--limit", "5"],
            vec!["history", "--limit", "0"],
            vec!["history", "--limit", "x"],
            vec!["history", "--offset", "1", "--offset", "2"],
            vec!["history", "--root"],
            vec!["history", "--root", ""],
        ] {
            assert!(parse(&bad).is_err(), "{bad:?}");
        }
    }
}
