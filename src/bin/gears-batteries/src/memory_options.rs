//! Explicit user decisions; listing and history options never imply approval.

use std::path::PathBuf;

use crate::pending::Decision;

pub const USAGE: &str = "usage: gears-batteries hook | tool NAME
       gears-batteries pending [--list | --approve ID | --deny ID | --postpone ID]
       gears-batteries history [--offset N] [--limit N]
       gears-batteries status
Memory and skill commands accept --workspace PATH and --root PATH (the Gears directory).";

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Pending {
        list: bool,
        decision: Option<(String, Decision)>,
    },
    History {
        offset: usize,
        limit: usize,
    },
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
        if !matches!(role, "pending" | "history" | "status") {
            return Err(USAGE.into());
        }
        let mut workspace = None;
        let mut root = None;
        let mut list = false;
        let mut decision = None;
        let mut offset = None;
        let mut limit = None;
        let mut rest = args.iter().skip(1);
        while let Some(flag) = rest.next() {
            if role == "pending" && flag == "--list" {
                if list || decision.is_some() {
                    return Err("choose one pending operation".into());
                }
                list = true;
                continue;
            }
            match (role, flag.as_str()) {
                (_, "--workspace" | "--root")
                | ("pending", "--approve" | "--deny" | "--postpone")
                | ("history", "--offset" | "--limit") => {}
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
                "--limit" => set(&mut limit, number(value, flag)?, flag)?,
                _ => {
                    if list || decision.is_some() {
                        return Err("choose one pending operation".into());
                    }
                    if value.len() != 64
                        || !value
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    {
                        return Err("pending id must be a complete lowercase content hash".into());
                    }
                    let choice = match flag.as_str() {
                        "--approve" => Decision::Approve,
                        "--deny" => Decision::Deny,
                        _ => Decision::Postpone,
                    };
                    decision = Some((value.clone(), choice));
                }
            }
        }
        let command = match role {
            "pending" => Command::Pending { list, decision },
            "history" => {
                let limit = limit.unwrap_or(20);
                if !(1..=100).contains(&limit) {
                    return Err("history limit must be 1–100".into());
                }
                Command::History {
                    offset: offset.unwrap_or(0),
                    limit,
                }
            }
            _ => Command::Status,
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
            root: absolute(root.map(Ok).unwrap_or_else(crate::default_root)?),
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
    fn pending_never_defaults_to_approval_and_rejects_ambiguous_options() {
        let root = ["--root", "/tmp/state"];
        let options = parse(&["pending", root[0], root[1]]).unwrap();
        assert_eq!(
            options.command,
            Command::Pending {
                list: false,
                decision: None
            }
        );
        assert_eq!(options.root, PathBuf::from(root[1]));
        let id = "a".repeat(64);
        assert_eq!(
            parse(&["pending", "--approve", &id, root[0], root[1]])
                .unwrap()
                .command,
            Command::Pending {
                list: false,
                decision: Some((id.clone(), Decision::Approve))
            }
        );
        for values in [
            vec!["pending", "--list", "--approve", &id],
            vec!["pending", "--deny", &id, "--postpone", &id],
            vec!["pending", "--approve", "short"],
            vec!["pending", "--list", "--list"],
            vec!["status", "--approve", &id],
            vec!["history", "--limit", "0"],
            vec!["history", "--limit", "101"],
            vec!["history", "--offset", "-1"],
            vec!["history", "--offset", "1", "--offset", "2"],
            vec!["history", "--workspace"],
            vec!["status", "--root", "one", "--root", "two"],
            vec!["status", "unknown"],
        ] {
            assert!(parse(&values).is_err(), "{values:?}");
        }
        let options = parse(&[
            "history",
            "--offset",
            "3",
            "--limit",
            "1",
            "--root",
            "state",
            "--workspace",
            "project",
        ])
        .unwrap();
        assert_eq!(
            options.command,
            Command::History {
                offset: 3,
                limit: 1
            }
        );
        assert_eq!(
            options.workspace,
            std::env::current_dir().unwrap().join("project")
        );
    }
}
