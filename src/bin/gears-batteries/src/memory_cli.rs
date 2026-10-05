//! Review exactly the content displayed; closed input postpones each item.

use std::io::{BufRead, Write};

use serde_json::{Value, json};

use crate::memory_format::Target;
use crate::memory_options::{Command, Options};
use crate::paths::ToolContext;
use crate::pending::{Decision, Proposal};

enum Item {
    Entry(String, Box<Proposal>),
    Workspace(String, String),
    Skill(String, Box<crate::skill_pending::Proposal>),
    ImportedSkill(String, String, Box<crate::skill_format::Content>),
    Unavailable(String, String),
}

impl Item {
    fn id(&self) -> &str {
        match self {
            Self::Entry(id, _)
            | Self::Workspace(id, _)
            | Self::Skill(id, _)
            | Self::ImportedSkill(id, _, _)
            | Self::Unavailable(id, _) => id,
        }
    }

    fn show(&self, context: &ToolContext) -> Value {
        match self {
            Self::Entry(id, proposal) => {
                let evidence = crate::memory_sources::describe(context, proposal)
                    .unwrap_or_else(|error| json!({"unavailable": error}));
                json!({"version": 1, "id": id, "kind": "entry", "change": proposal, "sources": evidence})
            }
            Self::Skill(id, proposal) => {
                let sources = crate::skill_sources::describe(context, proposal)
                    .unwrap_or_else(|error| json!({"unavailable": error}));
                json!({"version": 1, "id": id, "kind": "skill", "change": proposal, "sources": sources})
            }
            Self::ImportedSkill(id, name, content) => {
                json!({"version": 1, "id": id, "kind": "skill_import", "name": name, "content": content})
            }
            Self::Unavailable(name, error) => json!({"skill": name, "unavailable": error}),
            Self::Workspace(id, text) => json!({"version": 1, "id": id, "kind": "workspace_memory",
                "path": ".gears/MEMORY.md", "memory": text}),
        }
    }

    fn decide(&self, context: &ToolContext, decision: Decision) -> Result<(), String> {
        match self {
            Self::Entry(id, proposal) => {
                crate::memory::decide(context, proposal.target, id, decision)
            }
            Self::Skill(id, _) => crate::skill_pending::decide(context, id, decision),
            Self::ImportedSkill(hash, name, _) => {
                crate::skill_store::admit(context, name, hash, decision)
            }
            Self::Unavailable(_, _) => Err("unavailable skill cannot be admitted".into()),
            Self::Workspace(hash, _) => crate::workspace_memory::decide(context, hash, decision),
        }
    }
}

fn items(context: &ToolContext) -> Result<Vec<Item>, String> {
    let mut items = Vec::new();
    if let Some((hash, text)) = crate::workspace_memory::current(context)?
        && !crate::workspace_memory::approved(context, &hash)?
    {
        items.push(Item::Workspace(hash, text));
    }
    for target in [Target::Global, Target::Workspace] {
        items.extend(
            crate::pending::list(context, target)?
                .into_iter()
                .map(|(id, proposal)| Item::Entry(id, Box::new(proposal))),
        );
    }
    items.extend(
        crate::skill_pending::list(context)?
            .into_iter()
            .map(|(id, proposal)| Item::Skill(id, Box::new(proposal))),
    );
    for name in crate::skill_store::names(context)? {
        let candidate = (|| {
            let Some(content) = crate::skill_store::current(context, &name)? else {
                return Ok(None);
            };
            crate::skill_store::parse(context, &name, &content)?;
            let hash = content.hash();
            Ok((!crate::skill_store::approved(context, &name, &hash)?).then_some((hash, content)))
        })();
        match candidate {
            Ok(Some((hash, content))) => {
                items.push(Item::ImportedSkill(hash, name, Box::new(content)))
            }
            Ok(None) => {}
            Err(error) => items.push(Item::Unavailable(name, error)),
        }
    }
    Ok(items)
}

pub fn run(args: &[String], mut input: impl BufRead, mut output: impl Write) -> Result<(), String> {
    let options = Options::parse(args)?;
    let context = ToolContext::new(options.workspace, options.root, "cli".into(), None)?;
    match options.command {
        Command::History { offset, limit } => write_json(
            &mut output,
            &crate::memory_history::history(&context, offset, limit)?,
        ),
        Command::Status => write_json(&mut output, &crate::memory_history::status(&context)),
        Command::Pending { list, decision } => {
            let items = items(&context)?;
            if let Some((id, decision)) = decision {
                let mut matches = items.iter().filter(|item| item.id() == id);
                let item = matches.next().ok_or(
                    "pending id is unavailable in the selected workspace and Gears directory",
                )?;
                if matches.next().is_some() {
                    return Err("pending id is ambiguous across scopes".into());
                }
                write_json(&mut output, &item.show(&context))?;
                // A broken output pipe must not cause an unseen approval.
                output.flush().map_err(|error| error.to_string())?;
                item.decide(&context, decision)?;
                return write_json(&mut output, &json!({"id": id, "decision": decision}));
            }
            let count = items.len();
            for item in items {
                write_json(&mut output, &item.show(&context))?;
                if !list && !matches!(item, Item::Unavailable(_, _)) {
                    write!(output, "{} [approve/deny/postpone]: ", item.id())
                        .map_err(|error| error.to_string())?;
                    output.flush().map_err(|error| error.to_string())?;
                    let decision = read_decision(&mut input)?;
                    item.decide(&context, decision)?;
                    write_json(&mut output, &json!({"id": item.id(), "decision": decision}))?;
                }
            }
            write_json(&mut output, &json!({"displayed": count, "list_only": list}))
        }
    }
}

fn write_json(output: &mut impl Write, value: &Value) -> Result<(), String> {
    serde_json::to_writer_pretty(&mut *output, value).map_err(|error| error.to_string())?;
    output.write_all(b"\n").map_err(|error| error.to_string())
}

fn read_decision(input: &mut impl BufRead) -> Result<Decision, String> {
    let mut bytes = Vec::new();
    std::io::Read::take(input, 1025)
        .read_until(b'\n', &mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 1024 {
        return Err("memory decision exceeds 1024 bytes; item remains pending".into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "memory decision is not UTF-8")?;
    match text.trim() {
        "approve" => Ok(Decision::Approve),
        "deny" => Ok(Decision::Deny),
        "" | "postpone" => Ok(Decision::Postpone),
        _ => Err("expected approve, deny or postpone; item remains pending".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_input_postpones_and_invalid_answers_never_grant_authority() {
        assert_eq!(
            read_decision(&mut b"".as_slice()).unwrap(),
            Decision::Postpone
        );
        assert_eq!(
            read_decision(&mut b"\n".as_slice()).unwrap(),
            Decision::Postpone
        );
        let mut input = b"approve\ndeny\npostpone\n".as_slice();
        for expected in [Decision::Approve, Decision::Deny, Decision::Postpone] {
            assert_eq!(read_decision(&mut input).unwrap(), expected);
        }
        for input in [
            b"yes\n".as_slice(),
            b"approve deny\n",
            b"\xff\n",
            &[b'a'; 1025],
        ] {
            assert!(read_decision(&mut &*input).is_err());
        }
    }

    #[test]
    fn decisions_are_not_written_when_the_display_cannot_be_delivered() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "closed display",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let path =
            std::env::temp_dir().join(format!("batteries-memory-cli-{}", std::process::id()));
        std::fs::create_dir_all(path.join("workspace")).unwrap();
        let context = ToolContext::new(
            path.join("workspace"),
            path.join("state"),
            "cli".into(),
            None,
        )
        .unwrap();
        let proposal: Proposal = serde_json::from_value(json!({"version": 1, "target": "user",
            "before": null, "after": {"metadata": {"id": "preference", "kind": "user", "scope": "global",
            "source": {"session": "source", "entries": ["entry"]}, "date_ms": 1}, "text": "Prefer Rust."},
            "source": {"session": "source", "entries": ["entry"]}, "date_ms": 2})).unwrap();
        let id = crate::memory::propose(&context, &proposal)
            .unwrap()
            .unwrap();
        let args = vec![
            "pending".into(),
            "--approve".into(),
            id.clone(),
            "--workspace".into(),
            context.workspace.to_str().unwrap().into(),
            "--root".into(),
            context.state.path().to_str().unwrap().into(),
        ];
        assert!(
            run(&args, b"".as_slice(), Broken)
                .unwrap_err()
                .contains("closed display")
        );
        assert!(crate::pending::load(&context, Target::User, &id).is_ok());
        assert_eq!(
            crate::memory_history::history(&context, 0, 20).unwrap()["total"],
            0
        );
        std::fs::remove_dir_all(path).unwrap();
    }
}
