//! The system prompt.
//!
//! Identity, where the work is happening, what the tools expect — and then the
//! project's own instructions, read out of `AGENTS.md` or `CLAUDE.md` at the
//! workspace root. That last part is not decoration: gears working on the
//! Motor OS tree has to see the 100–300 loc patch rule and the testing
//! discipline, because those are what "done" means there.

use std::path::Path;

use crate::tools::instructions;

const GUIDANCE: &str = "\
How to work here:
* Paths are relative to the workspace root, and nothing outside it is
  reachable. Read a file before you change it.
* Before acting on a path below the workspace root, use project_instructions
  to load the nested instructions that apply there.
* Use repository_profile when repository structure or verification commands
  matter. Its commands are candidates only; discovery does not run them.
* Prefer edit_file to write_file: a write replaces the whole file, while an
  edit that does not match tells you so instead of destroying something.
* Long tool results come back with their middle elided. Ask for less rather
  than guessing at what was left out.
* run takes a program and an argument vector. There is no shell, so pipes,
  redirection, globbing and '&&' do nothing; run one program at a time, and
  prefer build and test to invoking the toolchain by hand.
* A command that ends with a non-zero status has run. Read what it printed:
  the compiler's diagnostics are the point of building.
* Changes to files, commands and fetches outside the allowed hosts are put to
  the user for permission. A refusal is an answer, not an error: do something
  else, or say why you need it.
* Say what you did, and say what you did not do. Do not report work as
  finished before it is.
";

/// What is different about being a sub-agent, which is most of what one needs
/// to be told: it starts from nothing but its task, and only its last message
/// is ever read.
const SUB_AGENT: &str = "\
You are a sub-agent. Another gears agent asked for this one piece of work and
is waiting for the answer. You cannot see its conversation and it will see
nothing of yours except your final message, so end by saying what you found or
did, in full and on its own — a summary nobody can ask a follow-up question
about. There is no user to ask one of, either.
";

const READ_ONLY: &str = "\
You have been given only the tools that change nothing. Say what should
change; do not try to change it.
";

const LINUX_CONTRACT: &str = "\
Linux Rust projects build and test with Cargo. Inspect the project's own
instructions before choosing commands or APIs.";

const MOTOR_CONTRACT: &str = "\
Motor OS Rust projects build and test with Lorry, which implements a strict
Cargo subset and is not Cargo. Motor OS is neither Linux nor a Rust Unix-family
target. rush provides a substantially POSIX shell, and selected POSIX APIs are
available through moto-rt and moto-rt-cabi, but compatibility is not complete.
Inspect the project's instructions and documented native APIs; do not assume
either complete POSIX compatibility or no POSIX support.";

/// The platform, as the model should understand it.
const fn platform() -> &'static str {
    #[cfg(target_os = "motor")]
    {
        "Motor OS"
    }
    #[cfg(not(target_os = "motor"))]
    {
        std::env::consts::OS
    }
}

const fn platform_contract() -> &'static str {
    if cfg!(target_os = "motor") {
        MOTOR_CONTRACT
    } else {
        LINUX_CONTRACT
    }
}

/// Assemble the prompt for a workspace and a set of tools.
pub fn build(workspace: &Path, tools: &[&str]) -> String {
    let mut text = format!(
        "You are gears, a coding agent. You are working on a real checkout on \
         the machine you are running on: the changes you make are real, and so \
         are the commands you run.\n\n\
         Workspace: {}\n\
         Platform: {}\n\
         Platform contract:\n{}\n\
         Tools: {}\n\n{GUIDANCE}",
        workspace.display(),
        platform(),
        platform_contract(),
        match tools.is_empty() {
            true => "none".to_string(),
            false => tools.join(", "),
        }
    );
    for document in instructions::load_at(workspace, workspace) {
        let name = document.source;
        let identity = document.identity;
        let doc = document.content;
        text.push_str(&format!(
            "\nThe project's own instructions follow, from {name} (identity \
             {identity}). Where they say something different from the guidance \
             above, they win.\n\n\
             --- {name} ---\n{doc}\n--- end of {name} ---\n"
        ));
    }
    text
}

/// The same prompt, for an agent working for another agent rather than for a
/// person. The project's own instructions still apply — a sub-agent editing
/// this tree is held to the same rules as the one that sent it.
pub fn sub_agent(workspace: &Path, tools: &[&str], read_only: bool) -> String {
    let mut text = build(workspace, tools);
    text.push_str(&format!("\n{SUB_AGENT}"));
    if read_only {
        text.push_str(READ_ONLY);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn workspace(name: &str) -> PathBuf {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "gears-prompt-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_prompt_says_where_the_work_is_and_what_there_is_to_work_with() {
        let dir = workspace("plain");
        let prompt = build(&dir, &["read_file", "write_file"]);
        assert!(prompt.contains(&dir.display().to_string()), "{prompt}");
        assert!(prompt.contains("read_file, write_file"), "{prompt}");
        assert!(prompt.contains(platform()), "{prompt}");
        assert!(prompt.contains(platform_contract()), "{prompt}");
        assert!(prompt.contains("edit_file"), "{prompt}");
        // Nothing to ingest: the prompt is complete without it.
        assert!(!prompt.contains("--- AGENTS.md ---"), "{prompt}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn platform_contracts_do_not_flatten_motor_into_linux_or_unix() {
        assert!(LINUX_CONTRACT.contains("Cargo"), "{LINUX_CONTRACT}");
        assert!(
            MOTOR_CONTRACT.contains("strict\nCargo subset"),
            "{MOTOR_CONTRACT}"
        );
        assert!(
            MOTOR_CONTRACT.contains("neither Linux nor"),
            "{MOTOR_CONTRACT}"
        );
        assert!(MOTOR_CONTRACT.contains("rush"), "{MOTOR_CONTRACT}");
        assert!(MOTOR_CONTRACT.contains("moto-rt-cabi"), "{MOTOR_CONTRACT}");
        assert!(MOTOR_CONTRACT.contains("not complete"), "{MOTOR_CONTRACT}");
    }

    #[test]
    fn project_instructions_are_ingested_and_named() {
        let dir = workspace("docs");
        std::fs::write(dir.join("AGENTS.md"), "Patches are 100-300 loc.\n").unwrap();
        std::fs::write(dir.join("CLAUDE.md"), "Run the full test three times.\n").unwrap();

        let prompt = build(&dir, &["read_file"]);
        assert!(prompt.contains("--- AGENTS.md ---"), "{prompt}");
        assert!(prompt.contains("Patches are 100-300 loc."), "{prompt}");
        assert!(prompt.contains("--- CLAUDE.md ---"), "{prompt}");
        assert!(
            prompt.contains("Run the full test three times."),
            "{prompt}"
        );
        // Order matters: AGENTS.md is the one the tree gears lives in uses.
        assert!(prompt.find("AGENTS.md") < prompt.find("CLAUDE.md"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A sub-agent is told the one thing it cannot work out for itself: that
    /// what it says last is all anybody will read.
    #[test]
    fn a_sub_agent_is_told_what_it_is() {
        let dir = workspace("sub");
        std::fs::write(dir.join("AGENTS.md"), "House rule: be terse.\n").unwrap();

        let prompt = sub_agent(&dir, &["read_file"], false);
        assert!(prompt.contains("You are a sub-agent"), "{prompt}");
        assert!(prompt.contains("final message"), "{prompt}");
        // The project's rules bind it too, and it is not told it is confined
        // when it is not.
        assert!(prompt.contains("House rule: be terse."), "{prompt}");
        assert!(!prompt.contains("change nothing"), "{prompt}");

        let prompt = sub_agent(&dir, &["read_file"], true);
        assert!(
            prompt.contains("only the tools that change nothing"),
            "{prompt}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_enormous_or_empty_document_is_handled() {
        let dir = workspace("big");
        std::fs::write(dir.join("AGENTS.md"), "x".repeat(200_000)).unwrap();
        std::fs::write(dir.join("CLAUDE.md"), "   \n\n").unwrap();

        let docs = instructions::load_at(&dir, &dir);
        assert_eq!(docs.len(), 1, "an empty document is not instructions");
        assert_eq!(docs[0].source, "AGENTS.md");
        assert!(
            docs[0].content.len() < 25 * 1024,
            "{} bytes",
            docs[0].content.len()
        );
        assert!(
            docs[0].content.contains("bytes elided"),
            "no elision marker"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn instruction_symlinks_are_never_ingested() {
        use std::os::unix::fs::symlink;

        let dir = workspace("linked-docs");
        let outside = dir.with_extension("secret");
        std::fs::write(&outside, "outside secret\n").unwrap();
        std::fs::write(dir.join("rules.md"), "inside through a link\n").unwrap();
        symlink(&outside, dir.join("AGENTS.md")).unwrap();
        symlink("rules.md", dir.join("CLAUDE.md")).unwrap();

        let prompt = build(&dir, &[]);
        assert!(!prompt.contains("outside secret"), "{prompt}");
        assert!(!prompt.contains("inside through a link"), "{prompt}");
        assert!(instructions::load_at(&dir, &dir).is_empty());

        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_file(outside).unwrap();
    }
}
