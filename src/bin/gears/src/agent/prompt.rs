//! The system prompt.
//!
//! Identity, where the work is happening, what the tools expect — and then the
//! project's own instructions, read out of `AGENTS.md` or `CLAUDE.md` at the
//! workspace root. That last part is not decoration: gears working on the
//! Motor OS tree has to see the 100–300 loc patch rule and the testing
//! discipline, because those are what "done" means there.

use std::path::Path;

use crate::tools::clamp;

/// Files whose contents are the project's instructions to whoever works on it.
pub const PROJECT_DOCS: [&str; 2] = ["AGENTS.md", "CLAUDE.md"];

/// Cap on one ingested document. A project can write as much as it likes; the
/// context window is still what it is.
const DOC_CAP: usize = 24 * 1024;

const GUIDANCE: &str = "\
How to work here:
* Paths are relative to the workspace root, and nothing outside it is
  reachable. Read a file before you change it.
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

/// Assemble the prompt for a workspace and a set of tools.
pub fn build(workspace: &Path, tools: &[&str]) -> String {
    let mut text = format!(
        "You are gears, a coding agent. You are working on a real checkout on \
         the machine you are running on: the changes you make are real, and so \
         are the commands you run.\n\n\
         Workspace: {}\n\
         Platform: {}\n\
         Tools: {}\n\n{GUIDANCE}",
        workspace.display(),
        platform(),
        match tools.is_empty() {
            true => "none".to_string(),
            false => tools.join(", "),
        }
    );
    for (name, doc) in project_docs(workspace) {
        text.push_str(&format!(
            "\nThe project's own instructions follow, from {name}. Where they \
             say something different from the guidance above, they win.\n\n\
             --- {name} ---\n{doc}\n--- end of {name} ---\n"
        ));
    }
    text
}

/// The project instruction files that exist, in order, read and capped.
pub fn project_docs(workspace: &Path) -> Vec<(&'static str, String)> {
    PROJECT_DOCS
        .iter()
        .filter_map(|name| {
            let text = std::fs::read_to_string(workspace.join(name)).ok()?;
            match text.trim().is_empty() {
                true => None,
                false => Some((*name, clamp(&text, DOC_CAP))),
            }
        })
        .collect()
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
        assert!(prompt.contains("edit_file"), "{prompt}");
        // Nothing to ingest: the prompt is complete without it.
        assert!(!prompt.contains("--- AGENTS.md ---"), "{prompt}");
        std::fs::remove_dir_all(&dir).unwrap();
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

    #[test]
    fn an_enormous_or_empty_document_is_handled() {
        let dir = workspace("big");
        std::fs::write(dir.join("AGENTS.md"), "x".repeat(200_000)).unwrap();
        std::fs::write(dir.join("CLAUDE.md"), "   \n\n").unwrap();

        let docs = project_docs(&dir);
        assert_eq!(docs.len(), 1, "an empty document is not instructions");
        assert_eq!(docs[0].0, "AGENTS.md");
        assert!(docs[0].1.len() < DOC_CAP + 100, "{} bytes", docs[0].1.len());
        assert!(docs[0].1.contains("bytes elided"), "no elision marker");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
