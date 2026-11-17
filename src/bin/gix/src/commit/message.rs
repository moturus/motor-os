use std::{borrow::Cow, io, io::Write, path::Path, process::Command};

use crate::cancellation::Cancellation;

#[cfg(target_os = "motor")]
const EDITOR: &str = "/user/bin/red";
#[cfg(not(target_os = "motor"))]
const EDITOR: &str = "/usr/bin/vim";
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// Called with the mutation guard held, after validating the staged commit.
pub(super) fn prepare<'a>(
    repo: &gix::Repository,
    provided: Option<&'a str>,
    merge: bool,
    cancellation: &Cancellation,
) -> crate::Result<Cow<'a, str>> {
    if let Some(message) = provided {
        return Ok(Cow::Borrowed(message));
    }
    cancellation.check()?;
    let initial = if merge {
        read(&repo.git_dir().join("MERGE_MSG"))?
    } else {
        String::new()
    };
    let path = repo.git_dir().join("COMMIT_EDITMSG");
    // Publish a fresh file so an existing symlink or hard link is never written through.
    let mut file = gix::lock::File::acquire_to_update_resource(
        &path,
        gix::lock::acquire::Fail::Immediately,
        None,
    )?;
    writeln!(file, "{initial}")?;
    writeln!(
        file,
        "# Please enter the commit message. Lines starting with '#' are ignored.\n\
         # An empty message aborts the commit."
    )?;
    file.flush()?;
    file.commit().map_err(|error| error.error)?;

    let status = Command::new(EDITOR)
        .arg(&path)
        .status()
        .map_err(|error| io::Error::new(error.kind(), format!("cannot start {EDITOR}: {error}")))?;
    cancellation.check()?;
    if !status.success() {
        return Err(io::Error::other(format!("{EDITOR} failed: {status}; commit aborted")).into());
    }
    let message = cleanup(&read(&path)?);
    if message.is_empty() {
        return Err(io::Error::other("aborting commit due to empty commit message").into());
    }
    Ok(Cow::Owned(message))
}

fn read(path: &Path) -> crate::Result<String> {
    let file = gix::features::fs::open_options_no_follow()
        .read(true)
        .open(path)?;
    Ok(String::from_utf8(gix::features::fs::read_to_end_bounded(
        &file,
        MAX_MESSAGE_BYTES,
    )?)?)
}

fn cleanup(message: &str) -> String {
    let mut cleaned = String::new();
    let mut blank = false;
    for line in message.lines() {
        if line.starts_with('#') {
            continue;
        }
        let line = line.trim_end_matches([' ', '\t', '\r']);
        if line.is_empty() {
            blank = !cleaned.is_empty();
            continue;
        }
        if blank {
            cleaned.push('\n');
            blank = false;
        }
        cleaned.push_str(line);
        cleaned.push('\n');
    }
    cleaned
}

#[cfg(test)]
mod tests {
    use super::cleanup;

    #[test]
    fn edited_messages_strip_comments_and_extra_whitespace() {
        assert_eq!(cleanup("\n# Instructions\n \t\n"), "");
        assert_eq!(
            cleanup("\nSubject \t\r\n# Comment\n\n\nBody\n\n  indented\n\n"),
            "Subject\n\nBody\n\n  indented\n"
        );
    }
}
