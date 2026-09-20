//! `gix checkout <branch>` and `gix checkout [--track] -b <new> [<start>]`.

use std::io::{self, Write};

use gix::{
    bstr::{BStr, BString, ByteSlice},
    refs::Category,
};

use crate::{
    branches::{self, UpstreamState},
    cancellation::Cancellation,
    head_ref,
    mutation::Guard,
    operation::Original,
    refs::{self, Kind},
    repository::OpenedRepository,
    switch,
};

/// The branch a new branch will follow: `branch.<name>.remote` and `branch.<name>.merge`.
struct Upstream {
    /// A configured remote, or `.` for a branch of this repository.
    remote: BString,
    merge: gix::refs::FullName,
    /// The name Git reports, such as `origin/main`.
    shown: String,
}

/// Check out an existing local branch under the rules of `gix switch`.
pub fn existing(
    opened: &mut OpenedRepository,
    branch: &str,
    mut out: impl Write,
    cancellation: &Cancellation,
) -> crate::Result {
    cancellation.check()?;
    let target = refs::qualified_name(Kind::Branch, branch)?;
    let original = head_ref::capture(&opened.repo)?;
    if let (Some(id), true) = (original.id, original.reference.as_ref() == Some(&target)) {
        eprintln!("Already on '{branch}'");
        return report_upstream(&opened.repo, &target, &id, &mut out, cancellation);
    }
    let guard = Guard::acquire(&opened.repo)?;
    let original = head_ref::capture(&opened.repo)?;
    let (target, commit) = head_ref::existing_local_branch(&opened.repo, branch)?;
    let prepared = switch::prepare(opened, &guard, &original, commit, cancellation)?;
    let message = moving_message(&original, branch);
    switch::finish(
        opened,
        guard,
        original,
        (target, commit),
        Some(prepared),
        &message,
        cancellation,
    )?;
    eprintln!("Switched to branch '{branch}'");
    let target = refs::qualified_name(Kind::Branch, branch)?;
    report_upstream(&opened.repo, &target, &commit, &mut out, cancellation)
}

/// Print Git's sentence about the upstream, without its hints about Git commands.
fn report_upstream(
    repo: &gix::Repository,
    branch: &gix::refs::FullName,
    local: &gix::oid,
    mut out: impl Write,
    cancellation: &Cancellation,
) -> crate::Result {
    let commits = |count: usize| if count == 1 { "commit" } else { "commits" };
    match branches::upstream_state(repo, branch.as_ref(), local, cancellation)? {
        None => {}
        Some(UpstreamState::Gone { name }) => {
            writeln!(
                out,
                "Your branch is based on '{name}', but the upstream is gone."
            )?;
        }
        Some(UpstreamState::Present {
            name,
            ahead: 0,
            behind: 0,
        }) => {
            writeln!(out, "Your branch is up to date with '{name}'.")?;
        }
        Some(UpstreamState::Present {
            name,
            ahead,
            behind: 0,
        }) => {
            writeln!(
                out,
                "Your branch is ahead of '{name}' by {ahead} {}.",
                commits(ahead)
            )?;
        }
        Some(UpstreamState::Present {
            name,
            ahead: 0,
            behind,
        }) => writeln!(
            out,
            "Your branch is behind '{name}' by {behind} {}, and can be fast-forwarded.",
            commits(behind)
        )?,
        // At least two commits are involved here, so Git's text is always plural.
        Some(UpstreamState::Present {
            name,
            ahead,
            behind,
        }) => writeln!(
            out,
            "Your branch and '{name}' have diverged,\nand have {ahead} and {behind} different commits each, respectively."
        )?,
    }
    out.flush()?;
    Ok(())
}

/// Create `branch` at `start` (HEAD by default) and check it out.
///
/// A remote-tracking start point becomes the upstream, as with Git's default
/// `branch.autoSetupMerge`; `track` also accepts a local branch and then requires one.
pub fn create(
    opened: &mut OpenedRepository,
    branch: &str,
    start: Option<&str>,
    track: bool,
    mut out: impl Write,
    cancellation: &Cancellation,
) -> crate::Result {
    cancellation.check()?;
    let target = refs::qualified_name(Kind::Branch, branch)?;
    let guard = Guard::acquire(&opened.repo)?;
    let original = head_ref::capture(&opened.repo)?;
    let repo = &opened.repo;
    if repo.try_find_reference(target.as_ref())?.is_some() {
        return Err(invalid(format!("a branch named '{branch}' already exists")).into());
    }
    let start_text = start.unwrap_or("HEAD");
    let commit = repo
        .rev_parse_single(start_text.as_bytes().as_bstr())?
        .object()?
        .peel_to_commit()?
        .id;
    let upstream = upstream(repo, start, &original, track)?;
    cancellation.check()?;

    // A branch at HEAD's own commit changes no file, so it keeps staged and local changes
    // as Git does. Any other start point needs the clean worktree `gix switch` requires.
    let prepared = if original.id == Some(commit) {
        head_ref::preflight_publication(&mut opened.repo)?;
        None
    } else {
        Some(switch::prepare(
            opened,
            &guard,
            &original,
            commit,
            cancellation,
        )?)
    };
    head_ref::require(&opened.repo, &original)?;
    // Stage the configuration first: a held or unwritable file must create nothing.
    let staged = match &upstream {
        Some(upstream) => Some(stage_upstream(&opened.repo, branch, upstream)?),
        None => None,
    };
    cancellation.check()?;

    // The branch and its upstream exist from here on, whatever happens to the checkout.
    opened.repo.reference(
        target.clone(),
        commit,
        gix::refs::transaction::PreviousValue::MustNotExist,
        format!("branch: Created from {start_text}"),
    )?;
    if let (Some(staged), Some(upstream)) = (staged, &upstream) {
        staged.commit().map_err(|error| error.error)?;
        writeln!(
            out,
            "branch '{branch}' set up to track '{}'.",
            upstream.shown
        )?;
        out.flush()?;
    }
    let message = moving_message(&original, branch);
    switch::finish(
        opened,
        guard,
        original,
        (target, commit),
        prepared,
        &message,
        cancellation,
    )?;
    eprintln!("Switched to a new branch '{branch}'");
    Ok(())
}

/// Decide what the new branch follows, before anything is created.
fn upstream(
    repo: &gix::Repository,
    start: Option<&str>,
    original: &Original,
    track: bool,
) -> crate::Result<Option<Upstream>> {
    // Without a start point, `--track` follows the current branch.
    let start_ref = match start {
        Some(start) => repo
            .try_find_reference(start)
            .ok()
            .flatten()
            .map(|reference| reference.name().to_owned()),
        None => original.reference.clone().filter(|_| track),
    };
    let not_a_branch = || {
        invalid(format!(
            "cannot set up tracking information; starting point '{}' is not a branch",
            start.unwrap_or("HEAD")
        ))
    };
    let Some(start_ref) = start_ref else {
        return if track {
            Err(not_a_branch().into())
        } else {
            Ok(None)
        };
    };
    match start_ref.as_ref().category() {
        Some(Category::RemoteBranch) => {
            let shown = start_ref.shorten().to_str_lossy().into_owned();
            match repo.upstream_branch_and_remote_for_tracking_branch(start_ref.as_ref()) {
                Ok(Some((merge, remote))) => Ok(remote.name().map(|name| Upstream {
                    remote: name.as_bstr().to_owned(),
                    merge,
                    shown,
                })),
                // No single remote fetches into this ref. Git only objects when asked to track.
                Ok(None) | Err(_) if !track => Ok(None),
                Ok(None) => Err(invalid(format!(
                    "cannot set up tracking information; no remote fetches into '{shown}'"
                ))
                .into()),
                Err(error) => Err(error.into()),
            }
        }
        Some(Category::LocalBranch) if track => Ok(Some(Upstream {
            remote: ".".into(),
            shown: start_ref.shorten().to_str_lossy().into_owned(),
            merge: start_ref,
        })),
        Some(Category::LocalBranch) => Ok(None),
        _ if track => Err(not_a_branch().into()),
        _ => Ok(None),
    }
}

/// Stage the repository's own configuration file with a new `[branch "<name>"]` section.
/// Committing the returned lock publishes it; dropping the lock discards it.
///
/// The file is parsed on its own: the opened repository's configuration has policy edits
/// and command-line values that must never reach the disk.
fn stage_upstream(
    repo: &gix::Repository,
    branch: &str,
    upstream: &Upstream,
) -> crate::Result<gix::lock::File> {
    let path = repo.git_dir().join("config");
    let mut lock = gix::lock::File::acquire_to_update_resource(
        &path,
        gix::lock::acquire::Fail::Immediately,
        None,
    )?;
    let mut config = gix::config::File::from_path_no_includes(path, gix::config::Source::Local)?;
    let section_name: &BStr = branch.into();
    while config.remove_section("branch", section_name).is_some() {}
    let mut section = config.new_section("branch", BString::from(branch))?;
    section.push("remote", upstream.remote.as_bstr())?;
    section.push("merge", upstream.merge.as_bstr())?;
    config.write_to(&mut lock)?;
    lock.flush()?;
    Ok(lock)
}

/// Git's HEAD reflog text, which `gix branch` reads back to describe a detached HEAD.
fn moving_message(original: &Original, branch: &str) -> String {
    let from = match (&original.reference, original.id) {
        (Some(reference), _) => reference.shorten().to_str_lossy().into_owned(),
        (None, Some(id)) => id.to_string(),
        (None, None) => "HEAD".into(),
    };
    format!("checkout: moving from {from} to {branch}")
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
