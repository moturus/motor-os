//! `gix branch [-a] [-v]`: list branches in the format of `git branch`.

use std::io::Write;

use gix::{
    bstr::{BStr, ByteSlice},
    prelude::ObjectIdExt,
    refs::{FullNameRef, TargetRef},
    remote::Direction,
};

use crate::cancellation::Cancellation;

#[derive(Clone, Copy, Default)]
pub struct Options {
    /// Also list remote-tracking branches, as `remotes/<name>`.
    pub all: bool,
    /// Add the abbreviated commit ID, the relation to the upstream and the subject.
    pub verbose: bool,
}

struct Row {
    current: bool,
    name: String,
    /// The text after the name: a symbolic target, or the verbose commit details.
    detail: Option<String>,
}

/// List branches without taking the mutation guard: inspection must not
/// create the persistent operation-lock file.
pub fn list(
    repo: &gix::Repository,
    options: Options,
    mut out: impl Write,
    cancellation: &Cancellation,
) -> crate::Result {
    cancellation.check()?;
    let head = repo.head()?;
    let current = head.referent_name().map(ToOwned::to_owned);
    let mut rows = Vec::new();
    if head.is_detached() {
        rows.push(detached_row(repo, &head, options)?);
    }

    let platform = repo.references()?;
    let mut groups = vec![("", platform.local_branches()?)];
    if options.all {
        groups.push(("remotes/", platform.remote_branches()?));
    }
    for (prefix, references) in groups {
        for reference in references {
            cancellation.check()?;
            let reference = reference?;
            let name = reference.name();
            let detail = match reference.target() {
                TargetRef::Symbolic(target) => Some(format!("-> {}", display(target.shorten()))),
                TargetRef::Object(id) if options.verbose => {
                    // Only local branches have an upstream to compare with.
                    let upstream = if prefix.is_empty() {
                        upstream_relation(repo, name, id, cancellation)?
                    } else {
                        String::new()
                    };
                    Some(commit_detail(repo, id, &upstream)?)
                }
                TargetRef::Object(_) => None,
            };
            rows.push(Row {
                current: current
                    .as_ref()
                    .is_some_and(|current| current.as_ref() == name),
                name: format!("{prefix}{}", display(name.shorten())),
                detail,
            });
        }
    }

    let width = rows
        .iter()
        .map(|row| row.name.chars().count())
        .max()
        .unwrap_or(0);
    for row in rows {
        cancellation.check()?;
        let marker = if row.current { '*' } else { ' ' };
        match row.detail {
            Some(detail) if options.verbose => {
                writeln!(out, "{marker} {:<width$} {detail}", row.name)?;
            }
            Some(detail) => writeln!(out, "{marker} {} {detail}", row.name)?,
            None => writeln!(out, "{marker} {}", row.name)?,
        }
    }
    out.flush()?;
    cancellation.check()
}

/// Describe a detached HEAD as Git does, from the last checkout in HEAD's reflog.
fn detached_row(
    repo: &gix::Repository,
    head: &gix::Head<'_>,
    options: Options,
) -> crate::Result<Row> {
    let head_id = head.id().map(gix::Id::detach);
    let mut log = head.log_iter();
    let last_checkout = log.rev()?.and_then(|mut lines| {
        lines.find_map(|line| {
            let line = line.ok()?;
            let moved = line.message.strip_prefix(b"checkout: moving from ")?;
            let target = &moved[moved.find(" to ")? + " to ".len()..];
            Some((target.as_bstr().to_owned(), line.new_oid))
        })
    });
    let name = match last_checkout {
        Some((target, checked_out)) => {
            // Name the ref only while it still points to what was checked out.
            let named = repo
                .try_find_reference(target.as_bstr())
                .ok()
                .flatten()
                .filter(|reference| {
                    let mut reference = reference.clone();
                    reference.peel_to_id().is_ok_and(|id| id == checked_out)
                })
                .map(|reference| {
                    let full = reference.name().as_bstr();
                    let short = full
                        .strip_prefix(b"refs/tags/")
                        .or_else(|| full.strip_prefix(b"refs/remotes/"))
                        .unwrap_or(full);
                    display(short.as_bstr())
                });
            let from =
                named.unwrap_or_else(|| checked_out.attach(repo).shorten_or_id().to_string());
            let relation = if head_id == Some(checked_out) {
                "at"
            } else {
                "from"
            };
            format!("(HEAD detached {relation} {from})")
        }
        None => "(no branch)".into(),
    };
    let detail = match head_id {
        Some(id) if options.verbose => Some(commit_detail(repo, &id, "")?),
        _ => None,
    };
    Ok(Row {
        current: true,
        name,
        detail,
    })
}

/// Format `<short id> [<upstream relation>] <subject>`.
fn commit_detail(repo: &gix::Repository, id: &gix::oid, upstream: &str) -> crate::Result<String> {
    let commit = repo.find_object(id)?.peel_to_commit()?;
    let subject = commit.message()?.summary();
    Ok(format!(
        "{} {upstream}{}",
        commit.short_id()?,
        display(subject.as_ref())
    ))
}

/// Return `[gone] `, `[ahead N] `, `[behind N] `, `[ahead N, behind M] ` or nothing.
fn upstream_relation(
    repo: &gix::Repository,
    branch: &FullNameRef,
    local: &gix::oid,
    cancellation: &Cancellation,
) -> crate::Result<String> {
    // An upstream in this repository (`branch.<name>.remote = .`) has no refspec to map through.
    let is_local = repo
        .branch_remote_name(branch.shorten(), Direction::Fetch)
        .is_some_and(|remote| remote.as_bstr() == ".");
    let upstream = if is_local {
        repo.branch_remote_ref_name(branch, Direction::Fetch)
            .transpose()?
    } else {
        repo.branch_remote_tracking_ref_name(branch, Direction::Fetch)
            .transpose()?
    };
    let Some(upstream) = upstream else {
        return Ok(String::new());
    };
    let Some(mut upstream) = repo.try_find_reference(upstream.as_ref())? else {
        return Ok("[gone] ".into());
    };
    let upstream = upstream.peel_to_id()?.detach();
    let ahead = count_unshared(repo, local, &upstream, cancellation)?;
    let behind = count_unshared(repo, &upstream, local, cancellation)?;
    Ok(match (ahead, behind) {
        (0, 0) => String::new(),
        (ahead, 0) => format!("[ahead {ahead}] "),
        (0, behind) => format!("[behind {behind}] "),
        (ahead, behind) => format!("[ahead {ahead}, behind {behind}] "),
    })
}

/// Count the commits reachable from `tip` but not from `other`.
fn count_unshared(
    repo: &gix::Repository,
    tip: &gix::oid,
    other: &gix::oid,
    cancellation: &Cancellation,
) -> crate::Result<usize> {
    let mut count = 0;
    for commit in repo
        .rev_walk([tip.to_owned()])
        .with_hidden([other.to_owned()])
        .all()?
    {
        cancellation.check()?;
        commit?;
        count += 1;
    }
    Ok(count)
}

/// Names and subjects come from remotes: keep control characters off the terminal.
fn display(text: &BStr) -> String {
    let text = text.to_str_lossy();
    let mut shown = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_control() {
            shown.extend(character.escape_default());
        } else {
            shown.push(character);
        }
    }
    shown
}
