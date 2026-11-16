//! A rebase that had to stop: the steps that write files, and `gix rebase --abort`.
//!
//! `operation::Rebase` describes the record. Every step here records itself before it writes
//! a file, so that `gix recover` or `gix rebase --abort` can finish it after an interruption.
//! References are published through a copy of the repository handle: the generic committer
//! that a reflog may need must never sign a replayed commit.

use std::{error::Error as StdError, fmt, io};

use gix::{bstr::ByteSlice, merge::tree::Conflict};

use crate::{
    cancellation::Cancellation,
    head_ref, merge,
    mutation::{self, Guard},
    operation::{self, Kind, Original, Rebase, Record, State, Step},
    replay::{self, Range, Stopped},
    repository::OpenedRepository,
    transition, tree_index,
};

/// Where a step leads: HEAD detached at `commit`, with `next` to replay from there.
struct Destination {
    commit: gix::ObjectId,
    next: Option<gix::ObjectId>,
    /// The tree and the conflicts of `next` to install, if gix can show them.
    shown: Option<(gix::ObjectId, Vec<Conflict>)>,
}

/// Stop the rebase that `pull` began at the commit that does not apply.
///
/// The files and HEAD move to `tip`, the last replayed commit. The conflict is installed if
/// gix can show it. The error that is returned tells the user how to go on.
pub(crate) fn stop(
    opened: &OpenedRepository,
    mut guard: Guard,
    target_ref: &gix::refs::FullName,
    range: &Range,
    (tip, stopped): (gix::ObjectId, Stopped),
    action: &str,
    cancellation: &Cancellation,
) -> crate::Result {
    let rebase = Rebase {
        original: range.original,
        onto: range.onto,
        base: range.base,
        next: Some(stopped.commit),
        step: None,
    };
    let label = replay::label(&opened.repo, stopped.commit)?;
    let reflog = if tip == range.onto {
        format!("{action} (start): checkout {tip}")
    } else {
        let object = opened.repo.find_commit(tip)?;
        let subject = replay::subject(object.decode()?.message);
        format!("{action} (pick): {}", subject.to_str_lossy())
    };
    let destination = Destination {
        commit: tip,
        next: Some(stopped.commit),
        shown: stopped.shown,
    };
    let rebase = (target_ref, rebase);
    let record = pause(
        opened,
        &mut guard,
        None,
        rebase,
        destination,
        &reflog,
        cancellation,
    )?;
    drop(guard);
    let conflict = if record.state == State::Ready {
        "the conflict is in your files"
    } else {
        "gix cannot show this kind of conflict"
    };
    Err(io::Error::other(format!(
        "could not apply {label}: {conflict}; run 'gix rebase --abort' to return to your branch"
    ))
    .into())
}

/// Move the files, the index and HEAD to `destination`, and leave the rebase stopped there.
///
/// `current` is the record of the rebase, or `None` for its first step. The worktree must
/// be clean: local changes refuse the step before anything is written.
fn pause(
    opened: &OpenedRepository,
    guard: &mut Guard,
    current: Option<&Record>,
    (target_ref, rebase): (&gix::refs::FullName, Rebase),
    destination: Destination,
    reflog: &str,
    cancellation: &Cancellation,
) -> crate::Result<Record> {
    let repo = &opened.repo;
    let head = head_ref::capture(repo)?;
    let head_commit = head
        .id
        .ok_or_else(|| invalid("a rebase needs a commit at HEAD"))?;
    let head_tree = repo.find_commit(head_commit)?.tree_id()?.detach();
    let commit_tree = repo.find_commit(destination.commit)?.tree_id()?.detach();
    let result_tree = match &destination.shown {
        Some((tree, _)) => *tree,
        None => commit_tree,
    };
    let prepared = transition::prepare(
        opened,
        guard.index(),
        &head_tree,
        &result_tree,
        cancellation,
    )?;
    if let Some((tree, conflicts)) = &destination.shown {
        // The index with the conflict stages must stay within the size that gix reads back.
        let workdir = repo
            .workdir()
            .ok_or_else(|| invalid("a rebase needs a worktree"))?;
        let mut index = tree_index::build(repo, tree, workdir, cancellation)?;
        merge::apply_conflicts(&mut index, conflicts)?;
        mutation::preflight_index(index)?;
    }
    let mut publisher = repo.clone();
    head_ref::preflight_publication(&mut publisher)?;
    head_ref::require(repo, &head)?;

    let step = |next_step| Rebase {
        next: destination.next,
        step: next_step,
        ..rebase
    };
    let incomplete = Record {
        state: State::Incomplete,
        kind: Kind::Rebase(step(Some(Step::Pause))),
        original: head.clone(),
        target_ref: target_ref.clone(),
        target_commit: destination.commit,
        result_tree,
        intended_commit: None,
    };
    cancellation.check()?;
    match current {
        Some(current) => guard.replace_operation(current, &incomplete)?,
        None => guard.create_operation(&incomplete)?,
    }
    let result: crate::Result<Record> = (|| {
        let mut index = transition::install(opened, guard, &incomplete, prepared, cancellation)?;
        if let Some((_, conflicts)) = &destination.shown
            && !merge::apply_conflicts(&mut index, conflicts)?
        {
            return Err(invalid("the conflict to show has no unresolved path").into());
        }
        guard.publish_fresh_index(index)?;
        guard.require_operation(&incomplete)?;
        let detached = Original {
            reference: None,
            id: Some(destination.commit),
        };
        if head != detached {
            let message = reflog.as_bytes().as_bstr();
            head_ref::detach(
                &mut publisher,
                &head,
                destination.commit,
                message,
                cancellation,
            )?;
        }
        #[cfg(feature = "native-test-support")]
        crate::test_support::checkpoint(crate::test_support::Failure::BeforeRebaseStopped)?;
        let stopped = Record {
            state: match destination.shown {
                Some(_) => State::Ready,
                None => State::Paused,
            },
            kind: Kind::Rebase(step(None)),
            original: detached,
            ..incomplete.clone()
        };
        guard.replace_operation(&incomplete, &stopped)?;
        Ok(stopped)
    })();
    result.map_err(|source| incomplete_error(cancellation.normalize_error(source)))
}

/// `gix rebase --abort`: return the files, the index and HEAD to the branch as it was.
pub fn abort(opened: &OpenedRepository, cancellation: &Cancellation) -> crate::Result {
    cancellation.check()?;
    let (guard, record) = Guard::acquire_rebase(&opened.repo)?;
    finish_abort(opened, guard, record, cancellation)
}

/// Abort the rebase of `record`, in whatever state it is, or finish an interrupted abort.
fn finish_abort(
    opened: &OpenedRepository,
    mut guard: Guard,
    record: Record,
    cancellation: &Cancellation,
) -> crate::Result {
    let repo = &opened.repo;
    let Kind::Rebase(rebase) = record.kind else {
        return Err(invalid("the operation is not a rebase").into());
    };
    if record.state == State::Publishing {
        return Err(invalid("a commit of the rebase is being published").into());
    }
    operation::require_objects(repo, &record, cancellation)?;
    // Only HEAD has moved since the rebase began. The branch is where it was.
    let branch = Original {
        reference: Some(record.target_ref.clone()),
        id: Some(rebase.original),
    };
    head_ref::require_local_branch(repo, record.target_ref.as_ref(), branch.id)?;
    let head = head_ref::capture(repo)?;
    if head != branch && head.reference.is_some() {
        return Err(invalid("HEAD is on a branch that the rebase did not start from").into());
    }
    // The result tree stays: with the index it names the paths that may have changed.
    let aborting = Record {
        state: State::Incomplete,
        kind: Kind::Rebase(Rebase {
            step: Some(Step::Abort),
            ..rebase
        }),
        original: head.clone(),
        target_commit: rebase.original,
        intended_commit: None,
        ..record.clone()
    };
    let original_tree = repo.find_commit(rebase.original)?.tree_id()?.detach();
    let prepared = transition::prepare_restore_to(
        opened,
        guard.index(),
        &aborting,
        original_tree,
        cancellation,
    )?;
    let mut publisher = repo.clone();
    head_ref::preflight_publication(&mut publisher)?;
    cancellation.check()?;
    guard.replace_operation(&record, &aborting)?;

    let result: crate::Result = (|| {
        let index = transition::install_restore(opened, &guard, &aborting, prepared, cancellation)?;
        guard.publish_fresh_index(index)?;
        #[cfg(feature = "native-test-support")]
        crate::test_support::checkpoint(crate::test_support::Failure::BeforeRebaseAborted)?;
        if head != branch {
            let message = format!(
                "rebase (abort): returning to {}",
                aborting.target_ref.as_bstr()
            );
            head_ref::attach(
                &mut publisher,
                &head,
                &aborting.target_ref,
                rebase.original,
                message.as_bytes().as_bstr(),
                cancellation,
            )?;
        }
        guard.remove_operation(&aborting)
    })();
    result.map_err(|source| incomplete_error(cancellation.normalize_error(source)))
}

/// Finish the interrupted step of a rebase, as `gix recover` does.
///
/// An abort is finished. Any other step ends at the commit it was moving to, with a clean
/// worktree and the rebase paused: recovery never has to know where the step began.
pub(crate) fn recover(
    opened: &OpenedRepository,
    mut guard: Guard,
    record: Record,
    cancellation: &Cancellation,
) -> crate::Result<&'static str> {
    let repo = &opened.repo;
    let Kind::Rebase(rebase) = record.kind else {
        return Err(invalid("the operation is not a rebase").into());
    };
    if rebase.step == Some(Step::Abort) {
        finish_abort(opened, guard, record, cancellation)?;
        return Ok("finished the abort of the rebase");
    }
    let detached = Original {
        reference: None,
        id: Some(record.target_commit),
    };
    let head = head_ref::capture(repo)?;
    if head != record.original && head != detached {
        return Err(invalid(&format!(
            "cannot recover the rebase: unexpected HEAD {head:?}"
        ))
        .into());
    }
    let tree = repo.find_commit(record.target_commit)?.tree_id()?.detach();
    let prepared =
        transition::prepare_restore_to(opened, guard.index(), &record, tree, cancellation)?;
    let mut publisher = repo.clone();
    head_ref::preflight_publication(&mut publisher)?;
    let index = transition::install_restore(opened, &guard, &record, prepared, cancellation)?;
    guard.publish_fresh_index(index)?;
    if head != detached {
        head_ref::detach(
            &mut publisher,
            &head,
            record.target_commit,
            b"rebase (recover): continuing an interrupted step".as_bstr(),
            cancellation,
        )?;
    }
    let paused = Record {
        state: State::Paused,
        kind: Kind::Rebase(Rebase {
            step: None,
            ..rebase
        }),
        original: detached,
        result_tree: tree,
        ..record.clone()
    };
    guard.replace_operation(&record, &paused)?;
    Ok("the rebase is paused; run 'gix rebase --abort' to return to your branch")
}

fn incomplete_error(source: Box<dyn StdError + Send + Sync>) -> Box<dyn StdError + Send + Sync> {
    Box::new(Incomplete { source })
}

#[derive(Debug)]
struct Incomplete {
    source: Box<dyn StdError + Send + Sync>,
}

impl fmt::Display for Incomplete {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(
            "a step of the rebase is incomplete; run 'gix recover' or 'gix rebase --abort'",
        )
    }
}

impl StdError for Incomplete {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.source.as_ref())
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
