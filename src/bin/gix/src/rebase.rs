//! A rebase that had to stop: `gix rebase --continue`, `--skip` and `--abort`.
//!
//! `operation::Rebase` describes the record. Every step here that writes files records
//! itself first, so that `gix recover` or `gix rebase --abort` can finish it after an
//! interruption. References are published through a copy of the repository handle: the
//! generic committer that a reflog may need must never sign a replayed commit.

use std::{
    error::Error as StdError,
    fmt,
    io::{self, Write},
};

use gix::{
    bstr::{BString, ByteSlice},
    index::entry::Stage,
    merge::tree::Conflict,
};

use crate::{
    cancellation::Cancellation,
    commit, head_ref, merge,
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
    /// The files hold a conflict to throw away. Otherwise the worktree must be clean:
    /// local changes refuse the step before anything is written.
    discard: bool,
    /// The reflog line of HEAD, if it moves.
    reflog: String,
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
        picked(&opened.repo, action, tip)?
    };
    let destination = Destination {
        commit: tip,
        next: Some(stopped.commit),
        shown: stopped.shown,
        discard: false,
        reflog,
    };
    let rebase = (target_ref, rebase);
    let record = pause(opened, &mut guard, None, rebase, destination, cancellation)?;
    drop(guard);
    Err(conflict(&label, record.state == State::Ready))
}

/// `gix rebase --continue`, or `gix rebase --skip` if `skip`.
///
/// Commit the resolved conflict, or leave its commit out, and replay the remaining commits.
/// That ends with the branch at its new tip, or at the next commit that does not apply.
pub fn resume(
    opened: &OpenedRepository,
    skip: bool,
    mut out: impl Write,
    cancellation: &Cancellation,
) -> crate::Result {
    cancellation.check()?;
    let repo = &opened.repo;
    let (mut guard, record) = Guard::acquire_rebase(repo)?;
    if record.state == State::Incomplete {
        return Err(invalid(
            "a step of the rebase was interrupted; run 'gix recover' or 'gix rebase --abort'",
        )
        .into());
    }
    let record = settle(opened, &guard, record, cancellation)?;
    let (rebase, range) = parts(&record)?;
    operation::require_objects(repo, &record, cancellation)?;
    let Some(next) = rebase.next else {
        if skip {
            return Err(invalid("no commit is left to skip; run 'gix rebase --continue'").into());
        }
        return finish(opened, guard, &record, out, cancellation);
    };
    head_ref::require(repo, &record.original)?;
    let todo = replay::todo(repo, &range, cancellation)?.commits;
    let position = todo
        .iter()
        .position(|id| *id == next)
        .ok_or_else(|| invalid("the rebase does not have the commit it stopped at"))?;
    // Where the replay goes on, and whether the files hold a conflict to throw away.
    let (record, start, discard) = match (record.state, skip) {
        (State::Ready, true) => (record, position + 1, true),
        (State::Ready, false) => {
            let after = todo.get(position + 1).copied();
            let paused = commit_resolution(opened, &guard, &record, after, cancellation)?;
            (paused, position + 1, false)
        }
        (_, skip) => (record, position + usize::from(skip), false),
    };

    // A resolution commit has moved the rebase on, so read where it is now.
    let (rebase, _) = parts(&record)?;
    let head = record.target_commit;
    let replayed = replay::run(opened, &todo[start..], head, cancellation)?;
    for dropped in &replayed.dropped {
        let label = replay::label(repo, *dropped)?;
        writeln!(out, "dropping {label} -- patch contents already upstream")?;
    }
    out.flush()?;
    let next = replayed.stopped.as_ref().map(|stopped| stopped.commit);
    let label = next.map(|commit| replay::label(repo, commit)).transpose()?;
    let shown = replayed.stopped.and_then(|stopped| stopped.shown);
    let record = if replayed.tip != head || shown.is_some() || discard {
        let destination = Destination {
            commit: replayed.tip,
            next,
            shown,
            discard,
            reflog: picked(repo, "rebase", replayed.tip)?,
        };
        let rebase = (&record.target_ref, rebase);
        let current = Some(&record);
        pause(
            opened,
            &mut guard,
            current,
            rebase,
            destination,
            cancellation,
        )?
    } else if rebase.next != next {
        // Nothing moves. Only a commit that gix cannot show was skipped.
        let paused = Record {
            kind: Kind::Rebase(Rebase { next, ..rebase }),
            ..record.clone()
        };
        guard.replace_operation(&record, &paused)?;
        paused
    } else {
        record
    };
    match label {
        Some(label) => Err(conflict(&label, record.state == State::Ready)),
        None => finish(opened, guard, &record, out, cancellation),
    }
}

/// Commit the index as the resolution of the commit that stopped the rebase.
///
/// Returns the paused record that follows: HEAD at the new commit, `after` to replay next.
fn commit_resolution(
    opened: &OpenedRepository,
    guard: &Guard,
    ready: &Record,
    after: Option<gix::ObjectId>,
    cancellation: &Cancellation,
) -> crate::Result<Record> {
    let repo = &opened.repo;
    let (rebase, _) = parts(ready)?;
    let commit = rebase
        .next
        .ok_or_else(|| invalid("the stopped rebase names no commit"))?;
    guard.require_ready(repo, ready, cancellation)?;
    let index = guard.index();
    let unresolved = |entry: &gix::index::Entry| entry.stage() != Stage::Unconflicted;
    if index.entries().iter().any(unresolved) {
        return Err(invalid(
            "a conflict is not resolved yet; edit the files and run 'gix add' on them, \
             then 'gix rebase --continue'",
        )
        .into());
    }
    let tree = tree_index::write(repo, index, cancellation)?;
    // The files must hold what was staged, because the next step starts from them.
    drop(transition::prepare(
        opened,
        index,
        &tree,
        &tree,
        cancellation,
    )?);
    let paused = |head: gix::ObjectId| Record {
        state: State::Paused,
        kind: Kind::Rebase(Rebase {
            next: after,
            step: None,
            ..rebase
        }),
        original: Original {
            reference: None,
            id: Some(head),
        },
        target_commit: head,
        result_tree: tree,
        intended_commit: None,
        ..ready.clone()
    };
    let head_tree = repo.find_commit(ready.target_commit)?.tree_id()?.detach();
    if tree == head_tree {
        // The resolution keeps nothing of the commit, so the commit is dropped, as in Git.
        let paused = paused(ready.target_commit);
        guard.replace_operation(ready, &paused)?;
        return Ok(paused);
    }
    let identities = commit::identities(repo)?;
    let new = replay::commit_as(repo, commit, ready.target_commit, tree, &identities)?;
    let reflog = picked(repo, "rebase", new)?.replacen("(pick)", "(continue)", 1);
    let mut publisher = repo.clone();
    head_ref::preflight_publication(&mut publisher)?;
    let publishing = Record {
        state: State::Publishing,
        intended_commit: Some(new),
        ..ready.clone()
    };
    cancellation.check()?;
    guard.replace_operation(ready, &publishing)?;
    let result: crate::Result<Record> = (|| {
        #[cfg(feature = "native-test-support")]
        crate::test_support::checkpoint(crate::test_support::Failure::BeforeResolutionPublished)?;
        let message = reflog.as_bytes().as_bstr();
        head_ref::detach(&mut publisher, &ready.original, new, message, cancellation)?;
        #[cfg(feature = "native-test-support")]
        crate::test_support::checkpoint(crate::test_support::Failure::AfterResolutionPublished)?;
        let paused = paused(new);
        guard.replace_operation(&publishing, &paused)?;
        Ok(paused)
    })();
    result.map_err(|source| {
        let source = cancellation.normalize_error(source);
        let text = "the resolution commit may not be published; run 'gix rebase --continue' again";
        Box::new(Interrupted { text, source }) as Box<dyn StdError + Send + Sync>
    })
}

/// Bring a record to rest that was interrupted while its resolution commit was published.
fn settle(
    opened: &OpenedRepository,
    guard: &Guard,
    record: Record,
    cancellation: &Cancellation,
) -> crate::Result<Record> {
    let (State::Publishing, Some(intended)) = (record.state, record.intended_commit) else {
        return Ok(record);
    };
    let repo = &opened.repo;
    let (rebase, range) = parts(&record)?;
    let head = head_ref::capture(repo)?;
    let settled = if head == record.original {
        // HEAD has not moved, so the staged resolution is still there to commit.
        Record {
            state: State::Ready,
            intended_commit: None,
            ..record.clone()
        }
    } else if head.reference.is_none() && head.id == Some(intended) {
        let todo = replay::todo(repo, &range, cancellation)?.commits;
        let position = todo.iter().position(|id| Some(*id) == rebase.next);
        let position =
            position.ok_or_else(|| invalid("the rebase does not have the commit it stopped at"))?;
        Record {
            state: State::Paused,
            kind: Kind::Rebase(Rebase {
                next: todo.get(position + 1).copied(),
                ..rebase
            }),
            original: head,
            target_commit: intended,
            result_tree: repo.find_commit(intended)?.tree_id()?.detach(),
            intended_commit: None,
            ..record.clone()
        }
    } else {
        return Err(invalid(&format!("unexpected HEAD {head:?} for the rebase")).into());
    };
    guard.replace_operation(&record, &settled)?;
    Ok(settled)
}

/// Move the files, the index and HEAD to `destination`, and leave the rebase stopped there.
///
/// `current` is the record of the rebase, or `None` for its first step.
fn pause(
    opened: &OpenedRepository,
    guard: &mut Guard,
    current: Option<&Record>,
    (target_ref, rebase): (&gix::refs::FullName, Rebase),
    destination: Destination,
    cancellation: &Cancellation,
) -> crate::Result<Record> {
    enum Prepared {
        Clean(transition::Prepared),
        Discard(transition::RestorePrepared),
    }

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
    let prepared = if destination.discard {
        let index = guard.index();
        Prepared::Discard(transition::prepare_restore_to(
            opened,
            index,
            &incomplete,
            result_tree,
            cancellation,
        )?)
    } else {
        Prepared::Clean(transition::prepare(
            opened,
            guard.index(),
            &head_tree,
            &result_tree,
            cancellation,
        )?)
    };
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
    cancellation.check()?;
    match current {
        Some(current) => guard.replace_operation(current, &incomplete)?,
        None => guard.create_operation(&incomplete)?,
    }

    let result: crate::Result<Record> = (|| {
        let mut index = match prepared {
            Prepared::Clean(prepared) => {
                transition::install(opened, guard, &incomplete, prepared, cancellation)?
            }
            Prepared::Discard(prepared) => {
                transition::install_restore(opened, guard, &incomplete, prepared, cancellation)?
            }
        };
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
            let message = destination.reflog.as_bytes().as_bstr();
            let commit = destination.commit;
            head_ref::detach(&mut publisher, &head, commit, message, cancellation)?;
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

/// Move the branch to the commit that HEAD is detached at, and attach HEAD to it again.
///
/// `record` is paused with no commit left. If this is interrupted, the record stays as it
/// is, and `gix rebase --continue` does what is left.
fn finish(
    opened: &OpenedRepository,
    guard: Guard,
    record: &Record,
    mut out: impl Write,
    cancellation: &Cancellation,
) -> crate::Result {
    let repo = &opened.repo;
    let (rebase, _) = parts(record)?;
    let (name, tip) = (&record.target_ref, record.target_commit);
    let attached = Original {
        reference: Some(name.clone()),
        id: Some(tip),
    };
    let head = head_ref::capture(repo)?;
    if head != attached {
        head_ref::require(repo, &record.original)?;
        let mut publisher = repo.clone();
        // An interrupted finish may have moved the branch already.
        if head_ref::require_local_branch(repo, name.as_ref(), Some(tip)).is_err() {
            let message = format!("rebase (finish): {} onto {}", name.as_bstr(), rebase.onto);
            head_ref::move_branch(
                &mut publisher,
                name,
                rebase.original,
                tip,
                message.as_bytes().as_bstr(),
                cancellation,
            )?;
        }
        #[cfg(feature = "native-test-support")]
        crate::test_support::checkpoint(crate::test_support::Failure::BeforeRebaseFinished)?;
        let message = format!("rebase (finish): returning to {}", name.as_bstr());
        let message = message.as_bytes().as_bstr();
        head_ref::attach(&mut publisher, &head, name, tip, message, cancellation)?;
    }
    guard.remove_operation(record)?;
    writeln!(out, "Successfully rebased and updated {}.", name.as_bstr())?;
    out.flush()?;
    Ok(())
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
    let record = settle(opened, &guard, record, cancellation)?;
    let (rebase, _) = parts(&record)?;
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
            let name = &aborting.target_ref;
            let message = format!("rebase (abort): returning to {}", name.as_bstr());
            let message = message.as_bytes().as_bstr();
            let commit = rebase.original;
            head_ref::attach(&mut publisher, &head, name, commit, message, cancellation)?;
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
    let (rebase, _) = parts(&record)?;
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
        let message = b"rebase (recover): finishing an interrupted step".as_bstr();
        let commit = record.target_commit;
        head_ref::detach(&mut publisher, &head, commit, message, cancellation)?;
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
    Ok("the rebase is paused; run 'gix rebase --continue' or 'gix rebase --abort'")
}

/// The rebase that `record` holds, and the commits that define it.
fn parts(record: &Record) -> crate::Result<(Rebase, Range)> {
    let Kind::Rebase(rebase) = record.kind else {
        return Err(invalid("the operation is not a rebase").into());
    };
    let range = Range {
        original: rebase.original,
        onto: rebase.onto,
        base: rebase.base,
    };
    Ok((rebase, range))
}

/// The reflog line for a move of HEAD to the replayed commit `tip`.
fn picked(repo: &gix::Repository, action: &str, tip: gix::ObjectId) -> crate::Result<String> {
    let object = repo.find_commit(tip)?;
    let subject = replay::subject(object.decode()?.message);
    Ok(format!("{action} (pick): {}", subject.to_str_lossy()))
}

/// What the user reads when a commit does not apply.
fn conflict(label: &BString, shown: bool) -> Box<dyn StdError + Send + Sync> {
    let advice = if shown {
        "Resolve the conflict in your files and run 'gix add' on them. Then run one of:\n  \
         gix rebase --continue   go on with the rebase\n  \
         gix rebase --skip       leave this commit out\n  \
         gix rebase --abort      return to your branch as it was"
    } else {
        "Gix cannot show this kind of conflict. The rebase is paused before the commit. \
         Run one of:\n  \
         gix rebase --skip       leave this commit out\n  \
         gix rebase --abort      return to your branch as it was"
    };
    io::Error::other(format!("could not apply {label}\n\n{advice}")).into()
}

fn incomplete_error(source: Box<dyn StdError + Send + Sync>) -> Box<dyn StdError + Send + Sync> {
    let text = "a step of the rebase is incomplete; run 'gix recover' or 'gix rebase --abort'";
    Box::new(Interrupted { text, source })
}

#[derive(Debug)]
struct Interrupted {
    text: &'static str,
    source: Box<dyn StdError + Send + Sync>,
}

impl fmt::Display for Interrupted {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(self.text)
    }
}

impl StdError for Interrupted {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.source.as_ref())
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
