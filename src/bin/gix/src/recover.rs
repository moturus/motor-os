use std::io;

use crate::{
    cancellation::Cancellation,
    head_ref,
    mutation::Guard,
    operation::{self, Kind, Original, Record, State},
    repository::OpenedRepository,
    transition,
};

/// Repair a recorded operation without replaying an already published ref update.
pub fn run(opened: &OpenedRepository, cancellation: &Cancellation) -> crate::Result<&'static str> {
    cancellation.check()?;
    let repo = &opened.repo;
    let (mut guard, record) = Guard::acquire_for_recovery(repo)?;
    operation::require_objects(repo, &record, cancellation)?;
    require_switch_branches(repo, &record)?;
    let observed = head_ref::capture(repo)?;
    let published = Original {
        reference: Some(record.target_ref.clone()),
        id: Some(record.intended_commit.unwrap_or(record.target_commit)),
    };

    match record.state {
        State::Incomplete
            if matches!(record.kind, Kind::Switch | Kind::FastForward) && observed == published =>
        {
            transition::require_result_index(
                repo,
                guard.index(),
                &record.result_tree,
                cancellation,
            )?;
            require_refs(repo, &record, &published)?;
            guard.cleanup_operation(&record, cancellation)?;
            Ok("preserved published update and finished cleanup")
        }
        State::Incomplete if observed == record.original => {
            let prepared =
                transition::prepare_restore(opened, guard.index(), &record, cancellation)?;
            require_refs(repo, &record, &record.original)?;
            let index =
                transition::install_restore(opened, &guard, &record, prepared, cancellation)?;
            guard.publish_fresh_index(index)?;
            require_refs(repo, &record, &record.original)?;
            guard.cleanup_operation(&record, cancellation)?;
            Ok("restored recorded original state")
        }
        State::Publishing if observed == published => {
            require_refs(repo, &record, &published)?;
            guard.cleanup_operation(&record, cancellation)?;
            Ok("preserved published merge commit and finished cleanup")
        }
        State::Publishing if observed == record.original => {
            guard.require_merge_head(&record)?;
            require_refs(repo, &record, &record.original)?;
            cancellation.check()?;
            let mut ready = record.clone();
            ready.state = State::Ready;
            ready.intended_commit = None;
            guard.replace_operation(&record, &ready)?;
            Ok("merge commit did not publish; merge is ready to commit or abort")
        }
        _ => Err(invalid(format!(
            "cannot recover {}: unexpected HEAD {:?}; recorded original is {:?}",
            record.description(),
            observed,
            record.original
        ))
        .into()),
    }
}

fn require_refs(repo: &gix::Repository, record: &Record, expected: &Original) -> crate::Result {
    head_ref::require(repo, expected)?;
    require_switch_branches(repo, record)
}

fn require_switch_branches(repo: &gix::Repository, record: &Record) -> crate::Result {
    if record.kind == Kind::Switch {
        head_ref::require_local_branch(
            repo,
            record.target_ref.as_ref(),
            Some(record.target_commit),
        )?;
        if let Some(original) = &record.original.reference
            && original != &record.target_ref
        {
            head_ref::require_local_branch(repo, original.as_ref(), record.original.id)?;
        }
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
