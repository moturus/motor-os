use std::{error::Error as StdError, fmt};

use gix::bstr::ByteSlice;

use crate::{
    cancellation::Cancellation,
    head_ref,
    mutation::Guard,
    operation::{Kind, Record, State},
    repository::OpenedRepository,
    transition,
};

/// Switch a clean worktree to an existing local branch.
pub fn run(
    opened: &mut OpenedRepository,
    branch: &str,
    cancellation: &Cancellation,
) -> crate::Result {
    cancellation.check()?;
    let mut guard = Guard::acquire(&opened.repo)?;
    let original = head_ref::capture(&opened.repo)?;
    let (target_ref, target_commit) = head_ref::existing_local_branch(&opened.repo, branch)?;
    let original_tree = match original.id {
        Some(id) => opened.repo.find_commit(id)?.tree_id()?.detach(),
        None => gix::ObjectId::empty_tree(opened.repo.object_hash()),
    };
    let target_tree = opened.repo.find_commit(target_commit)?.tree_id()?.detach();
    head_ref::preflight_publication(&mut opened.repo)?;
    let prepared = transition::prepare(
        opened,
        guard.index(),
        &original_tree,
        &target_tree,
        cancellation,
    )?;
    head_ref::require(&opened.repo, &original)?;
    head_ref::require_local_branch(&opened.repo, target_ref.as_ref(), Some(target_commit))?;
    cancellation.check()?;
    if original.reference.as_ref() == Some(&target_ref) && original.id == Some(target_commit) {
        return Ok(());
    }

    let record = Record {
        state: State::Incomplete,
        kind: Kind::Switch,
        original,
        target_ref: target_ref.clone(),
        target_commit,
        result_tree: target_tree,
        intended_commit: None,
    };
    guard.create_operation(&record)?;

    let result: crate::Result = (|| {
        let index = transition::install(opened, &guard, &record, prepared, cancellation)?;
        guard.publish_fresh_index(index)?;
        let message = format!("switch: {branch}");
        head_ref::attach(
            &mut opened.repo,
            &record.original,
            &target_ref,
            target_commit,
            message.as_bytes().as_bstr(),
            cancellation,
        )?;
        guard.remove_operation(&record)
    })();
    result.map_err(|source| Box::new(Incomplete { source }) as Box<dyn StdError + Send + Sync>)
}

#[derive(Debug)]
struct Incomplete {
    source: Box<dyn StdError + Send + Sync>,
}

impl fmt::Display for Incomplete {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("switch is incomplete; run 'gix recover' to repair it")
    }
}

impl StdError for Incomplete {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.source.as_ref())
    }
}
