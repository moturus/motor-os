use std::io;

use gix::bstr::ByteSlice;

use crate::{
    cancellation::Cancellation, repository::OpenedRepository, tracked_filters, tree_index,
};

/// Check out HEAD into a new, empty worktree and return its fresh in-memory index.
///
/// The caller must hold the mutation and index locks until it publishes the returned state.
pub fn initial(
    opened: &OpenedRepository,
    cancellation: &Cancellation,
) -> crate::Result<gix::index::State> {
    cancellation.check()?;
    let repo = &opened.repo;
    let workdir = repo.workdir().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "initial checkout requires a worktree",
        )
    })?;
    let tree = repo.head_tree_id_or_empty()?;
    let mut index = tree_index::build(repo, &tree, workdir, cancellation)?;
    tracked_filters::reject_unsupported(
        opened,
        &index,
        gix::worktree::stack::state::attributes::Source::IdMapping,
        cancellation,
    )?;

    let mut options =
        repo.checkout_options(gix::worktree::stack::state::attributes::Source::IdMapping)?;
    options.fs.symlink = false;
    options.thread_limit = Some(1);
    options.destination_is_initially_empty = true;
    options.overwrite_existing = false;
    options.keep_going = false;

    let mut objects = repo.objects.clone().into_arc()?;
    objects.ignore_replacements = true;
    cancellation.check()?;
    let files = gix::features::progress::Discard;
    let bytes = gix::features::progress::Discard;
    let outcome = gix::worktree::state::checkout(
        &mut index,
        workdir,
        objects,
        &files,
        &bytes,
        cancellation.flag(),
        options,
    )
    .map_err(|error| cancellation.normalize_error(error.into()))?;
    check_outcome(&outcome).map_err(|error| cancellation.normalize_error(error))?;
    cancellation.check()?;
    Ok(index)
}

pub(crate) fn check_outcome(outcome: &gix::worktree::state::checkout::Outcome) -> crate::Result {
    if let Some(record) = outcome.errors.first() {
        return Err(io::Error::other(format!(
            "checkout failed at '{}': {}",
            record.path.to_str_lossy().escape_debug(),
            record.error
        ))
        .into());
    }
    if let Some(collision) = outcome.collisions.first() {
        return Err(io::Error::new(
            collision.error_kind,
            format!(
                "checkout collided at '{}'",
                collision.path.to_str_lossy().escape_debug()
            ),
        )
        .into());
    }
    if let Some(path) = outcome
        .delayed_paths_unknown
        .first()
        .or_else(|| outcome.delayed_paths_unprocessed.first())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "checkout filter left path '{}' unresolved",
                path.to_str_lossy().escape_debug()
            ),
        )
        .into());
    }
    Ok(())
}
