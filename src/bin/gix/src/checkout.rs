use std::{fs, io, path::Path};

use gix::bstr::{BStr, BString, ByteSlice};

use crate::{
    cancellation::Cancellation, repository::OpenedRepository, selection, tracked_filters,
    tree_index,
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

/// The directory that the command was started in, as the prefix of the paths in it, if
/// it is a directory of the worktree below its top.
///
/// As Git, gix does not remove it when it becomes empty: the shell that ran the command
/// is still in it. `-r` does not change which directory that is.
pub(crate) fn start_directory(workdir: &Path) -> Option<BString> {
    let current = fs::canonicalize(".").ok()?;
    let relative = current.strip_prefix(fs::canonicalize(workdir).ok()?).ok()?;
    let mut prefix = gix::path::into_bstr(relative).into_owned();
    if prefix.is_empty() {
        return None;
    }
    prefix.push(b'/');
    Some(prefix)
}

/// Prune empty parents of a removed file. `keep` receives each directory's
/// index prefix, including its trailing slash.
pub(crate) fn prune_empty_parents(
    workdir: &Path,
    path: &BStr,
    mut keep: impl FnMut(&BStr) -> crate::Result<bool>,
) -> crate::Result {
    for slash in path.rfind_iter(b"/") {
        let parent = path[..slash].as_bstr();
        if keep(path[..=slash].as_bstr())?
            || !selection::checked_symlink_metadata(workdir, parent)?.is_some_and(|m| m.is_dir())
        {
            break;
        }
        match fs::remove_dir(workdir.join(gix::path::from_bstr(parent).as_ref())) {
            Ok(()) => {}
            // Motor OS reports nonempty directories as FileTooLarge.
            Err(error)
                if error.kind() == io::ErrorKind::DirectoryNotEmpty
                    || cfg!(target_os = "motor") && error.kind() == io::ErrorKind::FileTooLarge =>
            {
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
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
