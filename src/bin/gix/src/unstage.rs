use std::io;

use gix::bstr::{BStr, ByteSlice};

use crate::{
    cancellation::Cancellation, mutation::Guard, repository::OpenedRepository,
    selection::Selection, tree_index,
};

/// Restore selected index entries from HEAD without changing the worktree.
pub fn run(
    opened: &OpenedRepository,
    paths: &[String],
    cancellation: &Cancellation,
) -> crate::Result {
    let repo = &opened.repo;
    let workdir = repo
        .workdir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "unstage requires a worktree"))?;
    let selection = Selection::from_paths(workdir, paths)?;

    cancellation.check()?;
    let mut guard = Guard::acquire(repo)?;
    cancellation.check()?;
    let head = repo.head_tree_id_or_empty()?.detach();
    let head = tree_index::build(repo, &head, workdir, cancellation)?;

    for path in selection.paths() {
        cancellation.check()?;
        if !contains(guard.index(), path.as_bstr())? && !contains(&head, path.as_bstr())? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "explicit path '{}' did not match HEAD or the index",
                    path.to_str_lossy().escape_debug()
                ),
            )
            .into());
        }
    }
    if selected_entries_equal(guard.index(), &head, &selection, cancellation)? {
        return cancellation.check();
    }
    reject_retained_ancestors(guard.index(), &selection, cancellation)?;

    guard.publish_edited_index(|index| {
        index.remove_entries(|_, path, _| selection.selects(path));
        for entry in head.entries() {
            cancellation.check()?;
            let path = entry.path(&head);
            if selection.selects(path) {
                index.dangerously_push_entry(entry.stat, entry.id, entry.flags, entry.mode, path);
            }
        }
        Ok(())
    })?;
    cancellation.check()?;
    Ok(())
}

fn contains(index: &gix::index::State, path: &BStr) -> crate::Result<bool> {
    if path.is_empty() {
        return Ok(!index.entries().is_empty());
    }
    if index.entry_range(path).is_some() {
        return Ok(true);
    }
    let mut prefix = Vec::new();
    prefix.try_reserve_exact(path.len() + 1)?;
    prefix.extend_from_slice(path);
    prefix.push(b'/');
    Ok(index.prefixed_entries_range(prefix.as_bstr()).is_some())
}

fn reject_retained_ancestors(
    current: &gix::index::State,
    selection: &Selection,
    cancellation: &Cancellation,
) -> crate::Result {
    for path in selection.paths() {
        cancellation.check()?;
        for separator in path
            .iter()
            .enumerate()
            .filter_map(|(pos, byte)| (*byte == b'/').then_some(pos))
        {
            let ancestor = path[..separator].as_bstr();
            if current.entry_range(ancestor).is_some() && !selection.selects(ancestor) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "cannot unstage '{}': retained index entry '{}' obstructs its HEAD path",
                        path.to_str_lossy().escape_debug(),
                        ancestor.to_str_lossy().escape_debug()
                    ),
                )
                .into());
            }
        }
    }
    Ok(())
}

fn selected_entries_equal(
    current: &gix::index::State,
    head: &gix::index::State,
    selection: &Selection,
    cancellation: &Cancellation,
) -> crate::Result<bool> {
    let mut current_entries = current
        .entries()
        .iter()
        .filter(|entry| selection.selects(entry.path(current)));
    let mut head_entries = head
        .entries()
        .iter()
        .filter(|entry| selection.selects(entry.path(head)));
    loop {
        cancellation.check()?;
        match (current_entries.next(), head_entries.next()) {
            (None, None) => return Ok(true),
            (Some(current_entry), Some(head_entry))
                if current_entry.path(current) == head_entry.path(head)
                    && current_entry.id == head_entry.id
                    && current_entry.flags == head_entry.flags
                    && current_entry.mode == head_entry.mode => {}
            _ => return Ok(false),
        }
    }
}
