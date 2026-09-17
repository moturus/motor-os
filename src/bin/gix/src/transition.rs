use std::{
    cmp::Ordering,
    fs, io,
    path::{Path, PathBuf},
};

use gix::{
    bstr::{BStr, BString, ByteSlice},
    index::entry::{Flags, Mode, Stage, Stat},
    worktree::stack::state::attributes::Source,
};

use crate::{
    cancellation::Cancellation,
    checkout,
    mutation::Guard,
    operation::{Record, State},
    repository::OpenedRepository,
    selection,
    stage_blob::Converter,
    tracked_filters, tree_index,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub id: gix::ObjectId,
    pub mode: Mode,
}

#[derive(Debug)]
struct ObservedFile {
    stat: Stat,
    mode: Mode,
}

#[derive(Debug)]
pub struct Change {
    pub path: BString,
    pub original: Option<Snapshot>,
    pub target: Option<Snapshot>,
    observed: Option<ObservedFile>,
}

/// A repository-only tree delta. Worktree safety has not been preflighted.
#[derive(Debug)]
pub struct Delta {
    pub original_index: gix::index::State,
    pub target_index: gix::index::State,
    pub changes: Vec<Change>,
}

/// An observed preflight result, without worktree snapshot isolation.
#[derive(Debug)]
pub struct Prepared {
    pub result_tree: gix::ObjectId,
    pub target_index: gix::index::State,
    pub changes: Vec<Change>,
}

/// A fully preflighted restoration to the recorded original tree.
#[derive(Debug)]
pub struct RestorePrepared {
    expected_record: Record,
    original_index: gix::index::State,
    changes: Vec<Change>,
}

/// Compute a bounded tree delta and verify that the held index represents its original tree.
/// The caller retains its mutation guard; this step does not inspect worktree content.
pub fn compute(
    repo: &gix::Repository,
    locked_index: &gix::index::State,
    original_tree: &gix::oid,
    target_tree: &gix::oid,
    cancellation: &Cancellation,
) -> crate::Result<Delta> {
    let workdir = repo
        .workdir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "a worktree is required"))?;
    let original_index = tree_index::build(repo, original_tree, workdir, cancellation)?;
    let target_index = tree_index::build(repo, target_tree, workdir, cancellation)?;
    ensure_original_index(locked_index, &original_index)?;
    let changes = collect_changes(&original_index, &target_index, cancellation)?;
    Ok(Delta {
        original_index,
        target_index,
        changes,
    })
}

/// Validate filters, collisions, and tracked worktree content without writing repository state.
///
/// The caller retains its mutation guard and rechecks observed state and cancellation
/// immediately before destructive writes.
pub fn prepare(
    opened: &OpenedRepository,
    locked_index: &gix::index::State,
    original_tree: &gix::oid,
    target_tree: &gix::oid,
    cancellation: &Cancellation,
) -> crate::Result<Prepared> {
    let mut delta = compute(
        &opened.repo,
        locked_index,
        original_tree,
        target_tree,
        cancellation,
    )?;
    tracked_filters::reject_unsupported(
        opened,
        &delta.original_index,
        Source::WorktreeThenIdMapping,
        cancellation,
    )?;
    tracked_filters::reject_unsupported(
        opened,
        &delta.target_index,
        Source::IdMapping,
        cancellation,
    )?;
    preflight_collisions(&opened.repo, &delta, cancellation)?;

    let repo = &opened.repo;
    let mut converter = Converter::new(repo, &delta.original_index)?;
    for entry in delta.original_index.entries() {
        cancellation.check()?;
        if entry.mode == Mode::COMMIT {
            continue;
        }
        let path = entry.path(&delta.original_index);
        let actual = converter.consume_git_content(
            "verify transition",
            path,
            Some(entry.mode),
            cancellation,
            |data| {
                Ok(gix::objs::compute_hash(
                    repo.object_hash(),
                    gix::objs::Kind::Blob,
                    data,
                )?)
            },
        )?;
        let Some((id, mode, stat)) = actual else {
            return Err(path_error(io::ErrorKind::InvalidData, path, "is missing").into());
        };
        if (Snapshot { id, mode }) != snapshot(entry) {
            return Err(path_error(io::ErrorKind::InvalidData, path, "has local changes").into());
        }
        if let Ok(offset) = delta
            .changes
            .binary_search_by(|change| change.path.as_bstr().cmp(path))
        {
            delta.changes[offset].observed = Some(ObservedFile { stat, mode });
        }
    }
    cancellation.check()?;
    Ok(Prepared {
        result_tree: target_tree.to_owned(),
        target_index: delta.target_index,
        changes: delta.changes,
    })
}

/// Prepare an idempotent restoration of the operation's original tree.
///
/// This accepts conflicts and partial old/new index states. `current` is the validated index
/// snapshot held by the mutation guard. This does not write the worktree, index, refs, or record.
pub fn prepare_restore(
    opened: &OpenedRepository,
    current: &gix::index::State,
    record: &Record,
    cancellation: &Cancellation,
) -> crate::Result<RestorePrepared> {
    cancellation.check()?;
    if record.state != State::Incomplete {
        return Err(invalid("worktree restoration requires an incomplete operation").into());
    }
    let repo = &opened.repo;
    let workdir = repo
        .workdir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "a worktree is required"))?;
    let original_tree = match record.original.id {
        Some(id) => repo.find_commit(id)?.tree_id()?.detach(),
        None => gix::ObjectId::empty_tree(repo.object_hash()),
    };
    let original_index = tree_index::build(repo, &original_tree, workdir, cancellation)?;
    let result_index = tree_index::build(repo, &record.result_tree, workdir, cancellation)?;
    tracked_filters::reject_unsupported(opened, &original_index, Source::IdMapping, cancellation)?;

    let tree_changes = collect_changes(&original_index, &result_index, cancellation)?;
    drop(result_index);
    let capacity = tree_changes
        .len()
        .checked_add(original_index.entries().len())
        .and_then(|count| count.checked_add(current.entries().len()))
        .ok_or_else(|| io::Error::other("restore path count overflow"))?;
    let mut paths = Vec::new();
    paths.try_reserve(capacity)?;
    paths.extend(tree_changes.into_iter().map(|change| change.path));
    collect_current_differences(&original_index, current, workdir, cancellation, &mut paths)?;
    paths.sort_unstable();
    paths.dedup();

    let mut changes = Vec::new();
    changes.try_reserve(paths.len())?;
    for path in paths {
        cancellation.check()?;
        let target = original_index
            .entry_by_path_and_stage(path.as_bstr(), Stage::Unconflicted)
            .map(snapshot);
        if target.is_some_and(|entry| entry.mode == Mode::COMMIT) {
            continue;
        }
        if has_gitlink_ancestor(&original_index, path.as_bstr()) {
            return Err(path_error(
                io::ErrorKind::Unsupported,
                path.as_bstr(),
                "is inside an unchanged gitlink",
            )
            .into());
        }
        let observed = observe_current(workdir, path.as_bstr())?;
        changes.push(Change {
            path,
            original: None,
            target,
            observed,
        });
    }
    preflight_changes(repo, &changes, cancellation)?;
    cancellation.check()?;
    Ok(RestorePrepared {
        expected_record: record.clone(),
        original_index,
        changes,
    })
}

/// Require the complete, guard-validated current index to be the result tree at stage zero.
pub fn require_result_index(
    repo: &gix::Repository,
    current: &gix::index::State,
    result_tree: &gix::oid,
    cancellation: &Cancellation,
) -> crate::Result {
    cancellation.check()?;
    let workdir = repo
        .workdir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "a worktree is required"))?;
    let expected = tree_index::build(repo, result_tree, workdir, cancellation)?;
    if !index_matches_tree(current, &expected) {
        return Err(invalid("the index does not match the operation result tree").into());
    }
    cancellation.check()
}

/// Install a prepared restoration and return a fresh original-tree index.
///
/// The caller retains the exact incomplete record and publishes the returned index separately.
pub fn install_restore(
    opened: &OpenedRepository,
    guard: &Guard,
    record: &Record,
    prepared: RestorePrepared,
    cancellation: &Cancellation,
) -> crate::Result<gix::index::State> {
    cancellation.check()?;
    if record.state != State::Incomplete || prepared.expected_record != *record {
        return Err(invalid("restore preparation does not match the incomplete operation").into());
    }
    let mut index = install_prepared(
        opened,
        guard,
        record,
        prepared.original_index,
        prepared.changes,
        cancellation,
    )?;
    for entry in index.entries_mut() {
        entry.stat = Default::default();
    }
    cancellation.check()?;
    Ok(index)
}

/// Install a prepared transition and return the fresh target index for later publication.
///
/// The caller retains `guard` and the incomplete operation record. This function may partially
/// update the worktree on error, but never publishes the index, refs, or operation state.
pub fn install(
    opened: &OpenedRepository,
    guard: &Guard,
    record: &Record,
    prepared: Prepared,
    cancellation: &Cancellation,
) -> crate::Result<gix::index::State> {
    cancellation.check()?;
    if record.state != State::Incomplete {
        return Err(invalid("worktree installation requires an incomplete operation").into());
    }
    if record.result_tree != prepared.result_tree {
        return Err(invalid("operation result tree does not match the prepared transition").into());
    }
    install_prepared(
        opened,
        guard,
        record,
        prepared.target_index,
        prepared.changes,
        cancellation,
    )
}

fn install_prepared(
    opened: &OpenedRepository,
    guard: &Guard,
    record: &Record,
    mut target_index: gix::index::State,
    changes: Vec<Change>,
    cancellation: &Cancellation,
) -> crate::Result<gix::index::State> {
    let repo = &opened.repo;
    let workdir = repo
        .workdir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "a worktree is required"))?;
    let mut options = repo.checkout_options(Source::IdMapping)?;
    options.fs.symlink = false;
    options.thread_limit = Some(1);
    // Selected destinations are removed first and must be recreated exclusively.
    options.destination_is_initially_empty = true;
    options.overwrite_existing = false;
    options.keep_going = false;
    let mut objects = repo.objects.clone().into_arc()?;
    objects.ignore_replacements = true;

    for (entry, path) in target_index.entries_mut_with_paths() {
        let changed = changes
            .binary_search_by(|change| change.path.as_bstr().cmp(path))
            .is_ok_and(|offset| changes[offset].target.is_some());
        if !changed || entry.mode == Mode::COMMIT {
            entry.flags.insert(Flags::SKIP_WORKTREE);
        }
    }

    let target_directories = preflight_changes(repo, &changes, cancellation)?;
    for change in &changes {
        cancellation.check()?;
        if change.original.is_some() || change.observed.is_some() {
            recheck_observed(workdir, change)?;
        }
    }
    cancellation.check()?;
    guard.require_operation(record)?;

    for change in changes.iter().filter(|change| change.observed.is_some()) {
        cancellation.check()?;
        fs::remove_file(recheck_observed(workdir, change)?)?;
    }
    for offset in target_directories {
        remove_target_directory(workdir, &changes, offset, cancellation)?;
    }

    let discard = gix::features::progress::Discard;
    let outcome = gix::worktree::state::checkout(
        &mut target_index,
        workdir,
        objects,
        &discard,
        &discard,
        cancellation.flag(),
        options,
    )
    .map_err(|error| cancellation.normalize_error(error.into()))?;
    checkout::check_outcome(&outcome).map_err(|error| cancellation.normalize_error(error))?;
    for entry in target_index.entries_mut() {
        entry.flags.remove(Flags::SKIP_WORKTREE);
    }
    cancellation.check()?;
    Ok(target_index)
}

pub(crate) fn ensure_original_index(
    actual: &gix::index::State,
    expected: &gix::index::State,
) -> crate::Result {
    if !index_matches_tree(actual, expected) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the index does not match the original tree",
        )
        .into());
    }
    Ok(())
}

fn index_matches_tree(actual: &gix::index::State, expected: &gix::index::State) -> bool {
    actual.entries().len() == expected.entries().len()
        && actual
            .entries()
            .iter()
            .zip(expected.entries())
            .all(|(a, b)| {
                a.stage() == Stage::Unconflicted
                    && a.path(actual) == b.path(expected)
                    && a.id == b.id
                    && a.mode == b.mode
            })
}

fn collect_current_differences(
    original: &gix::index::State,
    current: &gix::index::State,
    workdir: &Path,
    cancellation: &Cancellation,
    out: &mut Vec<BString>,
) -> crate::Result {
    let mut offset = 0;
    while offset < current.entries().len() {
        cancellation.check()?;
        let end = current_group_end(current, offset);
        let group = &current.entries()[offset..end];
        let path = group[0].path(current);
        let old = original.entry_by_path_and_stage(path, Stage::Unconflicted);
        if group.len() != 1
            || group[0].stage() != Stage::Unconflicted
            || !old.is_some_and(|entry| entry.id == group[0].id && entry.mode == group[0].mode)
        {
            selection::validate_normalized(path, workdir)?;
            out.push(path.to_owned());
        }
        offset = end;
    }
    for old in original.entries() {
        cancellation.check()?;
        if current.entry_range(old.path(original)).is_none() {
            out.push(old.path(original).to_owned());
        }
    }
    Ok(())
}

fn current_group_end(index: &gix::index::State, start: usize) -> usize {
    let path = index.entries()[start].path(index);
    let mut end = start + 1;
    while end < index.entries().len() && index.entries()[end].path(index) == path {
        end += 1;
    }
    end
}

fn has_gitlink_ancestor(index: &gix::index::State, path: &BStr) -> bool {
    path.iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'/')
        .any(|(slash, _)| {
            index
                .entry_by_path_and_stage(path[..slash].as_bstr(), Stage::Unconflicted)
                .is_some_and(|entry| entry.mode == Mode::COMMIT)
        })
}

fn observe_current(workdir: &Path, path: &BStr) -> crate::Result<Option<ObservedFile>> {
    let Some(path_metadata) = selection::checked_symlink_metadata(workdir, path)? else {
        return Ok(None);
    };
    if path_metadata.is_dir() {
        return Ok(None);
    }
    if !path_metadata.is_file() {
        return Err(path_error(io::ErrorKind::Unsupported, path, "has an unsupported type").into());
    }
    let absolute = workdir.join(gix::path::from_bstr(path).as_ref());
    let metadata = gix::index::fs::Metadata::from_path_no_follow(&absolute)?;
    if !metadata.is_file() {
        return Err(path_error(
            io::ErrorKind::InvalidData,
            path,
            "changed type during preparation",
        )
        .into());
    }
    let mode = if metadata.is_executable() {
        Mode::FILE_EXECUTABLE
    } else {
        Mode::FILE
    };
    Ok(Some(ObservedFile {
        stat: Stat::from_fs(&metadata)?,
        mode,
    }))
}

fn collect_changes(
    original: &gix::index::State,
    target: &gix::index::State,
    cancellation: &Cancellation,
) -> crate::Result<Vec<Change>> {
    let mut out = Vec::new();
    let capacity = original
        .entries()
        .len()
        .checked_add(target.entries().len())
        .ok_or_else(|| io::Error::other("tree entry count overflow"))?;
    out.try_reserve(capacity)?;
    let (mut left, mut right) = (original.entries().iter(), target.entries().iter());
    let (mut a, mut b) = (left.next(), right.next());
    while a.is_some() || b.is_some() {
        cancellation.check()?;
        let order = match (a, b) {
            (Some(a), Some(b)) => a.path(original).cmp(b.path(target)),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => break,
        };
        let (path, before, after) = match order {
            Ordering::Less => {
                let entry = a.expect("present");
                let value = (entry.path(original).to_owned(), Some(snapshot(entry)), None);
                a = left.next();
                value
            }
            Ordering::Greater => {
                let entry = b.expect("present");
                let value = (entry.path(target).to_owned(), None, Some(snapshot(entry)));
                b = right.next();
                value
            }
            Ordering::Equal => {
                let (old, new) = (a.expect("present"), b.expect("present"));
                let (before, after) = (snapshot(old), snapshot(new));
                a = left.next();
                b = right.next();
                if before == after {
                    continue;
                }
                (old.path(original).to_owned(), Some(before), Some(after))
            }
        };
        if before.is_some_and(|entry| entry.mode == Mode::COMMIT)
            || after.is_some_and(|entry| entry.mode == Mode::COMMIT)
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "cannot transition '{}': gitlink transitions are not supported",
                    path.to_str_lossy().escape_debug()
                ),
            )
            .into());
        }
        out.push(Change {
            path,
            original: before,
            target: after,
            observed: None,
        });
    }
    Ok(out)
}

fn snapshot(entry: &gix::index::Entry) -> Snapshot {
    Snapshot {
        id: entry.id,
        mode: entry.mode,
    }
}

/// Reject worktree objects that would obstruct this delta without following symbolic links.
pub fn preflight_collisions(
    repo: &gix::Repository,
    delta: &Delta,
    cancellation: &Cancellation,
) -> crate::Result {
    preflight_changes(repo, &delta.changes, cancellation).map(drop)
}

fn preflight_changes(
    repo: &gix::Repository,
    changes: &[Change],
    cancellation: &Cancellation,
) -> crate::Result<Vec<usize>> {
    let workdir = repo
        .workdir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "a worktree is required"))?;
    let mut target_directories = Vec::new();
    for (offset, change) in changes.iter().enumerate() {
        cancellation.check()?;
        let target = change.path.as_bstr();
        for (slash, _) in target.iter().enumerate().filter(|(_, byte)| **byte == b'/') {
            let prefix = target[..slash].as_bstr();
            let absolute = workdir.join(gix::path::from_bstr(prefix).as_ref());
            let metadata = match fs::symlink_metadata(&absolute) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                Err(error) => return Err(error.into()),
            };
            if metadata.is_dir() {
                reject_repository(&absolute, prefix)?;
            } else if change.target.is_none() || metadata.is_file() && removable(changes, prefix) {
                break;
            } else {
                return Err(obstruction(prefix, "blocks a target path").into());
            }
        }

        if change.target.is_none() {
            continue;
        }
        let absolute = workdir.join(gix::path::from_bstr(target).as_ref());
        let metadata = match fs::symlink_metadata(&absolute) {
            Ok(metadata) => metadata,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        if metadata.is_dir() {
            reject_directory_contents(&absolute, workdir, changes, cancellation)?;
            target_directories.try_reserve(1)?;
            target_directories.push(offset);
        } else if !metadata.is_file() || !has_removable_source(change) {
            return Err(obstruction(target, "would be overwritten").into());
        }
    }
    Ok(target_directories)
}

fn recheck_observed(workdir: &Path, change: &Change) -> crate::Result<PathBuf> {
    let observed = change
        .observed
        .as_ref()
        .ok_or_else(|| invalid("changed source entry has no observation"))?;
    let path = change.path.as_bstr();
    let absolute = workdir.join(gix::path::from_bstr(path).as_ref());
    let Some(path_metadata) = selection::checked_symlink_metadata(workdir, path)? else {
        return Err(path_error(io::ErrorKind::InvalidData, path, "is missing").into());
    };
    let metadata = gix::index::fs::Metadata::from_path_no_follow(&absolute)?;
    if !path_metadata.is_file() || !metadata.is_file() {
        return Err(path_error(
            io::ErrorKind::InvalidData,
            path,
            "changed type since preparation",
        )
        .into());
    }
    let actual_stat = Stat::from_fs(&metadata)?;
    let actual_mode = if observed.mode == Mode::SYMLINK {
        Mode::SYMLINK
    } else if metadata.is_executable() {
        Mode::FILE_EXECUTABLE
    } else {
        Mode::FILE
    };
    if actual_stat != observed.stat || actual_mode != observed.mode {
        return Err(path_error(
            io::ErrorKind::InvalidData,
            path,
            "changed since preparation",
        )
        .into());
    }
    Ok(absolute)
}

fn remove_target_directory(
    workdir: &Path,
    changes: &[Change],
    target_offset: usize,
    cancellation: &Cancellation,
) -> crate::Result {
    let root = workdir.join(gix::path::from_bstr(changes[target_offset].path.as_bstr()).as_ref());
    let mut pending = Vec::new();
    pending.try_reserve(1)?;
    pending.push((root, false));
    while let Some((directory, visited)) = pending.pop() {
        cancellation.check()?;
        let relative = repository_path(workdir, &directory)?;
        let metadata = selection::checked_symlink_metadata(workdir, relative.as_bstr())?;
        if !metadata.is_some_and(|metadata| metadata.is_dir()) {
            return Err(obstruction(relative.as_bstr(), "changed during installation").into());
        }
        if visited {
            fs::remove_dir(directory)?;
            continue;
        }
        reject_repository(&directory, relative.as_bstr())?;
        pending.try_reserve(1)?;
        pending.push((directory.clone(), true));
        for entry in fs::read_dir(&directory)? {
            cancellation.check()?;
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            let relative = repository_path(workdir, &path)?;
            if !metadata.is_dir() || !has_removable_descendant(changes, relative.as_bstr())? {
                return Err(obstruction(relative.as_bstr(), "would be overwritten").into());
            }
            pending.try_reserve(1)?;
            pending.push((path, false));
        }
    }
    Ok(())
}

fn reject_directory_contents(
    root: &Path,
    workdir: &Path,
    changes: &[Change],
    cancellation: &Cancellation,
) -> crate::Result {
    let mut pending = Vec::<PathBuf>::new();
    pending.try_reserve(1)?;
    pending.push(root.to_owned());
    while let Some(directory) = pending.pop() {
        cancellation.check()?;
        let relative = repository_path(workdir, &directory)?;
        reject_repository(&directory, relative.as_bstr())?;
        for entry in fs::read_dir(&directory)? {
            cancellation.check()?;
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            let relative = repository_path(workdir, &path)?;
            if metadata.is_dir() {
                if !has_removable_descendant(changes, relative.as_bstr())? {
                    return Err(obstruction(relative.as_bstr(), "would be overwritten").into());
                }
                pending.try_reserve(1)?;
                pending.push(path);
            } else if !metadata.is_file() || !removable(changes, relative.as_bstr()) {
                return Err(obstruction(relative.as_bstr(), "would be overwritten").into());
            }
        }
    }
    Ok(())
}

fn reject_repository(directory: &Path, relative: &BStr) -> crate::Result {
    if metadata(directory.join(".git"))?.is_some() {
        return Err(obstruction(relative, "is a nested repository").into());
    }
    let looks_bare = metadata(directory.join("HEAD"))?.is_some_and(|meta| meta.is_file())
        && metadata(directory.join("objects"))?.is_some_and(|meta| meta.is_dir())
        && metadata(directory.join("refs"))?.is_some_and(|meta| meta.is_dir());
    if looks_bare {
        return Err(obstruction(relative, "is a nested repository").into());
    }
    Ok(())
}

fn metadata(path: PathBuf) -> io::Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn repository_path(workdir: &Path, path: &Path) -> crate::Result<BString> {
    let path = path.strip_prefix(workdir)?;
    Ok(gix::path::to_unix_separators_on_windows(gix::path::try_into_bstr(path)?).into_owned())
}

fn removable(changes: &[Change], path: &BStr) -> bool {
    changes
        .binary_search_by(|change| change.path.as_bstr().cmp(path))
        .is_ok_and(|offset| removable_change(&changes[offset]))
}

fn removable_change(change: &Change) -> bool {
    change.target.is_none() && has_removable_source(change)
}

fn has_removable_source(change: &Change) -> bool {
    change.observed.is_some() || change.original.is_some_and(|entry| ordinary(entry.mode))
}

fn has_removable_descendant(changes: &[Change], parent: &BStr) -> crate::Result<bool> {
    let mut prefix = Vec::new();
    prefix.try_reserve_exact(parent.len() + 1)?;
    prefix.extend_from_slice(parent);
    prefix.push(b'/');
    let prefix = BString::from(prefix);
    let offset = changes.partition_point(|change| change.path.as_bstr() < prefix.as_bstr());
    Ok(changes[offset..]
        .iter()
        .take_while(|change| change.path.starts_with(prefix.as_slice()))
        .any(removable_change))
}

fn ordinary(mode: Mode) -> bool {
    matches!(mode, Mode::FILE | Mode::FILE_EXECUTABLE | Mode::SYMLINK)
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn obstruction(path: &BStr, message: &str) -> io::Error {
    path_error(io::ErrorKind::AlreadyExists, path, message)
}

fn path_error(kind: io::ErrorKind, path: &BStr, message: &str) -> io::Error {
    io::Error::new(
        kind,
        format!(
            "worktree path '{}' {message}",
            path.to_str_lossy().escape_debug()
        ),
    )
}
