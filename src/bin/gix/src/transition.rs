use std::{
    cmp::Ordering,
    fs, io,
    path::{Path, PathBuf},
};

use gix::{
    bstr::{BStr, BString, ByteSlice},
    index::entry::{Mode, Stage, Stat},
    worktree::stack::state::attributes::Source,
};

use crate::{
    cancellation::Cancellation, repository::OpenedRepository, stage_blob::Converter,
    tracked_filters, tree_index,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub id: gix::ObjectId,
    pub mode: Mode,
}

#[derive(Debug)]
pub struct Change {
    pub path: BString,
    pub original: Option<Snapshot>,
    pub target: Option<Snapshot>,
    pub original_stat: Option<Stat>,
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
    pub target_index: gix::index::State,
    pub changes: Vec<Change>,
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
            delta.changes[offset].original_stat = Some(stat);
        }
    }
    cancellation.check()?;
    Ok(Prepared {
        target_index: delta.target_index,
        changes: delta.changes,
    })
}

fn ensure_original_index(
    actual: &gix::index::State,
    expected: &gix::index::State,
) -> crate::Result {
    let equal = actual.entries().len() == expected.entries().len()
        && actual
            .entries()
            .iter()
            .zip(expected.entries())
            .all(|(a, b)| {
                a.stage() == Stage::Unconflicted
                    && a.path(actual) == b.path(expected)
                    && a.id == b.id
                    && a.mode == b.mode
            });
    if !equal {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the index does not match the original tree",
        )
        .into());
    }
    Ok(())
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
            original_stat: None,
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
    let workdir = repo
        .workdir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "a worktree is required"))?;
    for change in &delta.changes {
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
            } else if change.target.is_none()
                || metadata.is_file() && removable(&delta.changes, prefix)
            {
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
            reject_directory_contents(&absolute, workdir, &delta.changes, cancellation)?;
        } else if !metadata.is_file() || !change.original.is_some_and(|entry| ordinary(entry.mode))
        {
            return Err(obstruction(target, "would be overwritten").into());
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
        .is_ok_and(|offset| {
            changes[offset]
                .original
                .is_some_and(|entry| ordinary(entry.mode))
                && changes[offset].target.is_none()
        })
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
        .any(|change| {
            change.original.is_some_and(|entry| ordinary(entry.mode)) && change.target.is_none()
        }))
}

fn ordinary(mode: Mode) -> bool {
    matches!(mode, Mode::FILE | Mode::FILE_EXECUTABLE | Mode::SYMLINK)
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
