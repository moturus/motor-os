use std::{cmp::Ordering, io};

use gix::{
    bstr::{BString, ByteSlice},
    index::entry::{Mode, Stage},
};

use crate::{cancellation::Cancellation, tree_index};

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
}

/// A repository-only tree delta. Worktree safety has not been preflighted.
#[derive(Debug)]
pub struct Delta {
    pub original_index: gix::index::State,
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
