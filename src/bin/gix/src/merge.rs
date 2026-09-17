use std::{error::Error as StdError, fmt, io};

use gix::{
    bstr::ByteSlice,
    index::entry::Stage,
    merge::{
        blob::{Resolution as BlobResolution, builtin_driver::text::Labels},
        tree::{Conflict, Resolution, TreatAsUnresolved, apply_index_entries},
    },
    worktree::stack::state::attributes::Source,
};

use crate::{
    cancellation::Cancellation,
    commit, head_ref, merge_policy,
    mutation::{self, Guard},
    operation::{Original, State},
    repository::OpenedRepository,
    tracked_filters, transition, tree_index,
};

#[derive(Debug)]
pub enum Preparation {
    UpToDate,
    FastForward {
        target_tree: gix::ObjectId,
    },
    Divergent {
        result_tree: gix::ObjectId,
        conflicts: Vec<Conflict>,
    },
}

/// Classify and, for divergence, compute a bounded merge result without changing published state.
///
/// The caller retains its mutation guard. Merge result objects may be written even if later
/// validation fails, but the worktree, index, references and operation record remain unchanged.
pub fn prepare(
    opened: &OpenedRepository,
    locked_index: &gix::index::State,
    original: &Original,
    target_commit: gix::ObjectId,
    cancellation: &Cancellation,
) -> crate::Result<Preparation> {
    cancellation.check()?;
    let repo = &opened.repo;
    if original.reference.as_ref().and_then(|name| name.category())
        != Some(gix::refs::Category::LocalBranch)
    {
        return Err(unsupported("merge requires HEAD attached to a local branch").into());
    }
    let workdir = repo
        .workdir()
        .ok_or_else(|| unsupported("merge requires a worktree"))?;
    let target_tree = repo.find_commit(target_commit)?.tree_id()?.detach();
    let original_tree = match original.id {
        Some(id) => repo.find_commit(id)?.tree_id()?.detach(),
        None => gix::ObjectId::empty_tree(repo.object_hash()),
    };
    let original_index = tree_index::build(repo, &original_tree, workdir, cancellation)?;
    transition::ensure_original_index(locked_index, &original_index)?;

    let Some(ours) = original.id else {
        return Ok(Preparation::FastForward { target_tree });
    };
    let base = match repo.merge_base(ours, target_commit) {
        Ok(base) => base.detach(),
        Err(gix::repository::merge_base::Error::NotFound { .. }) => {
            return Err(unsupported("cannot merge unrelated histories").into());
        }
        Err(error) => return Err(error.into()),
    };
    if base == target_commit {
        return Ok(Preparation::UpToDate);
    }
    if base == ours {
        return Ok(Preparation::FastForward { target_tree });
    }

    commit::identities(repo)?;
    let target_index = tree_index::build(repo, &target_tree, workdir, cancellation)?;
    // Ancestor cases never invoke the merge engine, so its driver policy applies only here.
    tracked_filters::reject_unsupported(opened, &original_index, Source::IdMapping, cancellation)?;
    tracked_filters::reject_unsupported(opened, &target_index, Source::IdMapping, cancellation)?;
    merge_policy::reject_unsupported(opened, &original_index, cancellation)?;
    merge_policy::reject_unsupported(opened, &target_index, cancellation)?;
    drop(original_index);
    drop(target_index);
    cancellation.check()?;
    let target_label = target_commit.to_string();
    let outcome = repo.merge_commits(
        ours,
        target_commit,
        Labels {
            ancestor: None,
            current: Some(b"HEAD".as_bstr()),
            other: Some(target_label.as_bytes().as_bstr()),
        },
        repo.tree_merge_options()?.into(),
    )?;
    cancellation.check()?;
    let mut tree = outcome.tree_merge.tree;
    let conflicts = outcome.tree_merge.conflicts;
    for conflict in conflicts
        .iter()
        .filter(|conflict| conflict.is_unresolved(TreatAsUnresolved::git()))
    {
        if !supported_text_conflict(conflict) {
            let path = conflict.changes_in_resolution().1.location();
            return Err(unsupported(format!(
                "merge conflict at '{}' is not a supported regular-text conflict",
                path.to_str_lossy().escape_debug()
            ))
            .into());
        }
    }
    let result_tree = tree.write()?.detach();
    let result_index = tree_index::build(repo, &result_tree, workdir, cancellation)?;
    tracked_filters::reject_unsupported(opened, &result_index, Source::IdMapping, cancellation)?;
    merge_policy::reject_unsupported(opened, &result_index, cancellation)?;
    let mut conflict_index = result_index;
    apply_conflicts(&mut conflict_index, &conflicts)?;
    mutation::preflight_index(conflict_index)?;
    cancellation.check()?;
    Ok(Preparation::Divergent {
        result_tree,
        conflicts,
    })
}

fn apply_conflicts(index: &mut gix::index::State, conflicts: &[Conflict]) -> crate::Result<bool> {
    let how = TreatAsUnresolved::git();
    let unresolved = conflicts.iter().any(|conflict| conflict.is_unresolved(how));
    let changed = apply_index_entries(
        conflicts,
        how,
        index,
        gix::merge::tree::apply_index_entries::RemovalMode::Prune,
    );
    if unresolved && !changed {
        return Err(invalid("unresolved merge conflicts did not change the result index").into());
    }
    for conflict in conflicts
        .iter()
        .filter(|conflict| conflict.is_unresolved(how))
    {
        let path = conflict.changes_in_resolution().1.location();
        let expected = conflict.entries();
        let Some(range) = index.entry_range(path) else {
            return Err(invalid(format!(
                "merge conflict index entries are missing for '{}'",
                path.to_str_lossy().escape_debug()
            ))
            .into());
        };
        let actual = &index.entries()[range];
        if actual.len() != expected.iter().flatten().count() {
            return Err(invalid("merge conflict produced unexpected index stages").into());
        }
        for (actual, (offset, expected)) in actual.iter().zip(
            expected
                .into_iter()
                .enumerate()
                .filter_map(|(offset, entry)| entry.map(|entry| (offset, entry))),
        ) {
            let stage = match offset {
                0 => Stage::Base,
                1 => Stage::Ours,
                2 => Stage::Theirs,
                _ => unreachable!("three conflict index entries"),
            };
            let expected_mode: gix::index::entry::Mode = expected.mode.into();
            if actual.stage() != stage || actual.id != expected.id || actual.mode != expected_mode {
                return Err(invalid("merge conflict produced unexpected index stages").into());
            }
        }
    }
    Ok(unresolved)
}

/// Discard an installed ready merge and restore its exact recorded original tree.
///
/// Preflight failures retain the Ready merge. Once the record becomes Incomplete, every failure
/// retains a recovery record and directs the caller to finish with `gix recover`.
pub fn abort(opened: &OpenedRepository, cancellation: &Cancellation) -> crate::Result {
    cancellation.check()?;
    let repo = &opened.repo;
    let (mut guard, ready) = Guard::acquire_ready_merge(repo)?;
    guard.require_ready_merge(repo, &ready, cancellation)?;

    let mut incomplete = ready.clone();
    incomplete.state = State::Incomplete;
    let prepared = transition::prepare_restore(opened, guard.index(), &incomplete, cancellation)?;
    guard.require_ready_merge(repo, &ready, cancellation)?;
    cancellation.check()?;
    guard.replace_operation(&ready, &incomplete)?;

    let result: crate::Result = (|| {
        let index =
            transition::install_restore(opened, &guard, &incomplete, prepared, cancellation)?;
        guard.publish_fresh_index(index)?;
        head_ref::require(repo, &incomplete.original)?;
        guard.cleanup_operation(&incomplete, cancellation)
    })();
    result.map_err(|source| incomplete_error("merge abort", cancellation.normalize_error(source)))
}

fn incomplete_error(
    action: &'static str,
    source: Box<dyn StdError + Send + Sync>,
) -> Box<dyn StdError + Send + Sync> {
    Box::new(IncompleteError { action, source })
}

#[derive(Debug)]
struct IncompleteError {
    action: &'static str,
    source: Box<dyn StdError + Send + Sync>,
}

impl fmt::Display for IncompleteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} is incomplete; run 'gix recover'",
            self.action
        )
    }
}

impl StdError for IncompleteError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.source.as_ref())
    }
}

fn supported_text_conflict(conflict: &Conflict) -> bool {
    let Ok(Resolution::OursModifiedTheirsModifiedThenBlobContentMerge { merged_blob }) =
        &conflict.resolution
    else {
        return false;
    };
    let (ours, theirs) = conflict.changes_in_resolution();
    let entries = conflict.entries();
    let (Some(ours_entry), Some(_)) = (entries[1], entries[2]) else {
        return false;
    };
    merged_blob.resolution == BlobResolution::Conflict
        && ours.location() == theirs.location()
        && ours.source_location() == theirs.source_location()
        && ours.source_location() == ours.location()
        && entries.iter().flatten().all(|entry| entry.mode.is_blob())
        && merged_blob.merged_blob_id != ours_entry.id
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn unsupported(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message.into())
}
