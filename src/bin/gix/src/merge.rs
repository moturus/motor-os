use std::io;

use gix::{
    bstr::ByteSlice,
    merge::{
        blob::{Resolution as BlobResolution, builtin_driver::text::Labels},
        tree::{Conflict, Resolution, TreatAsUnresolved},
    },
};

use crate::{
    cancellation::Cancellation, commit, merge_policy, operation::Original,
    repository::OpenedRepository, transition, tree_index,
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
    merge_policy::reject_unsupported(opened, &result_index, cancellation)?;
    cancellation.check()?;
    Ok(Preparation::Divergent {
        result_tree,
        conflicts,
    })
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

fn unsupported(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message.into())
}
