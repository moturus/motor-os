//! Replay commits onto another commit, as the picks of `git rebase` do.
//!
//! Only commits, trees and blobs are written. The worktree, the index and every reference
//! stay as they are, so a replay that fails or stops has changed nothing a user can see.

use std::{
    collections::{BinaryHeap, HashMap},
    io,
};

use gix::{
    bstr::{BStr, BString, ByteSlice},
    merge::{
        blob::builtin_driver::text::Labels,
        tree::{Conflict, TreatAsUnresolved},
    },
    objs::{CommitRefIter, Kind, commit::ref_iter::Token},
    prelude::ObjectIdExt,
    worktree::stack::state::attributes::Source,
};

use crate::{
    cancellation::Cancellation, commit, merge, merge_policy, object_database::Reader,
    repository::OpenedRepository, tracked_filters, tree_index,
};

/// The most commits one rebase reads: those it replays, and those it visits to find them.
pub const MAX_COMMITS: usize = 65_536;

/// The three commits that define a rebase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Range {
    /// The tip of the branch before the rebase.
    pub original: gix::ObjectId,
    /// The upstream commit that the branch moves onto.
    pub onto: gix::ObjectId,
    /// Where the branch left the upstream. Commits up to here are not replayed.
    pub base: gix::ObjectId,
}

/// How far a replay got.
#[derive(Debug)]
pub struct Replayed {
    /// The last commit made, or the starting point if none was made.
    pub tip: gix::ObjectId,
    /// Commits left out because `tip` already had their changes.
    pub dropped: Vec<gix::ObjectId>,
    /// The commit that does not apply on `tip`, if the replay had to stop.
    pub stopped: Option<Stopped>,
}

#[derive(Debug)]
pub struct Stopped {
    pub commit: gix::ObjectId,
    /// The tree with conflict markers and its conflicts, if gix can show them.
    pub shown: Option<(gix::ObjectId, Vec<Conflict>)>,
}

/// Replay the commits of `range` that follow `after` onto `tip`, oldest first.
///
/// `after` is the commit an earlier replay stopped at; `None` starts with the first commit.
pub fn run(
    opened: &OpenedRepository,
    range: &Range,
    after: Option<gix::ObjectId>,
    mut tip: gix::ObjectId,
    cancellation: &Cancellation,
) -> crate::Result<Replayed> {
    let repo = &opened.repo;
    let identities = commit::identities(repo)?;
    let commits = todo(repo, range, cancellation)?;
    let rest = match after {
        None => &commits[..],
        Some(after) => {
            let position = commits
                .iter()
                .position(|id| *id == after)
                .ok_or_else(|| invalid("the rebase does not have the commit it stopped at"))?;
            &commits[position + 1..]
        }
    };
    let mut tip_tree = repo.find_commit(tip)?.tree_id()?.detach();
    reject_unsupported(opened, tip_tree, cancellation)?;
    let mut dropped = Vec::new();
    for &id in rest {
        cancellation.check()?;
        let picked = pick(opened, id, tip_tree)?;
        cancellation.check()?;
        match picked {
            Pick::Commit(tree) => {
                reject_unsupported(opened, tree, cancellation)?;
                (tip, tip_tree) = (commit_as(repo, id, tip, tree, &identities)?, tree);
            }
            Pick::Dropped => dropped.push(id),
            Pick::Conflict(shown) => {
                if let Some((tree, _)) = &shown {
                    reject_unsupported(opened, *tree, cancellation)?;
                }
                let stopped = Some(Stopped { commit: id, shown });
                return Ok(Replayed {
                    tip,
                    dropped,
                    stopped,
                });
            }
        }
    }
    Ok(Replayed {
        tip,
        dropped,
        stopped: None,
    })
}

enum Pick {
    /// The tree of the commit to make.
    Commit(gix::ObjectId),
    /// The commit changes nothing anymore.
    Dropped,
    Conflict(Option<(gix::ObjectId, Vec<Conflict>)>),
}

/// Apply the change that commit `id` made to its first parent on top of `tip_tree`.
fn pick(
    opened: &OpenedRepository,
    id: gix::ObjectId,
    tip_tree: gix::ObjectId,
) -> crate::Result<Pick> {
    let repo = &opened.repo;
    let object = repo.find_commit(id)?;
    let commit = object.decode()?;
    let tree = commit.tree();
    let parent_tree = match commit.parents().next() {
        Some(parent) => repo.find_commit(parent)?.tree_id()?.detach(),
        None => gix::ObjectId::empty_tree(repo.object_hash()),
    };
    // Git's labels: `<short id> (<subject>)` for the commit, `parent of ...` for its base.
    let mut label = BString::from(id.attach(repo).shorten_or_id().to_string());
    label.extend_from_slice(b" (");
    label.extend_from_slice(subject(commit.message));
    label.push(b')');
    let mut parent_label = BString::from("parent of ");
    parent_label.extend_from_slice(&label);
    let outcome = repo.merge_trees(
        parent_tree,
        tip_tree,
        tree,
        Labels {
            ancestor: Some(parent_label.as_bstr()),
            current: Some(b"HEAD".as_bstr()),
            other: Some(label.as_bstr()),
        },
        repo.tree_merge_options()?,
    )?;
    let mut merged = outcome.tree;
    let conflicts = outcome.conflicts;
    let how = TreatAsUnresolved::git();
    let mut unresolved = conflicts
        .iter()
        .filter(|conflict| conflict.is_unresolved(how))
        .peekable();
    if unresolved.peek().is_some() {
        if !unresolved.all(merge::supported_text_conflict) {
            return Ok(Pick::Conflict(None));
        }
        return Ok(Pick::Conflict(Some((merged.write()?.detach(), conflicts))));
    }
    let result = merged.write()?.detach();
    // A commit that was empty from the start is kept, as Git keeps it.
    if result == tip_tree && tree != parent_tree {
        return Ok(Pick::Dropped);
    }
    Ok(Pick::Commit(result))
}

/// Write the replayed form of commit `id`: its author and message, on parent `tip`.
fn commit_as(
    repo: &gix::Repository,
    id: gix::ObjectId,
    tip: gix::ObjectId,
    tree: gix::ObjectId,
    identities: &commit::Identities,
) -> crate::Result<gix::ObjectId> {
    let object = repo.find_commit(id)?;
    let commit = object.decode()?;
    let replayed = gix::objs::Commit {
        tree,
        parents: [tip].into_iter().collect(),
        author: commit.author()?.to_owned()?,
        committer: identities.committer().clone(),
        // The message bytes are kept, so the encoding that describes them is kept too.
        encoding: commit.encoding.map(ToOwned::to_owned),
        message: commit.message.to_owned(),
        extra_headers: Vec::new(),
    };
    Ok(repo.write_object(&replayed)?.detach())
}

/// The first line of a commit message that is not blank, which is how Git names a commit.
fn subject(message: &BStr) -> &[u8] {
    message
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_default()
}

/// Refuse a tree whose attributes ask for a filter or a merge driver that gix cannot run.
fn reject_unsupported(
    opened: &OpenedRepository,
    tree: gix::ObjectId,
    cancellation: &Cancellation,
) -> crate::Result {
    let repo = &opened.repo;
    let workdir = repo
        .workdir()
        .ok_or_else(|| unsupported("rebase requires a worktree"))?;
    let index = tree_index::build(repo, &tree, workdir, cancellation)?;
    tracked_filters::reject_unsupported(opened, &index, Source::IdMapping, cancellation)?;
    merge_policy::reject_unsupported(opened, &index, cancellation)
}

/// A commit reached while looking for the commits to replay.
struct Seen {
    parents: Vec<gix::ObjectId>,
    time: i64,
    /// Reachable from the upstream side, so not replayed.
    hidden: bool,
    queued: bool,
}

struct Walk<'a> {
    objects: Reader<'a>,
    seen: HashMap<gix::ObjectId, Seen>,
    /// Commits whose parents are still to be reached, newest first.
    queue: BinaryHeap<(i64, gix::ObjectId)>,
    /// How many queued commits are not hidden.
    visible_queued: usize,
}

impl Walk<'_> {
    /// Record that commit `id` is reachable, from the upstream side if `hidden`.
    fn reach(&mut self, id: gix::ObjectId, hidden: bool) -> crate::Result {
        if let Some(commit) = self.seen.get_mut(&id) {
            // A commit first reached from the branch can turn out to be upstream as well.
            if hidden && !commit.hidden {
                commit.hidden = true;
                if commit.queued {
                    self.visible_queued -= 1;
                } else {
                    // Visit it again, so that its ancestors become hidden too.
                    commit.queued = true;
                    self.queue.push((commit.time, id));
                }
            }
            return Ok(());
        }
        if self.seen.len() == MAX_COMMITS {
            return Err(unsupported("the rebase would read more than 65,536 commits").into());
        }
        let object = self.objects.load_kind(id, Kind::Commit)?;
        let mut parents = Vec::new();
        let mut time = 0;
        for token in CommitRefIter::from_bytes(&object.data, id.kind()) {
            match token? {
                Token::Parent { id } => parents.push(id),
                Token::Committer { signature } => {
                    time = signature.seconds();
                    break;
                }
                _ => {}
            }
        }
        let commit = Seen {
            parents,
            time,
            hidden,
            queued: true,
        };
        self.seen.insert(id, commit);
        self.queue.push((time, id));
        self.visible_queued += usize::from(!hidden);
        Ok(())
    }
}

/// The commits a rebase of `range` replays, oldest first.
///
/// These are the commits reachable from the original tip but not from `onto` or `base`,
/// without merge commits, in the reverse of `git rev-list --topo-order`. As Git does without
/// a commit-graph, this trusts that no commit is older than its parents.
pub fn todo(
    repo: &gix::Repository,
    range: &Range,
    cancellation: &Cancellation,
) -> crate::Result<Vec<gix::ObjectId>> {
    let mut walk = Walk {
        objects: Reader::new(repo, cancellation),
        seen: HashMap::new(),
        queue: BinaryHeap::new(),
        visible_queued: 0,
    };
    walk.reach(range.original, false)?;
    walk.reach(range.onto, true)?;
    walk.reach(range.base, true)?;
    // Git's rule for the end: no queued commit is visible, and every queued commit is older
    // than all visible ones, so none of them can have a visible commit as an ancestor.
    let mut oldest_visible = i64::MAX;
    while let Some(&(time, id)) = walk.queue.peek() {
        if walk.visible_queued == 0 && time < oldest_visible {
            break;
        }
        walk.queue.pop();
        let commit = walk.seen.get_mut(&id).expect("queued commits were seen");
        commit.queued = false;
        let hidden = commit.hidden;
        if !hidden {
            walk.visible_queued -= 1;
            oldest_visible = oldest_visible.min(time);
        }
        for parent in commit.parents.clone() {
            walk.reach(parent, hidden)?;
        }
    }

    // Git's `--topo-order`: a commit comes after all its children, and the lines of history
    // that a merge joins are not mixed. The line of the last parent comes first.
    let seen = walk.seen;
    let visible = |id: &gix::ObjectId| seen.get(id).is_some_and(|commit| !commit.hidden);
    let mut children: HashMap<gix::ObjectId, usize> = HashMap::new();
    for commit in seen.values().filter(|commit| !commit.hidden) {
        for parent in commit.parents.iter().filter(|id| visible(id)) {
            *children.entry(*parent).or_default() += 1;
        }
    }
    let mut commits = Vec::new();
    let mut ready = Vec::from_iter(visible(&range.original).then_some(range.original));
    while let Some(id) = ready.pop() {
        cancellation.check()?;
        let parents = &seen[&id].parents;
        if parents.len() < 2 {
            commits.push(id);
        }
        for parent in parents {
            if let Some(count) = children.get_mut(parent) {
                *count -= 1;
                if *count == 0 {
                    ready.push(*parent);
                }
            }
        }
    }
    commits.reverse();
    Ok(commits)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn unsupported(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}
