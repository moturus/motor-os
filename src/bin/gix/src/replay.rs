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
    patch_id::Patch, repository::OpenedRepository, tracked_filters, tree_index,
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

/// Replay `commits` onto `tip` in the given order.
///
/// The commits are those that `todo()` lists, or the rest of them after a stop.
pub fn run(
    opened: &OpenedRepository,
    commits: &[gix::ObjectId],
    mut tip: gix::ObjectId,
    cancellation: &Cancellation,
) -> crate::Result<Replayed> {
    let repo = &opened.repo;
    let mut dropped = Vec::new();
    if commits.is_empty() {
        // Nothing to commit, so nobody has to be named as the committer.
        return Ok(Replayed {
            tip,
            dropped,
            stopped: None,
        });
    }
    let identities = commit::identities(repo)?;
    let mut tip_tree = repo.find_commit(tip)?.tree_id()?.detach();
    reject_unsupported(opened, tip_tree, cancellation)?;
    for &id in commits {
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
    let label = label(repo, id)?;
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
pub(crate) fn commit_as(
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

/// `<short id> (<subject>)`: Git's name for a commit in conflict markers and messages.
pub(crate) fn label(repo: &gix::Repository, id: gix::ObjectId) -> crate::Result<BString> {
    let object = repo.find_commit(id)?;
    let mut label = BString::from(id.attach(repo).shorten_or_id().to_string());
    label.extend_from_slice(b" (");
    label.extend_from_slice(subject(object.decode()?.message));
    label.push(b')');
    Ok(label)
}

/// The first line of a commit message that is not blank, which is how Git names a commit.
pub(crate) fn subject(message: &BStr) -> &[u8] {
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

/// From which commits of the rebase a commit can be reached.
const BRANCH: u8 = 1;
const ONTO: u8 = 2;
const BASE: u8 = 4;

/// Whether a commit with these flags is on one side only: reachable from the branch, or
/// from the upstream and the base, but not from both.
fn one_sided(from: u8) -> bool {
    (from & BRANCH != 0) != (from & (ONTO | BASE) != 0)
}

/// A commit reached while looking for the commits to replay.
struct Seen {
    parents: Vec<gix::ObjectId>,
    time: i64,
    /// `BRANCH`, `ONTO` and `BASE`, for each of them that reaches this commit.
    from: u8,
    queued: bool,
}

struct Walk<'a> {
    objects: Reader<'a>,
    seen: HashMap<gix::ObjectId, Seen>,
    /// Commits whose parents are still to be reached, newest first.
    queue: BinaryHeap<(i64, gix::ObjectId)>,
    /// How many queued commits are one-sided.
    one_sided_queued: usize,
}

impl Walk<'_> {
    /// Record that commit `id` is reachable from the commits that the flags `from` name.
    fn reach(&mut self, id: gix::ObjectId, from: u8) -> crate::Result {
        if let Some(commit) = self.seen.get_mut(&id) {
            let (before, after) = (commit.from, commit.from | from);
            if before != after {
                commit.from = after;
                if !commit.queued {
                    // Visit it again, so that its ancestors learn what reaches them.
                    commit.queued = true;
                    self.queue.push((commit.time, id));
                    self.one_sided_queued += usize::from(one_sided(after));
                } else if one_sided(before) && !one_sided(after) {
                    self.one_sided_queued -= 1;
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
            from,
            queued: true,
        };
        self.seen.insert(id, commit);
        self.queue.push((time, id));
        self.one_sided_queued += 1;
        Ok(())
    }
}

/// What a rebase does with the commits of its branch.
#[derive(Debug)]
pub struct Todo {
    /// The commits to replay, oldest first.
    pub commits: Vec<gix::ObjectId>,
    /// Commits left out because the upstream has a commit with the same change.
    pub applied: Vec<gix::ObjectId>,
}

/// The commits a rebase of `range` replays, and those it leaves out, as `git rebase` does.
///
/// The commits of the branch are those reachable from the original tip but not from `onto`
/// or `base`, without merge commits, in the reverse of `git rev-list --topo-order`. A
/// commit whose patch ID is that of a commit that only the upstream has is left out. Git
/// compares patch IDs only while the upstream contains `base`, and so does this.
///
/// As Git does without a commit-graph, this trusts that no commit is older than its parents.
/// The result depends on the three commits alone, so it is the same each time it is asked
/// for while a rebase is stopped.
pub fn todo(
    repo: &gix::Repository,
    range: &Range,
    cancellation: &Cancellation,
) -> crate::Result<Todo> {
    let mut walk = Walk {
        objects: Reader::new(repo, cancellation),
        seen: HashMap::new(),
        queue: BinaryHeap::new(),
        one_sided_queued: 0,
    };
    walk.reach(range.original, BRANCH)?;
    walk.reach(range.onto, ONTO)?;
    walk.reach(range.base, BASE)?;
    // Git's rule for the end: no queued commit is one-sided, and every queued commit is
    // older than all one-sided ones, so none of them can have such a commit as an ancestor.
    let mut oldest_one_sided = i64::MAX;
    while let Some(&(time, id)) = walk.queue.peek() {
        if walk.one_sided_queued == 0 && time < oldest_one_sided {
            break;
        }
        walk.queue.pop();
        let commit = walk.seen.get_mut(&id).expect("queued commits were seen");
        commit.queued = false;
        let from = commit.from;
        if one_sided(from) {
            walk.one_sided_queued -= 1;
            oldest_one_sided = oldest_one_sided.min(time);
        }
        for parent in commit.parents.clone() {
            walk.reach(parent, from)?;
        }
    }

    // Git's `--topo-order`: a commit comes after all its children, and the lines of history
    // that a merge joins are not mixed. The line of the last parent comes first.
    let Walk { objects, seen, .. } = walk;
    let visible = |id: &gix::ObjectId| seen.get(id).is_some_and(|commit| commit.from == BRANCH);
    let mut children: HashMap<gix::ObjectId, usize> = HashMap::new();
    for commit in seen.values().filter(|commit| commit.from == BRANCH) {
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

    // The commits that only the upstream has. They count only if the upstream contains the
    // base: otherwise the upstream was rewritten, and Git replays every commit as it is.
    let compare = seen[&range.base].from & ONTO != 0;
    let upstream = seen.iter().filter(|(_, commit)| commit.from == ONTO);
    let upstream: Vec<_> = upstream.map(|(id, _)| *id).collect();
    let applied = match compare {
        true => applied(&objects, &commits, &upstream)?,
        false => Vec::new(),
    };
    commits.retain(|id| !applied.contains(id));
    Ok(Todo { commits, applied })
}

/// The commits among `commits` whose patch ID is that of one of the `upstream` commits.
///
/// Like Git, compare the names of the changed files first, and read file contents only
/// for commits that agree in those. A commit that changes nothing is never left out.
fn applied(
    objects: &Reader<'_>,
    commits: &[gix::ObjectId],
    upstream: &[gix::ObjectId],
) -> crate::Result<Vec<gix::ObjectId>> {
    let mut applied = Vec::new();
    if commits.is_empty() || upstream.is_empty() {
        return Ok(applied);
    }
    let mut state = gix::diff::tree::State::default();
    let mut by_header: HashMap<gix::ObjectId, Vec<gix::ObjectId>> = HashMap::new();
    for &id in upstream {
        objects.cancellation().check()?;
        if let Some(patch) = Patch::of(objects, id, &mut state)?
            && !patch.is_empty()
        {
            by_header.entry(patch.header_id()?).or_default().push(id);
        }
    }
    // The full IDs of upstream commits, each computed when it is first needed.
    let mut full: HashMap<gix::ObjectId, gix::ObjectId> = HashMap::new();
    for &id in commits {
        objects.cancellation().check()?;
        let Some(patch) = Patch::of(objects, id, &mut state)? else {
            continue;
        };
        if patch.is_empty() {
            continue;
        }
        let Some(candidates) = by_header.get(&patch.header_id()?) else {
            continue;
        };
        let patch_id = patch.id(objects)?;
        for &candidate in candidates {
            let known = match full.get(&candidate) {
                Some(known) => *known,
                None => {
                    let patch = Patch::of(objects, candidate, &mut state)?;
                    let patch = patch.expect("the upstream commit had a patch before");
                    let known = patch.id(objects)?;
                    full.insert(candidate, known);
                    known
                }
            };
            if known == patch_id {
                applied.push(id);
                break;
            }
        }
    }
    Ok(applied)
}

fn unsupported(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}
