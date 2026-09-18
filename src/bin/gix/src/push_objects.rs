use std::{collections::HashSet, io, ops::ControlFlow};

use gix::objs::{
    CommitRefIter, Kind, TagRef, TreeRefIter, commit::ref_iter::Token, tree::EntryKind,
};

use crate::{cancellation::Cancellation, object_database::Reader};

/// Maximum number of commit or emitted object IDs retained by selection.
pub const MAX_OUTGOING_OBJECTS: usize = 65_536;
const MAX_TREE_CHANGES: usize = 65_536;
const MAX_PARENT_LINKS: usize = 131_072;
/// A bounded, ordered, deduplicated set of complete objects for one push source.
pub struct Selection {
    ids: Vec<gix::ObjectId>,
}

struct Builder {
    ids: Vec<gix::ObjectId>,
    seen: HashSet<gix::ObjectId>,
}

impl Selection {
    /// IDs in deterministic first-observed order.
    pub fn ids(&self) -> &[gix::ObjectId] {
        &self.ids
    }
}

/// Select every complete object needed to send `source`, omitting only ancestry
/// proven reachable from locally available advertised objects.
pub fn select(
    repo: &gix::Repository,
    source: gix::ObjectId,
    advertised: &[gix::ObjectId],
    cancellation: &Cancellation,
) -> crate::Result<Selection> {
    cancellation.check()?;
    let result = select_inner(repo, source, advertised, cancellation);
    match result {
        Ok(selection) => {
            cancellation.check()?;
            Ok(selection)
        }
        Err(error) => Err(cancellation.normalize_error(error)),
    }
}

fn select_inner(
    repo: &gix::Repository,
    source: gix::ObjectId,
    advertised: &[gix::ObjectId],
    cancellation: &Cancellation,
) -> crate::Result<Selection> {
    crate::object_database::validate_full(repo, "push")?;
    let objects = Reader::new(repo, cancellation);
    let mut selection = Builder {
        ids: Vec::new(),
        seen: HashSet::new(),
    };
    let (target, kind) = peel_source(&objects, source, &mut selection)?;
    match kind {
        Kind::Commit => select_commits(&objects, target, advertised, &mut selection)?,
        Kind::Tree => select_tree(
            &objects,
            None,
            target,
            &mut selection,
            &mut gix::diff::tree::State::default(),
        )?,
        Kind::Blob => {
            selection.insert(target)?;
        }
        Kind::Tag => unreachable!("peeling stops at a non-tag"),
    }
    Ok(Selection { ids: selection.ids })
}

fn peel_source(
    objects: &Reader<'_>,
    source: gix::ObjectId,
    selection: &mut Builder,
) -> crate::Result<(gix::ObjectId, Kind)> {
    let object = objects.load(source)?;
    peel_tags(objects, source, object, |id| selection.insert(id).map(drop))
}

fn select_commits(
    objects: &Reader<'_>,
    tip: gix::ObjectId,
    advertised: &[gix::ObjectId],
    selection: &mut Builder,
) -> crate::Result {
    let reachable = preflight_commits(objects, tip)?;
    let hidden = hidden_commits(objects, advertised, &reachable)?;
    drop(reachable);

    objects.cancellation().check()?;
    let walk = objects
        .repository()
        .find_commit(tip)?
        .ancestors()
        .with_hidden(hidden)
        .use_commit_graph(false)
        .all()?;
    let mut tree_diff = gix::diff::tree::State::default();
    for info in walk {
        objects.cancellation().check()?;
        let id = info?.id;
        let object = objects.load_kind(id, Kind::Commit)?;
        let (root, first_parent) = commit_tree_and_first_parent(&object.data, id.kind())?;
        selection.insert(id)?;
        let left = first_parent
            .map(|parent| {
                let object = objects.load_kind(parent, Kind::Commit)?;
                commit_tree_and_first_parent(&object.data, parent.kind()).map(|parsed| parsed.0)
            })
            .transpose()?;
        select_tree(objects, left, root, selection, &mut tree_diff)?;
    }
    Ok(())
}

/// Prove ancestry with the same checked, bounded all-parent walk used for selection.
pub(crate) fn is_ancestor(
    repo: &gix::Repository,
    tip: gix::ObjectId,
    ancestor: gix::ObjectId,
    cancellation: &Cancellation,
) -> crate::Result<bool> {
    let reachable = preflight_commits(&Reader::new(repo, cancellation), tip)
        .map_err(|error| cancellation.normalize_error(error))?;
    cancellation.check()?;
    Ok(reachable.contains(&ancestor))
}

fn preflight_commits(
    objects: &Reader<'_>,
    tip: gix::ObjectId,
) -> crate::Result<HashSet<gix::ObjectId>> {
    let mut reachable = HashSet::new();
    let mut pending = Vec::new();
    let mut parent_links = 0;
    insert_bounded(&mut reachable, tip, "push history exceeds the commit limit")?;
    pending.try_reserve(1)?;
    pending.push(tip);
    while let Some(id) = pending.pop() {
        objects.cancellation().check()?;
        let object = objects.load_kind(id, Kind::Commit)?;
        let mut has_tree = false;
        for token in CommitRefIter::from_bytes(&object.data, id.kind()) {
            match token? {
                Token::Tree { .. } => has_tree = true,
                Token::Parent { id: parent } => {
                    count_visit(
                        &mut parent_links,
                        MAX_PARENT_LINKS,
                        "push history exceeds the parent-link limit",
                    )?;
                    if insert_bounded(
                        &mut reachable,
                        parent,
                        "push history exceeds the commit limit",
                    )? {
                        pending.try_reserve(1)?;
                        pending.push(parent);
                    }
                }
                _ => {}
            }
        }
        if !has_tree {
            return Err(invalid(format!("commit {id} has no tree")).into());
        }
    }
    Ok(reachable)
}

fn hidden_commits(
    objects: &Reader<'_>,
    advertised: &[gix::ObjectId],
    reachable: &HashSet<gix::ObjectId>,
) -> crate::Result<Vec<gix::ObjectId>> {
    let mut hidden = Vec::new();
    let mut seen = HashSet::new();
    for advertised in advertised {
        objects.cancellation().check()?;
        let hidden_id = if reachable.contains(advertised) {
            Some(*advertised)
        } else {
            peel_advertised(objects, *advertised, reachable)?
        };
        if let Some(id) = hidden_id
            && insert_bounded(&mut seen, id, "too many advertised commit tips")?
        {
            hidden.try_reserve(1)?;
            hidden.push(id);
        }
    }
    Ok(hidden)
}

fn peel_advertised(
    objects: &Reader<'_>,
    advertised: gix::ObjectId,
    reachable: &HashSet<gix::ObjectId>,
) -> crate::Result<Option<gix::ObjectId>> {
    let Some(object) = objects.try_load(advertised)? else {
        return Ok(None);
    };
    let (id, kind) = peel_tags(objects, advertised, object, |_| Ok(()))?;
    Ok((kind == Kind::Commit && reachable.contains(&id)).then_some(id))
}

fn peel_tags<'repo>(
    objects: &Reader<'repo>,
    mut current: gix::ObjectId,
    mut object: gix::Object<'repo>,
    mut visit: impl FnMut(gix::ObjectId) -> crate::Result,
) -> crate::Result<(gix::ObjectId, Kind)> {
    let mut tags = HashSet::new();
    while object.kind == Kind::Tag {
        if !insert_bounded(&mut tags, current, "annotated tag chain is too long")? {
            return Err(invalid("annotated tag chain contains a cycle").into());
        }
        visit(current)?;
        let tag = TagRef::from_bytes(&object.data, current.kind())?;
        let target = tag.target();
        let next = objects.load(target)?;
        if next.kind != tag.target_kind {
            return Err(invalid(format!(
                "tag {current} declares {:?} target {target}, which is {:?}",
                tag.target_kind, next.kind
            ))
            .into());
        }
        current = target;
        object = next;
    }
    Ok((current, object.kind))
}

fn select_tree(
    objects: &Reader<'_>,
    left: Option<gix::ObjectId>,
    right: gix::ObjectId,
    selection: &mut Builder,
    state: &mut gix::diff::tree::State,
) -> crate::Result {
    let left = left
        .map(|id| objects.load_kind(id, Kind::Tree))
        .transpose()?;
    let right_object = objects.load_kind(right, Kind::Tree)?;
    selection.insert(right)?;
    let left_data = left
        .as_ref()
        .map_or(&[][..], |object| object.data.as_slice());
    let mut visitor = TreeVisitor {
        objects,
        selection,
        error: None,
        changes: 0,
    };
    let result = gix::diff::tree(
        TreeRefIter::from_bytes(left_data, right.kind()),
        TreeRefIter::from_bytes(&right_object.data, right.kind()),
        state,
        &objects.repository().objects,
        &mut visitor,
    );
    if let Some(error) = visitor.error {
        return Err(error);
    }
    result?;
    Ok(())
}

struct TreeVisitor<'a, 'repo> {
    objects: &'a Reader<'repo>,
    selection: &'a mut Builder,
    error: Option<Box<dyn std::error::Error + Send + Sync>>,
    changes: usize,
}

impl gix::diff::tree::Visit for TreeVisitor<'_, '_> {
    fn pop_front_tracked_path_and_set_current(&mut self) {}
    fn push_back_tracked_path_component(&mut self, _component: &gix::bstr::BStr) {}
    fn push_path_component(&mut self, _component: &gix::bstr::BStr) {}
    fn pop_path_component(&mut self) {}

    fn visit(&mut self, change: gix::diff::tree::visit::Change) -> ControlFlow<()> {
        let result = (|| -> crate::Result {
            count_visit(
                &mut self.changes,
                MAX_TREE_CHANGES,
                "tree comparison exceeds the change limit",
            )?;
            self.objects.cancellation().check()?;
            let (id, mode) = match change {
                gix::diff::tree::visit::Change::Deletion {
                    oid, entry_mode, ..
                } => {
                    // The diff queues deleted trees too; validate before it reads them.
                    if entry_mode.is_tree() {
                        self.objects.load_kind(oid, Kind::Tree)?;
                    }
                    return Ok(());
                }
                gix::diff::tree::visit::Change::Addition {
                    oid, entry_mode, ..
                } => (oid, entry_mode),
                gix::diff::tree::visit::Change::Modification {
                    previous_oid,
                    previous_entry_mode,
                    oid,
                    entry_mode,
                } => {
                    if previous_entry_mode.is_tree() {
                        self.objects.load_kind(previous_oid, Kind::Tree)?;
                    }
                    (oid, entry_mode)
                }
            };
            let kind = match mode.kind() {
                EntryKind::Tree => Kind::Tree,
                EntryKind::Blob | EntryKind::BlobExecutable | EntryKind::Link => Kind::Blob,
                EntryKind::Commit => return Ok(()),
            };
            self.objects.load_kind(id, kind)?;
            self.selection.insert(id)?;
            Ok(())
        })();
        match result {
            Ok(()) => ControlFlow::Continue(()),
            Err(error) => {
                self.error = Some(error);
                ControlFlow::Break(())
            }
        }
    }
}

fn count_visit(count: &mut usize, limit: usize, message: &'static str) -> crate::Result {
    *count = count
        .checked_add(1)
        .filter(|count| *count <= limit)
        .ok_or_else(|| invalid(message))?;
    Ok(())
}

impl Builder {
    fn insert(&mut self, id: gix::ObjectId) -> crate::Result<bool> {
        if self.seen.contains(&id) {
            return Ok(false);
        }
        if self.ids.len() == MAX_OUTGOING_OBJECTS {
            return Err(invalid("push requires too many outgoing objects").into());
        }
        self.seen.try_reserve(1)?;
        self.ids.try_reserve(1)?;
        self.seen.insert(id);
        self.ids.push(id);
        Ok(true)
    }
}

fn commit_tree_and_first_parent(
    data: &[u8],
    hash: gix::hash::Kind,
) -> crate::Result<(gix::ObjectId, Option<gix::ObjectId>)> {
    let mut tree = None;
    let mut first_parent = None;
    for token in CommitRefIter::from_bytes(data, hash) {
        match token? {
            Token::Tree { id } => tree = Some(id),
            Token::Parent { id } if first_parent.is_none() => first_parent = Some(id),
            _ => {}
        }
    }
    Ok((
        tree.ok_or_else(|| invalid("commit has no tree"))?,
        first_parent,
    ))
}

fn insert_bounded(
    set: &mut HashSet<gix::ObjectId>,
    id: gix::ObjectId,
    limit: &'static str,
) -> crate::Result<bool> {
    if set.contains(&id) {
        return Ok(false);
    }
    if set.len() == MAX_OUTGOING_OBJECTS {
        return Err(invalid(limit).into());
    }
    set.try_reserve(1)?;
    Ok(set.insert(id))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_counters_reject_the_first_excess_visit() -> crate::Result {
        for limit in [MAX_TREE_CHANGES, MAX_PARENT_LINKS] {
            let mut count = limit - 1;
            count_visit(&mut count, limit, "visit limit")?;
            assert!(count_visit(&mut count, limit, "visit limit").is_err());
            assert_eq!(count, limit);
        }
        Ok(())
    }
}
