//! Git's patch ID of a commit: a hash of what the commit changes, without line numbers and
//! without whitespace.
//!
//! `git rebase` leaves out a commit whose patch ID is that of a commit the upstream has.
//! What is hashed here follows `diff_get_patch_id()` in Git's `diff.c` byte for byte, so an
//! ID computed here is the ID that Git computes, and `git patch-id --stable` prints. The ID
//! depends on the objects of the commit alone: no configuration, index or attribute file.

use std::{io, ops::ControlFlow};

use gix::{
    bstr::{BStr, BString},
    diff::{
        blob::{
            Algorithm, Diff, InternedInput, UnifiedDiff,
            unified_diff::{ConsumeHunk, ContextSize, DiffLineKind, HunkHeader},
        },
        tree::{Recorder, Visit, recorder, visit},
    },
    objs::{CommitRefIter, Kind, TreeRefIter, commit::ref_iter::Token, tree::EntryMode},
};

use crate::object_database::Reader;

/// A commit that changes more paths than this has no patch ID here, so it is never left out.
const MAX_CHANGES: usize = 65_536;
/// Git looks for a NUL byte this far into a file to call it binary.
const BINARY_PROBE: usize = 8_000;
/// A file larger than this counts as binary, so that it is never compared line by line.
/// Git draws this line at 512 MiB.
const MAX_TEXT_BYTES: u64 = 16 * 1024 * 1024;

/// One file that a commit adds, removes or changes.
struct Change {
    path: BString,
    old: Option<(EntryMode, gix::ObjectId)>,
    new: Option<(EntryMode, gix::ObjectId)>,
}

/// The changes of one commit to its only parent, ready to be hashed.
pub(crate) struct Patch {
    changes: Vec<Change>,
}

impl Patch {
    /// Read what `commit` changes. `None` for a merge commit, which has no patch ID in Git,
    /// and for a commit that changes too many paths.
    pub(crate) fn of(
        objects: &Reader<'_>,
        commit: gix::ObjectId,
        state: &mut gix::diff::tree::State,
    ) -> crate::Result<Option<Self>> {
        let (tree, parents) = tree_and_parents(objects, commit)?;
        let parent_tree = match parents[..] {
            [] => None,
            [parent] => Some(tree_and_parents(objects, parent)?.0),
            _ => return Ok(None),
        };
        let old = parent_tree
            .map(|id| objects.load_kind(id, Kind::Tree))
            .transpose()?;
        let new = objects.load_kind(tree, Kind::Tree)?;
        let old_data = old.as_ref().map_or(&[][..], |tree| tree.data.as_slice());
        let mut visitor = Bounded {
            recorder: Recorder::default(),
            objects,
            error: None,
        };
        let result = gix::diff::tree(
            TreeRefIter::from_bytes(old_data, commit.kind()),
            TreeRefIter::from_bytes(&new.data, commit.kind()),
            state,
            &objects.repository().objects,
            &mut visitor,
        );
        if let Some(error) = visitor.error {
            return Err(error);
        }
        if visitor.recorder.records.len() > MAX_CHANGES {
            return Ok(None);
        }
        result?;

        // Git compares files only. A directory that turns into a file, or a file into a
        // directory, shows as the file being added or removed.
        let file = |mode: EntryMode, id| (!mode.is_tree()).then_some((mode, id));
        let mut changes = Vec::new();
        for record in visitor.recorder.records {
            let (path, old, new) = match record {
                recorder::Change::Addition {
                    entry_mode,
                    oid,
                    path,
                    ..
                } => (path, None, file(entry_mode, oid)),
                recorder::Change::Deletion {
                    entry_mode,
                    oid,
                    path,
                    ..
                } => (path, file(entry_mode, oid), None),
                recorder::Change::Modification {
                    previous_entry_mode,
                    previous_oid,
                    entry_mode,
                    oid,
                    path,
                } => (
                    path,
                    file(previous_entry_mode, previous_oid),
                    file(entry_mode, oid),
                ),
            };
            if old.is_some() || new.is_some() {
                changes.push(Change { path, old, new });
            }
        }
        Ok(Some(Patch { changes }))
    }

    /// Whether the commit changes no file.
    pub(crate) fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// The ID of the names and modes of the changed files alone. It is cheap, and two
    /// commits with different header IDs have different patch IDs.
    pub(crate) fn header_id(&self) -> crate::Result<gix::ObjectId> {
        let mut sum = Sum::default();
        for change in &self.changes {
            let mut hasher = gix::hash::hasher(gix::hash::Kind::Sha1);
            change.hash_header(&mut hasher);
            sum.add(hasher.try_finalize()?);
        }
        Ok(sum.id())
    }

    /// The patch ID, as `git patch-id --stable` prints it.
    pub(crate) fn id(&self, objects: &Reader<'_>) -> crate::Result<gix::ObjectId> {
        let mut sum = Sum::default();
        for change in &self.changes {
            objects.cancellation().check()?;
            let mut hasher = gix::hash::hasher(gix::hash::Kind::Sha1);
            change.hash_header(&mut hasher);
            change.hash_content(objects, &mut hasher)?;
            sum.add(hasher.try_finalize()?);
        }
        Ok(sum.id())
    }
}

impl Change {
    fn hash_header(&self, hasher: &mut gix::hash::Hasher) {
        let path = without_space(&self.path);
        hasher.update(b"diff--gita/");
        hasher.update(&path);
        hasher.update(b"b/");
        hasher.update(&path);
        let mode = |mode: EntryMode| format!("{:06o}", mode.value());
        match (self.old, self.new) {
            (None, Some((new, _))) => {
                hasher.update(b"newfilemode");
                hasher.update(mode(new).as_bytes());
            }
            (Some((old, _)), None) => {
                hasher.update(b"deletedfilemode");
                hasher.update(mode(old).as_bytes());
            }
            (Some((old, _)), Some((new, _))) if old != new => {
                hasher.update(b"oldmode");
                hasher.update(mode(old).as_bytes());
                hasher.update(b"newmode");
                hasher.update(mode(new).as_bytes());
            }
            _ => {}
        }
    }

    fn hash_content(&self, objects: &Reader<'_>, hasher: &mut gix::hash::Hasher) -> crate::Result {
        let old = self.old.map(|side| content(objects, side)).transpose()?;
        let new = self.new.map(|side| content(objects, side)).transpose()?;
        let binary = |side: &Option<Option<Vec<u8>>>| match side {
            Some(None) => true,
            Some(Some(data)) => data[..data.len().min(BINARY_PROBE)].contains(&0),
            None => false,
        };
        if binary(&old) || binary(&new) {
            // A binary file is named by the objects it had and has. A missing side is null.
            for side in [self.old, self.new] {
                let id =
                    side.map_or_else(|| gix::ObjectId::null(gix::hash::Kind::Sha1), |side| side.1);
                hasher.update(id.to_hex().to_string().as_bytes());
            }
            return Ok(());
        }
        let path = without_space(&self.path);
        match self.old {
            Some(_) => {
                hasher.update(b"---a/");
                hasher.update(&path);
            }
            None => hasher.update(b"---/dev/null"),
        }
        match self.new {
            Some(_) => {
                hasher.update(b"+++b/");
                hasher.update(&path);
            }
            None => hasher.update(b"+++/dev/null"),
        }
        let old = old.flatten().unwrap_or_default();
        let new = new.flatten().unwrap_or_default();
        // The diff that Git makes for a patch ID: Myers, hunks moved down as far as they
        // go, three lines of context, and no regard for the configured algorithm.
        let input = InternedInput::new(old.as_slice(), new.as_slice());
        let mut diff = Diff::compute(Algorithm::Myers, &input);
        diff.postprocess_no_heuristic(&input);
        let lines = Lines { hasher };
        UnifiedDiff::new(&diff, &input, lines, ContextSize::symmetrical(3)).consume()?;
        Ok(())
    }
}

/// The bytes that Git compares for one side of a change. `None` for a file that is too
/// large to be compared as text.
fn content(
    objects: &Reader<'_>,
    (mode, id): (EntryMode, gix::ObjectId),
) -> crate::Result<Option<Vec<u8>>> {
    if mode.is_commit() {
        // Git shows a submodule as this one line.
        return Ok(Some(format!("Subproject commit {id}\n").into_bytes()));
    }
    let header = objects.repository().find_header(id)?;
    if header.kind() != Kind::Blob {
        return Err(invalid(format!("object {id} of a file is not a blob")).into());
    }
    if header.size() > MAX_TEXT_BYTES {
        return Ok(None);
    }
    Ok(Some(objects.load_kind(id, Kind::Blob)?.detach().data))
}

/// Hashes the lines of a diff the way Git does for a patch ID: without hunk headers, and
/// without whitespace, which takes the marker of a context line with it.
struct Lines<'a> {
    hasher: &'a mut gix::hash::Hasher,
}

impl ConsumeHunk for Lines<'_> {
    type Out = ();

    fn consume_hunk(
        &mut self,
        _header: HunkHeader,
        lines: &[(DiffLineKind, &[u8])],
    ) -> io::Result<()> {
        for &(kind, line) in lines {
            match kind {
                DiffLineKind::Context => {}
                DiffLineKind::Add => self.hasher.update(b"+"),
                DiffLineKind::Remove => self.hasher.update(b"-"),
            }
            self.hasher.update(&without_space(line));
        }
        Ok(())
    }

    fn finish(self) {}
}

/// Git's `remove_space()`: drop blanks, tabs, newlines and carriage returns.
fn without_space(bytes: &[u8]) -> Vec<u8> {
    let space = |byte: &u8| matches!(byte, b' ' | b'\t' | b'\n' | b'\r');
    bytes.iter().copied().filter(|byte| !space(byte)).collect()
}

/// Git adds up the hashes of the changed files, so their order does not matter.
#[derive(Default)]
struct Sum([u8; 20]);

impl Sum {
    fn add(&mut self, hash: gix::ObjectId) {
        let mut carry = 0_u16;
        for (sum, byte) in self.0.iter_mut().zip(hash.as_bytes()) {
            carry += u16::from(*sum) + u16::from(*byte);
            *sum = carry as u8;
            carry >>= 8;
        }
    }

    fn id(&self) -> gix::ObjectId {
        gix::ObjectId::from_bytes_or_panic(&self.0)
    }
}

/// The tree and the parents of a commit.
fn tree_and_parents(
    objects: &Reader<'_>,
    commit: gix::ObjectId,
) -> crate::Result<(gix::ObjectId, Vec<gix::ObjectId>)> {
    let object = objects.load_kind(commit, Kind::Commit)?;
    let mut tree = None;
    let mut parents = Vec::new();
    for token in CommitRefIter::from_bytes(&object.data, commit.kind()) {
        match token? {
            Token::Tree { id } => tree = Some(id),
            Token::Parent { id } => parents.push(id),
            _ => break,
        }
    }
    let tree = tree.ok_or_else(|| invalid(format!("commit {commit} has no tree")))?;
    Ok((tree, parents))
}

/// Records the changes between two trees, and stops when there are too many of them.
struct Bounded<'a, 'repo> {
    recorder: Recorder,
    objects: &'a Reader<'repo>,
    error: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Visit for Bounded<'_, '_> {
    fn pop_front_tracked_path_and_set_current(&mut self) {
        self.recorder.pop_front_tracked_path_and_set_current();
    }

    fn push_back_tracked_path_component(&mut self, component: &BStr) {
        self.recorder.push_back_tracked_path_component(component);
    }

    fn push_path_component(&mut self, component: &BStr) {
        self.recorder.push_path_component(component);
    }

    fn pop_path_component(&mut self) {
        self.recorder.pop_path_component();
    }

    fn visit(&mut self, change: visit::Change) -> ControlFlow<()> {
        if let Err(error) = self.objects.cancellation().check() {
            self.error = Some(error);
            return ControlFlow::Break(());
        }
        if self.recorder.records.len() > MAX_CHANGES {
            return ControlFlow::Break(());
        }
        self.recorder.visit(change)
    }
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// The patch ID of `commit`, or `None` if Git gives it none.
pub fn of(
    repo: &gix::Repository,
    commit: gix::ObjectId,
    cancellation: &crate::cancellation::Cancellation,
) -> crate::Result<Option<gix::ObjectId>> {
    let objects = Reader::new(repo, cancellation);
    let mut state = gix::diff::tree::State::default();
    match Patch::of(&objects, commit, &mut state)? {
        Some(patch) => patch.id(&objects).map(Some),
        None => Ok(None),
    }
}
