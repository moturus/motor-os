//! `gix apply`: apply patches to the files of the worktree, to the index, or to both.
//!
//! The steps are those of `apply.c` in Git. Every patch of a patch file is checked first,
//! against the files as the patches before it leave them. Only if all of them apply is
//! anything written, so a patch file that does not apply changes nothing. Patch files are
//! applied one after the other, and the index is written once, after the last of them: a
//! patch file that does not apply leaves the index as it was, also when the patch files
//! before it have changed files of the worktree.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, mpsc},
    thread,
    time::Duration,
};

use gix::{
    bstr::{BStr, BString, ByteSlice},
    index::entry::{Flags, Mode, Stage, Stat},
    objs::{Kind, Write as _},
    worktree::stack::state::attributes::Source,
};

use crate::{
    cancellation::Cancellation,
    checkout,
    mutation::{self, Guard},
    patch::{Image, Parser, Patch, kind},
    repository::OpenedRepository,
    selection,
    stage_blob::Converter,
    tracked_filters, transition,
};

/// The most patch text that one patch file, or standard input, may hold.
pub const MAX_PATCH_BYTES: u64 = 128 * 1024 * 1024;

/// How long a wait for standard input goes on before it looks for a cancellation.
const STDIN_POLL: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    /// Only say whether the patches apply.
    pub check: bool,
    /// Apply the patches backwards.
    pub reverse: bool,
    /// Change the index too. The files have to be as the index has them.
    pub index: bool,
    /// Change the index only, and read the files from it.
    pub cached: bool,
    /// How many leading directories to remove from the names in a patch.
    pub strip: Option<usize>,
}

impl Options {
    /// Whether the patches change the index, and so read what they change from it.
    fn uses_index(self) -> bool {
        self.index || self.cached
    }
}

/// The contents and the mode of a file.
#[derive(Clone)]
struct File {
    data: Vec<u8>,
    mode: Mode,
}

/// What patches leave at the paths that they change. `None` means that no file is there.
type Files = BTreeMap<BString, Option<File>>;

/// The paths that the patches of one patch file take away from where they are.
#[derive(Default)]
struct Doomed {
    /// By a deletion or by a rename.
    removed: BTreeSet<BString>,
    /// By a rename, which reads the file of the worktree whatever the patches before it
    /// have left at its path.
    renamed: BTreeSet<BString>,
}

/// The reasons why patches do not apply, in the words of Git.
#[derive(Debug)]
struct Rejected(Vec<String>);

impl fmt::Display for Rejected {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // One reason per line. `main` writes "gix: " in front of the first line.
        formatter.write_str(&self.0.join("\ngix: "))
    }
}

impl std::error::Error for Rejected {}

/// Apply the patch files `patches`, or the patch on `stdin` if there are none.
pub fn run(
    opened: &OpenedRepository,
    options: Options,
    patches: &[PathBuf],
    stdin: impl Read + Send + 'static,
    cancellation: &Cancellation,
) -> crate::Result {
    let mut prefix = opened.prefix.clone();
    if !prefix.is_empty() {
        prefix.push(b'/');
    }
    let mut parser = Parser::new(options.strip, &prefix);
    let mut stdin = Some(stdin);
    let mut target = None;
    let stdin_only = [PathBuf::from("-")];
    for path in if patches.is_empty() {
        &stdin_only
    } else {
        patches
    } {
        cancellation.check()?;
        let text = if path.as_os_str() != "-" {
            let file = fs::File::open(path).map_err(|error| {
                let message = format!("can't open patch '{}': {error}", path.display());
                io::Error::new(error.kind(), message)
            })?;
            read_patch(file)?
        } else if let Some(stdin) = stdin.take() {
            read_stdin(stdin, cancellation)?
        } else {
            // Standard input was read to its end.
            Vec::new()
        };
        let mut list = parser.parse(&text)?;
        if list.is_empty() {
            return Err(invalid("No valid patches in input".into()));
        }
        if options.reverse {
            list.iter_mut().for_each(Patch::reverse);
            list.reverse();
        }
        // Started in a subdirectory, apply leaves out the patches for files outside of it,
        // as Git does. A rename is selected by its destination in the requested direction.
        list.retain(|patch| {
            let name = patch.new_name.as_ref().or(patch.old_name.as_ref());
            name.is_some_and(|name| name.len() > prefix.len() && name.starts_with(&prefix))
        });
        if list.is_empty() {
            continue;
        }
        if options.check {
            // A check changes nothing: it needs no lock, and every patch file is checked
            // against the same files.
            let index = opened.repo.index_or_empty()?;
            mutation::validate_index(&index, !options.uses_index())?;
            Session::new(opened, &index, options, cancellation)?.check_patches(list)?;
            continue;
        }
        let target = match &mut target {
            Some(target) => target,
            None => target.insert(Target::acquire(opened, options, cancellation)?),
        };
        target.apply(list)?;
    }
    if let Some(target) = target {
        target.publish()?;
    }
    cancellation.check()
}

/// Read a whole patch, which is bounded like every input that gix holds in memory.
fn read_patch(input: impl Read) -> crate::Result<Vec<u8>> {
    let mut text = Vec::new();
    input.take(MAX_PATCH_BYTES + 1).read_to_end(&mut text)?;
    if text.len() as u64 > MAX_PATCH_BYTES {
        return Err(invalid("the patch exceeds the 128 MiB limit".into()));
    }
    Ok(text)
}

/// Read the patch on standard input.
///
/// A terminal of Motor OS has no end of input, and Ctrl+C does not end a program that
/// handles it, as gix does. So another thread reads, and this one waits for it and for a
/// cancellation. If that comes first, the reader is left behind and ends with the program.
fn read_stdin(
    stdin: impl Read + Send + 'static,
    cancellation: &Cancellation,
) -> crate::Result<Vec<u8>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("gix-stdin".into())
        .spawn(move || _ = sender.send(read_patch(stdin)))?;
    loop {
        match receiver.recv_timeout(STDIN_POLL) {
            Ok(text) => return text,
            Err(mpsc::RecvTimeoutError::Timeout) => cancellation.check()?,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(io::Error::other("the reader of standard input stopped").into());
            }
        }
    }
}

/// What the patch files of a run that changes something share: the locks, and the index
/// as the patch files so far leave it.
///
/// As in Git, the index is written once, after the last patch file. A patch file that does
/// not apply ends the run before that, and so leaves the index as it was.
struct Target<'a> {
    opened: &'a OpenedRepository,
    options: Options,
    cancellation: &'a Cancellation,
    guard: Guard,
    index: gix::index::State,
    /// The paths whose entries in `index` are not those of the locked index.
    paths: BTreeSet<BString>,
    /// The directory that the command was started in. It stays when it becomes empty.
    stay: Option<BString>,
}

impl<'a> Target<'a> {
    fn acquire(
        opened: &'a OpenedRepository,
        options: Options,
        cancellation: &'a Cancellation,
    ) -> crate::Result<Self> {
        let guard = if options.uses_index() {
            Guard::acquire(&opened.repo)?
        } else {
            Guard::acquire_for_worktree(&opened.repo)?
        };
        Ok(Target {
            opened,
            options,
            cancellation,
            index: (**guard.index()).clone(),
            guard,
            paths: BTreeSet::new(),
            stay: checkout::start_directory(workdir(&opened.repo)?),
        })
    }

    /// Apply the patches of one patch file: all of them, or none. The files of the
    /// worktree change at once, the index of this run takes the changes for `publish()`.
    fn apply(&mut self, patches: Vec<Patch<'_>>) -> crate::Result {
        let mut session = Session::new(self.opened, &self.index, self.options, self.cancellation)?;
        let files = session.check_patches(patches)?;
        let Session { observed, .. } = session;

        // The index needs the new blobs in the repository. The worktree alone does not, so
        // that a plain `apply` adds nothing to it.
        let mut objects = self.opened.repo.objects.clone();
        if !self.options.uses_index() {
            objects.enable_object_memory();
        }
        // The index as the patches leave it. Without `--index` it only tells checkout what
        // to write and where the attributes are.
        let mut staged = self.index.clone();
        staged.remove_entries(|_, path, _| files.contains_key(path));
        let mut written = BTreeSet::new();
        let mut removed = BTreeSet::new();
        for (path, file) in files {
            self.cancellation.check()?;
            if let Some(file) = file {
                let id = objects.write_buf(Kind::Blob, &file.data)?;
                let stat = Stat::default();
                staged.dangerously_push_entry(stat, id, Flags::empty(), file.mode, path.as_bstr());
                written.insert(path);
            } else {
                removed.insert(path);
            }
        }
        staged.sort_entries();
        if self.options.uses_index() {
            for path in &written {
                let mut below = path.clone();
                below.push(b'/');
                let above = path
                    .iter()
                    .enumerate()
                    .filter(|(_, byte)| **byte == b'/')
                    .any(|(slash, _)| staged.entry_range(path[..slash].as_bstr()).is_some());
                if above || staged.prefixed_entries_range(below.as_bstr()).is_some() {
                    return Err(invalid(format!(
                        "'{}' appears as both a file and as a directory",
                        show(path.as_bstr())
                    )));
                }
            }
            mutation::preflight_index(staged.clone())?;
        }

        if !self.options.cached {
            staged = self.write_worktree(staged, objects, &written, &removed, &observed)?;
        }
        if self.options.uses_index() {
            self.index = staged;
            self.paths.append(&mut written);
            self.paths.append(&mut removed);
        }
        Ok(())
    }

    /// Replace the files of the worktree that the patches change, and return `staged`
    /// with the state of the files that were written.
    ///
    /// Until the first file is removed, an error leaves the worktree as it was. An error
    /// after that is an `Incomplete` error.
    fn write_worktree(
        &self,
        mut staged: gix::index::State,
        objects: gix::OdbHandle,
        written: &BTreeSet<BString>,
        removed: &BTreeSet<BString>,
        observed: &BTreeMap<BString, Stat>,
    ) -> crate::Result<gix::index::State> {
        let repo = &self.opened.repo;
        let workdir = workdir(repo)?;
        // Checkout writes the files of the patches and leaves every other file alone.
        for (entry, path) in staged.entries_mut_with_paths() {
            if !written.contains(path) {
                entry.flags.insert(Flags::SKIP_WORKTREE);
            }
        }
        let mut options = repo.checkout_options(Source::WorktreeThenIdMapping)?;
        options.fs.symlink = false;
        options.thread_limit = Some(1);
        // The files that change are removed first, and every file is created anew.
        options.destination_is_initially_empty = true;
        options.overwrite_existing = false;
        options.keep_going = false;
        let mut objects = objects.into_arc()?;
        objects.ignore_replacements = true;

        // No file may have changed since it was read, and no file may have appeared.
        let mut removals = Vec::new();
        let mut directories = Vec::new();
        for path in written.union(removed) {
            self.cancellation.check()?;
            let absolute = workdir.join(gix::path::from_bstr(path.as_bstr()).as_ref());
            let metadata = selection::checked_symlink_metadata(workdir, path.as_bstr())?;
            let unchanged = match (observed.get(path), metadata) {
                (None, None) => true,
                // A directory whose files the patches remove. It makes way for a file: the
                // check has made sure that nothing is left in it.
                (None, Some(metadata)) if metadata.is_dir() => {
                    directories.push(absolute);
                    true
                }
                (Some(stat), Some(metadata)) if metadata.is_file() => {
                    removals.push(absolute.clone());
                    let now = gix::index::fs::Metadata::from_path_no_follow(&absolute)?;
                    Stat::from_fs(&now)? == *stat
                }
                _ => false,
            };
            if !unchanged {
                return Err(invalid(format!(
                    "worktree path '{}' changed while the patch was applied",
                    show(path.as_bstr())
                )));
            }
        }
        self.cancellation.check()?;

        // From here on the work is not interrupted: the new contents exist in memory only.
        let install = || -> crate::Result {
            for path in &removals {
                fs::remove_file(path)?;
            }
            for directory in &directories {
                remove_empty_tree(directory)?;
            }
            // Checkout must not be given an index without entries, so only call it with work.
            if !written.is_empty() {
                let discard = gix::features::progress::Discard;
                let outcome = gix::worktree::state::checkout(
                    &mut staged,
                    workdir,
                    objects,
                    &discard,
                    &discard,
                    &AtomicBool::new(false),
                    options,
                )?;
                checkout::check_outcome(&outcome)?;
            }
            // As Git: a directory that a deleted file leaves empty goes away with it, but
            // not the one that the command was started in.
            for path in removed {
                checkout::prune_empty_parents(workdir, path.as_bstr(), |directory| {
                    Ok(self.stay.as_ref().is_some_and(|stay| stay == directory))
                })?;
            }
            Ok(())
        };
        install().map_err(|source| Incomplete { source })?;
        // The mark was for checkout. The index of this run has every file.
        for entry in staged.entries_mut() {
            entry.flags.remove(Flags::SKIP_WORKTREE);
        }
        Ok(staged)
    }

    /// Write the index of this run, now that every patch file has applied.
    fn publish(self) -> crate::Result {
        if !self.options.uses_index() {
            return Ok(());
        }
        let Target {
            options,
            mut guard,
            index: staged,
            paths,
            ..
        } = self;
        guard
            .publish_edited_index(|index| {
                index.remove_entries(|_, path, _| paths.contains(path));
                for entry in staged.entries() {
                    let path = entry.path(&staged);
                    if paths.contains(path) {
                        let flags = Flags::empty();
                        index.dangerously_push_entry(entry.stat, entry.id, flags, entry.mode, path);
                    }
                }
                Ok(())
            })
            .map_err(|source| match options.cached {
                true => source,
                false => Incomplete { source }.into(),
            })?;
        Ok(())
    }
}

fn workdir(repo: &gix::Repository) -> crate::Result<&Path> {
    repo.workdir()
        .ok_or_else(|| unsupported("apply requires a worktree".into()))
}

/// The check of the patches of one patch file: where it looks, and what it has read.
struct Session<'a> {
    opened: &'a OpenedRepository,
    index: &'a gix::index::State,
    workdir: &'a Path,
    options: Options,
    cancellation: &'a Cancellation,
    converter: Option<Converter<'a, 'a>>,
    /// The state of every worktree file that was read, to see a later change of it.
    observed: BTreeMap<BString, Stat>,
    /// Missing worktree sources read from the index by a copy.
    missing_copies: BTreeMap<BString, File>,
}

impl<'a> Session<'a> {
    /// `index` is the index that the patches are checked against.
    fn new(
        opened: &'a OpenedRepository,
        index: &'a gix::index::State,
        options: Options,
        cancellation: &'a Cancellation,
    ) -> crate::Result<Self> {
        Ok(Session {
            opened,
            index,
            workdir: workdir(&opened.repo)?,
            options,
            cancellation,
            converter: None,
            observed: BTreeMap::new(),
            missing_copies: BTreeMap::new(),
        })
    }

    /// Check the patches in their order, and return what they leave.
    fn check_patches(&mut self, patches: Vec<Patch<'_>>) -> crate::Result<Files> {
        for patch in &patches {
            self.validate(patch)?;
        }
        if !self.options.cached {
            tracked_filters::reject_unsupported_selected(
                self.opened,
                self.index,
                Source::WorktreeThenIdMapping,
                patches
                    .iter()
                    .filter_map(|patch| patch.old_name.as_ref())
                    .map(|name| {
                        let name = name.as_bstr();
                        let mode = self
                            .index
                            .entry_by_path(name)
                            .map_or(Mode::FILE, |e| e.mode);
                        (name, mode)
                    }),
                self.cancellation,
            )?;
        }
        let mut doomed = Doomed::default();
        for patch in &patches {
            let Some(old) = &patch.old_name else {
                continue;
            };
            if patch.is_rename {
                doomed.renamed.insert(old.clone());
            }
            if patch.is_rename || patch.new_name.is_none() {
                doomed.removed.insert(old.clone());
            }
        }
        let mut changed = Files::new();
        let mut reasons = Vec::new();
        for mut patch in patches {
            self.cancellation.check()?;
            if let Err(error) = self.check_patch(&mut patch, &mut changed, &doomed) {
                // The other patches are still checked, to report all that do not apply.
                reasons.extend(error.downcast::<Rejected>()?.0);
            }
        }
        if !reasons.is_empty() {
            return Err(Rejected(reasons).into());
        }
        // A copy leaves its source in place. Restore a missing indexed source unless
        // another patch in this file already determines what belongs there.
        for (path, file) in std::mem::take(&mut self.missing_copies) {
            changed.entry(path).or_insert(Some(file));
        }
        self.check_result_filters(&changed)?;
        Ok(changed)
    }

    /// Check the attributes checkout will see after the old files are removed.
    fn check_result_filters(&self, files: &Files) -> crate::Result {
        let policy = &self.opened.command_policy;
        if self.options.cached || !policy.has_unsupported_filters() {
            return Ok(());
        }
        let written = files
            .iter()
            .filter_map(|(path, file)| file.as_ref().map(|file| (path.as_bstr(), file.mode)));
        if !files
            .keys()
            .any(|p| p.as_slice() == b".gitattributes" || p.ends_with(b"/.gitattributes"))
        {
            return tracked_filters::reject_unsupported_selected(
                self.opened,
                self.index,
                Source::WorktreeThenIdMapping,
                written,
                self.cancellation,
            );
        }

        // Supply patched attribute files from memory. For untouched directories
        // the worktree takes precedence, with the current index as a fallback.
        let repo = self.opened.repo.clone().with_object_memory();
        let mut attributes = gix::index::State::new(repo.object_hash());
        let mut directories = BTreeSet::from([&b""[..]]);
        for (path, _) in written.clone() {
            directories.extend(path.find_iter(b"/").map(|slash| &path.as_bytes()[..=slash]));
        }
        for dir in directories {
            self.cancellation.check()?;
            let name = [dir, b".gitattributes"].concat();
            let path = name.as_bstr();
            let id = match files.get(path) {
                Some(Some(file)) if matches!(file.mode, Mode::FILE | Mode::FILE_EXECUTABLE) => {
                    repo.write_blob(&file.data)?.detach()
                }
                // Mask the old attribute file on disk if it is deleted or becomes a link.
                Some(_) => repo.write_blob([])?.detach(),
                None => {
                    let Some(entry) = self.index.entry_by_path(path) else {
                        continue;
                    };
                    if !matches!(entry.mode, Mode::FILE | Mode::FILE_EXECUTABLE)
                        || self.inspect(path)?.is_some()
                    {
                        continue;
                    }
                    entry.id
                }
            };
            attributes.dangerously_push_entry(
                Stat::default(),
                id,
                Flags::empty(),
                Mode::FILE,
                path,
            );
        }
        attributes.sort_entries();
        let stack = repo.attributes_only(&attributes, Source::IdMappingThenWorktree)?;
        tracked_filters::check_attributes(policy, stack, written, self.cancellation)
    }

    /// Refuse names that cannot be files of this worktree, and what gix cannot change.
    fn validate(&self, patch: &Patch<'_>) -> crate::Result {
        for name in [&patch.old_name, &patch.new_name].into_iter().flatten() {
            let name = name.as_bstr();
            selection::validate_normalized(name, self.workdir).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("invalid path '{}': {error}", show(name)),
                )
            })?;
            let submodule = self
                .index
                .entry_by_path_and_stage(name, Stage::Unconflicted)
                .is_some_and(|entry| entry.mode == Mode::COMMIT);
            let inside = transition::has_gitlink_ancestor(self.index, name);
            if inside || submodule || [patch.old_mode, patch.new_mode].contains(&0o160000) {
                return Err(unsupported(format!(
                    "cannot apply to '{}': changes to submodules are not supported",
                    show(name)
                )));
            }
        }
        Ok(())
    }

    /// Check one patch and add what it leaves to `changed`.
    ///
    /// A patch that does not apply is a `Rejected` error.
    fn check_patch(
        &mut self,
        patch: &mut Patch<'_>,
        changed: &mut Files,
        doomed: &Doomed,
    ) -> crate::Result {
        let name = show(patch.name());
        let mut image = Vec::new();
        if let Some(old) = patch.old_name.clone() {
            // A rename or a copy reads the file as it was before the patches.
            let earlier = (!patch.is_rename && !patch.is_copy).then_some(&changed);
            let file = match earlier.and_then(|changed| changed.get(&old)) {
                Some(None) => {
                    return Err(reject(format!("path {name} has been renamed/deleted")));
                }
                Some(Some(file)) => Some(file.clone()),
                None => self.read(old.as_bstr(), patch)?,
            };
            match file {
                Some(file) => {
                    patch.is_new.get_or_insert(false);
                    let mode = file.mode.bits();
                    if patch.old_mode == 0 {
                        patch.old_mode = mode;
                    }
                    if kind(mode) != kind(patch.old_mode) {
                        return Err(reject(format!("{name}: wrong type")));
                    }
                    if patch.new_mode == 0 && patch.is_delete == Some(false) {
                        patch.new_mode = mode;
                    }
                    image = file.data;
                }
                // A patch that does not say whether it creates the file does so if there
                // is none.
                None if patch.is_new.is_none() => {
                    patch.is_new = Some(true);
                    patch.is_delete = Some(false);
                    patch.old_name = None;
                }
                None if self.options.uses_index() => {
                    return Err(reject(format!("{name}: does not exist in index")));
                }
                None => return Err(reject(format!("{name}: No such file or directory"))),
            }
        }

        if let Some(new) = patch.new_name.clone()
            && (patch.is_new == Some(true) || patch.is_rename || patch.is_copy)
        {
            // A file may be where another patch of this patch file removes one.
            let removed = |path: &BStr| match changed.get(path) {
                Some(state) => state.is_none(),
                None => doomed.removed.contains(path),
            };
            // The new file itself may be where one is gone already, or where a later
            // rename takes one away. A later deletion does not count: it deletes this
            // new file, and what is in its place now would never be looked at.
            let replaces = match changed.get(&new) {
                Some(state) => state.is_none(),
                None => doomed.renamed.contains(&new),
            };
            if !replaces {
                self.check_free(new.as_bstr(), &removed)?;
            }
            if patch.new_mode == 0 {
                patch.new_mode = match patch.is_new {
                    Some(true) => 0o100644,
                    _ => patch.old_mode,
                };
            }
        }
        if let (Some(old), Some(new)) = (&patch.old_name, &patch.new_name) {
            if patch.new_mode == 0 {
                patch.new_mode = patch.old_mode;
            }
            if kind(patch.old_mode) != kind(patch.new_mode) {
                let of_old = if old == new {
                    String::new()
                } else {
                    format!(" of {}", show(old.as_bstr()))
                };
                return Err(reject(format!(
                    "new mode ({:o}) of {} does not match old mode ({:o}){of_old}",
                    patch.new_mode,
                    show(new.as_bstr()),
                    patch.old_mode
                )));
            }
        }

        let result = if patch.hunks.is_empty() {
            image
        } else {
            let mut lines = Image::new(&image)?;
            for hunk in &patch.hunks {
                // Very many hunks take their time, so a cancellation is seen between them.
                self.cancellation.check()?;
                if !lines.apply(hunk)? {
                    let failed = format!("patch failed: {name}:{}", hunk.old_start);
                    return Err(does_not_apply(&name, vec![failed]));
                }
            }
            lines.into_contents()?
        };
        if patch.is_delete == Some(true) && !result.is_empty() {
            let reason = "removal patch leaves file contents".into();
            return Err(does_not_apply(&name, vec![reason]));
        }

        if let Some(new) = &patch.new_name {
            let Some(mode) = file_mode(patch.new_mode) else {
                return Err(reject(format!("{name}: wrong type")));
            };
            changed.insert(new.clone(), Some(File { data: result, mode }));
        }
        if let Some(old) = &patch.old_name {
            if patch.is_rename {
                // A rename consumes the original source. Another rename in the
                // same patch may already have installed its destination here.
                changed.entry(old.clone()).or_insert(None);
            } else if patch.new_name.is_none() {
                changed.insert(old.clone(), None);
            }
        }
        Ok(())
    }

    /// The file at `path` where the patches are applied: in the worktree, or with
    /// `--cached` in the index. `None` if there is no file.
    fn read(&mut self, path: &BStr, patch: &Patch<'_>) -> crate::Result<Option<File>> {
        let entry = self
            .index
            .entry_by_path_and_stage(path, Stage::Unconflicted);
        if !self.options.uses_index() {
            return self.read_worktree(
                path,
                entry.map(|entry| entry.mode),
                patch.crlf_in_preimage(),
            );
        }
        let Some(entry) = entry else {
            return Ok(None);
        };
        let staged = |repo: &gix::Repository| -> crate::Result<File> {
            let data = repo.find_blob(entry.id)?.take_data();
            let mode = entry.mode;
            Ok(File { data, mode })
        };
        if self.options.cached {
            return staged(&self.opened.repo).map(Some);
        }
        // With `--index` the file has to be what the index has. As in Git, a file that
        // is missing is taken from the index.
        let hash = self.opened.repo.object_hash();
        match self.read_worktree(path, Some(entry.mode), false)? {
            None => {
                self.check_parents(path, &|_| false)?;
                let file = staged(&self.opened.repo)?;
                if patch.is_copy {
                    self.missing_copies
                        .entry(path.to_owned())
                        .or_insert_with(|| file.clone());
                }
                Ok(Some(file))
            }
            Some(file)
                if file.mode == entry.mode
                    && gix::objs::compute_hash(hash, Kind::Blob, &file.data)? == entry.id =>
            {
                Ok(Some(file))
            }
            Some(_) => Err(reject(format!("{}: does not match index", show(path)))),
        }
    }

    /// Read a file of the worktree as Git stores it: with the conversions that `add` makes.
    /// `index_mode` is the mode that the index has for the path, if it has the path.
    fn read_worktree(
        &mut self,
        path: &BStr,
        index_mode: Option<Mode>,
        keep_crlf: bool,
    ) -> crate::Result<Option<File>> {
        let Some(metadata) = self.inspect(path)? else {
            return Ok(None);
        };
        if !metadata.is_file() {
            return Err(reject(format!("{}: wrong type", show(path))));
        }
        // Without symbolic links, a link is a file that the index knows to be a link.
        let prior = match index_mode {
            Some(Mode::SYMLINK) => Mode::SYMLINK,
            _ => Mode::FILE,
        };
        let converter = match &mut self.converter {
            Some(converter) => converter,
            None => self
                .converter
                .insert(Converter::new(&self.opened.repo, self.index)?),
        };
        let loaded = converter.consume_content(
            "apply",
            path,
            Some(prior),
            self.cancellation,
            keep_crlf,
            |data| {
                let mut bytes = Vec::new();
                bytes.try_reserve_exact(data.len())?;
                bytes.extend_from_slice(data);
                Ok(bytes)
            },
        )?;
        Ok(loaded.map(|(data, mode, stat)| {
            self.observed.insert(path.to_owned(), stat);
            File { data, mode }
        }))
    }

    /// Look at a path of the worktree without following a symbolic link.
    fn inspect(&self, path: &BStr) -> crate::Result<Option<fs::Metadata>> {
        selection::checked_symlink_metadata(self.workdir, path).map_err(|error| {
            if error.kind() == io::ErrorKind::Unsupported {
                reject(format!(
                    "affected file '{}' is beyond a symbolic link",
                    show(path)
                ))
            } else {
                error.into()
            }
        })
    }

    /// Require that a file can be created at `path`: nothing is there, and nothing but
    /// directories is above it. `removed` says which files the patches remove.
    fn check_free(&self, path: &BStr, removed: &dyn Fn(&BStr) -> bool) -> crate::Result {
        let exists = |place: &str| reject(format!("{}: already exists in {place}", show(path)));
        if self.options.uses_index() && self.index.entry_range(path).is_some() {
            return Err(exists("index"));
        }
        if self.options.cached {
            return Ok(());
        }
        match self.inspect(path)? {
            None => {}
            // As in Git, a directory may be there if the patches remove every file in it.
            Some(metadata) if metadata.is_dir() && self.vanishes(path, removed)? => {}
            Some(_) => return Err(exists("working directory")),
        }
        self.check_parents(path, removed)
    }

    /// Whether nothing is left of the directory at `path` once the patches have removed
    /// their files.
    fn vanishes(&self, path: &BStr, removed: &dyn Fn(&BStr) -> bool) -> crate::Result<bool> {
        let mut pending = vec![path.to_owned()];
        while let Some(directory) = pending.pop() {
            self.cancellation.check()?;
            let relative = gix::path::from_bstr(directory.as_bstr());
            for entry in fs::read_dir(self.workdir.join(relative.as_ref()))? {
                let entry = entry?;
                let name = entry.file_name();
                let Ok(name) = gix::path::os_str_into_bstr(&name) else {
                    return Ok(false);
                };
                let mut child = directory.clone();
                child.push(b'/');
                child.extend_from_slice(name);
                let metadata = fs::symlink_metadata(entry.path())?;
                if metadata.is_dir() {
                    pending.push(child);
                } else if !metadata.is_file() || !removed(child.as_bstr()) {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Require that the worktree has nothing but directories above `path`, or nothing.
    fn check_parents(&self, path: &BStr, removed: &dyn Fn(&BStr) -> bool) -> crate::Result {
        for (slash, _) in path.iter().enumerate().filter(|(_, byte)| **byte == b'/') {
            let parent = path[..slash].as_bstr();
            match self.inspect(parent)? {
                None => break,
                Some(metadata) if metadata.is_dir() => {}
                // A file in the way is fine if a patch removes it.
                Some(_) if removed(parent) => break,
                Some(_) => {
                    return Err(reject(format!(
                        "{}: '{}' is not a directory",
                        show(path),
                        show(parent)
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Remove a directory in which only directories are left.
fn remove_empty_tree(directory: &Path) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if !fs::symlink_metadata(&path)?.is_dir() {
            let message = format!("'{}' is in the way", path.display());
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, message));
        }
        remove_empty_tree(&path)?;
    }
    fs::remove_dir(directory)
}

/// An error after the first file was changed. Nothing can undo the change.
#[derive(Debug)]
struct Incomplete {
    source: Box<dyn std::error::Error + Send + Sync>,
}

impl fmt::Display for Incomplete {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("apply did not finish, and some files may have changed")
    }
}

impl std::error::Error for Incomplete {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// The modes that a file of the worktree can have.
fn file_mode(mode: u32) -> Option<Mode> {
    match mode {
        0o100644 => Some(Mode::FILE),
        0o100755 => Some(Mode::FILE_EXECUTABLE),
        0o120000 => Some(Mode::SYMLINK),
        _ => None,
    }
}

fn show(path: &BStr) -> String {
    path.to_str_lossy().escape_debug().to_string()
}

fn reject(reason: String) -> Box<dyn std::error::Error + Send + Sync> {
    Rejected(vec![reason]).into()
}

/// The patch for the file `name` does not apply, for `reasons`. As in Git, the last line
/// says so.
fn does_not_apply(
    name: &str,
    mut reasons: Vec<String>,
) -> Box<dyn std::error::Error + Send + Sync> {
    reasons.push(format!("{name}: patch does not apply"));
    Rejected(reasons).into()
}

fn invalid(message: String) -> Box<dyn std::error::Error + Send + Sync> {
    io::Error::new(io::ErrorKind::InvalidData, message).into()
}

fn unsupported(message: String) -> Box<dyn std::error::Error + Send + Sync> {
    io::Error::new(io::ErrorKind::Unsupported, message).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wait_for_standard_input_ends_with_a_cancellation() {
        /// A terminal at which nothing is typed: it has no data and no end.
        struct Silent(mpsc::Receiver<()>);
        impl Read for Silent {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                // The test ends the wait when it drops the sender.
                _ = self.0.recv();
                Ok(0)
            }
        }
        let (silence, waits) = mpsc::channel();
        let cancellation = Cancellation::new();
        cancellation.cancel();
        let error = read_stdin(Silent(waits), &cancellation).unwrap_err();
        assert!(crate::cancellation::was_cancelled(error.as_ref()));
        drop(silence);

        // Input that ends is the patch.
        let text = read_stdin(&b"a patch"[..], &Cancellation::new()).unwrap();
        assert_eq!(text, b"a patch");
    }
}
