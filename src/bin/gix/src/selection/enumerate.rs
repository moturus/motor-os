use std::{collections::BTreeSet, io, ops::ControlFlow, path::Path};

use gix::{
    bstr::{BStr, BString, ByteSlice},
    index::entry::Mode,
};

use super::{
    MAX_CANDIDATES, MAX_PATH_BYTES, Selection, checked_symlink_metadata, contains, invalid,
    validate_normalized,
};
use crate::cancellation::Cancellation;

/// Enumerate selected index paths and non-ignored worktree additions without
/// reading or hashing file contents. The returned paths are sorted and unique.
pub fn enumerate(
    repo: &gix::Repository,
    index: &gix::index::State,
    selection: &Selection,
    cancellation: &Cancellation,
) -> crate::Result<Vec<BString>> {
    let workdir = repo
        .workdir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "a worktree is required"))?;
    let mut candidates = BTreeSet::<BString>::new();
    let mut path_bytes = 0usize;
    for entry in index.entries() {
        cancellation.check()?;
        let path = entry.path(index);
        if selection.selects(path) {
            insert(&mut candidates, &mut path_bytes, path, workdir)?;
        }
    }

    preflight_explicit_paths(repo, index, selection, &candidates, workdir)?;

    // The raw index may not carry UPTODATE classification flags, so the
    // delegate checks exact membership before retaining any emitted path.
    let pathspecs = selection.pathspecs();
    let mut collector = Collector {
        selection,
        index,
        workdir,
        candidates: &mut candidates,
        path_bytes: &mut path_bytes,
        error: None,
    };
    repo.dirwalk(
        index,
        pathspecs.iter().map(|path| path.as_bstr()),
        cancellation.flag(),
        repo.dirwalk_options()?
            .emit_untracked(gix::dir::walk::EmissionMode::Matching),
        &mut collector,
    )?;
    if let Some(error) = collector.error {
        return Err(error.into());
    }
    cancellation.check()?;
    Ok(candidates.into_iter().collect())
}

struct Collector<'a> {
    selection: &'a Selection,
    index: &'a gix::index::State,
    workdir: &'a Path,
    candidates: &'a mut BTreeSet<BString>,
    path_bytes: &'a mut usize,
    error: Option<io::Error>,
}

impl gix::dir::walk::Delegate for Collector<'_> {
    fn can_recurse(
        &mut self,
        entry: gix::dir::EntryRef<'_>,
        for_deletion: Option<gix::dir::walk::ForDeletionMode>,
        root_is_repository: bool,
    ) -> bool {
        if is_gitlink(self.index, entry.rela_path.as_ref()) {
            return false;
        }
        entry.status.can_recurse(
            entry.disk_kind,
            entry.pathspec_match,
            for_deletion,
            root_is_repository,
        )
    }

    fn emit(
        &mut self,
        entry: gix::dir::EntryRef<'_>,
        _collapsed: Option<gix::dir::entry::Status>,
    ) -> gix::dir::walk::Action {
        let path = entry.rela_path.as_ref();
        if entry.status != gix::dir::entry::Status::Untracked
            || !self.selection.selects(path)
            || self.index.entry_range(path).is_some()
        {
            return ControlFlow::Continue(());
        }
        match insert(self.candidates, self.path_bytes, path, self.workdir) {
            Ok(()) => ControlFlow::Continue(()),
            Err(error) => {
                self.error = Some(error);
                ControlFlow::Break(())
            }
        }
    }
}

fn insert(
    candidates: &mut BTreeSet<BString>,
    path_bytes: &mut usize,
    path: &BStr,
    workdir: &Path,
) -> io::Result<()> {
    if candidates.contains(path) {
        return Ok(());
    }
    validate_normalized(path, workdir)?;
    if candidates.len() == MAX_CANDIDATES {
        return Err(invalid("selected paths exceed their count limit"));
    }
    *path_bytes = (*path_bytes)
        .checked_add(path.len())
        .filter(|bytes| *bytes <= MAX_PATH_BYTES)
        .ok_or_else(|| invalid("selected paths exceed their byte limit"))?;
    candidates.insert(path.to_owned());
    Ok(())
}

fn is_gitlink(index: &gix::index::State, path: &BStr) -> bool {
    index.entry_range(path).is_some_and(|range| {
        index.entries()[range]
            .iter()
            .any(|entry| entry.mode == Mode::COMMIT)
    })
}

fn gitlink_ancestor<'a>(index: &gix::index::State, path: &'a BStr) -> Option<&'a BStr> {
    let mut prefix = path;
    while let Some(slash) = prefix.rfind_byte(b'/') {
        prefix = prefix[..slash].as_bstr();
        if is_gitlink(index, prefix) {
            return Some(prefix);
        }
    }
    None
}

fn preflight_explicit_paths(
    repo: &gix::Repository,
    index: &gix::index::State,
    selection: &Selection,
    tracked: &BTreeSet<BString>,
    workdir: &Path,
) -> crate::Result {
    let paths = selection.paths();
    let mut excludes = repo.excludes(
        index,
        None,
        gix::worktree::stack::state::ignore::Source::WorktreeThenIdMappingIfNotSkipped,
    )?;
    for path in paths {
        if path.is_empty() {
            continue;
        }
        if let Some(gitlink) = gitlink_ancestor(index, path.as_bstr()) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "explicit path '{}' is inside gitlink '{}'",
                    path.to_str_lossy().escape_debug(),
                    gitlink.to_str_lossy().escape_debug()
                ),
            )
            .into());
        }
        let metadata = checked_symlink_metadata(workdir, path.as_bstr())?;
        if tracked
            .iter()
            .any(|candidate| contains(path.as_bstr(), candidate.as_bstr()))
        {
            continue;
        }
        let Some(metadata) = metadata else {
            return Err(invalid(format!(
                "explicit path '{}' did not match a worktree or index path",
                path.to_str_lossy().escape_debug()
            ))
            .into());
        };
        let relative = gix::path::from_bstr(path.as_bstr());
        let mode = metadata.is_dir().then_some(Mode::DIR);
        if excludes.at_path(relative.as_ref(), mode)?.is_excluded() {
            return Err(invalid(format!(
                "explicit path '{}' is ignored",
                path.to_str_lossy().escape_debug()
            ))
            .into());
        }
    }
    Ok(())
}
