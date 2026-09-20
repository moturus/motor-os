use std::{fs, io, path::PathBuf};

use gix::{
    bstr::{BStr, ByteSlice},
    index::entry::{Flags, Mode, Stage},
    prelude::HeaderExt,
    worktree::stack::state::attributes::Source,
};

use crate::{
    cancellation::Cancellation,
    checkout,
    mutation::Guard,
    repository::OpenedRepository,
    selection::{self, Selection},
    tracked_filters,
};

/// Restore selected tracked worktree paths from the locked index.
pub fn run(
    opened: &OpenedRepository,
    paths: &[String],
    cancellation: &Cancellation,
) -> crate::Result {
    let repo = &opened.repo;
    let workdir = repo
        .workdir()
        .ok_or_else(|| unsupported("restore requires a worktree"))?;
    let selection = Selection::from_paths(workdir, paths)?;
    cancellation.check()?;
    let guard = Guard::acquire(repo)?;
    let index = guard.index();

    let mut selected = Vec::new();
    let mut path_bytes = 0usize;
    for entry in index.entries() {
        cancellation.check()?;
        let path = entry.path(index);
        if !selection.selects(path) {
            continue;
        }
        selection::validate_normalized(path, workdir)?;
        if selected.len() == selection::MAX_CANDIDATES {
            return Err(invalid("selected paths exceed their count limit").into());
        }
        path_bytes = path_bytes
            .checked_add(path.len())
            .filter(|bytes| *bytes <= selection::MAX_PATH_BYTES)
            .ok_or_else(|| invalid("selected paths exceed their byte limit"))?;
        if entry.stage() != Stage::Unconflicted {
            return Err(path_error(path, "the index entry is conflicted").into());
        }
        match entry.mode {
            Mode::COMMIT | Mode::FILE | Mode::FILE_EXECUTABLE | Mode::SYMLINK => {}
            _ => return Err(path_error(path, "the indexed file mode is unsupported").into()),
        }
        selected.push(entry);
    }
    for requested in selection.paths() {
        if !selected
            .iter()
            .any(|entry| selection::contains(requested.as_bstr(), entry.path(index)))
        {
            if let Some(gitlink) = gitlink_ancestor(index, requested.as_bstr()) {
                return Err(unsupported(format!(
                    "explicit path '{}' is inside gitlink '{}'",
                    requested.to_str_lossy().escape_debug(),
                    gitlink.to_str_lossy().escape_debug()
                ))
                .into());
            }
            return Err(invalid(format!(
                "explicit path '{}' did not match an index path",
                requested.to_str_lossy().escape_debug()
            ))
            .into());
        }
    }

    tracked_filters::reject_unsupported_selected(
        opened,
        index,
        Source::IdMapping,
        selected.iter().filter_map(|entry| {
            (entry.mode != Mode::COMMIT).then_some((entry.path(index), entry.mode))
        }),
        cancellation,
    )?;
    for entry in selected.iter().filter(|entry| entry.mode != Mode::COMMIT) {
        cancellation.check()?;
        let path = entry.path(index);
        let header = repo.objects.header(entry.id)?;
        if header.kind() != gix::objs::Kind::Blob {
            return Err(path_error(path, "the index entry must reference a blob").into());
        }
        let _ = preflight_destination(workdir, path)?;
    }

    // Keep all indexed attributes available while skipping unselected output.
    let mut checkout_index = (**index).clone();
    for (entry, path) in checkout_index.entries_mut_with_paths() {
        if !selection.selects(path) || entry.mode == Mode::COMMIT {
            entry.flags.insert(Flags::SKIP_WORKTREE);
        }
    }
    let mut options = repo.checkout_options(Source::IdMapping)?;
    options.fs.symlink = false;
    options.thread_limit = Some(1);
    options.destination_is_initially_empty = false;
    options.overwrite_existing = false;
    options.keep_going = false;
    let mut objects = repo.objects.clone().into_arc()?;
    objects.ignore_replacements = true;
    let discard = gix::features::progress::Discard;

    // Recreate files to replace read-only outputs and reset link-text permissions.
    for entry in selected.iter().filter(|entry| entry.mode != Mode::COMMIT) {
        cancellation.check()?;
        if let Some((path, directory)) = preflight_destination(workdir, entry.path(index))? {
            if directory {
                fs::remove_dir(path)?;
            } else {
                fs::remove_file(path)?;
            }
        }
    }

    let outcome = gix::worktree::state::checkout(
        &mut checkout_index,
        workdir,
        objects,
        &discard,
        &discard,
        cancellation.flag(),
        options,
    )
    .map_err(|error| cancellation.normalize_error(error.into()))?;
    checkout::check_outcome(&outcome).map_err(|error| cancellation.normalize_error(error))?;
    cancellation.check()
}

fn preflight_destination(
    workdir: &std::path::Path,
    path: &BStr,
) -> crate::Result<Option<(PathBuf, bool)>> {
    let display = path.to_str_lossy().escape_debug().to_string();
    let relative = gix::path::from_bstr(path);
    let mut current = workdir.to_owned();
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        let std::path::Component::Normal(component) = component else {
            return Err(invalid(format!(
                "selected path '{display}' is not worktree-relative"
            ))
            .into());
        };
        current.push(component);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::NotADirectory => {
                return Err(path_error(path, "a worktree ancestor is not a directory").into());
            }
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() {
            return Err(path_error(path, "the worktree path contains a symbolic link").into());
        }
        if components.peek().is_some() {
            if !metadata.is_dir() {
                return Err(path_error(path, "a worktree ancestor is not a directory").into());
            }
        } else if metadata.is_file() {
            return Ok(Some((current, false)));
        } else if metadata.is_dir() {
            if fs::read_dir(&current)?.next().transpose()?.is_some() {
                return Err(path_error(path, "a worktree directory is not empty").into());
            }
            return Ok(Some((current, true)));
        } else {
            return Err(path_error(path, "the worktree path has an unsupported file type").into());
        }
    }
    Err(invalid("selected path is empty").into())
}

fn gitlink_ancestor<'a>(index: &gix::index::State, mut path: &'a BStr) -> Option<&'a BStr> {
    while let Some(slash) = path.rfind_byte(b'/') {
        path = path[..slash].as_bstr();
        if index.entry_range(path).is_some_and(|range| {
            index.entries()[range]
                .iter()
                .any(|entry| entry.mode == Mode::COMMIT)
        }) {
            return Some(path);
        }
    }
    None
}

fn path_error(path: &BStr, message: &str) -> io::Error {
    unsupported(format!(
        "cannot restore '{}': {message}",
        path.to_str_lossy().escape_debug()
    ))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn unsupported(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message.into())
}
