use std::{collections::BTreeMap, io};

use gix::{
    bstr::{BStr, BString, ByteSlice},
    index::entry::{Flags, Mode, Stage},
    worktree::stack::state::attributes::Source,
};

use crate::{
    cancellation::Cancellation,
    mutation::Guard,
    repository::OpenedRepository,
    selection::{self, Selection},
    stage_blob::{Converter, StagedBlob},
    tracked_filters,
};

struct Candidate {
    prior_mode: Option<Mode>,
    writes_blob: bool,
}

enum Prior {
    File(Option<Mode>),
    Gitlink,
}

/// Stage the selected worktree and index changes in one index publication.
pub fn run(
    opened: &OpenedRepository,
    all: bool,
    paths: &[String],
    cancellation: &Cancellation,
) -> crate::Result {
    let repo = &opened.repo;
    let workdir = repo
        .workdir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "add requires a worktree"))?;
    let selection = if all {
        if !paths.is_empty() {
            return Err(invalid("add -A does not accept paths").into());
        }
        Selection::all()
    } else {
        Selection::from_paths(workdir, paths)?
    };

    cancellation.check()?;
    let (mut guard, ready) = Guard::acquire_for_ready_mutation(repo)?;
    if let Some(record) = ready.as_ref() {
        guard.require_ready_merge(repo, record, cancellation)?;
    }
    let candidates = selection::enumerate(repo, guard.index(), &selection, cancellation)?;
    let mut classified = BTreeMap::<BString, Candidate>::new();
    for path in candidates {
        cancellation.check()?;
        let prior = prior(guard.index(), path.as_bstr())?;
        let metadata = selection::checked_symlink_metadata(workdir, path.as_bstr())?;
        let (prior_mode, writes_blob) = match prior {
            Prior::Gitlink => {
                if metadata.as_ref().is_some_and(|metadata| !metadata.is_dir()) {
                    return Err(unsupported(path.as_bstr(), "a gitlink was replaced").into());
                }
                continue;
            }
            Prior::File(prior_mode) => match metadata {
                Some(metadata) if metadata.is_file() => (prior_mode, true),
                Some(metadata) if metadata.is_dir() && prior_mode.is_some() => (prior_mode, false),
                None if prior_mode.is_some() => (prior_mode, false),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!(
                            "selected untracked path '{}' disappeared",
                            path.to_str_lossy().escape_debug()
                        ),
                    )
                    .into());
                }
                Some(_) => {
                    return Err(unsupported(
                        path.as_bstr(),
                        "the worktree path has an unsupported file type",
                    )
                    .into());
                }
            },
        };
        classified.insert(
            path,
            Candidate {
                prior_mode,
                writes_blob,
            },
        );
    }

    tracked_filters::reject_unsupported_selected(
        opened,
        guard.index(),
        Source::WorktreeThenIdMapping,
        classified
            .iter()
            .filter(|(_, candidate)| candidate.writes_blob)
            .map(|(path, candidate)| (path.as_bstr(), candidate.prior_mode.unwrap_or(Mode::FILE))),
        cancellation,
    )?;

    let mut prepared = BTreeMap::<BString, Option<StagedBlob>>::new();
    for (path, candidate) in &classified {
        if candidate.writes_blob {
            preflight_file_directory(guard.index(), path.as_bstr(), &mut prepared)?;
        } else {
            prepared.insert(path.clone(), None);
        }
    }

    let mut converter = Converter::new(repo, guard.index())?;
    for (path, candidate) in classified {
        cancellation.check()?;
        if candidate.writes_blob {
            let blob = converter
                .stage(path.as_bstr(), candidate.prior_mode, cancellation)?
                .ok_or_else(|| changed(path.as_bstr()))?;
            prepared.insert(path, Some(blob));
        } else {
            match selection::checked_symlink_metadata(workdir, path.as_bstr())? {
                None => {}
                Some(metadata) if metadata.is_dir() => {}
                Some(_) => return Err(changed(path.as_bstr()).into()),
            }
        }
    }
    drop(converter);
    reject_file_ancestor_pairs(&prepared)?;
    if prepared.is_empty() {
        return cancellation.check();
    }

    cancellation.check()?;
    if let Some(record) = ready.as_ref() {
        guard.require_ready_merge(repo, record, cancellation)?;
    }
    guard.publish_edited_index(move |index| {
        index.remove_entries(|_, path, _| prepared.contains_key(path));
        for (path, change) in prepared {
            if let Some(blob) = change {
                index.dangerously_push_entry(
                    blob.stat,
                    blob.id,
                    Flags::empty(),
                    blob.mode,
                    path.as_bstr(),
                );
            }
        }
        Ok(())
    })?;
    cancellation.check()
}

fn prior(index: &gix::index::State, path: &BStr) -> crate::Result<Prior> {
    let Some(range) = index.entry_range(path) else {
        return Ok(Prior::File(None));
    };
    let entries = &index.entries()[range];
    if entries.len() == 1 && entries[0].stage() == Stage::Unconflicted {
        return match entries[0].mode {
            Mode::COMMIT => Ok(Prior::Gitlink),
            mode @ (Mode::FILE | Mode::FILE_EXECUTABLE | Mode::SYMLINK) => {
                Ok(Prior::File(Some(mode)))
            }
            _ => Err(unsupported(path, "the indexed file mode is not supported").into()),
        };
    }
    if entries
        .iter()
        .all(|entry| matches!(entry.mode, Mode::FILE | Mode::FILE_EXECUTABLE))
    {
        Ok(Prior::File(Some(Mode::FILE)))
    } else {
        Err(unsupported(path, "only regular-file conflicts can be resolved").into())
    }
}

fn preflight_file_directory(
    index: &gix::index::State,
    path: &BStr,
    prepared: &mut BTreeMap<BString, Option<StagedBlob>>,
) -> crate::Result {
    let mut descendant_prefix = Vec::new();
    descendant_prefix.try_reserve_exact(path.len() + 1)?;
    descendant_prefix.extend_from_slice(path);
    descendant_prefix.push(b'/');
    if index
        .prefixed_entries_range(descendant_prefix.as_bstr())
        .is_some_and(|range| {
            index.entries()[range]
                .iter()
                .any(|entry| entry.mode == Mode::COMMIT)
        })
    {
        return Err(unsupported(path, "an indexed descendant is a gitlink").into());
    }

    let mut ancestor = path;
    while let Some(slash) = ancestor.rfind_byte(b'/') {
        ancestor = ancestor[..slash].as_bstr();
        let Some(range) = index.entry_range(ancestor) else {
            continue;
        };
        let entries = &index.entries()[range];
        if entries.len() != 1 || entries[0].stage() != Stage::Unconflicted {
            return Err(unsupported(path, "an indexed ancestor is conflicted").into());
        }
        if entries[0].mode == Mode::COMMIT {
            return Err(unsupported(path, "an indexed ancestor is a gitlink").into());
        }
        if !matches!(
            entries[0].mode,
            Mode::FILE | Mode::FILE_EXECUTABLE | Mode::SYMLINK
        ) {
            return Err(unsupported(path, "an indexed ancestor has an unsupported mode").into());
        }
        prepared.entry(ancestor.to_owned()).or_insert(None);
    }
    Ok(())
}

fn reject_file_ancestor_pairs(prepared: &BTreeMap<BString, Option<StagedBlob>>) -> crate::Result {
    for (path, change) in prepared {
        if change.is_none() {
            continue;
        }
        let mut ancestor = path.as_bstr();
        while let Some(slash) = ancestor.rfind_byte(b'/') {
            ancestor = ancestor[..slash].as_bstr();
            if prepared.get(ancestor).is_some_and(Option::is_some) {
                return Err(
                    unsupported(path.as_bstr(), "another prepared file is its ancestor").into(),
                );
            }
        }
    }
    Ok(())
}

fn changed(path: &BStr) -> io::Error {
    unsupported(path, "the worktree path changed after filter preflight")
}

fn unsupported(path: &BStr, message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "cannot stage '{}': {message}",
            path.to_str_lossy().escape_debug()
        ),
    )
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
