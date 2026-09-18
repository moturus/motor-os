use std::io;

use gix::{
    bstr::{BStr, ByteSlice},
    index::entry::Mode,
    prelude::Find,
};

use crate::{
    cancellation::Cancellation,
    repository::OpenedRepository,
    stage_blob::{Converter, MAX_BLOB_BYTES},
};

#[derive(Debug, Clone, Copy)]
pub enum Source {
    Missing,
    Object {
        id: gix::ObjectId,
        mode: Mode,
    },
    Worktree {
        index_id: gix::ObjectId,
        index_mode: Mode,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub enum Loaded {
    Missing,
    Gitlink { id: gix::ObjectId },
    Blob { mode: Mode, bytes: Vec<u8> },
}

#[derive(Debug, Eq, PartialEq)]
pub struct Pair {
    pub old: Loaded,
    pub new: Loaded,
}

/// Loads bounded canonical Git inputs while retaining no blob-content cache.
pub struct Loader<'repo, 'index> {
    repo: &'repo gix::Repository,
    index: &'index gix::index::State,
    converter: Option<Converter<'repo, 'index>>,
}

impl<'repo, 'index> Loader<'repo, 'index> {
    /// Create a loader whose attribute/filter pipeline remains lazy.
    pub fn new(opened: &'repo OpenedRepository, index: &'index gix::index::State) -> Self {
        Self {
            repo: &opened.repo,
            index,
            converter: None,
        }
    }

    /// Reuse this loader and drop each pair before loading the next one.
    /// The caller owns selection, conflict/filter preflight, classification, and rendering.
    pub fn load_pair(
        &mut self,
        path: &BStr,
        old: Source,
        new: Source,
        cancellation: &Cancellation,
    ) -> crate::Result<Pair> {
        let old = self.load_source(path, old, cancellation)?;
        let new = self.load_source(path, new, cancellation)?;
        Ok(Pair { old, new })
    }

    fn load_source(
        &mut self,
        path: &BStr,
        source: Source,
        cancellation: &Cancellation,
    ) -> crate::Result<Loaded> {
        cancellation.check()?;
        match source {
            Source::Missing => Ok(Loaded::Missing),
            Source::Object { id, mode } => load_object(self.repo, path, id, mode, cancellation),
            Source::Worktree {
                index_id,
                index_mode: Mode::COMMIT,
            } => Ok(Loaded::Gitlink { id: index_id }),
            Source::Worktree { index_mode, .. } => {
                if !matches!(
                    index_mode,
                    Mode::FILE | Mode::FILE_EXECUTABLE | Mode::SYMLINK
                ) {
                    return Err(unsupported(path, "the indexed file mode is not supported").into());
                }
                if self.converter.is_none() {
                    self.converter = Some(Converter::new(self.repo, self.index)?);
                }
                let loaded = self
                    .converter
                    .as_mut()
                    .expect("initialized above")
                    .consume_git_content("diff", path, Some(index_mode), cancellation, |data| {
                        let mut bytes = Vec::new();
                        bytes.try_reserve_exact(data.len())?;
                        bytes.extend_from_slice(data);
                        Ok(bytes)
                    })?;
                Ok(match loaded {
                    Some((bytes, mode, _stat)) => Loaded::Blob { mode, bytes },
                    None => Loaded::Missing,
                })
            }
        }
    }
}

fn load_object(
    repo: &gix::Repository,
    path: &BStr,
    id: gix::ObjectId,
    mode: Mode,
    cancellation: &Cancellation,
) -> crate::Result<Loaded> {
    if mode == Mode::COMMIT {
        return Ok(Loaded::Gitlink { id });
    }
    if !matches!(mode, Mode::FILE | Mode::FILE_EXECUTABLE | Mode::SYMLINK) {
        return Err(unsupported(path, "the object file mode is not supported").into());
    }

    let header = repo
        .try_find_header(id)?
        .ok_or_else(|| missing_object(path, id))?;
    if header.kind() != gix::objs::Kind::Blob {
        return Err(unsupported(path, "the object is not a blob").into());
    }
    let size = usize::try_from(header.size())
        .ok()
        .filter(|size| *size <= MAX_BLOB_BYTES)
        .ok_or_else(|| unsupported(path, "object data exceeds the 16 MiB limit"))?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size)?;
    cancellation.check()?;
    let (kind, actual_size) = {
        let object = repo
            .try_find(&id, &mut bytes)?
            .ok_or_else(|| missing_object(path, id))?;
        (object.kind, object.data.len())
    };
    if kind != gix::objs::Kind::Blob || actual_size != size || bytes.len() != size {
        return Err(unsupported(path, "object data changed while reading").into());
    }
    cancellation.check()?;
    Ok(Loaded::Blob { mode, bytes })
}

fn unsupported(path: &BStr, message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "cannot diff '{}': {message}",
            path.to_str_lossy().escape_debug()
        ),
    )
}

fn missing_object(path: &BStr, id: gix::ObjectId) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "cannot diff '{}': object {id} is missing",
            path.to_str_lossy().escape_debug()
        ),
    )
}
