use std::{
    fs::File,
    io::{self, Read},
};

use gix::{
    bstr::{BStr, ByteSlice},
    filter::plumbing::pipeline::convert::ToGitOutcome,
    index::entry::{Mode, Stat},
};

use crate::{cancellation::Cancellation, selection};

pub(crate) const MAX_BLOB_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub struct StagedBlob {
    pub id: gix::ObjectId,
    pub mode: Mode,
    pub stat: Stat,
}

/// Convert one already-selected worktree path into a bounded blob.
///
/// The caller owns path selection, conflict handling, and filter preflight for the complete
/// selection before calling [`stage`](Self::stage).
pub struct Converter<'repo, 'index> {
    repo: &'repo gix::Repository,
    index: &'index gix::index::State,
    pipeline: gix::filter::Pipeline<'repo>,
}

impl<'repo, 'index> Converter<'repo, 'index> {
    pub fn new(
        repo: &'repo gix::Repository,
        index: &'index gix::index::State,
    ) -> crate::Result<Self> {
        let attributes = repo.attributes_only(
            index,
            gix::worktree::stack::state::attributes::Source::WorktreeThenIdMapping,
        )?;
        Ok(Self {
            repo,
            index,
            pipeline: gix::filter::Pipeline::new(repo, attributes.detach())?,
        })
    }

    /// Return `None` when the selected path no longer exists.
    pub fn stage(
        &mut self,
        path: &BStr,
        prior_mode: Option<Mode>,
        cancellation: &Cancellation,
    ) -> crate::Result<Option<StagedBlob>> {
        let repo = self.repo;
        self.consume_git_content("stage", path, prior_mode, cancellation, |bytes| {
            Ok(repo.write_blob(bytes)?.detach())
        })
        .map(|blob| blob.map(|(id, mode, stat)| StagedBlob { id, mode, stat }))
    }

    /// Pass canonical Git content to the callback while conversion buffers remain valid.
    pub(crate) fn consume_git_content<T>(
        &mut self,
        action: &str,
        path: &BStr,
        prior_mode: Option<Mode>,
        cancellation: &Cancellation,
        consume: impl FnOnce(&[u8]) -> crate::Result<T>,
    ) -> crate::Result<Option<(T, Mode, Stat)>> {
        cancellation.check()?;
        if matches!(prior_mode, Some(Mode::COMMIT | Mode::DIR)) {
            return Err(unsupported(action, path, "gitlink transitions are not supported").into());
        }
        if !matches!(
            prior_mode,
            None | Some(Mode::FILE | Mode::FILE_EXECUTABLE | Mode::SYMLINK)
        ) {
            return Err(unsupported(action, path, "the indexed file mode is not supported").into());
        }

        let workdir = self.repo.workdir().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "staging requires a worktree")
        })?;
        let relative = gix::path::from_bstr(path);
        let absolute = workdir.join(relative.as_ref());
        let Some(path_metadata) = selection::checked_symlink_metadata(workdir, path)? else {
            return if prior_mode.is_some() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "selected untracked path '{}' disappeared",
                        path.to_str_lossy().escape_debug()
                    ),
                )
                .into())
            };
        };
        if path_metadata.is_dir() {
            return if prior_mode.is_some() {
                Ok(None)
            } else {
                Err(unsupported(action, path, "the worktree path is not a regular file").into())
            };
        }
        if !path_metadata.is_file() {
            return Err(unsupported(
                action,
                path,
                "the worktree path has an unsupported file type",
            )
            .into());
        }

        let file = File::open(&absolute)?;
        let metadata = gix::index::fs::Metadata::from_file(&file)?;
        let Some(current_path_metadata) = selection::checked_symlink_metadata(workdir, path)?
        else {
            return Err(
                unsupported(action, path, "the worktree path changed while opening it").into(),
            );
        };
        if !metadata.is_file() || !current_path_metadata.is_file() {
            return Err(
                unsupported(action, path, "the worktree path changed while opening it").into(),
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.dev() != current_path_metadata.dev()
                || metadata.ino() != current_path_metadata.ino()
            {
                return Err(unsupported(
                    action,
                    path,
                    "the worktree path changed while opening it",
                )
                .into());
            }
        }

        let length = usize::try_from(metadata.len())
            .ok()
            .filter(|length| *length <= MAX_BLOB_BYTES)
            .ok_or_else(|| {
                unsupported(action, path, "the worktree file exceeds the 16 MiB limit")
            })?;
        let stat = Stat::from_fs(&metadata)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length)?;
        cancellation.check()?;
        file.take(MAX_BLOB_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        cancellation.check()?;
        if bytes.len() != length || bytes.len() > MAX_BLOB_BYTES {
            return Err(
                unsupported(action, path, "the worktree file changed size while reading").into(),
            );
        }
        let mode = match prior_mode {
            Some(Mode::SYMLINK) => Mode::SYMLINK,
            _ if metadata.is_executable() => Mode::FILE_EXECUTABLE,
            _ => Mode::FILE,
        };

        let converted = if mode == Mode::SYMLINK {
            bytes.as_slice()
        } else {
            let converted =
                self.pipeline
                    .convert_to_git(bytes.as_slice(), relative.as_ref(), self.index)?;
            match converted {
                ToGitOutcome::Unchanged(bytes) | ToGitOutcome::Buffer(bytes) => bytes,
                ToGitOutcome::Process(_) => {
                    return Err(
                        unsupported(action, path, "external filters are not supported").into(),
                    );
                }
            }
        };
        if converted.len() > MAX_BLOB_BYTES {
            return Err(
                unsupported(action, path, "converted data exceeds the 16 MiB limit").into(),
            );
        }
        cancellation.check()?;
        let value = consume(converted)?;
        cancellation.check()?;
        Ok(Some((value, mode, stat)))
    }
}

fn unsupported(action: &str, path: &BStr, message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "cannot {action} '{}': {message}",
            path.to_str_lossy().escape_debug()
        ),
    )
}
