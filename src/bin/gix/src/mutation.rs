use std::{
    ffi::OsStr,
    fs::{self, OpenOptions, TryLockError},
    io::{self, BufWriter, Write},
    path::Path,
};

use gix::bstr::ByteSlice;

use crate::operation;

pub const OPERATION_LOCK_FILE: &str = "gix-operation-lock";
pub const OPERATION_FILE: &str = "gix-operation";
pub const INCOMPLETE_CLONE_FILE: &str = "gix-incomplete-clone";
const OPERATION_UPDATE_LOCK_FILE: &str = "gix-operation.lock";

const INDEX_BYTES_LIMIT: usize = 16 * 1024 * 1024;

const FOREIGN_OPERATIONS: [&str; 6] = [
    "MERGE_HEAD",
    "CHERRY_PICK_HEAD",
    "REVERT_HEAD",
    "rebase-apply",
    "rebase-merge",
    "sequencer",
];

/// Locks one ordinary mutation in the required operation-lock/index-lock order.
///
/// The caller must already have applied the common repository policy. The
/// operation lock remains held after either publication method consumes the
/// index lock. Retained-index edits are made inside `publish_edited_index()` so
/// it can compare stat caches to the timestamp captured before the edit.
pub struct Guard {
    index_lock: Option<gix::lock::File>,
    index: gix::index::File,
    // Fields drop in declaration order; release the advisory lock last.
    _operation_lock: fs::File,
}

impl Guard {
    pub fn acquire(repo: &gix::Repository) -> crate::Result<Self> {
        let operation_path = repo.git_dir().join(OPERATION_LOCK_FILE);
        reject_non_file(&operation_path)?;
        let operation_lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&operation_path)?;
        let metadata = operation_lock.metadata()?;
        if !metadata.is_file() || metadata.len() != 0 {
            return unsupported("the persistent gix operation lock is not an empty regular file");
        }
        match operation_lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "another gix mutation holds the repository operation lock",
                )
                .into());
            }
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }

        let index_lock = gix::lock::File::acquire_to_update_resource(
            repo.index_path(),
            gix::lock::acquire::Fail::Immediately,
            None,
        )?;
        if exists(&repo.git_dir().join(OPERATION_UPDATE_LOCK_FILE))? {
            return unsupported("repository has a stale gix operation update lock");
        }
        if let Some(record) = operation::read(&repo.git_dir().join(OPERATION_FILE))? {
            return unsupported(format!(
                "repository has unfinished gix {} operation",
                record.description()
            ));
        }
        reject_operation_state(repo.git_dir())?;
        validate_repository(repo)?;

        // Bypass the repository's shared snapshot: mutation must read the
        // index after acquiring index.lock.
        let index = match repo.open_index() {
            Ok(index) => index,
            Err(gix::worktree::open_index::Error::IndexFile(
                gix::index::file::init::Error::Io(error),
            )) if error.kind() == io::ErrorKind::NotFound => gix::index::File::from_state(
                gix::index::State::new(repo.object_hash()),
                repo.index_path(),
            ),
            Err(error) => return Err(error.into()),
        };
        validate_index(&index)?;
        Ok(Guard {
            index_lock: Some(index_lock),
            index,
            _operation_lock: operation_lock,
        })
    }

    pub fn index(&self) -> &gix::index::File {
        &self.index
    }

    /// Publish a newly reconstructed state with no retained stat/cache data.
    /// The caller must not use this for an edited copy of the loaded index.
    pub fn publish_fresh_index(
        &mut self,
        state: gix::index::State,
    ) -> crate::Result<gix::hash::ObjectId> {
        let index = gix::index::File::from_state(state, std::path::PathBuf::new());
        validate_index(&index)?;
        let lock = self.take_index_lock()?;
        publish_index(lock, &index)
    }

    /// Edit and publish the index loaded after taking `index.lock`.
    ///
    /// Racy stat caches are invalidated against the old index timestamp after
    /// the edit. Entry flags, including conflict stages, are left unchanged;
    /// the ordinary unsupported-flag validation still applies before writing.
    pub fn publish_edited_index(
        &mut self,
        edit: impl FnOnce(&mut gix::index::State) -> crate::Result,
    ) -> crate::Result<gix::hash::ObjectId> {
        let old_timestamp = self.index.timestamp();
        edit(&mut self.index)?;
        self.index.sort_entries();
        validate_index(&self.index)?;

        let stat_options = gix::index::entry::stat::Options {
            trust_ctime: false,
            check_stat: false,
            use_nsec: false,
            use_stdev: false,
        };
        for entry in self.index.entries_mut() {
            if entry.stat.is_racy(old_timestamp, stat_options) {
                entry.stat.size = 0;
            }
        }
        let lock = self.take_index_lock()?;
        publish_index(lock, &self.index)
    }

    fn take_index_lock(&mut self) -> crate::Result<gix::lock::File> {
        self.index_lock
            .take()
            .ok_or_else(|| io::Error::other("the index lock was already consumed").into())
    }
}

fn publish_index(
    lock: gix::lock::File,
    index: &gix::index::File,
) -> crate::Result<gix::hash::ObjectId> {
    let limited = LimitedWriter {
        inner: lock,
        remaining: INDEX_BYTES_LIMIT,
    };
    let mut writer = BufWriter::with_capacity(64 * 1024, limited);
    let (_, checksum) = index.write_to(
        &mut writer,
        gix::index::write::Options {
            extensions: gix::index::write::Extensions::None,
            skip_hash: false,
        },
    )?;
    writer.flush()?;
    writer
        .into_inner()
        .map_err(|error| error.into_error())?
        .inner
        .commit()
        .map_err(|error| error.error)?;
    Ok(checksum)
}

struct LimitedWriter<W> {
    inner: W,
    remaining: usize,
}

impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "serialized index exceeds the 16 MiB native reader limit",
            ));
        }
        let written = self.inner.write(bytes)?;
        self.remaining -= written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn validate_repository(repo: &gix::Repository) -> crate::Result {
    if repo.object_hash() != gix::hash::Kind::Sha1 {
        return unsupported("only SHA-1 repositories support mutation");
    }
    if repo.namespace().is_some() {
        return unsupported("reference namespaces are unsupported for mutation");
    }
    let shallow = repo.git_dir().join("shallow");
    if repo.shallow_file() != shallow {
        return unsupported("repository configuration selected a different shallow file");
    }
    match fs::metadata(&shallow) {
        Ok(metadata) if !metadata.is_file() || metadata.len() != 0 => {
            return unsupported("shallow repositories are unsupported for mutation");
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let store = repo.objects.store_ref();
    reject_promisor_packs(store.path())?;
    for object_dir in store.alternate_db_paths()? {
        reject_promisor_packs(&object_dir)?;
    }

    let snapshot = repo.config_snapshot();
    for key in [
        "core.sparseCheckout",
        "core.sparseCheckoutCone",
        "index.sparse",
    ] {
        if snapshot.try_boolean(key)?.unwrap_or(false) {
            return unsupported(format!("{key} is unsupported for mutation"));
        }
    }
    if snapshot.try_boolean("index.skipHash")?.unwrap_or(false) {
        return unsupported("index.skipHash is unsupported for mutation");
    }
    let config = snapshot.plumbing();
    if config
        .sections_by_name("extensions")
        .into_iter()
        .flatten()
        .any(|section| section.contains_value_name("partialClone"))
    {
        return unsupported("partial-clone repositories are unsupported for mutation");
    }
    for section in config.sections_by_name("remote").into_iter().flatten() {
        if section.contains_value_name("partialCloneFilter") {
            return unsupported("partial-clone filters are unsupported for mutation");
        }
        if section.contains_value_name("promisor")
            && config
                .boolean_by("remote", section.header().subsection_name(), "promisor")?
                .unwrap_or(false)
        {
            return unsupported("promisor remotes are unsupported for mutation");
        }
    }
    Ok(())
}

fn reject_promisor_packs(object_dir: &Path) -> crate::Result {
    match fs::read_dir(object_dir.join("pack")) {
        Ok(entries) => {
            for entry in entries {
                if entry?.path().extension() == Some(OsStr::new("promisor")) {
                    return unsupported("promisor packs are unsupported for mutation");
                }
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn validate_index(index: &gix::index::File) -> crate::Result {
    index.verify_entries()?;
    if index.is_sparse() {
        return unsupported("sparse indexes are unsupported for mutation");
    }
    for (flag, name) in [
        (gix::index::entry::Flags::INTENT_TO_ADD, "intent-to-add"),
        (gix::index::entry::Flags::SKIP_WORKTREE, "skip-worktree"),
        (gix::index::entry::Flags::ASSUME_VALID, "assume-valid"),
    ] {
        if let Some(entry) = index
            .entries()
            .iter()
            .find(|entry| entry.flags.contains(flag))
        {
            return unsupported(format!(
                "index entry '{}' uses unsupported {name}",
                entry.path(index).to_str_lossy()
            ));
        }
    }
    Ok(())
}

fn reject_operation_state(git_dir: &Path) -> crate::Result {
    if exists(&git_dir.join(INCOMPLETE_CLONE_FILE))? {
        return unsupported(format!(
            "repository has unfinished gix state '{INCOMPLETE_CLONE_FILE}'"
        ));
    }
    for name in FOREIGN_OPERATIONS {
        if exists(&git_dir.join(name))? {
            return unsupported(format!(
                "repository has unsupported operation state '{name}'"
            ));
        }
    }
    Ok(())
}

pub(crate) fn owned_operation(git_dir: &Path) -> io::Result<Option<String>> {
    if exists(&git_dir.join(INCOMPLETE_CLONE_FILE))? {
        return Ok(Some("incomplete-clone".into()));
    }
    Ok(operation::read(&git_dir.join(OPERATION_FILE))?.map(|record| record.description()))
}

fn reject_non_file(path: &Path) -> crate::Result {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            unsupported("the persistent gix operation lock is not a regular file")
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn unsupported<T>(message: impl Into<String>) -> crate::Result<T> {
    Err(io::Error::new(io::ErrorKind::Unsupported, message.into()).into())
}
