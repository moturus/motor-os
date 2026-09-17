use std::{
    ffi::OsStr,
    fs::{self, OpenOptions, TryLockError},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
};

use gix::bstr::ByteSlice;

use crate::operation::{self, Kind, Record, State};

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
    operation_path: PathBuf,
    // Fields drop in declaration order; release the advisory lock last.
    _operation_lock: fs::File,
}

impl Guard {
    pub fn acquire(repo: &gix::Repository) -> crate::Result<Self> {
        let (guard, _) = Self::acquire_with(repo, Admission::Ordinary)?;
        Ok(guard)
    }

    /// Acquire the mutation locks for an interrupted operation which recovery may finish.
    pub fn acquire_for_recovery(repo: &gix::Repository) -> crate::Result<(Self, Record)> {
        let (guard, record) = Self::acquire_with(repo, Admission::Recovery)?;
        let Some(record) = record else {
            return unsupported("repository has no interrupted gix operation");
        };
        Ok((guard, record))
    }

    fn acquire_with(
        repo: &gix::Repository,
        admission: Admission,
    ) -> crate::Result<(Self, Option<Record>)> {
        let lock_path = repo.git_dir().join(OPERATION_LOCK_FILE);
        reject_non_file(&lock_path)?;
        let operation_lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)?;
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
        let operation_path = repo.git_dir().join(OPERATION_FILE);
        if exists(&repo.git_dir().join(OPERATION_UPDATE_LOCK_FILE))? {
            return unsupported("repository has a stale gix operation update lock");
        }
        let record = operation::read(&operation_path)?;
        let allow_merge_head = match (admission, record.as_ref()) {
            (Admission::Ordinary, Some(record)) => {
                return unsupported(format!(
                    "repository has unfinished gix {} operation",
                    record.description()
                ));
            }
            (Admission::Ordinary, None) => false,
            (Admission::Recovery, None) => {
                return unsupported("repository has no interrupted gix operation");
            }
            (Admission::Recovery, Some(record)) if record.state == State::Ready => {
                return unsupported("ready merge must be committed or aborted");
            }
            (Admission::Recovery, Some(record)) => record.kind == Kind::Merge,
        };
        reject_operation_state(repo.git_dir(), allow_merge_head)?;
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
        Ok((
            Guard {
                index_lock: Some(index_lock),
                index,
                operation_path,
                _operation_lock: operation_lock,
            },
            record,
        ))
    }

    pub fn index(&self) -> &gix::index::File {
        &self.index
    }

    pub fn create_operation(&self, next: &Record) -> crate::Result {
        if next.state != State::Incomplete {
            return unsupported("a new gix operation must be incomplete");
        }
        let lock = operation_lock(&self.operation_path)?;
        if operation::read(&self.operation_path)?.is_some() {
            return unsupported("repository already has a gix operation");
        }
        write_operation(lock, next)
    }

    /// Require the exact operation record to remain persisted under this guard.
    pub(crate) fn require_operation(&self, expected: &Record) -> crate::Result {
        require_operation(&self.operation_path, expected)
    }

    pub fn replace_operation(&self, expected: &Record, next: &Record) -> crate::Result {
        operation::validate_transition(expected, next)?;
        let lock = operation_lock(&self.operation_path)?;
        require_operation(&self.operation_path, expected)?;
        write_operation(lock, next)
    }

    pub fn remove_operation(&self, expected: &Record) -> crate::Result {
        let lock = operation_lock(&self.operation_path)?;
        require_operation(&self.operation_path, expected)?;
        fs::remove_file(&self.operation_path)?;
        drop(lock);
        Ok(())
    }

    /// Remove owned merge files before the operation record, retaining the record on failure.
    /// The caller must validate the recorded objects and current refs before cleanup.
    pub fn cleanup_operation(
        &self,
        expected: &Record,
        cancellation: &crate::cancellation::Cancellation,
    ) -> crate::Result {
        cancellation.check()?;
        self.require_operation(expected)?;
        if expected.kind == Kind::Merge {
            for name in ["MERGE_HEAD", "MERGE_MSG"] {
                cancellation.check()?;
                let path = self.operation_path.with_file_name(name);
                match fs::symlink_metadata(&path) {
                    Ok(metadata) if metadata.is_file() => fs::remove_file(path)?,
                    Ok(_) => {
                        return unsupported(format!(
                            "owned merge state '{name}' is not a regular file"
                        ));
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        cancellation.check()?;
        self.remove_operation(expected)
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

#[derive(Clone, Copy)]
enum Admission {
    Ordinary,
    Recovery,
}

fn operation_lock(path: &Path) -> crate::Result<gix::lock::File> {
    Ok(gix::lock::File::acquire_to_update_resource(
        path,
        gix::lock::acquire::Fail::Immediately,
        None,
    )?)
}

fn require_operation(path: &Path, expected: &Record) -> crate::Result {
    match operation::read(path)? {
        Some(actual) if actual == *expected => Ok(()),
        Some(_) => unsupported("gix operation changed while it was being updated"),
        None => unsupported("gix operation disappeared while it was being updated"),
    }
}

fn write_operation(mut lock: gix::lock::File, record: &Record) -> crate::Result {
    lock.write_all(&record.encode()?)?;
    lock.flush()?;
    lock.commit().map_err(|error| error.error)?;
    Ok(())
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

fn reject_operation_state(git_dir: &Path, allow_merge_head: bool) -> crate::Result {
    if exists(&git_dir.join(INCOMPLETE_CLONE_FILE))? {
        return unsupported(format!(
            "repository has unfinished gix state '{INCOMPLETE_CLONE_FILE}'"
        ));
    }
    for name in FOREIGN_OPERATIONS {
        if allow_merge_head && name == "MERGE_HEAD" {
            continue;
        }
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
