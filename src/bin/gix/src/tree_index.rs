use std::{
    collections::{HashSet, VecDeque},
    io,
    path::Path,
};

use gix::{
    bstr::{BStr, BString, ByteSlice},
    index::entry::{Flags, Mode},
    objs::tree::EntryKind,
    prelude::{Find, Header},
};

use crate::cancellation::Cancellation;

// Motor caps components at 255 bytes and absolute paths below 1024 bytes.
const LIMITS: Limits = Limits {
    max_entries: 65_536,
    max_path_bytes: 8 * 1024 * 1024,
    max_blob_bytes: 16 * 1024 * 1024,
    max_source_blob_bytes: 128 * 1024 * 1024,
    max_component_bytes: 255,
    max_absolute_path_bytes: 1024,
};

// Fresh SHA-1 v2 indexes add at most 70 bytes per entry and 32 bytes per file.
// Keep every index we publish below the Motor reader's 16 MiB ceiling.
const _: () = assert!(LIMITS.max_path_bytes + LIMITS.max_entries * 70 + 32 <= 16 * 1024 * 1024);

#[derive(Clone, Copy)]
struct Limits {
    max_entries: usize,
    max_path_bytes: usize,
    max_blob_bytes: u64,
    max_source_blob_bytes: u64,
    max_component_bytes: usize,
    max_absolute_path_bytes: usize,
}

/// Build a bounded index from a target tree after validating every checkout path.
///
/// The repository must already use the application's bounded object-read policy.
pub fn build(
    repo: &gix::Repository,
    root: &gix::oid,
    destination: &Path,
    cancellation: &Cancellation,
) -> crate::Result<gix::index::State> {
    let destination = destination.canonicalize()?;
    let destination = destination
        .to_str()
        .ok_or_else(|| invalid("checkout destination is not UTF-8"))?;
    build_with_limits(repo, root, destination, cancellation, LIMITS)
}

/// Write the validated index snapshot held by the mutation guard as a tree
/// rooted at the empty tree.
pub fn write(
    repo: &gix::Repository,
    index: &gix::index::State,
    cancellation: &Cancellation,
) -> crate::Result<gix::ObjectId> {
    cancellation.check()?;
    index.verify_entries()?;
    for entry in index.entries() {
        cancellation.check()?;
        if entry.stage() != gix::index::entry::Stage::Unconflicted {
            return Err(invalid(format!(
                "index entry '{}' is unresolved",
                entry.path(index).to_str_lossy()
            ))
            .into());
        }
        if !matches!(
            entry.mode,
            Mode::FILE | Mode::FILE_EXECUTABLE | Mode::SYMLINK | Mode::COMMIT
        ) {
            return Err(invalid(format!(
                "index entry '{}' has unsupported mode {:o}",
                entry.path(index).to_str_lossy(),
                entry.mode.bits()
            ))
            .into());
        }
        let path = entry.path(index);
        // The editor accepts placeholders and file-to-tree replacement; an index must not.
        if entry.id.is_null() {
            return Err(invalid(format!(
                "index entry '{}' has a null object ID",
                path.to_str_lossy().escape_debug()
            ))
            .into());
        }
        for (offset, byte) in path.iter().enumerate() {
            if *byte != b'/' {
                continue;
            }
            let ancestor = path[..offset].as_bstr();
            if index
                .entry_by_path_and_stage(ancestor, gix::index::entry::Stage::Unconflicted)
                .is_some()
            {
                return Err(invalid(format!(
                    "index entry '{}' is an ancestor of '{}'",
                    ancestor.to_str_lossy().escape_debug(),
                    path.to_str_lossy().escape_debug()
                ))
                .into());
            }
        }
    }

    let mut editor = repo.empty_tree().edit()?;
    for entry in index.entries() {
        cancellation.check()?;
        let mode = entry
            .mode
            .to_tree_entry_mode()
            .expect("supported index modes convert to tree modes");
        editor.upsert(entry.path(index), mode.kind(), entry.id)?;
    }
    cancellation.check()?;
    Ok(editor.write()?.detach())
}

fn build_with_limits(
    repo: &gix::Repository,
    root: &gix::oid,
    destination: &str,
    cancellation: &Cancellation,
    limits: Limits,
) -> crate::Result<gix::index::State> {
    let object_hash = repo.object_hash();
    if !destination.starts_with('/') || destination.len() >= limits.max_absolute_path_bytes {
        return Err(invalid("checkout destination is not a bounded absolute path").into());
    }

    let mut state = gix::index::State::new(object_hash);
    let mut queue = VecDeque::new();
    queue.try_reserve(1)?;
    queue.push_back((root.to_owned(), BString::default()));
    let mut tree_buffer = Vec::new();
    let mut entry_count = 0usize;
    let mut path_bytes = 0usize;
    let mut source_blob_bytes = 0u64;

    while let Some((tree_id, prefix)) = queue.pop_front() {
        cancellation.check()?;
        if tree_id == gix::ObjectId::empty_tree(object_hash) {
            continue;
        }
        let tree = repo
            .objects
            .try_find(&tree_id, &mut tree_buffer)?
            .ok_or_else(|| invalid(format!("tree {tree_id} is missing")))?;
        if tree.kind != gix::objs::Kind::Tree {
            return Err(invalid(format!("object {tree_id} is not a tree")).into());
        }

        // Counting directories and full paths bounds the queue; per-tree uniqueness also catches
        // file/tree conflicts independently of Git tree ordering.
        let mut names = HashSet::<&BStr>::new();
        for entry in gix::objs::TreeRefIter::from_bytes(tree.data, tree.object_hash) {
            cancellation.check()?;
            let entry = entry?;
            entry_count = entry_count
                .checked_add(1)
                .filter(|count| *count <= limits.max_entries)
                .ok_or_else(|| invalid("target tree has too many entries"))?;
            let kind = supported_kind(entry.mode)?;
            validate_component(entry.filename, kind, limits.max_component_bytes)?;
            names.try_reserve(1)?;
            if !names.insert(entry.filename) {
                return Err(invalid(format!(
                    "target tree contains duplicate name '{}'",
                    entry.filename.to_str_lossy().escape_debug()
                ))
                .into());
            }

            let path_len = prefix
                .len()
                .checked_add(usize::from(!prefix.is_empty()))
                .and_then(|len| len.checked_add(entry.filename.len()))
                .ok_or_else(|| invalid("target path length overflow"))?;
            path_bytes = path_bytes
                .checked_add(path_len)
                .filter(|bytes| *bytes <= limits.max_path_bytes)
                .ok_or_else(|| invalid("target tree paths exceed their byte limit"))?;
            let separator = usize::from(destination != "/");
            let absolute_len = destination
                .len()
                .checked_add(separator)
                .and_then(|len| len.checked_add(path_len))
                .ok_or_else(|| invalid("target absolute path length overflow"))?;
            if absolute_len >= limits.max_absolute_path_bytes {
                return Err(invalid("target absolute path exceeds the Motor limit").into());
            }

            let mut path = Vec::new();
            path.try_reserve_exact(path_len)?;
            path.extend_from_slice(&prefix);
            if !prefix.is_empty() {
                path.push(b'/');
            }
            path.extend_from_slice(entry.filename);
            let path: BString = path.into();

            if kind == EntryKind::Tree {
                queue.try_reserve(1)?;
                queue.push_back((entry.oid.to_owned(), path));
                continue;
            }
            if matches!(
                kind,
                EntryKind::Blob | EntryKind::BlobExecutable | EntryKind::Link
            ) {
                let header = repo
                    .objects
                    .try_header(entry.oid)?
                    .ok_or_else(|| invalid(format!("blob {} is missing", entry.oid)))?;
                if header.kind() != gix::objs::Kind::Blob {
                    return Err(invalid(format!("object {} is not a blob", entry.oid)).into());
                }
                if header.size() > limits.max_blob_bytes {
                    return Err(
                        invalid(format!("blob {} exceeds its byte limit", entry.oid)).into(),
                    );
                }
                source_blob_bytes = source_blob_bytes
                    .checked_add(header.size())
                    .filter(|bytes| *bytes <= limits.max_source_blob_bytes)
                    .ok_or_else(|| invalid("target source blobs exceed their byte limit"))?;
            }
            state.dangerously_push_entry(
                Default::default(),
                entry.oid.to_owned(),
                Flags::empty(),
                Mode::from(kind),
                path.as_ref(),
            );
        }
    }
    state.sort_entries();
    state.verify_entries()?;
    Ok(state)
}

fn supported_kind(mode: gix::objs::tree::EntryMode) -> crate::Result<EntryKind> {
    let raw = mode.value();
    match raw & 0o170000 {
        0o040000 | 0o100000 | 0o120000 | 0o160000 => Ok(mode.kind()),
        _ => Err(invalid(format!("target tree contains unsupported mode {raw:o}")).into()),
    }
}

fn validate_component(name: &BStr, kind: EntryKind, max_bytes: usize) -> crate::Result {
    gix::validate::path::component(
        name,
        (kind == EntryKind::Link).then_some(gix::validate::path::component::Mode::Symlink),
        Default::default(),
    )?;
    let utf8 = std::str::from_utf8(name)?;
    if name.len() > max_bytes || utf8.trim().len() != utf8.len() || utf8.starts_with("..") {
        return Err(invalid(format!(
            "target tree component '{}' is invalid on Motor",
            utf8.escape_debug()
        ))
        .into());
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, time::SystemTime};

    use super::*;

    struct Cleanup(PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn entry(name: &str, kind: EntryKind, oid: gix::ObjectId) -> gix::objs::tree::Entry {
        gix::objs::tree::Entry {
            mode: kind.into(),
            filename: name.into(),
            oid,
        }
    }

    fn tree(
        repo: &gix::Repository,
        entries: Vec<gix::objs::tree::Entry>,
    ) -> crate::Result<gix::ObjectId> {
        Ok(repo.write_object(gix::objs::Tree { entries })?.detach())
    }

    #[test]
    fn writes_all_index_modes_and_rejects_conflicts() -> crate::Result {
        let path = std::env::temp_dir().join(format!(
            "motor-gix-tree-write-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_nanos()
        ));
        let _cleanup = Cleanup(path.clone());
        let repo = gix::init_bare(path)?;
        let empty = gix::index::State::new(repo.object_hash());
        assert_eq!(
            write(&repo, &empty, &Cancellation::new())?,
            gix::ObjectId::empty_tree(repo.object_hash())
        );

        let blob = repo.write_blob(b"data")?.detach();
        let gitlink = gix::ObjectId::from_bytes_or_panic(&[1; 20]);
        assert!(!repo.has_object(gitlink));
        let mut index = gix::index::State::new(repo.object_hash());
        for (path, mode, id) in [
            ("nested/file", Mode::FILE, blob),
            ("executable", Mode::FILE_EXECUTABLE, blob),
            ("link", Mode::SYMLINK, blob),
            ("submodule", Mode::COMMIT, gitlink),
        ] {
            index.dangerously_push_entry(
                Default::default(),
                id,
                Flags::empty(),
                mode,
                path.as_bytes().as_bstr(),
            );
        }
        index.sort_entries();
        index.verify_entries()?;

        let tree = repo.find_tree(write(&repo, &index, &Cancellation::new())?)?;
        for (path, kind, id) in [
            ("nested/file", EntryKind::Blob, blob),
            ("executable", EntryKind::BlobExecutable, blob),
            ("link", EntryKind::Link, blob),
            ("submodule", EntryKind::Commit, gitlink),
        ] {
            let entry = tree
                .lookup_entry_by_path(path)?
                .ok_or_else(|| invalid(format!("tree entry '{path}' is missing")))?;
            assert_eq!((entry.mode().kind(), entry.object_id()), (kind, id));
        }

        // A sorted index may still contain leaves that cannot coexist in a tree.
        for (paths, id, expected) in [
            (&["a", "a.b", "a/c"][..], blob, "ancestor"),
            (&["null"][..], repo.object_hash().null(), "null object ID"),
        ] {
            let mut invalid_index = gix::index::State::new(repo.object_hash());
            for path in paths {
                invalid_index.dangerously_push_entry(
                    Default::default(),
                    id,
                    Flags::empty(),
                    Mode::FILE,
                    path.as_bytes().as_bstr(),
                );
            }
            invalid_index.verify_entries()?;
            let error = write(&repo, &invalid_index, &Cancellation::new())
                .expect_err("invalid index entries were silently dropped");
            assert!(error.to_string().contains(expected), "{error}");
        }

        index.dangerously_push_entry(
            Default::default(),
            blob,
            Flags::from_stage(gix::index::entry::Stage::Ours),
            Mode::FILE,
            b"conflict".as_bstr(),
        );
        index.sort_entries();
        assert!(write(&repo, &index, &Cancellation::new()).is_err());
        Ok(())
    }

    #[test]
    fn valid_modes_bounds_paths_and_collisions() -> crate::Result {
        let path = std::env::temp_dir().join(format!(
            "motor-gix-tree-index-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_nanos()
        ));
        let _cleanup = Cleanup(path.clone());
        let repo = gix::init_bare(path)?;
        let blob = repo.write_blob(b"data")?.detach();
        let nested = tree(&repo, vec![entry("file", EntryKind::Blob, blob)])?;
        let mut regular = entry("exec", EntryKind::Blob, blob);
        regular.mode = gix::objs::tree::EntryMode::try_from(0o100664)
            .map_err(|mode| invalid(format!("test mode {mode:o} was rejected")))?;
        let root = tree(
            &repo,
            vec![
                entry("dir", EntryKind::Tree, nested),
                regular,
                entry("link", EntryKind::Link, blob),
                entry("submodule", EntryKind::Commit, blob),
            ],
        )?;
        let cancellation = Cancellation::new();
        let limits = Limits {
            max_entries: 5,
            max_path_bytes: 28,
            max_blob_bytes: 4,
            max_source_blob_bytes: 12,
            max_component_bytes: 255,
            max_absolute_path_bytes: 1024,
        };
        let state = build_with_limits(&repo, &root, "/x", &cancellation, limits)?;
        assert_eq!(state.entries().len(), 4);
        let regular = state
            .entries()
            .iter()
            .find(|entry| entry.path(&state) == b"exec")
            .ok_or_else(|| invalid("normalized regular entry is missing"))?;
        assert_eq!(regular.mode, Mode::FILE);
        let rejects = |root: &gix::oid, limits| {
            build_with_limits(&repo, root, "/x", &cancellation, limits).is_err()
        };

        let constraints: [fn(&mut Limits); 6] = [
            |limits| limits.max_entries = 4,
            |limits| limits.max_path_bytes = 27,
            |limits| limits.max_blob_bytes = 3,
            |limits| limits.max_source_blob_bytes = 11,
            |limits| limits.max_component_bytes = 3,
            |limits| limits.max_absolute_path_bytes = 12,
        ];
        for constrain in constraints {
            let mut constrained = limits;
            constrain(&mut constrained);
            assert!(rejects(&root, constrained));
        }

        let duplicate = tree(
            &repo,
            vec![
                entry("same", EntryKind::Blob, blob),
                entry("same", EntryKind::Tree, nested),
            ],
        )?;
        let invalid_name = tree(&repo, vec![entry("..bad", EntryKind::Blob, blob)])?;
        let wrong_blob = tree(&repo, vec![entry("bad", EntryKind::Blob, nested)])?;
        let mut bad_mode = entry("mode", EntryKind::Blob, blob);
        bad_mode.mode = gix::objs::tree::EntryMode::try_from(0o130000)
            .map_err(|mode| invalid(format!("test mode {mode:o} was rejected")))?;
        let bad_mode = tree(&repo, vec![bad_mode])?;
        assert!(
            [
                duplicate,
                invalid_name,
                wrong_blob,
                bad_mode,
                blob,
                gix::hash::Kind::Sha1.null(),
            ]
            .iter()
            .all(|root| rejects(root, limits))
        );

        let cancelled = Cancellation::new();
        cancelled.cancel();
        assert!(build_with_limits(&repo, &root, "/x", &cancelled, limits).is_err());
        Ok(())
    }
}
