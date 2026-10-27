use super::*;
use moto_sdk::async_fs::{BLOCK_SIZE, FileSystem, ROOT_ID};
use std::future::Future;

const MODE: RolePermissions = RolePermissions::all(AccessPermissions::Rwx);
const SYS: Role = Role::System;
const PAGE: u64 = BLOCK_SIZE as u64;

fn run(future: impl Future<Output = ()>) {
    let mut future = std::pin::pin!(future);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(future.as_mut().poll(&mut cx).is_ready());
}

fn fs(cap: u64, cache: u64) -> MemFs {
    MemFs::new(MemFsConfig {
        max_size: cap,
        free_cache_cap: cache,
        root_mode: MODE,
    })
    .unwrap()
}

fn file(fs: &mut MemFs, name: &str) -> EntryId {
    fs.create_entry_sync(SYS, ROOT_ID, EntryKind::File, name, MODE)
        .unwrap()
}

fn error<T>(result: Result<T>, kind: ErrorKind) {
    assert_eq!(result.err().expect("expected failure").kind(), kind);
}

fn bytes(fs: &MemFs, id: EntryId, offset: u64, len: usize) -> Vec<u8> {
    let mut buf = vec![0xee; len];
    let read = fs.read_sync(SYS, id, offset, &mut buf).unwrap();
    buf.truncate(read);
    buf
}

#[test]
fn trait_namespace_and_metadata() {
    run(async {
        let mut fs = fs(64 * 1024, PAGE);
        let root_usage = fs.used_bytes();
        assert_eq!(fs.entry_count(), 1);
        assert_eq!(fs.name(SYS, 0).await.unwrap(), "/");
        assert_eq!(fs.get_parent(SYS, 0).await.unwrap(), None);
        assert_eq!(fs.get_next_entry(SYS, 0).await.unwrap(), None);
        assert_eq!(fs.get_first_entry(SYS, 0).await.unwrap(), None);
        assert_eq!(FileSystem::num_blocks(&fs), 16);
        assert_eq!(
            fs.empty_blocks().await.unwrap(),
            (fs.max_size() - root_usage) / PAGE
        );
        let dir = fs
            .create_entry(SYS, 0, EntryKind::Directory, "dir", MODE)
            .await
            .unwrap();
        let z = fs
            .create_entry(SYS, dir, EntryKind::File, "z", MODE)
            .await
            .unwrap();
        let a = fs
            .create_entry(SYS, dir, EntryKind::File, "a", MODE)
            .await
            .unwrap();
        assert_eq!(fs.get_first_entry(SYS, dir).await.unwrap(), Some(a));
        assert_eq!(fs.get_next_entry(SYS, a).await.unwrap(), Some(z));
        assert_eq!(fs.get_next_entry(SYS, z).await.unwrap(), None);
        assert_eq!(fs.get_parent(SYS, z).await.unwrap(), Some(dir));
        assert_eq!(
            fs.stat(SYS, dir, "z").await.unwrap(),
            Some((z, EntryKind::File))
        );
        assert_eq!(fs.stat(SYS, dir, "missing").await.unwrap(), None);
        assert_eq!(fs.metadata(SYS, dir).await.unwrap().size, 2);
        let created = fs.metadata(SYS, z).await.unwrap();
        assert!(created.created.as_nanos() > 0);
        assert_eq!(created.created.as_nanos(), created.modified.as_nanos());
        assert_eq!(fs.write(SYS, z, 2, b"hello").await.unwrap(), 5);
        let mut buf = [0xff; 9];
        assert_eq!(fs.read(SYS, z, 0, &mut buf).await.unwrap(), 7);
        assert_eq!(&buf, b"\0\0hello\xff\xff");
        assert!(
            fs.metadata(SYS, z).await.unwrap().modified.as_nanos() >= created.modified.as_nanos()
        );
        fs.resize(SYS, z, 3).await.unwrap();
        assert_eq!(fs.copy_file_range(SYS, z, 0, a, 0, 20).await.unwrap(), 3);
        assert_eq!(bytes(&fs, a, 0, 9), b"\0\0h");
        fs.move_noreplace(SYS, a, 0, "b").await.unwrap();
        fs.move_entry(SYS, z, 0, "b").await.unwrap();
        error(fs.metadata(SYS, a).await, ErrorKind::InvalidInput);
        assert_eq!(fs.get_parent(SYS, z).await.unwrap(), Some(0));
        assert_eq!(fs.name(SYS, z).await.unwrap(), "b");
        fs.flush().await.unwrap();
        fs.delete_entry(SYS, dir).await.unwrap();
        fs.delete_entry(SYS, z).await.unwrap();
        assert_eq!(fs.used_bytes(), root_usage);
        assert_eq!(fs.entry_count(), 1);
    });
}

#[test]
fn sparse_boundaries_and_zeroing() {
    run(async {
        let mut fs = fs(16 * 1024, 2 * PAGE);
        let id = file(&mut fs, "sparse");
        let empty = fs.used_bytes();
        let far = 1 << 40;
        fs.resize(SYS, id, far).await.unwrap();
        assert_eq!(fs.used_bytes(), empty);
        assert_eq!(bytes(&fs, id, far - PAGE, BLOCK_SIZE), vec![0; BLOCK_SIZE]);
        fs.write(SYS, id, far - 3, b"abc").await.unwrap();
        assert_eq!(fs.used_bytes(), empty + BLOCK_CHARGE);
        let mut expected = vec![0; BLOCK_SIZE];
        expected[BLOCK_SIZE - 3..].copy_from_slice(b"abc");
        assert_eq!(bytes(&fs, id, far - PAGE, BLOCK_SIZE), expected);
        fs.resize(SYS, id, far - 2).await.unwrap();
        fs.resize(SYS, id, far).await.unwrap();
        assert_eq!(bytes(&fs, id, far - 3, 3), b"a\0\0");
        fs.resize(SYS, id, 0).await.unwrap();
        assert_eq!(fs.used_bytes(), empty);
        fs.resize(SYS, id, u64::MAX).await.unwrap();
        fs.write(SYS, id, u64::MAX - 1, &[42]).await.unwrap();
        assert_eq!(bytes(&fs, id, u64::MAX - 2, 2), [0, 42]);
        error(
            fs.write(SYS, id, u64::MAX, &[1]).await,
            ErrorKind::InvalidInput,
        );
        error(
            fs.read(SYS, id, u64::MAX, &mut [0]).await,
            ErrorKind::InvalidInput,
        );
        error(
            fs.write(SYS, id, PAGE - 1, &[1, 2]).await,
            ErrorKind::InvalidInput,
        );
        error(
            fs.read(SYS, id, PAGE - 1, &mut [0; 2]).await,
            ErrorKind::InvalidInput,
        );
        assert_eq!(fs.write(SYS, id, u64::MAX, &[]).await.unwrap(), 0);
        assert_eq!(fs.read(SYS, id, u64::MAX, &mut []).await.unwrap(), 0);
        fs.resize(SYS, id, 0).await.unwrap();
        assert_eq!(fs.used_bytes(), empty);
        assert_eq!(fs.metadata(SYS, id).await.unwrap().size, 0);
        // Cross-block primitives are rejected even at EOF, before touching a buffer.
        error(
            fs.read(SYS, id, PAGE - 1, &mut [0; 2]).await,
            ErrorKind::InvalidInput,
        );
    });
}

#[test]
fn quota_and_failed_writes_are_atomic() {
    run(async {
        error(
            MemFs::new(MemFsConfig {
                max_size: ENTRY_CHARGE,
                free_cache_cap: 0,
                root_mode: MODE,
            }),
            ErrorKind::StorageFull,
        );
        let mut fs = fs(
            ENTRY_CHARGE + 1 + ENTRY_CHARGE + DIR_LINK_CHARGE + 1 + BLOCK_CHARGE,
            0,
        );
        let id = file(&mut fs, "f");
        let initial = fs.used_bytes();
        let cache = fs.free_block_cache();
        cache.fail_alloc(true);
        error(fs.write(SYS, id, 5, b"no").await, ErrorKind::StorageFull);
        assert_eq!(fs.used_bytes(), initial);
        assert_eq!(fs.metadata(SYS, id).await.unwrap().size, 0);
        assert_eq!(cache.page_counts(), (0, 0));
        cache.fail_alloc(false);
        fs.write(SYS, id, 0, b"yes").await.unwrap();
        assert_eq!(fs.used_bytes(), fs.max_size());
        let metadata = fs.metadata(SYS, id).await.unwrap();
        error(fs.write(SYS, id, PAGE, b"no").await, ErrorKind::StorageFull);
        assert_eq!(fs.used_bytes(), fs.max_size());
        assert_eq!(fs.metadata(SYS, id).await.unwrap().size, metadata.size);
        assert_eq!(
            fs.metadata(SYS, id).await.unwrap().modified.as_nanos(),
            metadata.modified.as_nanos()
        );
        assert_eq!(bytes(&fs, id, 0, 3), b"yes");
        // The same atomicity holds when quota is available but the page
        // allocator refuses an extension of a nonempty file.
        fs.cap += BLOCK_CHARGE;
        cache.fail_alloc(true);
        error(fs.write(SYS, id, PAGE, b"no").await, ErrorKind::StorageFull);
        assert_eq!(fs.used_bytes(), initial + BLOCK_CHARGE);
        assert_eq!(fs.metadata(SYS, id).await.unwrap().size, metadata.size);
        assert_eq!(bytes(&fs, id, 0, 3), b"yes");
        assert_eq!(cache.page_counts(), (1, 0));
        cache.fail_alloc(false);
        fs.cap -= BLOCK_CHARGE;
        // Overwrite and sparse growth still work at the cap.
        fs.write(SYS, id, 1, b"!").await.unwrap();
        fs.resize(SYS, id, 1 << 40).await.unwrap();
        assert_eq!(fs.used_bytes(), fs.max_size());
        assert_eq!(bytes(&fs, id, 0, 3), b"y!s");
        fs.resize(SYS, id, 0).await.unwrap();
        assert_eq!(fs.used_bytes(), initial);
        assert_eq!(cache.page_counts(), (1, 1));
    });
}

#[test]
fn metadata_charges_and_rename_rollback() {
    run(async {
        let mut fs = fs(8 * 1024, 0);
        let baseline = fs.used_bytes();
        let name = "é"; // Charge UTF-8 bytes once, not characters or two copies.
        let a = file(&mut fs, name);
        assert_eq!(
            fs.used_bytes(),
            baseline + ENTRY_CHARGE + DIR_LINK_CHARGE + name.len() as u64
        );
        fs.move_entry(SYS, a, 0, "longer").await.unwrap();
        assert_eq!(
            fs.used_bytes(),
            baseline + ENTRY_CHARGE + DIR_LINK_CHARGE + "longer".len() as u64
        );
        fs.move_entry(SYS, a, 0, name).await.unwrap();
        let mut ids = vec![a];
        loop {
            let name = format!("f{}", ids.len());
            match fs.create_entry(SYS, 0, EntryKind::File, &name, MODE).await {
                Ok(id) => ids.push(id),
                Err(err) => {
                    assert_eq!(err.kind(), ErrorKind::StorageFull);
                    break;
                }
            }
        }
        assert!(ids.len() < 20);
        let usage = fs.used_bytes();
        // Force precisely the current usage, leaving no room for a longer name.
        fs.cap = usage;
        error(
            fs.move_entry(SYS, a, 0, "longer").await,
            ErrorKind::StorageFull,
        );
        assert_eq!(fs.name(SYS, a).await.unwrap(), name);
        assert_eq!(fs.used_bytes(), usage);
        // Replacement's reclaimed entry charge is available to the same rename.
        fs.move_entry(SYS, a, 0, "f1").await.unwrap();
        error(fs.metadata(SYS, ids[1]).await, ErrorKind::InvalidInput);
        assert!(fs.used_bytes() < usage);
        fs.delete_entry(SYS, a).await.unwrap();
        for &id in &ids[2..] {
            fs.delete_entry(SYS, id).await.unwrap();
        }
        assert_eq!(fs.used_bytes(), baseline);
    });
}

#[test]
fn cache_ownership_reuse_and_drain() {
    run(async {
        let mut fs = fs(128 * 1024, PAGE + 17);
        let root_usage = fs.used_bytes();
        let id = file(&mut fs, "data");
        let cache = fs.free_block_cache();
        for page in 0..3 {
            fs.write(SYS, id, page * PAGE, &[0xab; BLOCK_SIZE])
                .await
                .unwrap();
        }
        assert_eq!(cache.page_counts(), (3, 0));
        fs.resize(SYS, id, PAGE).await.unwrap();
        assert_eq!(cache.cached_free_bytes(), PAGE);
        assert_eq!(cache.page_counts(), (3, 1));
        cache.fail_alloc(true); // A cached page must satisfy the next allocation.
        fs.write(SYS, id, 2 * PAGE + 4, b"x").await.unwrap();
        assert_eq!(bytes(&fs, id, 2 * PAGE, 8), b"\0\0\0\0x");
        fs.resize(SYS, id, 3 * PAGE).await.unwrap();
        let contents = bytes(&fs, id, 2 * PAGE, BLOCK_SIZE);
        assert_eq!(contents[4], b'x');
        assert!(
            contents[..4]
                .iter()
                .chain(contents[5..].iter())
                .all(|&b| b == 0)
        );
        assert_eq!(cache.page_counts(), (3, 1));
        fs.delete_entry(SYS, id).await.unwrap();
        assert_eq!(fs.used_bytes(), root_usage);
        assert_eq!(cache.page_counts(), (3, 2));
        let other = file(&mut fs, "other");
        fs.write(SYS, other, 8, &[7]).await.unwrap();
        assert_eq!(bytes(&fs, other, 0, 9), [0, 0, 0, 0, 0, 0, 0, 0, 7]);
        fs.delete_entry(SYS, other).await.unwrap();
        assert_eq!(cache.page_counts(), (3, 2));
        // Draining via a cloned handle doesn't borrow the filesystem.
        let _exclusive_fs_borrow = &mut fs;
        cache.release_free_blocks();
        assert_eq!(cache.cached_free_bytes(), 0);
        assert_eq!(cache.page_counts(), (3, 3));
        cache.release_free_blocks();
        assert_eq!(cache.page_counts(), (3, 3));
        cache.fail_alloc(false);
        let id = file(&mut fs, "again");
        fs.write(SYS, id, 0, &[1]).await.unwrap();
        fs.delete_entry(SYS, id).await.unwrap();
        drop(fs);
        assert_eq!(cache.cached_free_bytes(), PAGE);
        cache.release_free_blocks();
        assert_eq!(cache.page_counts(), (4, 4));
    });
}

#[test]
fn copies_commit_complete_chunks() {
    run(async {
        let mut fs = fs(64 * 1024, 0);
        let from = file(&mut fs, "from");
        let to = file(&mut fs, "to");
        for n in 0..3 {
            fs.write(SYS, from, n * PAGE, &[n as u8 + 1; BLOCK_SIZE])
                .await
                .unwrap();
        }
        fs.cap = fs.used_bytes() + BLOCK_CHARGE;
        assert_eq!(
            fs.copy_file_range(SYS, from, 0, to, 0, 3 * PAGE)
                .await
                .unwrap(),
            PAGE
        );
        assert_eq!(bytes(&fs, to, 0, BLOCK_SIZE), vec![1; BLOCK_SIZE]);
        assert_eq!(fs.metadata(SYS, to).await.unwrap().size, PAGE);
        error(
            fs.copy_file_range(SYS, from, 0, to, PAGE, PAGE).await,
            ErrorKind::StorageFull,
        );
        let usage = fs.used_bytes();
        error(
            fs.copy_file_range(SYS, from, u64::MAX, to, 0, 2).await,
            ErrorKind::InvalidInput,
        );
        error(
            fs.copy_file_range(SYS, from, 0, to, u64::MAX, 2).await,
            ErrorKind::InvalidInput,
        );
        assert_eq!(fs.used_bytes(), usage);
        fs.cap = 64 * 1024;
        fs.resize(SYS, to, 0).await.unwrap();
        assert_eq!(
            fs.copy_file_range(SYS, from, PAGE - 2, to, PAGE - 3, PAGE + 9)
                .await
                .unwrap(),
            PAGE + 9
        );
        assert_eq!(bytes(&fs, to, PAGE - 3, 3), [1, 1, 2]);
        assert_eq!(bytes(&fs, to, 2 * PAGE, 6), vec![3; 6]);
        assert_eq!(
            fs.copy_file_range(SYS, from, 3 * PAGE, to, 0, 1)
                .await
                .unwrap(),
            0
        );
        // Forward self-copy uses a bounded bounce buffer just like motor-fs.
        fs.write(SYS, to, 0, b"abcd").await.unwrap();
        assert_eq!(fs.copy_file_range(SYS, to, 0, to, 1, 3).await.unwrap(), 3);
        assert_eq!(bytes(&fs, to, 0, 4), b"aabc");
    });
}

#[test]
fn invalid_namespace_operations() {
    run(async {
        let mut fs = fs(64 * 1024, 0);
        let parent = fs
            .create_entry(SYS, 0, EntryKind::Directory, "parent", MODE)
            .await
            .unwrap();
        let child = fs
            .create_entry(SYS, parent, EntryKind::Directory, "child", MODE)
            .await
            .unwrap();
        let file = file(&mut fs, "file");
        let usage = fs.used_bytes();
        error(
            fs.delete_entry(SYS, parent).await,
            ErrorKind::DirectoryNotEmpty,
        );
        error(
            fs.move_entry(SYS, parent, child, "cycle").await,
            ErrorKind::InvalidInput,
        );
        error(
            fs.move_entry(SYS, file, 0, "parent").await,
            ErrorKind::DirectoryNotEmpty,
        );
        error(
            fs.move_noreplace(SYS, child, 0, "file").await,
            ErrorKind::AlreadyExists,
        );
        error(
            fs.move_entry(SYS, file, 0, "file").await,
            ErrorKind::InvalidInput,
        );
        error(fs.delete_entry(SYS, 0).await, ErrorKind::InvalidInput);
        error(
            fs.move_entry(SYS, 0, parent, "root").await,
            ErrorKind::InvalidInput,
        );
        error(fs.stat(SYS, file, "x").await, ErrorKind::NotADirectory);
        error(
            fs.get_first_entry(SYS, file).await,
            ErrorKind::NotADirectory,
        );
        error(
            fs.read(SYS, parent, 0, &mut [0]).await,
            ErrorKind::IsADirectory,
        );
        error(
            fs.write(SYS, parent, 0, &[0]).await,
            ErrorKind::IsADirectory,
        );
        error(fs.resize(SYS, parent, 0).await, ErrorKind::IsADirectory);
        for name in ["/", "..", "..abc", " x", "x ", "a/b", &"x".repeat(256)] {
            error(
                fs.create_entry(SYS, 0, EntryKind::File, name, MODE).await,
                ErrorKind::InvalidFilename,
            );
            error(fs.stat(SYS, 0, name).await, ErrorKind::InvalidFilename);
            error(
                fs.move_entry(SYS, file, 0, name).await,
                ErrorKind::InvalidFilename,
            );
        }
        assert_eq!(fs.used_bytes(), usage);
        assert_eq!(fs.get_parent(SYS, child).await.unwrap(), Some(parent));
        // Preserve the existing validator's accepted edge cases.
        for name in ["", ".", "a\0b", "é"] {
            let id = fs
                .create_entry(SYS, 0, EntryKind::File, name, MODE)
                .await
                .unwrap();
            assert_eq!(fs.stat(SYS, 0, name).await.unwrap().unwrap().0, id);
            fs.delete_entry(SYS, id).await.unwrap();
        }
        fs.delete_entry(SYS, child).await.unwrap();
        // motor-fs allows replacement across kinds when the directory is empty.
        fs.move_entry(SYS, file, 0, "parent").await.unwrap();
        error(fs.metadata(SYS, parent).await, ErrorKind::InvalidInput);
    });
}

#[test]
fn local_ids_never_alias_or_repeat() {
    run(async {
        let mut fs = fs(64 * 1024, 0);
        for counter in [0, 1, LOW_ID_MASK, LOW_ID_MASK + 1, u64::MAX] {
            assert_eq!(decode(encode(counter)).unwrap(), counter);
        }
        let first = file(&mut fs, "first");
        for bit in (56..64).chain(72..128) {
            let forged = first | (1_u128 << bit);
            error(fs.metadata(SYS, forged).await, ErrorKind::InvalidInput);
        }
        fs.delete_entry(SYS, first).await.unwrap();
        let second = file(&mut fs, "second");
        assert_ne!(first, second);
        error(fs.write(SYS, first, 0, &[1]).await, ErrorKind::InvalidInput);
        fs.last_id = LOW_ID_MASK;
        let high = file(&mut fs, "high");
        assert_eq!(high, 1 << 64);
        assert_eq!(fs.name(SYS, high).await.unwrap(), "high");
        fs.last_id = u64::MAX;
        error(
            fs.create_entry(SYS, 0, EntryKind::File, "exhausted", MODE)
                .await,
            ErrorKind::StorageFull,
        );
        assert_eq!(fs.stat(SYS, 0, "exhausted").await.unwrap(), None);
    });
}

#[test]
fn permission_matrix() {
    run(async {
        let accesses = [
            AccessPermissions::Rwx,
            AccessPermissions::Rx,
            AccessPermissions::Rw,
            AccessPermissions::R,
            AccessPermissions::None,
        ];
        for role in ROLES {
            for access in accesses {
                let mut fs = fs(64 * 1024, 0);
                let dir = fs
                    .create_entry(SYS, 0, EntryKind::Directory, "dir", MODE)
                    .await
                    .unwrap();
                let id = fs
                    .create_entry(SYS, dir, EntryKind::File, "file", MODE)
                    .await
                    .unwrap();
                fs.write(SYS, id, 0, b"x").await.unwrap();
                fs.set_all_permissions(SYS, id, RolePermissions::all(access))
                    .await
                    .unwrap();
                assert_eq!(
                    fs.read(role, id, 0, &mut [0]).await.is_ok(),
                    access.can_read()
                );
                assert_eq!(
                    fs.write(role, id, 0, b"y").await.is_ok(),
                    access.can_write()
                );
                assert_eq!(fs.resize(role, id, 2).await.is_ok(), access.can_write());
                // Metadata/name/parent queries are ungated, matching motor-fs.
                fs.metadata(role, id).await.unwrap();
                fs.name(role, id).await.unwrap();
                fs.get_parent(role, id).await.unwrap();
                fs.set_all_permissions(SYS, dir, RolePermissions::all(access))
                    .await
                    .unwrap();
                assert_eq!(
                    fs.stat(role, dir, "file").await.is_ok(),
                    access.can_execute()
                );
                assert_eq!(
                    fs.get_first_entry(role, dir).await.is_ok(),
                    access.can_execute()
                );
                assert_eq!(
                    fs.get_next_entry(role, id).await.is_ok(),
                    access.can_execute()
                );
                assert_eq!(
                    fs.create_entry(role, dir, EntryKind::File, "new", MODE)
                        .await
                        .is_ok(),
                    access.can_write()
                );
                assert_eq!(
                    fs.move_entry(role, id, dir, "renamed").await.is_ok(),
                    access.can_write()
                );
                assert_eq!(
                    fs.set_all_permissions(role, id, RolePermissions::all(access))
                        .await
                        .is_ok(),
                    access.can_write()
                );
                assert_eq!(fs.delete_entry(role, id).await.is_ok(), access.can_write());
            }
            for target in ROLES {
                for old in accesses {
                    for new in accesses {
                        let mut fs = fs(16 * 1024, 0);
                        let id = file(&mut fs, "file");
                        // Set the target and all lower roles while leaving higher
                        // roles Rwx, making the authority rule the decisive check.
                        fs.set_permissions(SYS, id, target, old).await.unwrap();
                        let before = fs.metadata(SYS, id).await.unwrap();
                        let allowed = may_set(role, target, old, new);
                        let result = fs.set_permissions(role, id, target, new).await;
                        assert_eq!(
                            result.is_ok(),
                            allowed,
                            "{role:?} {target:?} {old:?} -> {new:?}"
                        );
                        let after = fs.metadata(SYS, id).await.unwrap();
                        if allowed {
                            assert_eq!(after.access(target).unwrap(), new);
                            assert!(perms_monotonic(after.permissions().unwrap()));
                            for &lower in &ROLES[..target as usize] {
                                assert_eq!(
                                    after.access(lower).unwrap(),
                                    before.access(lower).unwrap().meet(new)
                                );
                            }
                        } else {
                            assert_eq!(after.permissions().unwrap(), before.permissions().unwrap());
                            assert_eq!(after.modified.as_nanos(), before.modified.as_nanos());
                        }
                    }
                }
            }
        }
    });
}

#[test]
fn permission_authority_and_both_parents() {
    run(async {
        let mut fs = fs(64 * 1024, 0);
        let dir = fs
            .create_entry(SYS, 0, EntryKind::Directory, "dir", MODE)
            .await
            .unwrap();
        let id = file(&mut fs, "file");
        let bad_mode = RolePermissions::new(
            AccessPermissions::R,
            AccessPermissions::Rw,
            AccessPermissions::None,
        );
        error(
            fs.set_all_permissions(SYS, id, bad_mode).await,
            ErrorKind::PermissionDenied,
        );
        error(
            fs.create_entry(SYS, 0, EntryKind::File, "bad", bad_mode)
                .await,
            ErrorKind::PermissionDenied,
        );
        error(
            MemFs::new(MemFsConfig {
                max_size: 4096,
                free_cache_cap: 0,
                root_mode: bad_mode,
            }),
            ErrorKind::PermissionDenied,
        );
        for caller in [Role::Interactive, Role::None] {
            error(
                fs.set_permissions(caller, 0, caller, AccessPermissions::Rx)
                    .await,
                ErrorKind::PermissionDenied,
            );
            error(
                fs.set_all_permissions(caller, 0, MODE).await,
                ErrorKind::PermissionDenied,
            );
            error(
                fs.create_entry(
                    caller,
                    0,
                    EntryKind::File,
                    "restricted-system",
                    RolePermissions::all(AccessPermissions::R),
                )
                .await,
                ErrorKind::PermissionDenied,
            );
        }
        fs.set_permissions(SYS, id, Role::Interactive, AccessPermissions::R)
            .await
            .unwrap();
        error(
            fs.set_permissions(Role::None, id, Role::None, AccessPermissions::Rw)
                .await,
            ErrorKind::PermissionDenied,
        );
        // Exact setters authorize only fields that change; single-role setters
        // still reject touching a higher role even when its value is unchanged.
        let mode = fs.metadata(SYS, id).await.unwrap().permissions().unwrap();
        fs.set_all_permissions(Role::None, id, mode).await.unwrap();
        error(
            fs.set_permissions(Role::None, id, SYS, AccessPermissions::Rwx)
                .await,
            ErrorKind::PermissionDenied,
        );
        fs.set_permissions(SYS, dir, Role::None, AccessPermissions::Rx)
            .await
            .unwrap();
        error(
            fs.move_entry(Role::None, id, dir, "moved").await,
            ErrorKind::PermissionDenied,
        );
        fs.move_entry(SYS, id, dir, "moved").await.unwrap();
        error(
            fs.move_entry(Role::None, id, 0, "back").await,
            ErrorKind::PermissionDenied,
        );
        error(
            fs.set_all_permissions(Role::None, id, mode).await,
            ErrorKind::PermissionDenied,
        );
        assert_eq!(fs.get_parent(SYS, id).await.unwrap(), Some(dir));
    });
}

#[test]
fn unchecked_lookup_ignores_traverse_rights() {
    let mut fs = fs(64 * 1024, 0);
    let dir = fs
        .create_entry_sync(SYS, ROOT_ID, EntryKind::Directory, "dir", MODE)
        .unwrap();
    let id = fs
        .create_entry_sync(SYS, dir, EntryKind::File, "file", MODE)
        .unwrap();
    fs.set_all_permissions_sync(SYS, dir, RolePermissions::all(AccessPermissions::Rw))
        .unwrap();
    error(fs.stat_sync(SYS, dir, "file"), ErrorKind::PermissionDenied);
    assert_eq!(
        fs.lookup_unchecked(dir, "file").unwrap(),
        Some((id, EntryKind::File))
    );
    assert_eq!(fs.lookup_unchecked(dir, "absent").unwrap(), None);
    error(fs.lookup_unchecked(dir, "a/b"), ErrorKind::InvalidFilename);
    error(fs.lookup_unchecked(id, "file"), ErrorKind::NotADirectory);
    fs.delete_entry_sync(SYS, id).unwrap();
    error(fs.lookup_unchecked(id, "file"), ErrorKind::InvalidInput);
}
