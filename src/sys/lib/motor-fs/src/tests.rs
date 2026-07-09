use async_fs::EntryId;
use async_fs::EntryKind;
use async_fs::FileSystem;
use async_fs::AccessPermissions;
use async_fs::Role;
use async_fs::file_block_device::AsyncFileBlockDevice;
use camino::Utf8PathBuf;
use rand::Rng;
use std::io::ErrorKind;
use std::io::Result;
use std::io::Write;
use std::sync::Once;
use std::time::SystemTime;

use crate::RESERVED_BLOCKS;

type MotorFs = crate::MotorFs<AsyncFileBlockDevice>;
static LOGGER: Once = Once::new();
fn init_logger() {
    LOGGER.call_once(|| {
        env_logger::init();
    });
}

async fn create_fs(tag: &str, num_blocks: u64) -> Result<MotorFs> {
    let path = std::env::temp_dir().join(tag);
    let path = Utf8PathBuf::from_path_buf(path).unwrap();
    std::fs::remove_file(path.clone()).ok();

    let bd = async_fs::file_block_device::AsyncFileBlockDevice::create(&path, num_blocks).await?;
    MotorFs::format(Box::new(bd)).await
}

async fn open_fs(tag: &str) -> Result<MotorFs> {
    let path = std::env::temp_dir().join(tag);
    let path = Utf8PathBuf::from_path_buf(path).unwrap();

    let bd = async_fs::file_block_device::AsyncFileBlockDevice::open(&path).await?;
    MotorFs::open(Box::new(bd)).await
}

#[test]
fn basic() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(basic_test()).unwrap();
}

#[test]
fn readdir() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(readdir_test()).unwrap();
}

#[test]
fn midsize_file() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(midsize_file_test()).unwrap();
}

#[test]
fn hash_collision() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(hash_collision_test()).unwrap();
}

#[test]
fn hash_collision_stress() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(hash_collision_stress_test()).unwrap();
}

#[test]
fn hash_collision_move() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(hash_collision_move_test()).unwrap();
}

#[test]
fn readdir_large_dir() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(readdir_large_dir_test()).unwrap();
}

#[test]
fn delete_reopen() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(delete_reopen_test()).unwrap();
}

#[test]
fn no_lost_commits() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(no_lost_commits_test()).unwrap();
}

#[test]
fn random_file() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(random_file_test()).unwrap();
}

#[test]
fn copy_file() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(copy_file_test()).unwrap();
}

#[test]
fn resize_truncate() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(resize_truncate_test()).unwrap();
}

#[test]
fn resize_truncate_random() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(resize_truncate_random_test()).unwrap();
}

#[test]
fn resize_truncate_wide_leaf() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(resize_truncate_wide_leaf_test()).unwrap();
}

#[test]
fn inline_data() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(inline_data_test()).unwrap();
}

#[test]
fn inline_truncate_spine() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(inline_truncate_spine_test()).unwrap();
}

#[test]
fn resize_truncate_crash_regrow() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(resize_truncate_crash_regrow_test()).unwrap();
}

#[test]
fn resize_truncate_accounting_walk() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(resize_truncate_accounting_walk_test()).unwrap();
}

#[test]
fn resize_truncate_no_alloc() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(resize_truncate_no_alloc_test()).unwrap();
}

#[test]
#[ignore]
fn write_speed() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(write_speed_test()).unwrap();
}

#[test]
#[ignore]
fn native_write_speed() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(native_write_speed_test()).unwrap();
}

#[test]
#[ignore]
fn native_write_speed_async() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(native_write_speed_async_test()).unwrap();
}

#[test]
fn txn_log_replay() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();

    rt.block_on(txn_log_replay_test()).unwrap();
}

async fn basic_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 256;

    let ts_format = SystemTime::now();
    let mut fs = create_fs("motor_fs_basic_test", NUM_BLOCKS).await?;

    assert_eq!(NUM_BLOCKS, fs.num_blocks());
    assert_eq!(
        NUM_BLOCKS - RESERVED_BLOCKS as u64,
        fs.empty_blocks().await?
    );

    let root = crate::ROOT_DIR_ID;
    assert!(fs.get_parent(Role::System, root).await?.is_none());

    assert!(ts_format <= fs.metadata(Role::System, root).await?.created.into());
    assert!(ts_format <= fs.metadata(Role::System, root).await?.modified.into());

    assert_eq!(0, fs.metadata(Role::System, root).await?.size);
    assert!(fs.stat(Role::System, root, "first").await?.is_none());

    let ts_first_dir = SystemTime::now();

    let first = fs
        .create_entry(Role::System, root, async_fs::EntryKind::Directory, "first", [AccessPermissions::Rwx; 3])
        .await?;
    assert_eq!(1, fs.metadata(Role::System, root).await?.size);

    assert_eq!(0, fs.metadata(Role::System, first).await?.size);
    assert_eq!(root, fs.get_parent(Role::System, first).await?.unwrap());

    assert_eq!(
        fs.create_entry(Role::System, first, async_fs::EntryKind::Directory, "/", [AccessPermissions::Rwx; 3])
            .await
            .err()
            .unwrap()
            .kind(),
        ErrorKind::InvalidFilename
    );

    assert_eq!(
        (first, EntryKind::Directory),
        fs.stat(Role::System, root, "first").await?.unwrap()
    );

    // Check timestamps.
    let root_metadata = fs.metadata(Role::System, root).await?;
    let first_metadata = fs.metadata(Role::System, first).await?;
    let ts_now = SystemTime::now();

    assert_eq!(root_metadata.kind(), EntryKind::Directory);
    assert_eq!(first_metadata.kind(), EntryKind::Directory);

    assert!(ts_format <= root_metadata.created.into());
    assert!(ts_format <= root_metadata.modified.into());

    assert!(ts_first_dir >= root_metadata.created.into());
    assert!(ts_first_dir <= root_metadata.modified.into());

    assert!(ts_first_dir <= first_metadata.created.into());
    assert!(ts_first_dir <= first_metadata.modified.into());

    assert!(ts_now >= root_metadata.modified.into());
    assert!(ts_now >= first_metadata.created.into());
    assert!(ts_now >= first_metadata.modified.into());

    fs.delete_entry(Role::System, first).await.unwrap();
    assert_eq!(
        ErrorKind::InvalidInput,
        fs.delete_entry(Role::System, first).await.err().unwrap().kind()
    );
    assert_eq!(
        ErrorKind::InvalidInput,
        fs.delete_entry(Role::System, root).await.err().unwrap().kind()
    );

    assert_eq!(
        fs.empty_blocks().await.unwrap(),
        NUM_BLOCKS - RESERVED_BLOCKS as u64
    );
    let root_metadata = fs.metadata(Role::System, root).await?;
    assert!(ts_now <= root_metadata.modified.into());

    let dir1 = fs.create_entry(Role::System, root, EntryKind::Directory, "dir1", [AccessPermissions::Rwx; 3]).await?;
    let dir2 = fs.create_entry(Role::System, root, EntryKind::Directory, "dir2", [AccessPermissions::Rwx; 3]).await?;
    let dir3 = fs.create_entry(Role::System, root, EntryKind::Directory, "dir3", [AccessPermissions::Rwx; 3]).await?;
    assert_eq!(3, fs.metadata(Role::System, root).await?.size);
    assert_eq!(
        fs.empty_blocks().await.unwrap(),
        NUM_BLOCKS - RESERVED_BLOCKS as u64 - 3
    );

    let dir22 = fs.create_entry(Role::System, dir2, EntryKind::Directory, "dir22", [AccessPermissions::Rwx; 3]).await?;
    assert_eq!(dir2, fs.get_parent(Role::System, dir22).await?.unwrap());

    // File.
    let file = fs.create_entry(Role::System, dir2, EntryKind::File, "file", [AccessPermissions::Rwx; 3]).await?;
    assert_eq!(dir2, fs.get_parent(Role::System, file).await?.unwrap());
    assert_eq!(2, fs.metadata(Role::System, dir2).await?.size);

    const BYTES: &[u8] = "once upon a time there was a tree upon a hill".as_bytes();
    assert_eq!(BYTES.len(), fs.write(Role::System, file, 0, BYTES).await.unwrap());
    assert_eq!(BYTES.len() as u64, fs.metadata(Role::System, file).await?.size);
    // This file (45 bytes) is stored inline in its entry block: no data block.
    assert_eq!(
        fs.empty_blocks().await.unwrap(),
        NUM_BLOCKS - RESERVED_BLOCKS as u64 - 5
    );

    let mut buf = [0_u8; 256];
    assert_eq!(BYTES.len(), fs.read(Role::System, file, 0, &mut buf).await.unwrap());
    for idx in 0..BYTES.len() {
        assert_eq!(BYTES[idx], buf[idx]);
    }

    // Truncate.
    fs.resize(Role::System, file, 3).await.unwrap();
    assert_eq!(3, fs.read(Role::System, file, 0, &mut buf).await.unwrap());
    for idx in 0..3 {
        assert_eq!(BYTES[idx], buf[idx]);
    }

    fs.resize(Role::System, file, 0).await.unwrap();
    assert_eq!(0, fs.read(Role::System, file, 0, &mut buf).await.unwrap());
    assert_eq!(
        fs.empty_blocks().await.unwrap(),
        NUM_BLOCKS - RESERVED_BLOCKS as u64 - 5
    );

    // Resize up: populate with zeroes.
    fs.resize(Role::System, file, BYTES.len() as u64).await.unwrap();
    assert_eq!(BYTES.len(), fs.read(Role::System, file, 0, &mut buf).await.unwrap());
    for idx in 0..BYTES.len() {
        assert_eq!(0, buf[idx]);
    }
    assert_eq!(
        fs.empty_blocks().await.unwrap(),
        NUM_BLOCKS - RESERVED_BLOCKS as u64 - 5
    );

    // Move.
    assert_eq!("dir22", fs.name(Role::System, dir22).await?);
    fs.move_entry(Role::System, dir22, dir2, "dir22_new").await?;
    assert_eq!("dir22_new", fs.name(Role::System, dir22).await?);
    fs.move_entry(Role::System, dir22, root, "dir22").await?;
    assert_eq!("dir22", fs.name(Role::System, dir22).await?);
    assert_eq!(4, fs.metadata(Role::System, root).await.unwrap().size);
    assert_eq!(root, fs.get_parent(Role::System, dir22).await?.unwrap());
    assert_eq!(
        fs.empty_blocks().await.unwrap(),
        NUM_BLOCKS - RESERVED_BLOCKS as u64 - 5
    );

    // Grow the file past the inline cutoff before deleting it, so it migrates to
    // tree storage (a data block) -- exercising inline->tree and the multi-block
    // delete path.
    assert_eq!(BYTES.len(), fs.write(Role::System, file, 0, BYTES).await.unwrap());
    assert_eq!(
        BYTES.len(),
        fs.write(Role::System, file, crate::INLINE_CAPACITY, BYTES).await.unwrap()
    );
    assert_eq!(
        fs.empty_blocks().await.unwrap(),
        NUM_BLOCKS - RESERVED_BLOCKS as u64 - 6
    );

    // Clear out.
    fs.delete_entry(Role::System, file).await.unwrap();
    fs.delete_entry(Role::System, dir1).await.unwrap();
    fs.delete_entry(Role::System, dir2).await.unwrap();
    fs.delete_entry(Role::System, dir3).await.unwrap();
    fs.delete_entry(Role::System, dir22).await.unwrap();
    assert_eq!(0, fs.metadata(Role::System, root).await.unwrap().size);
    assert_eq!(
        NUM_BLOCKS - RESERVED_BLOCKS as u64,
        fs.empty_blocks().await?
    );

    println!("basic_test PASS");
    Ok(())
}

async fn readdir_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 256;

    let mut fs = create_fs("motor_fs_readdir_test", NUM_BLOCKS).await?;

    let root = crate::ROOT_DIR_ID;
    let parent_id = fs
        .create_entry(Role::System, root, EntryKind::Directory, "parent", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();

    let mut entries = std::collections::HashMap::<EntryId, (EntryKind, String)>::new();

    // Insert some dirs and files, while keeping track of them in entries.
    for idx in 0..23 {
        let name = format!("dir_{idx}");
        entries.insert(
            fs.create_entry(Role::System, parent_id, EntryKind::Directory, name.as_str(), [AccessPermissions::Rwx; 3])
                .await
                .unwrap(),
            (EntryKind::Directory, name),
        );
    }
    for idx in 0..44 {
        let name = format!("file_{idx}");
        entries.insert(
            fs.create_entry(Role::System, parent_id, EntryKind::File, name.as_str(), [AccessPermissions::Rwx; 3])
                .await
                .unwrap(),
            (EntryKind::File, name),
        );
    }

    // Now "readdir" parent.
    let mut entry_id = fs.get_first_entry(Role::System, parent_id).await.unwrap().unwrap();
    loop {
        let stored_data = entries.remove(&entry_id).unwrap();
        let metadata = fs.metadata(Role::System, entry_id).await.unwrap();
        assert_eq!(stored_data.0, metadata.kind());
        assert_eq!(stored_data.1, fs.name(Role::System, entry_id).await.unwrap());

        if let Some(next_entry_id) = fs.get_next_entry(Role::System, entry_id).await.unwrap() {
            entry_id = next_entry_id;
        } else {
            break;
        };
    }

    println!("readdir_test PASS");
    Ok(())
}

/// Collect all entry names in a directory by walking `get_first`/`get_next`.
/// This traverses both the per-hash collision lists and the directory tree.
async fn collect_dir_names(fs: &mut MotorFs, dir: EntryId) -> Vec<String> {
    let mut names = Vec::new();
    let mut cur = fs.get_first_entry(Role::System, dir).await.unwrap();
    while let Some(id) = cur {
        names.push(fs.name(Role::System, id).await.unwrap());
        cur = fs.get_next_entry(Role::System, id).await.unwrap();
    }
    names
}

async fn hash_collision_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 256;
    let mut fs = create_fs("motor_fs_hash_collision_test", NUM_BLOCKS).await?;
    let full = fs.empty_blocks().await.unwrap();

    let root = crate::ROOT_DIR_ID;
    let dir = fs
        .create_entry(Role::System, root, EntryKind::Directory, "d", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();

    // In debug test builds the name hash is the first 8 bytes of the name, so
    // these four (sharing the prefix "collide_") land in one hash bucket and
    // exercise the collision list; in release the hash is seeded CityHash and
    // they simply land in distinct buckets (still a valid functional test).
    let colliding = ["collide_a", "collide_b", "collide_c", "collide_d"];
    #[cfg(debug_assertions)]
    {
        use crate::layout::DirEntryBlock;
        let h = DirEntryBlock::hash_debug(colliding[0]);
        for name in &colliding {
            assert_eq!(DirEntryBlock::hash_debug(name), h, "names must collide");
        }
        assert_ne!(DirEntryBlock::hash_debug("zzz"), h);
    }

    let mut ids = std::collections::HashMap::new();
    for name in colliding {
        let id = fs.create_entry(Role::System, dir, EntryKind::File, name, [AccessPermissions::Rwx; 3]).await.unwrap();
        assert!(ids.insert(name, id).is_none());
    }
    // Two non-colliding entries, to keep the tree non-trivial.
    for name in ["zzz", "yyy"] {
        fs.create_entry(Role::System, dir, EntryKind::File, name, [AccessPermissions::Rwx; 3]).await.unwrap();
    }

    // Re-creating a colliding name must still fail with AlreadyExists.
    assert_eq!(
        fs.create_entry(Role::System, dir, EntryKind::File, "collide_b", [AccessPermissions::Rwx; 3])
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::AlreadyExists
    );

    // Every colliding name resolves, each to its own distinct block.
    let mut blocks = std::collections::HashSet::new();
    for name in colliding {
        let (id, kind) = fs.stat(Role::System, dir, name).await.unwrap().unwrap();
        assert_eq!(kind, EntryKind::File);
        assert_eq!(id, ids[name]);
        assert!(blocks.insert(id));
    }

    // readdir sees all six.
    let listed = collect_dir_names(&mut fs, dir).await;
    assert_eq!(listed.len(), 6);
    for name in colliding {
        assert!(
            listed.iter().any(|n| n == name),
            "missing {name} in {listed:?}"
        );
    }

    // Delete in an order that exercises every collision-list case. The list is
    // a -> b -> c -> d (append order; `a` is the head).

    // 1. Middle: delete `c` (splice out of the list).
    fs.delete_entry(Role::System, ids["collide_c"]).await.unwrap();
    assert!(fs.stat(Role::System, dir, "collide_c").await.unwrap().is_none());
    for name in ["collide_a", "collide_b", "collide_d"] {
        assert!(fs.stat(Role::System, dir, name).await.unwrap().is_some(), "{name} gone");
    }
    assert_eq!(collect_dir_names(&mut fs, dir).await.len(), 5);

    // 2. Head with a successor: delete `a` (promote `b` to head).
    fs.delete_entry(Role::System, ids["collide_a"]).await.unwrap();
    assert!(fs.stat(Role::System, dir, "collide_a").await.unwrap().is_none());
    for name in ["collide_b", "collide_d"] {
        assert!(fs.stat(Role::System, dir, name).await.unwrap().is_some(), "{name} gone");
    }
    assert_eq!(collect_dir_names(&mut fs, dir).await.len(), 4);

    // 3. Tail: delete `d` (splice out the last list element).
    fs.delete_entry(Role::System, ids["collide_d"]).await.unwrap();
    assert!(fs.stat(Role::System, dir, "collide_d").await.unwrap().is_none());
    assert!(fs.stat(Role::System, dir, "collide_b").await.unwrap().is_some());
    assert_eq!(collect_dir_names(&mut fs, dir).await.len(), 3);

    // 4. Sole remaining of the bucket: delete `b` (the tree link goes away).
    fs.delete_entry(Role::System, ids["collide_b"]).await.unwrap();
    assert!(fs.stat(Role::System, dir, "collide_b").await.unwrap().is_none());
    assert_eq!(collect_dir_names(&mut fs, dir).await.len(), 2);

    // The non-colliding entries are untouched throughout.
    for name in ["zzz", "yyy"] {
        assert!(fs.stat(Role::System, dir, name).await.unwrap().is_some());
    }

    // Re-create colliding names after the bucket was fully emptied.
    for name in ["collide_a", "collide_b"] {
        fs.create_entry(Role::System, dir, EntryKind::File, name, [AccessPermissions::Rwx; 3]).await.unwrap();
        assert!(fs.stat(Role::System, dir, name).await.unwrap().is_some());
    }
    assert_eq!(collect_dir_names(&mut fs, dir).await.len(), 4);

    // Tear everything down and confirm the free-block accounting is exact.
    for name in ["collide_a", "collide_b", "zzz", "yyy"] {
        let (id, _) = fs.stat(Role::System, dir, name).await.unwrap().unwrap();
        fs.delete_entry(Role::System, id).await.unwrap();
    }
    assert_eq!(collect_dir_names(&mut fs, dir).await.len(), 0);
    fs.delete_entry(Role::System, dir).await.unwrap();
    assert_eq!(fs.empty_blocks().await.unwrap(), full);

    println!("hash_collision_test PASS");
    Ok(())
}

async fn hash_collision_stress_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 512;
    let mut fs = create_fs("motor_fs_hash_collision_stress_test", NUM_BLOCKS).await?;
    let full = fs.empty_blocks().await.unwrap();

    let root = crate::ROOT_DIR_ID;
    let dir = fs
        .create_entry(Role::System, root, EntryKind::Directory, "stress", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();

    // All share the prefix "samehash" (8 bytes) => one collision bucket in debug.
    // N is deliberately larger than the transaction block cache (16): building
    // and unlinking within such a list must walk it with untracked reads, so a
    // long bucket does not overflow the cache.
    const N: usize = 25;
    let names: Vec<String> = (0..N).map(|i| format!("samehash{i:02}")).collect();
    #[cfg(debug_assertions)]
    {
        use crate::layout::DirEntryBlock;
        let h = DirEntryBlock::hash_debug(&names[0]);
        for name in &names {
            assert_eq!(DirEntryBlock::hash_debug(name), h);
        }
    }

    for name in &names {
        fs.create_entry(Role::System, dir, EntryKind::File, name, [AccessPermissions::Rwx; 3]).await.unwrap();
    }
    assert_eq!(collect_dir_names(&mut fs, dir).await.len(), N);

    // Delete in a deliberately mixed order (heads, tails, middles, and the
    // current head repeatedly), checking the whole bucket stays consistent after
    // each deletion. `7` is coprime to `N`, so this visits every index once.
    let order: Vec<usize> = (0..N).map(|i| (i * 7) % N).collect();
    let mut deleted = std::collections::HashSet::new();
    for &idx in &order {
        let (id, _) = fs.stat(Role::System, dir, &names[idx]).await.unwrap().unwrap();
        fs.delete_entry(Role::System, id).await.unwrap();
        deleted.insert(idx);

        let mut expected = 0;
        for (i, name) in names.iter().enumerate() {
            if deleted.contains(&i) {
                assert!(fs.stat(Role::System, dir, name).await.unwrap().is_none(), "{name} resurrected");
            } else {
                assert!(fs.stat(Role::System, dir, name).await.unwrap().is_some(), "{name} vanished");
                expected += 1;
            }
        }
        assert_eq!(collect_dir_names(&mut fs, dir).await.len(), expected);
    }

    assert_eq!(collect_dir_names(&mut fs, dir).await.len(), 0);
    fs.delete_entry(Role::System, dir).await.unwrap();
    assert_eq!(fs.empty_blocks().await.unwrap(), full);

    println!("hash_collision_stress_test PASS");
    Ok(())
}

async fn hash_collision_move_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 256;
    let mut fs = create_fs("motor_fs_hash_collision_move_test", NUM_BLOCKS).await?;
    let full = fs.empty_blocks().await.unwrap();

    let root = crate::ROOT_DIR_ID;
    let a = fs
        .create_entry(Role::System, root, EntryKind::Directory, "a", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();
    let b = fs
        .create_entry(Role::System, root, EntryKind::Directory, "b", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();

    // All names share the prefix "movehash" (8 bytes): one bucket per directory
    // in debug builds.
    let a1 = fs.create_entry(Role::System, a, EntryKind::File, "movehash_a1", [AccessPermissions::Rwx; 3]).await.unwrap();
    let _a2 = fs.create_entry(Role::System, a, EntryKind::File, "movehash_a2", [AccessPermissions::Rwx; 3]).await.unwrap();
    let a3 = fs.create_entry(Role::System, a, EntryKind::File, "movehash_a3", [AccessPermissions::Rwx; 3]).await.unwrap();
    fs.create_entry(Role::System, b, EntryKind::File, "movehash_b1", [AccessPermissions::Rwx; 3]).await.unwrap();

    // Move the MIDDLE of A's list (a2) into B's bucket (collides with b1 there).
    // A: a1 -> a2 -> a3  =>  a1 -> a3 ; B: b1  =>  b1 -> b2.
    fs.move_entry(Role::System, _a2, b, "movehash_b2").await.unwrap();
    assert!(fs.stat(Role::System, a, "movehash_a2").await.unwrap().is_none());
    assert!(fs.stat(Role::System, b, "movehash_b2").await.unwrap().is_some());
    for name in ["movehash_a1", "movehash_a3"] {
        assert!(fs.stat(Role::System, a, name).await.unwrap().is_some(), "{name} lost");
    }
    assert!(fs.stat(Role::System, b, "movehash_b1").await.unwrap().is_some());
    assert_eq!(collect_dir_names(&mut fs, a).await.len(), 2);
    assert_eq!(collect_dir_names(&mut fs, b).await.len(), 2);

    // Move the HEAD of A's list (a1) into B (promotes a3 to A's head).
    fs.move_entry(Role::System, a1, b, "movehash_b3").await.unwrap();
    assert!(fs.stat(Role::System, a, "movehash_a1").await.unwrap().is_none());
    assert!(fs.stat(Role::System, a, "movehash_a3").await.unwrap().is_some());
    for name in ["movehash_b1", "movehash_b2", "movehash_b3"] {
        assert!(fs.stat(Role::System, b, name).await.unwrap().is_some(), "{name} lost");
    }
    assert_eq!(collect_dir_names(&mut fs, a).await.len(), 1);
    assert_eq!(collect_dir_names(&mut fs, b).await.len(), 3);

    // Rename the now-sole entry in A to another colliding name (sole-entry
    // unlink + sole-entry relink).
    fs.move_entry(Role::System, a3, a, "movehash_a9").await.unwrap();
    assert!(fs.stat(Role::System, a, "movehash_a3").await.unwrap().is_none());
    assert!(fs.stat(Role::System, a, "movehash_a9").await.unwrap().is_some());
    assert_eq!(collect_dir_names(&mut fs, a).await.len(), 1);

    // Tear down and confirm accounting.
    for (parent, name) in [
        (a, "movehash_a9"),
        (b, "movehash_b1"),
        (b, "movehash_b2"),
        (b, "movehash_b3"),
    ] {
        let (id, _) = fs.stat(Role::System, parent, name).await.unwrap().unwrap();
        fs.delete_entry(Role::System, id).await.unwrap();
    }
    fs.delete_entry(Role::System, a).await.unwrap();
    fs.delete_entry(Role::System, b).await.unwrap();
    assert_eq!(fs.empty_blocks().await.unwrap(), full);

    println!("hash_collision_move_test PASS");
    Ok(())
}

async fn readdir_large_dir_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 1024;
    let mut fs = create_fs("motor_fs_readdir_large_dir_test", NUM_BLOCKS).await?;
    let full = fs.empty_blocks().await.unwrap();

    let root = crate::ROOT_DIR_ID;
    let dir = fs
        .create_entry(Role::System, root, EntryKind::Directory, "big", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();

    // Enough distinct-hash names to split the directory's B+ tree root into
    // multiple levels (the root's order is 226), so iterating must step between
    // leaves through internal nodes -- exercising `Node::next_child`'s non-leaf
    // path. Eight-character names are distinct hashes in debug builds.
    const N: usize = 300;
    let mut expected = std::collections::HashSet::new();
    for i in 0..N {
        let name = format!("{i:08}");
        fs.create_entry(Role::System, dir, EntryKind::File, &name, [AccessPermissions::Rwx; 3]).await.unwrap();
        assert!(expected.insert(name));
    }
    // A few colliding names too, so iteration also steps from a multi-entry hash
    // bucket to the next key across the tree.
    for name in ["zzzzzzzzA", "zzzzzzzzB", "zzzzzzzzC"] {
        fs.create_entry(Role::System, dir, EntryKind::File, name, [AccessPermissions::Rwx; 3]).await.unwrap();
        assert!(expected.insert(name.to_string()));
    }

    // Iterating the directory must return every entry exactly once.
    let listed = collect_dir_names(&mut fs, dir).await;
    assert_eq!(listed.len(), expected.len(), "duplicate or missing entries");
    let listed_set: std::collections::HashSet<String> = listed.into_iter().collect();
    assert_eq!(listed_set, expected);

    // Each is reachable individually too.
    for name in &expected {
        assert!(fs.stat(Role::System, dir, name).await.unwrap().is_some(), "{name} missing");
    }

    // Tear down (collapsing the tree back) and confirm exact accounting.
    for name in &expected {
        let (id, _) = fs.stat(Role::System, dir, name).await.unwrap().unwrap();
        fs.delete_entry(Role::System, id).await.unwrap();
    }
    assert_eq!(collect_dir_names(&mut fs, dir).await.len(), 0);
    fs.delete_entry(Role::System, dir).await.unwrap();
    assert_eq!(fs.empty_blocks().await.unwrap(), full);

    println!("readdir_large_dir_test PASS");
    Ok(())
}

/// Create a ~9MB file on a 16MB partition. Should easily fit.
async fn midsize_file_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 1024 * 1024 * 16 / 4096;

    let mut fs = create_fs("motor_fs_midsize_file_test", NUM_BLOCKS).await?;
    assert_eq!(
        NUM_BLOCKS - RESERVED_BLOCKS as u64,
        fs.empty_blocks().await.unwrap()
    );

    let root = crate::ROOT_DIR_ID;
    let parent_id = fs
        .create_entry(Role::System, root, EntryKind::Directory, "parent dir", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();

    let mut bytes = vec![0_u8; 1024 * 1024 * 11 + 1001];
    for byte in &mut bytes {
        *byte = std::random::random(..);
    }

    let file_id = fs
        .create_entry(Role::System, parent_id, EntryKind::File, "foo", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();

    // Write.
    let mut file_offset = 0;
    while file_offset < bytes.len() {
        let len = 4096.min(bytes.len() - file_offset);
        let buf = &bytes.as_slice()[file_offset..(file_offset + len)];

        let written = fs.write(Role::System, file_id, file_offset as u64, buf).await.unwrap();
        assert_eq!(written, len);
        file_offset += written;
    }

    // Read.
    let mut bytes_back = vec![];
    bytes_back.resize(bytes.len(), 0);

    let mut offset = 0;

    while offset < bytes.len() {
        let len = 4096.min(bytes.len() - offset);
        let buf = &mut bytes_back.as_mut_slice()[offset..(offset + len)];

        let read = fs.read(Role::System, file_id, offset as u64, buf).await.unwrap();
        assert_eq!(read, len);

        offset += read;
    }

    // Clear: test free block accounting.
    fs.delete_entry(Role::System, file_id).await.unwrap();
    assert!(
        fs.read(Role::System, file_id, 4096, &mut bytes.as_mut_slice()[..4096])
            .await
            .is_err()
    );
    assert!(
        fs.write(Role::System, file_id, 4096, &bytes.as_slice()[..4096])
            .await
            .is_err()
    );
    fs.delete_entry(Role::System, parent_id).await.unwrap();
    assert_eq!(
        NUM_BLOCKS - RESERVED_BLOCKS as u64,
        fs.empty_blocks().await.unwrap()
    );

    // Recreate a large file: this tests reallocating blocks from a deleted file.
    let file_id = fs
        .create_entry(Role::System, crate::ROOT_DIR_ID, EntryKind::File, "bar", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();

    // Write.
    let mut file_offset = 0;
    while file_offset < bytes.len() {
        let len = 4096.min(bytes.len() - file_offset);
        let buf = &bytes.as_slice()[file_offset..(file_offset + len)];

        let written = fs.write(Role::System, file_id, file_offset as u64, buf).await.unwrap();
        assert_eq!(written, len);
        file_offset += written;
    }

    fs.delete_entry(Role::System, file_id).await.unwrap();
    assert_eq!(
        NUM_BLOCKS - RESERVED_BLOCKS as u64,
        fs.empty_blocks().await.unwrap()
    );

    println!("midsize_file_test PASS");
    Ok(())
}

async fn assert_empty(fs: &mut MotorFs) {
    let root = crate::ROOT_DIR_ID;
    assert_eq!(0, fs.metadata(Role::System, root).await.unwrap().size);
    let num_blocks = fs.num_blocks();
    assert_eq!(
        num_blocks - RESERVED_BLOCKS as u64,
        fs.empty_blocks().await.unwrap()
    );
}

async fn delete_reopen_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 1024 * 1024 * 16 / 4096;
    const FS_TAG: &str = "motor_fs_delete_reopen_test";
    let mut fs = create_fs(FS_TAG, NUM_BLOCKS).await?;

    let root = crate::ROOT_DIR_ID;

    assert_eq!(NUM_BLOCKS, fs.num_blocks());
    assert_empty(&mut fs).await;

    let foo_id = fs.create_entry(Role::System, root, EntryKind::File, "foo", [AccessPermissions::Rwx; 3]).await.unwrap();
    fs.write(Role::System, foo_id, 0, b"foobar").await.unwrap();
    assert_eq!(
        fs.stat(Role::System, root, "foo").await.unwrap().unwrap(),
        (foo_id, EntryKind::File)
    );

    let bar_id = fs.create_entry(Role::System, root, EntryKind::File, "bar", [AccessPermissions::Rwx; 3]).await.unwrap();
    fs.write(Role::System, bar_id, 0, b"foobarbaz").await.unwrap();
    assert_eq!(
        fs.stat(Role::System, root, "bar").await.unwrap().unwrap(),
        (bar_id, EntryKind::File)
    );

    fs.flush().await?;

    let mut fs = open_fs(FS_TAG).await?;
    assert_eq!(
        fs.stat(Role::System, root, "foo").await.unwrap().unwrap(),
        (foo_id, EntryKind::File)
    );
    assert_eq!(
        fs.stat(Role::System, root, "bar").await.unwrap().unwrap(),
        (bar_id, EntryKind::File)
    );

    fs.delete_entry(Role::System, foo_id).await.unwrap();

    let baz_id = fs.create_entry(Role::System, root, EntryKind::File, "baz", [AccessPermissions::Rwx; 3]).await.unwrap();
    fs.write(Role::System, baz_id, 0, b"baz").await.unwrap();
    assert_eq!(
        fs.stat(Role::System, root, "baz").await.unwrap().unwrap(),
        (baz_id, EntryKind::File)
    );

    fs.delete_entry(Role::System, bar_id).await.unwrap();
    assert!(fs.stat(Role::System, root, "foo").await.unwrap().is_none());
    assert!(fs.stat(Role::System, root, "bar").await.unwrap().is_none());

    fs.flush().await?;

    let mut fs = open_fs(FS_TAG).await?;
    assert!(fs.stat(Role::System, root, "foo").await.unwrap().is_none());
    assert!(fs.stat(Role::System, root, "bar").await.unwrap().is_none());
    fs.delete_entry(Role::System, baz_id).await.unwrap();
    assert!(fs.delete_entry(Role::System, baz_id).await.is_err());
    fs.flush().await?;

    assert_empty(&mut fs).await;

    println!("delete_reopen_test PASS");
    Ok(())
}

async fn no_lost_commits_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 1024 * 1024 * 4 / 4096;
    const FS_TAG: &str = "motor_fs_no_lost_commits_test";
    let mut fs = create_fs(FS_TAG, NUM_BLOCKS).await?;

    let root = crate::ROOT_DIR_ID;
    let foo_id = fs.create_entry(Role::System, root, EntryKind::File, "foo", [AccessPermissions::Rwx; 3]).await.unwrap();

    // Wait for flush timeout.
    tokio::time::sleep(std::time::Duration::from_millis(
        crate::fs::MAX_FLUSH_DELAY_MS + 10,
    ))
    .await;

    // Note: no explicit flushing.
    core::mem::drop(fs);

    let mut fs = open_fs(FS_TAG).await?;
    assert_eq!(
        fs.stat(Role::System, root, "foo").await.unwrap().unwrap(),
        (foo_id, EntryKind::File)
    );

    println!("no_lost_commits_test PASS");
    Ok(())
}

async fn txn_log_replay_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 1024 * 1024 * 4 / 4096;
    const FS_TAG: &str = "motor_fs_txn_log_replay_test";

    let mut replay_cnt = 0;
    for _ in 0..100 {
        let mut fs = create_fs(FS_TAG, NUM_BLOCKS).await?;
        fs.set_error_pct(0).await;

        let foo_id = fs
            .create_entry(Role::System, crate::ROOT_DIR_ID, EntryKind::File, "foo", [AccessPermissions::Rwx; 3])
            .await
            .unwrap();

        let bar_id = fs
            .create_entry(Role::System, crate::ROOT_DIR_ID, EntryKind::File, "bar", [AccessPermissions::Rwx; 3])
            .await
            .unwrap();

        fs.set_error_pct(20).await;

        // Wait for flush timeout.
        tokio::time::sleep(std::time::Duration::from_millis(
            crate::fs::MAX_FLUSH_DELAY_MS + 10,
        ))
        .await;

        // Note: no explicit flushing.
        core::mem::drop(fs);

        let mut fs = open_fs(FS_TAG).await?;
        if let Some(maybe_stat) = fs.stat(Role::System, crate::ROOT_DIR_ID, "foo").await.unwrap() {
            assert_eq!(maybe_stat, (foo_id, EntryKind::File));
            fs.delete_entry(Role::System, foo_id).await.unwrap();
        }
        if let Some(maybe_stat) = fs.stat(Role::System, crate::ROOT_DIR_ID, "bar").await.unwrap() {
            assert_eq!(maybe_stat, (bar_id, EntryKind::File));
            fs.delete_entry(Role::System, bar_id).await.unwrap();
        }

        if fs.replayed_txn_log_on_open() {
            replay_cnt += 1;
            if replay_cnt >= 3 {
                break;
            }
        }
    }
    if replay_cnt >= 3 {
        println!("txn_log_replay_test PASS");
        Ok(())
    } else {
        Err(std::io::Error::from(ErrorKind::InvalidData))
    }
}

#[test]
fn test_hash_debug() {
    #[cfg(debug_assertions)]
    {
        assert_eq!(
            crate::DirEntryBlock::hash_debug("012345678"),
            crate::DirEntryBlock::hash_debug("0123456789")
        );
    }
}

async fn random_file_test() -> Result<()> {
    use rand::RngCore;
    use rand::thread_rng;
    let mut rng = thread_rng();

    const PARTITION_SZ: u64 = 1024 * 1024 * 8;
    const NUM_BLOCKS: u64 = PARTITION_SZ / 4096;

    // B+ tree overhead should be less than one block per 100.
    const FILE_SZ: u64 = PARTITION_SZ - (RESERVED_BLOCKS as u64 + NUM_BLOCKS / 100 + 1) * 4096;

    let mut fs = create_fs("motor_fs_random_file_test", NUM_BLOCKS).await?;
    assert_eq!(
        NUM_BLOCKS - RESERVED_BLOCKS as u64,
        fs.empty_blocks().await.unwrap()
    );

    let file_id = fs
        .create_entry(Role::System, crate::ROOT_DIR_ID, EntryKind::File, "foo", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();

    let mut bytes = std::collections::HashMap::new();

    let mut blocks = Vec::with_capacity(FILE_SZ as usize / 4096);
    for idx in 0..(FILE_SZ / 4096) {
        blocks.push(idx as usize);
    }

    // Fill the file up to FILE_SZ at random offsets: this tests btree insertion.
    while !blocks.is_empty() {
        let block_idx: usize = rng.r#gen::<usize>() % blocks.len();
        let block_no = blocks.remove(block_idx);

        let mut block = Box::new(async_fs::Block::new_zeroed());
        rng.fill_bytes(block.as_bytes_mut());

        fs.write(Role::System, file_id, (block_no * 4096) as u64, block.as_bytes())
            .await
            .unwrap();

        bytes.insert(block_no, block);
    }

    assert_eq!(FILE_SZ, fs.metadata(Role::System, file_id).await?.size);

    // Fill the remainder.
    loop {
        let block_no = bytes.len();
        let mut block = Box::new(async_fs::Block::new_zeroed());
        rng.fill_bytes(block.as_bytes_mut());

        match fs
            .write(Role::System, file_id, (block_no * 4096) as u64, block.as_bytes())
            .await
        {
            Ok(_) => {}
            Err(err) => {
                assert_eq!(err.kind(), ErrorKind::StorageFull);
                break;
            }
        }

        bytes.insert(block_no, block);
    }

    assert!(fs.empty_blocks().await.unwrap() < 1);
    let file_sz = fs.metadata(Role::System, file_id).await?.size;
    log::debug!("file size: {file_sz}; blocks: {}", file_sz / 4096);
    assert_eq!((file_sz / 4096) as usize, bytes.len());

    // Check the data.
    let mut file_bytes = async_fs::Block::new_zeroed();
    for idx in 0..bytes.len() {
        fs.read(Role::System, file_id, (idx * 4096) as u64, file_bytes.as_bytes_mut())
            .await
            .unwrap();

        let block = bytes.get(&idx).unwrap();
        assert!(file_bytes.as_bytes() == block.as_bytes());
    }

    // Remove blocks at random offsets: this tests btree deletion.
    let mut blocks = Vec::with_capacity(bytes.len());
    for idx in 0..bytes.len() {
        blocks.push(idx as usize);
    }
    while !blocks.is_empty() {
        let block_idx: usize = rng.r#gen::<usize>() % blocks.len();
        let block_no = blocks.remove(block_idx);

        fs.test_remove_block_at_offset(file_id, (block_no * 4096) as u64)
            .await
            .unwrap();
    }

    assert_eq!(file_sz, fs.metadata(Role::System, file_id).await?.size);
    assert_eq!(
        NUM_BLOCKS - RESERVED_BLOCKS as u64 - 1, // The entry block is still there.
        fs.empty_blocks().await.unwrap()
    );

    println!("random_file_test PASS");
    Ok(())
}

async fn copy_file_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 1024 * 1024 * 16 / 4096;

    let mut fs = create_fs("motor_fs_copy_file_test", NUM_BLOCKS).await?;

    let root = crate::ROOT_DIR_ID;

    // Source data spanning several blocks plus a partial tail.
    let src_bytes: Vec<u8> = (0..(4096 * 3 + 777)).map(|idx| (idx % 251) as u8).collect();

    let src = fs.create_entry(Role::System, root, EntryKind::File, "src", [AccessPermissions::Rwx; 3]).await.unwrap();

    // Write the source file, respecting block boundaries.
    let mut off = 0;
    while off < src_bytes.len() {
        let len = 4096.min(src_bytes.len() - off);
        let written = fs
            .write(Role::System, src, off as u64, &src_bytes[off..off + len])
            .await
            .unwrap();
        assert_eq!(written, len);
        off += written;
    }

    // Helper to read back a whole file into a Vec.
    async fn read_all(fs: &mut MotorFs, file_id: EntryId, size: usize) -> Vec<u8> {
        let mut out = vec![0_u8; size];
        let mut off = 0;
        while off < size {
            let len = 4096.min(size - off);
            let read = fs
                .read(Role::System, file_id, off as u64, &mut out[off..off + len])
                .await
                .unwrap();
            assert_eq!(read, len);
            off += read;
        }
        out
    }

    // 1. Full-file copy into a fresh, aligned destination.
    let dst = fs.create_entry(Role::System, root, EntryKind::File, "dst", [AccessPermissions::Rwx; 3]).await.unwrap();
    let copied = fs
        .copy_file_range(Role::System, src, 0, dst, 0, src_bytes.len() as u64)
        .await
        .unwrap();
    assert_eq!(copied, src_bytes.len() as u64);
    assert_eq!(src_bytes.len() as u64, fs.metadata(Role::System, dst).await?.size);
    assert_eq!(src_bytes, read_all(&mut fs, dst, src_bytes.len()).await);

    // 2. Copy a sub-range with unaligned source and dest offsets, crossing
    //    block boundaries on both sides.
    let from_offset = 100;
    let to_offset = 5000; // Into the second block of the dest.
    let range = 4096 * 2 + 33;
    let dst2 = fs
        .create_entry(Role::System, root, EntryKind::File, "dst2", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();
    let copied = fs
        .copy_file_range(Role::System, 
            src,
            from_offset as u64,
            dst2,
            to_offset as u64,
            range as u64,
        )
        .await
        .unwrap();
    assert_eq!(copied, range as u64);

    let dst2_back = read_all(&mut fs, dst2, to_offset + range).await;
    // The skipped prefix in the dest is a hole, i.e. zeroes.
    assert!(dst2_back[..to_offset].iter().all(|b| *b == 0));
    assert_eq!(
        &src_bytes[from_offset..from_offset + range],
        &dst2_back[to_offset..to_offset + range]
    );

    // 3. Request more bytes than the source has: only the available bytes
    //    are copied, and the returned count reflects that.
    let dst3 = fs
        .create_entry(Role::System, root, EntryKind::File, "dst3", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();
    let from_offset = src_bytes.len() - 500;
    let copied = fs
        .copy_file_range(Role::System, src, from_offset as u64, dst3, 0, 100_000)
        .await
        .unwrap();
    assert_eq!(copied, 500);
    assert_eq!(
        &src_bytes[from_offset..],
        read_all(&mut fs, dst3, 500).await.as_slice()
    );

    // 4. Copying from an offset at or past the source EOF copies nothing.
    let dst4 = fs
        .create_entry(Role::System, root, EntryKind::File, "dst4", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();
    let copied = fs
        .copy_file_range(Role::System, src, src_bytes.len() as u64, dst4, 0, 4096)
        .await
        .unwrap();
    assert_eq!(copied, 0);
    assert_eq!(0, fs.metadata(Role::System, dst4).await?.size);

    // Clean up.
    fs.delete_entry(Role::System, src).await.unwrap();
    fs.delete_entry(Role::System, dst).await.unwrap();
    fs.delete_entry(Role::System, dst2).await.unwrap();
    fs.delete_entry(Role::System, dst3).await.unwrap();
    fs.delete_entry(Role::System, dst4).await.unwrap();
    assert_eq!(
        NUM_BLOCKS - RESERVED_BLOCKS as u64,
        fs.empty_blocks().await.unwrap()
    );

    println!("copy_file_test PASS");
    Ok(())
}

// Position-dependent byte pattern, used to validate resize truncation.
fn resize_pat(block_idx: u64, off: usize) -> u8 {
    block_idx
        .wrapping_mul(131)
        .wrapping_add((off as u64).wrapping_mul(7))
        .wrapping_add(off as u64) as u8
}

async fn resize_write_blocks(fs: &mut MotorFs, file: EntryId, count: u64) {
    let mut buf = vec![0u8; 4096];
    for b in 0..count {
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = resize_pat(b, i);
        }
        assert_eq!(4096, fs.write(Role::System, file, b * 4096, &buf).await.unwrap());
    }
}

/// Reads the first `size` bytes of `file`, block by block, and checks them
/// against [`resize_pat`].
async fn resize_verify(fs: &mut MotorFs, file: EntryId, size: u64) {
    assert_eq!(size, fs.metadata(Role::System, file).await.unwrap().size);
    let mut buf = vec![0u8; 4096];
    let mut off = 0u64;
    while off < size {
        let block_idx = off / 4096;
        let len = 4096.min((size - off) as usize);
        assert_eq!(len, fs.read(Role::System, file, off, &mut buf[..len]).await.unwrap());
        for (i, &byte) in buf[..len].iter().enumerate() {
            assert_eq!(
                byte,
                resize_pat(block_idx, i),
                "content mismatch at block {block_idx} byte {i} (size {size})"
            );
        }
        off += len as u64;
    }
}

/// Writes `size` (< one block) bytes into block 0 of `file`, matching
/// [`resize_pat`] for block 0, so [`resize_verify`] can check it.
async fn resize_write_partial(fs: &mut MotorFs, file: EntryId, size: u64) {
    assert!(size <= 4096);
    if size == 0 {
        return;
    }
    let buf: Vec<u8> = (0..size as usize).map(|i| resize_pat(0, i)).collect();
    assert_eq!(size as usize, fs.write(Role::System, file, 0, &buf).await.unwrap());
}

/// Exercises inline small-file storage and every transition across the cutoff:
/// inline read/write, inline<->tree on write and on resize, and (carefully)
/// tree->inline truncation, with exact free-block accounting throughout.
async fn inline_data_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 256;
    let cap = crate::INLINE_CAPACITY; // 3640
    let mut fs = create_fs("motor_fs_inline_data_test", NUM_BLOCKS).await?;
    let full = fs.empty_blocks().await.unwrap();
    let root = crate::ROOT_DIR_ID;

    // --- Inline basics and the exact cutoff boundary. ---
    let file = fs.create_entry(Role::System, root, EntryKind::File, "f", [AccessPermissions::Rwx; 3]).await.unwrap();
    assert_eq!(full - 1, fs.empty_blocks().await.unwrap());

    // A file of exactly `cap` bytes is inline: no data block.
    resize_write_partial(&mut fs, file, cap).await;
    resize_verify(&mut fs, file, cap).await;
    assert_eq!(
        full - 1,
        fs.empty_blocks().await.unwrap(),
        "exactly cap bytes must stay inline"
    );

    // One more byte crosses the cutoff: the file migrates to a data block.
    let b = [resize_pat(0, cap as usize)];
    assert_eq!(1, fs.write(Role::System, file, cap, &b).await.unwrap());
    resize_verify(&mut fs, file, cap + 1).await;
    assert_eq!(
        full - 2,
        fs.empty_blocks().await.unwrap(),
        "cap+1 bytes must use a data block"
    );

    // Truncate back to cap: tree -> inline, the data block is freed.
    fs.resize(Role::System, file, cap).await.unwrap();
    resize_verify(&mut fs, file, cap).await;
    assert_eq!(full - 1, fs.empty_blocks().await.unwrap(), "back to inline");

    // Truncate to tiny, then to zero, then delete: accounting returns to full.
    fs.resize(Role::System, file, 7).await.unwrap();
    resize_verify(&mut fs, file, 7).await;
    fs.resize(Role::System, file, 0).await.unwrap();
    assert_eq!(0, fs.metadata(Role::System, file).await.unwrap().size);
    assert_eq!(0, fs.read(Role::System, file, 0, &mut [0u8; 4]).await.unwrap());
    assert_eq!(full - 1, fs.empty_blocks().await.unwrap());
    fs.delete_entry(Role::System, file).await.unwrap();
    assert_eq!(full, fs.empty_blocks().await.unwrap());

    // --- tree -> inline from a genuinely multi-block file. ---
    let file = fs.create_entry(Role::System, root, EntryKind::File, "big", [AccessPermissions::Rwx; 3]).await.unwrap();
    resize_write_blocks(&mut fs, file, 5).await; // 5 full blocks => tree
    resize_verify(&mut fs, file, 5 * 4096).await;
    fs.resize(Role::System, file, 100).await.unwrap(); // tree -> inline; [0,100) survive
    resize_verify(&mut fs, file, 100).await;
    assert_eq!(
        full - 1,
        fs.empty_blocks().await.unwrap(),
        "tree->inline frees everything but the entry"
    );
    fs.delete_entry(Role::System, file).await.unwrap();
    assert_eq!(full, fs.empty_blocks().await.unwrap());

    // --- inline -> tree by growing (sparse), then tree -> inline back. ---
    let file = fs.create_entry(Role::System, root, EntryKind::File, "g", [AccessPermissions::Rwx; 3]).await.unwrap();
    resize_write_partial(&mut fs, file, 50).await; // inline
    assert_eq!(full - 1, fs.empty_blocks().await.unwrap());
    fs.resize(Role::System, file, 10 * 4096).await.unwrap(); // grow past cutoff: sparse tree
    assert_eq!(10 * 4096, fs.metadata(Role::System, file).await.unwrap().size);
    {
        let mut buf = vec![0xAAu8; 4096];
        assert_eq!(4096, fs.read(Role::System, file, 0, &mut buf).await.unwrap());
        for (i, &byte) in buf.iter().enumerate() {
            let expected = if i < 50 { resize_pat(0, i) } else { 0 };
            assert_eq!(byte, expected, "byte {i}");
        }
        // A block deep in the hole reads as zeros.
        assert_eq!(4096, fs.read(Role::System, file, 8192, &mut buf).await.unwrap());
        assert!(buf.iter().all(|&x| x == 0));
    }
    // Growing 50 inline bytes created exactly one data block (block 0).
    assert_eq!(full - 2, fs.empty_blocks().await.unwrap());
    fs.resize(Role::System, file, 50).await.unwrap(); // tree -> inline, [0,50) survive
    resize_verify(&mut fs, file, 50).await;
    assert_eq!(full - 1, fs.empty_blocks().await.unwrap());
    fs.delete_entry(Role::System, file).await.unwrap();
    assert_eq!(full, fs.empty_blocks().await.unwrap());

    // --- sparse hole: data only at a high offset, then truncate into the hole. ---
    let file = fs.create_entry(Role::System, root, EntryKind::File, "s", [AccessPermissions::Rwx; 3]).await.unwrap();
    {
        let buf: Vec<u8> = (0..100).map(|i| resize_pat(2, i)).collect();
        assert_eq!(100, fs.write(Role::System, file, 2 * 4096, &buf).await.unwrap()); // block 2 => tree
    }
    assert_eq!(2 * 4096 + 100, fs.metadata(Role::System, file).await.unwrap().size);
    fs.resize(Role::System, file, 80).await.unwrap(); // truncate into the (block 0) hole
    {
        let mut buf = vec![0xFFu8; 80];
        assert_eq!(80, fs.read(Role::System, file, 0, &mut buf).await.unwrap());
        assert!(buf.iter().all(|&x| x == 0), "hole must read back as zero");
    }
    assert_eq!(full - 1, fs.empty_blocks().await.unwrap());
    fs.delete_entry(Role::System, file).await.unwrap();
    assert_eq!(full, fs.empty_blocks().await.unwrap());

    println!("inline_data_test PASS");
    Ok(())
}

/// Tree -> inline collapse when the surviving single block hangs off a thin tree
/// spine (left behind by truncating a multi-level tree without rebalancing), plus
/// truncating a large file straight to inline and to zero.
async fn inline_truncate_spine_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 512;
    let cap = crate::INLINE_CAPACITY;
    let mut fs = create_fs("motor_fs_inline_truncate_spine_test", NUM_BLOCKS).await?;
    let full = fs.empty_blocks().await.unwrap();
    let root = crate::ROOT_DIR_ID;

    // 300 blocks => the tree has internal nodes (root order is 226).
    let file = fs.create_entry(Role::System, root, EntryKind::File, "f", [AccessPermissions::Rwx; 3]).await.unwrap();
    resize_write_blocks(&mut fs, file, 300).await;
    resize_verify(&mut fs, file, 300 * 4096).await;

    // Truncate to just above the cutoff but within one block: this keeps only
    // block 0 but leaves a thin tree spine above it (no rebalance on truncate).
    fs.resize(Role::System, file, cap + 1).await.unwrap();
    resize_verify(&mut fs, file, cap + 1).await;

    // Now collapse to inline: the collapse must free that whole spine plus the
    // data block, leaving just the entry.
    fs.resize(Role::System, file, 64).await.unwrap();
    resize_verify(&mut fs, file, 64).await;
    assert_eq!(full - 1, fs.empty_blocks().await.unwrap(), "spine fully freed");
    fs.delete_entry(Role::System, file).await.unwrap();
    assert_eq!(full, fs.empty_blocks().await.unwrap());

    // Truncate a large multi-level file straight to a small inline size.
    let file = fs.create_entry(Role::System, root, EntryKind::File, "f2", [AccessPermissions::Rwx; 3]).await.unwrap();
    resize_write_blocks(&mut fs, file, 300).await;
    fs.resize(Role::System, file, 1234).await.unwrap(); // tree -> inline directly
    resize_verify(&mut fs, file, 1234).await;
    assert_eq!(full - 1, fs.empty_blocks().await.unwrap());

    // ...and straight to zero.
    fs.resize(Role::System, file, 0).await.unwrap();
    assert_eq!(0, fs.metadata(Role::System, file).await.unwrap().size);
    assert_eq!(full - 1, fs.empty_blocks().await.unwrap());
    fs.delete_entry(Role::System, file).await.unwrap();
    assert_eq!(full, fs.empty_blocks().await.unwrap());

    println!("inline_truncate_spine_test PASS");
    Ok(())
}

async fn resize_truncate_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 1024 * 1024 * 8 / 4096; // 8 MB.
    const BS: u64 = 4096;
    let full = NUM_BLOCKS - RESERVED_BLOCKS as u64;

    let mut fs = create_fs("motor_fs_resize_truncate_test", NUM_BLOCKS).await?;
    assert_eq!(full, fs.empty_blocks().await.unwrap());

    let root = crate::ROOT_DIR_ID;
    let file = fs.create_entry(Role::System, root, EntryKind::File, "big", [AccessPermissions::Rwx; 3]).await.unwrap();

    // > 226 blocks forces a multi-level B+ tree, so truncation must walk it.
    const N0: u64 = 600;
    resize_write_blocks(&mut fs, file, N0).await;
    resize_verify(&mut fs, file, N0 * BS).await;

    // (1) Aligned multi-block truncation (resize case (c)).
    fs.resize(Role::System, file, 350 * BS).await.unwrap();
    resize_verify(&mut fs, file, 350 * BS).await;

    // (2) Unaligned multi-block truncation: the kept tail must be zeroed.
    let unaligned = 100 * BS + 1000;
    fs.resize(Role::System, file, unaligned).await.unwrap();
    resize_verify(&mut fs, file, unaligned).await;

    // Grow back over the dropped tail; it must read back as zeroes.
    fs.resize(Role::System, file, 101 * BS).await.unwrap();
    let mut buf = vec![0u8; 4096];
    assert_eq!(4096, fs.read(Role::System, file, 100 * BS, &mut buf).await.unwrap());
    for (i, &byte) in buf.iter().enumerate().take(1000) {
        assert_eq!(byte, resize_pat(100, i), "live tail byte {i}");
    }
    for (i, byte) in buf.iter().enumerate().take(4096).skip(1000) {
        assert_eq!(*byte, 0, "stale tail byte {i} was not zeroed");
    }

    // (3) Truncate the whole file away (still multi-block => case (c)).
    fs.resize(Role::System, file, 0).await.unwrap();
    assert_eq!(0, fs.metadata(Role::System, file).await?.size);
    // Everything but the entry block has been freed.
    assert_eq!(full - 1, fs.empty_blocks().await.unwrap());

    // (4) Re-grow and re-write: this drains the free list (allocating from the
    //     orphan files created during truncation), exercising their structure.
    resize_write_blocks(&mut fs, file, 200).await;
    resize_verify(&mut fs, file, 200 * BS).await;

    // (5) Fill the device, draining every orphan and forcing free-block accounting
    //     checks on empty-area allocations (a wrong count would panic there).
    let filler = fs
        .create_entry(Role::System, root, EntryKind::File, "filler", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();
    let zero = vec![0u8; 4096];
    let mut k = 0u64;
    loop {
        match fs.write(Role::System, filler, k * BS, &zero).await {
            Ok(_) => k += 1,
            Err(err) => {
                assert_eq!(err.kind(), ErrorKind::StorageFull);
                break;
            }
        }
    }
    assert!(fs.empty_blocks().await.unwrap() < 1);

    // (6) Delete everything; every block must be reclaimed.
    fs.delete_entry(Role::System, file).await.unwrap();
    fs.delete_entry(Role::System, filler).await.unwrap();
    assert_eq!(full, fs.empty_blocks().await.unwrap());

    println!("resize_truncate_test PASS");
    Ok(())
}

async fn resize_truncate_random_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 1024 * 1024 * 8 / 4096; // 8 MB.
    const BS: u64 = 4096;
    let full = NUM_BLOCKS - RESERVED_BLOCKS as u64;

    let mut fs = create_fs("motor_fs_resize_truncate_random_test", NUM_BLOCKS).await?;

    let root = crate::ROOT_DIR_ID;
    let file = fs.create_entry(Role::System, root, EntryKind::File, "f", [AccessPermissions::Rwx; 3]).await.unwrap();

    // A wider file: truncating to a size landing inside a full leaf chops off
    // more branches than the orphan root node can hold, exercising the orphan's
    // intermediate-node path.
    const N0: u64 = 1200;
    resize_write_blocks(&mut fs, file, N0).await;
    resize_verify(&mut fs, file, N0 * BS).await;

    // Truncate down through a sequence of decreasing sizes, mixing aligned and
    // unaligned cuts; the surviving prefix must stay intact after every step.
    for &(blocks, extra) in &[
        (900u64, 17u64),
        (640, 0),
        (250, 4095),
        (137, 1),
        (3, 100),
        (1, 0),
    ] {
        let new_size = blocks * BS + extra;
        fs.resize(Role::System, file, new_size).await.unwrap();
        resize_verify(&mut fs, file, new_size).await;
    }

    // Back to empty, then reuse the freed space.
    fs.resize(Role::System, file, 0).await.unwrap();
    assert_eq!(full - 1, fs.empty_blocks().await.unwrap());

    resize_write_blocks(&mut fs, file, 300).await;
    resize_verify(&mut fs, file, 300 * BS).await;

    fs.delete_entry(Role::System, file).await.unwrap();
    assert_eq!(full, fs.empty_blocks().await.unwrap());

    println!("resize_truncate_random_test PASS");
    Ok(())
}

async fn resize_truncate_wide_leaf_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 1024 * 1024 * 8 / 4096; // 8 MB.
    const BS: u64 = 4096;
    let full = NUM_BLOCKS - RESERVED_BLOCKS as u64;

    let mut fs = create_fs("motor_fs_resize_truncate_wide_leaf_test", NUM_BLOCKS).await?;

    let root = crate::ROOT_DIR_ID;

    // Sequential appends grow the right-most leaf up to a full node before it
    // splits. By stopping while that leaf is near-full and truncating near its
    // start, a single leaf-level chop removes more branches than an orphan root
    // node can hold, forcing the orphan's intermediate-node path.
    for &build in &[367u64, 494, 621, 748] {
        let file = fs.create_entry(Role::System, root, EntryKind::File, "w", [AccessPermissions::Rwx; 3]).await.unwrap();
        resize_write_blocks(&mut fs, file, build).await;

        // first_stale_key lands a little past the start of the right-most leaf.
        let new_size = (build - 247) * BS;
        fs.resize(Role::System, file, new_size).await.unwrap();
        resize_verify(&mut fs, file, new_size).await;

        fs.resize(Role::System, file, 0).await.unwrap();
        assert_eq!(full - 1, fs.empty_blocks().await.unwrap());

        fs.delete_entry(Role::System, file).await.unwrap();
        assert_eq!(full, fs.empty_blocks().await.unwrap());
    }

    println!("resize_truncate_wide_leaf_test PASS");
    Ok(())
}

/// A crash partway through a multi-block (case (c)) truncation must never leave
/// reachable stale data above the recorded file size: re-growing the file later
/// must read back zeroes over the truncated region, not pre-truncation bytes.
///
/// The truncation is interrupted after a controlled number of B+ tree levels via
/// [`crate::txn::TRUNCATE_MAX_STEPS`], standing in for a power loss mid-operation.
async fn resize_truncate_crash_regrow_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 1024 * 1024 * 8 / 4096; // 8 MB.
    const BS: u64 = 4096;
    const FS_TAG: &str = "motor_fs_resize_truncate_crash_regrow_test";
    // > 226 blocks forces a multi-level tree, so truncation is case (c).
    const N0: u64 = 600;
    const NEW_BLOCKS: u64 = 200;
    let root = crate::ROOT_DIR_ID;

    // Simulate a crash after each possible number of completed truncation levels,
    // including 0 (crash right at the start) and a value past the tree depth (the
    // truncation runs to completion).
    for cap in 0..4usize {
        let mut fs = create_fs(FS_TAG, NUM_BLOCKS).await?;
        let file = fs.create_entry(Role::System, root, EntryKind::File, "f", [AccessPermissions::Rwx; 3]).await.unwrap();
        resize_write_blocks(&mut fs, file, N0).await;
        fs.flush().await.unwrap();

        // Truncate, but stop after `cap` tree levels, as if the machine died
        // before the remaining levels (and the final size fix-up) ran.
        crate::txn::TRUNCATE_MAX_STEPS.with(|c| c.set(cap));
        fs.resize(Role::System, file, NEW_BLOCKS * BS).await.unwrap();
        crate::txn::TRUNCATE_MAX_STEPS.with(|c| c.set(usize::MAX));
        fs.flush().await.unwrap();
        drop(fs);

        // Reopen (replaying the txn log) and read the recovered size.
        let mut fs = open_fs(FS_TAG).await?;
        let recovered = fs.metadata(Role::System, file).await.unwrap().size;
        assert!(
            recovered >= NEW_BLOCKS * BS,
            "cap {cap}: recovered size {recovered} below requested truncation"
        );

        // Grow the file back to its original length. Everything above the
        // recovered EOF must read back as zeroes.
        fs.resize(Role::System, file, N0 * BS).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let mut off = recovered;
        while off < N0 * BS {
            let block_start = off & !(BS - 1);
            let len = ((BS - (off - block_start)) as usize).min((N0 * BS - off) as usize);
            assert_eq!(len, fs.read(Role::System, file, off, &mut buf[..len]).await.unwrap());
            for (i, &byte) in buf[..len].iter().enumerate() {
                assert_eq!(
                    byte, 0,
                    "cap {cap}: stale data above recovered EOF {recovered} at offset {}",
                    off + i as u64
                );
            }
            off += len as u64;
        }

        drop(fs);
    }

    println!("resize_truncate_crash_regrow_test PASS");
    Ok(())
}

/// The block accounting during a multi-block truncation must walk the *smaller*
/// of the surviving / chopped-off sides, deriving the other by subtraction from
/// the file's recorded block count. In particular truncate-to-zero must not walk
/// the chopped-off tree at all.
async fn resize_truncate_accounting_walk_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 1024 * 1024 * 8 / 4096; // 8 MB.
    const BS: u64 = 4096;
    let full = NUM_BLOCKS - RESERVED_BLOCKS as u64;
    let root = crate::ROOT_DIR_ID;

    let mut fs = create_fs("motor_fs_resize_truncate_accounting_walk_test", NUM_BLOCKS).await?;
    let file = fs.create_entry(Role::System, root, EntryKind::File, "f", [AccessPermissions::Rwx; 3]).await.unwrap();

    // > 226 blocks => the tree has internal nodes, so the chopped-off forest holds
    // several tree nodes that a naive count would walk.
    const N0: u64 = 1200;
    resize_write_blocks(&mut fs, file, N0).await;

    // (1) Truncate to zero: the surviving side is empty, so the chopped count is
    //     the whole (known) subtree total -- nothing to walk.
    crate::bplus_tree::COUNT_SUBTREE_VISITS.with(|c| c.set(0));
    fs.resize(Role::System, file, 0).await.unwrap();
    let visits = crate::bplus_tree::COUNT_SUBTREE_VISITS.with(|c| c.get());
    assert_eq!(visits, 0, "truncate-to-zero visited {visits} tree nodes; expected 0");
    // Accounting must still be exact: only the entry block remains in use.
    assert_eq!(full - 1, fs.empty_blocks().await.unwrap());

    // (2) Truncate-to-tiny: only the thin surviving spine is walked, never the
    //     large chopped-off remainder.
    resize_write_blocks(&mut fs, file, N0).await;
    resize_verify(&mut fs, file, N0 * BS).await;

    crate::bplus_tree::COUNT_SUBTREE_VISITS.with(|c| c.set(0));
    fs.resize(Role::System, file, BS).await.unwrap();
    let visits = crate::bplus_tree::COUNT_SUBTREE_VISITS.with(|c| c.get());
    // The surviving spine is at most one node per tree level (<= 4); walking the
    // chopped-off side would instead visit every leaf (and any middle nodes).
    assert!(visits <= 4, "truncate-to-tiny visited {visits} tree nodes; expected the spine only");
    resize_verify(&mut fs, file, BS).await;

    // Accounting is still exact end-to-end: everything is reclaimed on delete.
    fs.delete_entry(Role::System, file).await.unwrap();
    assert_eq!(full, fs.empty_blocks().await.unwrap());

    println!("resize_truncate_accounting_walk_test PASS");
    Ok(())
}

/// A multi-block truncation must allocate nothing: its orphan container blocks
/// come from the blocks being truncated away. This is verified directly with the
/// `ALLOC_BLOCK_CALLS` counter, and the free-block accounting is checked before,
/// during and after -- including a truncation on a completely full device, which
/// can only succeed if it allocates nothing.
async fn resize_truncate_no_alloc_test() -> Result<()> {
    const NUM_BLOCKS: u64 = 1024 * 1024 * 8 / 4096; // 8 MB.
    const BS: u64 = 4096;
    const FS_TAG: &str = "motor_fs_resize_truncate_no_alloc_test";
    // > 226 blocks => a multi-level tree, so truncation chops subtree roots and
    // must source its orphan container from inside the chopped-off forest.
    const N0: u64 = 600;
    let full = NUM_BLOCKS - RESERVED_BLOCKS as u64;
    let root = crate::ROOT_DIR_ID;

    let mut fs = create_fs(FS_TAG, NUM_BLOCKS).await?;
    let file = fs.create_entry(Role::System, root, EntryKind::File, "big", [AccessPermissions::Rwx; 3]).await.unwrap();
    resize_write_blocks(&mut fs, file, N0).await;
    resize_verify(&mut fs, file, N0 * BS).await;

    let before = fs.empty_blocks().await.unwrap();

    // (1) A multi-block truncation allocates nothing, and only frees blocks.
    crate::layout::ALLOC_BLOCK_CALLS.with(|c| c.set(0));
    fs.resize(Role::System, file, 137 * BS).await.unwrap();
    assert_eq!(
        0,
        crate::layout::ALLOC_BLOCK_CALLS.with(|c| c.get()),
        "truncation allocated a block"
    );
    resize_verify(&mut fs, file, 137 * BS).await;
    let after = fs.empty_blocks().await.unwrap();
    assert!(after > before, "empty_blocks did not grow: {before} -> {after}");

    // (2) Truncate the rest away (also allocation-free); only the entry remains.
    crate::layout::ALLOC_BLOCK_CALLS.with(|c| c.set(0));
    fs.resize(Role::System, file, 0).await.unwrap();
    assert_eq!(0, crate::layout::ALLOC_BLOCK_CALLS.with(|c| c.get()));
    assert_eq!(full - 1, fs.empty_blocks().await.unwrap());

    // (3) Re-grow to a multi-level tree and fill the device completely. A
    //     truncation on a full device must still succeed -- it allocates nothing
    //     -- which the previous allocate-based design could not do.
    resize_write_blocks(&mut fs, file, N0).await;
    let filler = fs
        .create_entry(Role::System, root, EntryKind::File, "filler", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();
    let zero = vec![0u8; BS as usize];
    let mut k = 0u64;
    loop {
        match fs.write(Role::System, filler, k * BS, &zero).await {
            Ok(_) => k += 1,
            Err(err) => {
                assert_eq!(err.kind(), ErrorKind::StorageFull);
                break;
            }
        }
    }
    assert!(fs.empty_blocks().await.unwrap() < 1, "device is not full");

    crate::layout::ALLOC_BLOCK_CALLS.with(|c| c.set(0));
    fs.resize(Role::System, file, 100 * BS).await.unwrap(); // StorageFull if it allocated.
    assert_eq!(0, crate::layout::ALLOC_BLOCK_CALLS.with(|c| c.get()));
    resize_verify(&mut fs, file, 100 * BS).await;

    // (4) Everything is reclaimed on delete: the accounting is exact end-to-end.
    fs.delete_entry(Role::System, file).await.unwrap();
    fs.delete_entry(Role::System, filler).await.unwrap();
    assert_eq!(full, fs.empty_blocks().await.unwrap());

    println!("resize_truncate_no_alloc_test PASS");
    Ok(())
}

async fn write_speed_test() -> Result<()> {
    // use futures::StreamExt;
    use rand::RngCore;
    use rand::thread_rng;

    let mut rng = thread_rng();

    const PARTITION_SZ: u64 = 1024 * 1024 * 256;
    const NUM_BLOCKS: u64 = PARTITION_SZ / 4096;

    // B+ tree overhead should be less than one block per 100.
    const FILE_BLOCKS: u64 = NUM_BLOCKS - (RESERVED_BLOCKS as u64 + NUM_BLOCKS / 100 + 1);

    let mut fs = create_fs("motor_fs_write_speed_test", NUM_BLOCKS).await?;

    let mut block = Box::new(async_fs::Block::new_zeroed());
    rng.fill_bytes(block.as_bytes_mut());

    let file_id = fs
        .create_entry(Role::System, crate::ROOT_DIR_ID, EntryKind::File, "foo", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();

    let started = std::time::Instant::now();
    // let mut completion_queue = futures::stream::FuturesUnordered::new();

    for idx in 0..FILE_BLOCKS {
        // completion_queue.push(fs.write(Role::System, file_id, idx * 4096, block.as_bytes()));
        fs.write(Role::System, file_id, idx * 4096, block.as_bytes())
            .await
            .unwrap();
    }

    // while let Some(completion) = completion_queue.next().await {
    //     completion.unwrap();
    // }

    let elapsed = started.elapsed();

    // let file_sz = fs.metadata(Role::System, file_id).await?.size;
    // assert_eq!(file_sz, FILE_BLOCKS * 4096);
    let file_sz = FILE_BLOCKS * 4096;

    let write_speed_mbps = (file_sz as f64) / elapsed.as_secs_f64() / (1024.0 * 1024.0);
    println!("Write speed: {:.3} MB/s", write_speed_mbps);

    println!("write_speed_test PASS");
    Ok(())
}

async fn native_write_speed_test() -> Result<()> {
    use rand::RngCore;
    use rand::thread_rng;

    let mut rng = thread_rng();

    const PARTITION_SZ: u64 = 1024 * 1024 * 256;
    const NUM_BLOCKS: u64 = PARTITION_SZ / 4096;

    const FILE_BLOCKS: u64 = NUM_BLOCKS - (RESERVED_BLOCKS as u64 + NUM_BLOCKS / 100 + 1);

    let mut block = Box::new(async_fs::Block::new_zeroed());
    rng.fill_bytes(block.as_bytes_mut());

    let mut file = std::fs::File::create("/tmp/motor_fs_native_write_speed_test").unwrap();

    let started = std::time::Instant::now();
    for _idx in 0..FILE_BLOCKS {
        file.write_all(block.as_bytes()).unwrap();
    }

    file.flush().unwrap();
    let elapsed = started.elapsed();

    let file_sz = FILE_BLOCKS * 4096;

    let write_speed_mbps = (file_sz as f64) / elapsed.as_secs_f64() / (1024.0 * 1024.0);
    println!("Native write speed: {:.3} MB/s", write_speed_mbps);

    println!("native_write_speed_test PASS");
    Ok(())
}

async fn native_write_speed_async_test() -> Result<()> {
    use rand::RngCore;
    use rand::thread_rng;
    use tokio::io::AsyncWriteExt;

    let mut rng = thread_rng();

    const PARTITION_SZ: u64 = 1024 * 1024 * 256;
    const NUM_BLOCKS: u64 = PARTITION_SZ / 4096;

    const FILE_BLOCKS: u64 = NUM_BLOCKS - (RESERVED_BLOCKS as u64 + NUM_BLOCKS / 100 + 1);

    let mut block = Box::new(async_fs::Block::new_zeroed());
    rng.fill_bytes(block.as_bytes_mut());

    let mut file = tokio::fs::File::create("/tmp/motor_fs_native_write_speed_async_test")
        .await
        .unwrap();

    let started = std::time::Instant::now();

    for _idx in 0..FILE_BLOCKS {
        file.write_all(block.as_bytes()).await.unwrap();
    }

    file.flush().await.unwrap();

    let elapsed = started.elapsed();

    // let file_sz = fs.metadata(Role::System, file_id).await?.size;
    // assert_eq!(file_sz, FILE_BLOCKS * 4096);
    let file_sz = FILE_BLOCKS * 4096;

    let write_speed_mbps = (file_sz as f64) / elapsed.as_secs_f64() / (1024.0 * 1024.0);
    println!("Native async write speed: {:.3} MB/s", write_speed_mbps);

    println!("native_write_speed_async_test PASS");
    Ok(())
}

// ---------------------------------------------------------------------------
// Permissions (Phase 1 / Mode S). See PERMISSIONS_DESIGN.md.
// ---------------------------------------------------------------------------

#[test]
fn access_encoding_roundtrip() {
    // (§8.1) try_from round-trips 0..=4, rejects the rest; (§8.2) zero == Rwx.
    for (byte, acc) in [
        (0u8, AccessPermissions::Rwx),
        (1, AccessPermissions::Rx),
        (2, AccessPermissions::Rw),
        (3, AccessPermissions::R),
        (4, AccessPermissions::None),
    ] {
        assert_eq!(AccessPermissions::try_from(byte).unwrap(), acc);
        assert_eq!(acc as u8, byte);
    }
    for byte in 5u8..=255 {
        assert!(AccessPermissions::try_from(byte).is_err(), "byte {byte} should be invalid");
    }
    assert_eq!(AccessPermissions::try_from(0).unwrap(), AccessPermissions::Rwx);
}

#[test]
fn access_triple_and_gate() {
    // (§8.3) triple() correctness + the "r gates w,x" invariant.
    assert_eq!(AccessPermissions::Rwx.triple(), (true, true, true));
    assert_eq!(AccessPermissions::Rx.triple(), (true, false, true));
    assert_eq!(AccessPermissions::Rw.triple(), (true, true, false));
    assert_eq!(AccessPermissions::R.triple(), (true, false, false));
    assert_eq!(AccessPermissions::None.triple(), (false, false, false));
    for a in [AccessPermissions::Rwx, AccessPermissions::Rx, AccessPermissions::Rw, AccessPermissions::R, AccessPermissions::None] {
        let (r, w, x) = a.triple();
        assert!(r || (!w && !x), "{a:?} grants w/x without r");
    }
}

#[test]
fn access_zeroed_metadata_is_rwx() {
    // (§8.2) A zeroed Metadata reads back as fully permissive for every role.
    let m = async_fs::Metadata::zeroed();
    for role in [Role::None, Role::Interactive, Role::System] {
        assert_eq!(m.access(role).unwrap(), AccessPermissions::Rwx);
    }
}

#[test]
fn access_can_narrow_to_lattice() {
    // (§8.4) can_narrow_to over the lattice, incl. the Rx<->Rw incomparability.
    use AccessPermissions::{R, Rw, Rwx, Rx};
    for t in [Rwx, Rx, Rw, R, AccessPermissions::None] {
        assert!(Rwx.can_narrow_to(t)); // Rwx narrows to everything
        assert!(t.can_narrow_to(t)); // reflexive
    }
    assert!(!Rx.can_narrow_to(Rw)); // incomparable
    assert!(!Rw.can_narrow_to(Rx));
    assert!(Rx.can_narrow_to(R));
    assert!(Rx.can_narrow_to(AccessPermissions::None));
    assert!(!Rx.can_narrow_to(Rwx));
    assert!(R.can_narrow_to(AccessPermissions::None));
    assert!(!R.can_narrow_to(Rw));
    assert!(AccessPermissions::None.can_narrow_to(AccessPermissions::None));
    assert!(!AccessPermissions::None.can_narrow_to(R));
}

#[test]
fn access_meet_is_glb() {
    // (§8.5) meet() is a valid, commutative, idempotent greatest-lower-bound.
    use AccessPermissions::{R, Rw, Rwx, Rx};
    let all = [Rwx, Rx, Rw, R, AccessPermissions::None];
    for a in all {
        assert_eq!(a.meet(a), a);
        for b in all {
            let m = a.meet(b);
            assert_eq!(m, b.meet(a)); // commutative
            assert!(a.can_narrow_to(m) && b.can_narrow_to(m)); // lower bound
            assert_eq!(AccessPermissions::try_from(m as u8).unwrap(), m); // always valid
        }
    }
    assert_eq!(Rx.meet(Rw), R); // keep only the shared 'r'
    assert_eq!(Rwx.meet(Rw), Rw);
    assert_eq!(R.meet(AccessPermissions::None), AccessPermissions::None);
}

#[test]
fn perms_monotonic_check() {
    // (§8.6) accepts nested arrays, rejects inversions and incomparable pairs.
    use AccessPermissions::{R, Rw, Rwx, Rx};
    let idx = |n: AccessPermissions, i: AccessPermissions, s: AccessPermissions| {
        let mut p = [Rwx; 3];
        p[Role::None as usize] = n;
        p[Role::Interactive as usize] = i;
        p[Role::System as usize] = s;
        p
    };
    assert!(async_fs::perms_monotonic(idx(R, Rw, Rwx)));
    assert!(async_fs::perms_monotonic(idx(AccessPermissions::None, R, Rwx)));
    assert!(async_fs::perms_monotonic(idx(Rwx, Rwx, Rwx)));
    assert!(!async_fs::perms_monotonic(idx(Rwx, R, R))); // None wider than Interactive
    assert!(!async_fs::perms_monotonic(idx(AccessPermissions::None, Rx, Rw))); // Rx not ⊆ Rw
}

#[test]
fn may_set_matrix() {
    // (§8.7) exhaustive authority matrix, incl. System's own byte never widens.
    use async_fs::may_set;
    use AccessPermissions::{R, Rwx};
    let roles = [Role::None, Role::Interactive, Role::System];
    for &c in &roles {
        for &t in &roles {
            let widen = may_set(c, t, R, Rwx);
            let narrow = may_set(c, t, Rwx, R);
            match (c as u8).cmp(&(t as u8)) {
                core::cmp::Ordering::Greater => assert!(widen && narrow, "{c:?}->{t:?}"),
                core::cmp::Ordering::Equal => assert!(!widen && narrow, "own {c:?}"),
                core::cmp::Ordering::Less => assert!(!widen && !narrow, "{c:?}->{t:?}"),
            }
        }
    }
    // The System byte is non-wideable even when the caller is System.
    assert!(!may_set(Role::System, Role::System, R, Rwx));
    assert!(may_set(Role::System, Role::System, Rwx, R));
}

#[test]
fn permissions_storage() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();
    rt.block_on(permissions_storage_test()).unwrap();
}

async fn permissions_storage_test() -> Result<()> {
    // (§8.8/8.9/8.14) create with default & restricted perms, reject
    // non-monotonic / over-privileged creation, and persist across reopen.
    const NUM_BLOCKS: u64 = 1024 * 1024 * 16 / 4096;
    const FS_TAG: &str = "motor_fs_permissions_storage_test";
    let mut fs = create_fs(FS_TAG, NUM_BLOCKS).await?;
    let root = crate::ROOT_DIR_ID;

    // Default perms => every role is Rwx.
    let f = fs
        .create_entry(Role::System, root, EntryKind::File, "f", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();
    for role in [Role::None, Role::Interactive, Role::System] {
        assert_eq!(fs.metadata(Role::System, f).await?.access(role).unwrap(), AccessPermissions::Rwx);
    }

    // Restricted but monotonic: None=R ⊆ Interactive=Rw ⊆ System=Rwx.
    let mut p = [AccessPermissions::Rwx; 3];
    p[Role::None as usize] = AccessPermissions::R;
    p[Role::Interactive as usize] = AccessPermissions::Rw;
    let g = fs
        .create_entry(Role::System, root, EntryKind::File, "g", p)
        .await
        .unwrap();
    assert_eq!(fs.metadata(Role::System, g).await?.access(Role::None).unwrap(), AccessPermissions::R);
    assert_eq!(fs.metadata(Role::System, g).await?.access(Role::Interactive).unwrap(), AccessPermissions::Rw);
    assert_eq!(fs.metadata(Role::System, g).await?.access(Role::System).unwrap(), AccessPermissions::Rwx);

    // A lower-privileged caller may create with the default perms (the higher
    // roles stay Rwx) and may restrict its own/lower roles monotonically.
    let i = fs
        .create_entry(Role::Interactive, root, EntryKind::File, "i", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();
    assert_eq!(fs.metadata(Role::System, i).await?.access(Role::System).unwrap(), AccessPermissions::Rwx);
    let mut ip = [AccessPermissions::Rwx; 3];
    ip[Role::None as usize] = AccessPermissions::R;
    ip[Role::Interactive as usize] = AccessPermissions::Rw;
    fs.create_entry(Role::Interactive, root, EntryKind::File, "i2", ip)
        .await
        .unwrap();

    // Non-monotonic creation is rejected.
    let mut bad = [AccessPermissions::Rwx; 3];
    bad[Role::Interactive as usize] = AccessPermissions::R; // None(Rwx) wider than Interactive(R)
    assert_eq!(
        fs.create_entry(Role::System, root, EntryKind::File, "bad", bad)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );

    // An Interactive caller cannot restrict the System byte at creation.
    let mut sysrestrict = [AccessPermissions::Rwx; 3];
    sysrestrict[Role::System as usize] = AccessPermissions::R;
    assert_eq!(
        fs.create_entry(Role::Interactive, root, EntryKind::File, "nope", sysrestrict)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );

    // Restricted perms survive a flush + reopen; fresh entries stay Rwx.
    fs.flush().await?;
    let mut fs = open_fs(FS_TAG).await?;
    assert_eq!(fs.metadata(Role::System, g).await?.access(Role::Interactive).unwrap(), AccessPermissions::Rw);
    assert_eq!(fs.metadata(Role::System, g).await?.access(Role::None).unwrap(), AccessPermissions::R);
    assert_eq!(fs.metadata(Role::System, f).await?.access(Role::None).unwrap(), AccessPermissions::Rwx);
    Ok(())
}

#[test]
fn permissions_authority() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();
    rt.block_on(permissions_authority_test()).unwrap();
}

/// The decoded permission for `role` on `id` (queried as System).
async fn perm_of(fs: &mut MotorFs, id: EntryId, role: Role) -> AccessPermissions {
    fs.metadata(Role::System, id).await.unwrap().access(role).unwrap()
}

async fn permissions_authority_test() -> Result<()> {
    // (§8.10/8.11/8.12/8.13) set_permissions authority, cap, cascade, sealing.
    const NUM_BLOCKS: u64 = 1024 * 1024 * 16 / 4096;
    const FS_TAG: &str = "motor_fs_permissions_authority_test";
    let mut fs = create_fs(FS_TAG, NUM_BLOCKS).await?;
    let root = crate::ROOT_DIR_ID;

    // --- Authority (item 10) ---
    let a = fs
        .create_entry(Role::System, root, EntryKind::File, "auth", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();
    // Own-byte narrow ok.
    fs.set_permissions(Role::Interactive, a, Role::Interactive, AccessPermissions::Rx).await.unwrap();
    assert_eq!(perm_of(&mut fs, a, Role::Interactive).await, AccessPermissions::Rx);
    // Own-byte widen denied.
    assert_eq!(
        fs.set_permissions(Role::Interactive, a, Role::Interactive, AccessPermissions::Rwx)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
    // Strictly-higher target forbidden (None cannot touch System).
    assert_eq!(
        fs.set_permissions(Role::None, a, Role::System, AccessPermissions::R)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
    // System may narrow a lower role freely.
    fs.set_permissions(Role::System, a, Role::None, AccessPermissions::None).await.unwrap();
    assert_eq!(perm_of(&mut fs, a, Role::None).await, AccessPermissions::None);

    // --- Cascade (item 12) ---
    let c = fs
        .create_entry(Role::System, root, EntryKind::File, "cascade", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();
    fs.set_permissions(Role::System, c, Role::System, AccessPermissions::Rx).await.unwrap(); // drop w
    for role in [Role::None, Role::Interactive, Role::System] {
        assert!(!perm_of(&mut fs, c, role).await.can_write(), "{role:?} kept write");
        assert!(AccessPermissions::Rx.can_narrow_to(perm_of(&mut fs, c, role).await)); // ⊆ System
    }

    // --- Cap (item 11) ---
    let d = fs
        .create_entry(Role::System, root, EntryKind::File, "cap", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();
    fs.set_permissions(Role::System, d, Role::System, AccessPermissions::R).await.unwrap(); // cascade -> all R
    assert_eq!(perm_of(&mut fs, d, Role::Interactive).await, AccessPermissions::R);
    // Widening Interactive past the System=R ceiling is denied.
    assert_eq!(
        fs.set_permissions(Role::System, d, Role::Interactive, AccessPermissions::Rw)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
    // Widening None past the Interactive=R ceiling is denied.
    assert_eq!(
        fs.set_permissions(Role::System, d, Role::None, AccessPermissions::Rw)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );

    // --- Sealing (item 13) ---
    let s = fs
        .create_entry(Role::System, root, EntryKind::File, "seal", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();
    fs.set_permissions(Role::System, s, Role::System, AccessPermissions::Rx).await.unwrap(); // seal writes
    for role in [Role::None, Role::Interactive, Role::System] {
        assert!(!perm_of(&mut fs, s, role).await.can_write());
    }
    // Write can never be re-granted to anyone.
    assert!(fs.set_permissions(Role::System, s, Role::System, AccessPermissions::Rwx).await.is_err());
    assert!(fs.set_permissions(Role::System, s, Role::Interactive, AccessPermissions::Rw).await.is_err());
    assert!(fs.set_permissions(Role::System, s, Role::None, AccessPermissions::Rw).await.is_err());
    // Seal survives reopen.
    fs.flush().await?;
    let mut fs = open_fs(FS_TAG).await?;
    assert!(!fs.metadata(Role::System, s).await?.access(Role::System).unwrap().can_write());
    Ok(())
}

#[test]
fn permissions_enforcement() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();
    rt.block_on(permissions_enforcement_test()).unwrap();
}

async fn permissions_enforcement_test() -> Result<()> {
    // (§8.15, Mode E) data-path enforcement: read/write/resize on files, and
    // create/delete/move/list gated by the parent directory.
    const NUM_BLOCKS: u64 = 1024 * 1024 * 16 / 4096;
    const FS_TAG: &str = "motor_fs_permissions_enforcement_test";
    let mut fs = create_fs(FS_TAG, NUM_BLOCKS).await?;
    let root = crate::ROOT_DIR_ID;
    let denied = |r: Result<()>| assert_eq!(r.unwrap_err().kind(), ErrorKind::PermissionDenied);

    let dir = fs
        .create_entry(Role::System, root, EntryKind::Directory, "d", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();
    let file = fs
        .create_entry(Role::System, dir, EntryKind::File, "f", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();
    fs.write(Role::System, file, 0, b"hello").await.unwrap();

    // --- read (r on the file) ---
    fs.set_permissions(Role::System, file, Role::None, AccessPermissions::None).await.unwrap();
    let mut buf = [0u8; 8];
    assert_eq!(
        fs.read(Role::None, file, 0, &mut buf).await.unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
    assert!(fs.read(Role::System, file, 0, &mut buf).await.unwrap() > 0); // System still can

    // --- write / resize (w on the file) ---
    fs.set_permissions(Role::System, file, Role::None, AccessPermissions::R).await.unwrap();
    denied(fs.write(Role::None, file, 0, b"x").await.map(|_| ()));
    denied(fs.resize(Role::None, file, 0).await);
    assert!(fs.read(Role::None, file, 0, &mut buf).await.is_ok()); // R still grants read

    // --- listing/lookup requires execute (x); modification requires write (w) ---
    // Rx: traverse + read, no write -> can stat/list, cannot create/delete.
    fs.set_permissions(Role::System, dir, Role::None, AccessPermissions::Rx).await.unwrap();
    assert!(fs.stat(Role::None, dir, "f").await.unwrap().is_some()); // x grants lookup
    assert!(fs.get_first_entry(Role::None, dir).await.unwrap().is_some()); // x grants listing
    denied(
        fs.create_entry(Role::None, dir, EntryKind::File, "new", [AccessPermissions::Rwx; 3])
            .await
            .map(|_| ()),
    );
    denied(fs.delete_entry(Role::None, file).await);

    // R (no execute): lookup/listing denied even though read is present.
    fs.set_permissions(Role::System, dir, Role::None, AccessPermissions::R).await.unwrap();
    denied(fs.stat(Role::None, dir, "f").await.map(|_| ()));
    denied(fs.get_first_entry(Role::None, dir).await.map(|_| ()));

    // None: still denied.
    fs.set_permissions(Role::System, dir, Role::None, AccessPermissions::None).await.unwrap();
    denied(fs.stat(Role::None, dir, "f").await.map(|_| ()));
    denied(fs.get_first_entry(Role::None, dir).await.map(|_| ()));

    // --- move (w on BOTH parents) ---
    let a = fs
        .create_entry(Role::System, root, EntryKind::Directory, "a", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();
    let b = fs
        .create_entry(Role::System, root, EntryKind::Directory, "b", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();
    let m = fs
        .create_entry(Role::System, a, EntryKind::File, "m", [AccessPermissions::Rwx; 3])
        .await
        .unwrap();
    // No write on the source dir 'a' -> denied.
    fs.set_permissions(Role::System, a, Role::None, AccessPermissions::R).await.unwrap();
    denied(fs.move_entry(Role::None, m, b, "m2").await);
    // Restore 'a', deny the destination dir 'b' -> still denied.
    fs.set_permissions(Role::System, a, Role::None, AccessPermissions::Rwx).await.unwrap();
    fs.set_permissions(Role::System, b, Role::None, AccessPermissions::R).await.unwrap();
    denied(fs.move_entry(Role::None, m, b, "m2").await);
    // System has write on both -> succeeds.
    fs.move_entry(Role::System, m, b, "m2").await.unwrap();
    Ok(())
}

// ------------------------- Concurrency tests -------------------------------
//
// Read-only FS operations take &self and may interleave (single-threaded,
// cooperative). Writers require &mut self, so reader/writer exclusion is
// enforced by the type system here and by an async RwLock in sys-io. The
// tests below exercise concurrent readers and the block cache's
// pending-read deduplication.

/// Tracks the number of device reads currently in flight, and the maximum
/// that was ever in flight (i.e. the achieved read concurrency).
#[derive(Default)]
struct InFlightStats {
    current: std::cell::Cell<u64>,
    max: std::cell::Cell<u64>,
}

/// A block device wrapper that counts per-block device reads and widens the
/// read window (via yield_now) so that concurrent cache misses of the same
/// block actually collide.
struct CountingBlockDevice {
    inner: AsyncFileBlockDevice,
    reads: std::rc::Rc<std::cell::RefCell<std::collections::BTreeMap<u64, u64>>>,
    in_flight: std::rc::Rc<InFlightStats>,
}

#[async_trait::async_trait(?Send)]
impl async_fs::AsyncBlockDevice for CountingBlockDevice {
    type Completion = <AsyncFileBlockDevice as async_fs::AsyncBlockDevice>::Completion;

    fn num_blocks(&self) -> u64 {
        self.inner.num_blocks()
    }

    async fn read_block<T: AsMut<fittings::iobuf::IoBuf> + Unpin>(
        &self,
        block_no: u64,
        block: T,
    ) -> (T, Result<()>) {
        *self.reads.borrow_mut().entry(block_no).or_insert(0) += 1;
        let current = self.in_flight.current.get() + 1;
        self.in_flight.current.set(current);
        self.in_flight
            .max
            .set(self.in_flight.max.get().max(current));
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        let result = self.inner.read_block(block_no, block).await;
        self.in_flight
            .current
            .set(self.in_flight.current.get() - 1);
        result
    }

    async fn write_block<T: AsRef<fittings::iobuf::IoBuf> + Unpin>(
        &self,
        block_no: u64,
        block: T,
    ) -> (T, Result<()>) {
        self.inner.write_block(block_no, block).await
    }

    async fn write_block_with_completion(
        &self,
        block_no: u64,
        block: async_fs::block_cache::CheckpointedBlock,
    ) -> Result<Self::Completion> {
        self.inner.write_block_with_completion(block_no, block).await
    }

    async fn flush(&self) -> Result<()> {
        self.inner.flush().await
    }
}

type ReadCounts = std::rc::Rc<std::cell::RefCell<std::collections::BTreeMap<u64, u64>>>;

/// Creates a MotorFs over a counting block device, with one file of
/// `num_file_blocks` blocks, where block `i` is filled with byte
/// `(i * 31 + 7) as u8`. Returns (fs, file_id, read counters,
/// in-flight read stats).
///
/// The FS is written with a plain device, flushed, and reopened through the
/// counting device, so the block cache is cold and every test read hits the
/// device (a freshly written FS keeps everything cached, which would make
/// the read counts vacuous).
async fn create_concurrency_test_fs(
    tag: &str,
    num_file_blocks: u64,
) -> Result<(
    std::rc::Rc<crate::MotorFs<CountingBlockDevice>>,
    EntryId,
    ReadCounts,
    std::rc::Rc<InFlightStats>,
)> {
    const NUM_BLOCKS: u64 = 1024 * 1024 * 16 / 4096;
    let path = std::env::temp_dir().join(tag);
    let path = Utf8PathBuf::from_path_buf(path).unwrap();
    std::fs::remove_file(path.clone()).ok();

    let bd = AsyncFileBlockDevice::create(&path, NUM_BLOCKS).await?;
    let mut fs = crate::MotorFs::format(Box::new(bd)).await?;

    let file_id = fs
        .create_entry(
            Role::System,
            crate::ROOT_DIR_ID,
            EntryKind::File,
            "concurrent",
            [AccessPermissions::Rwx; 3],
        )
        .await
        .unwrap();

    let mut block = [0_u8; 4096];
    for key in 0..num_file_blocks {
        block.fill((key * 31 + 7) as u8);
        let written = fs
            .write(Role::System, file_id, key * 4096, &block)
            .await
            .unwrap();
        assert_eq!(written, 4096);
    }

    fs.flush().await?;
    drop(fs);

    let bd = AsyncFileBlockDevice::open(&path).await?;
    let reads: ReadCounts = Default::default();
    let in_flight: std::rc::Rc<InFlightStats> = Default::default();
    let bd = CountingBlockDevice {
        inner: bd,
        reads: reads.clone(),
        in_flight: in_flight.clone(),
    };
    let fs = crate::MotorFs::open(Box::new(bd)).await?;

    // Only count reads from here on (opening did its own).
    reads.borrow_mut().clear();
    in_flight.max.set(0);
    Ok((std::rc::Rc::new(fs), file_id, reads, in_flight))
}

fn expected_block_byte(key: u64) -> u8 {
    (key * 31 + 7) as u8
}

/// N tasks concurrently read the whole file (each starting at a different
/// phase); every task must see the correct content, and, thanks to
/// pending-read deduplication + the (large enough) cache, no block may be
/// read from the device more than once.
async fn concurrent_reads_test() -> Result<()> {
    const FILE_BLOCKS: u64 = 128;
    const NUM_READERS: u64 = 8;

    let (fs, file_id, reads, _) =
        create_concurrency_test_fs("motor_fs_concurrent_reads_test", FILE_BLOCKS).await?;

    let mut join_handles = vec![];
    for reader in 0..NUM_READERS {
        let fs = fs.clone();
        join_handles.push(tokio::task::spawn_local(async move {
            let mut buf = [0_u8; 4096];
            for step in 0..FILE_BLOCKS {
                // Each reader starts at its own phase to mix hits, misses,
                // and concurrent misses of the same block.
                let key = (step + reader * FILE_BLOCKS / NUM_READERS) % FILE_BLOCKS;
                let read = fs
                    .read(Role::System, file_id, key * 4096, &mut buf)
                    .await
                    .unwrap();
                assert_eq!(read, 4096);
                assert!(
                    buf.iter().all(|b| *b == expected_block_byte(key)),
                    "corrupt read of block {key}"
                );
            }
        }));
    }

    for handle in join_handles {
        handle.await.unwrap();
    }

    for (block_no, count) in reads.borrow().iter() {
        assert_eq!(
            *count, 1,
            "block {block_no} was read {count} times from the device"
        );
    }

    Ok(())
}

#[test]
fn concurrent_reads() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();
    rt.block_on(concurrent_reads_test()).unwrap();
}

/// Prefetch warms the cache: after prefetch(0..N), reading the file causes
/// no further device reads of its data blocks.
async fn prefetch_test() -> Result<()> {
    const FILE_BLOCKS: u64 = 64;

    let (fs, file_id, reads, _) =
        create_concurrency_test_fs("motor_fs_prefetch_test", FILE_BLOCKS).await?;

    fs.prefetch(file_id, 0, FILE_BLOCKS).await;
    let reads_after_prefetch = reads.borrow().clone();

    let mut buf = [0_u8; 4096];
    for key in 0..FILE_BLOCKS {
        let read = fs
            .read(Role::System, file_id, key * 4096, &mut buf)
            .await
            .unwrap();
        assert_eq!(read, 4096);
        assert!(buf.iter().all(|b| *b == expected_block_byte(key)));
    }

    assert_eq!(
        *reads.borrow(),
        reads_after_prefetch,
        "reading a prefetched file must not touch the device"
    );

    // Prefetching past EOF or with a bogus id must not panic or read.
    fs.prefetch(file_id, FILE_BLOCKS * 2, 16).await;
    fs.prefetch(file_id ^ 0xdead_beef, 0, 16).await;

    Ok(())
}

#[test]
fn prefetch() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();
    rt.block_on(prefetch_test()).unwrap();
}

/// Many tasks concurrently read the *same* single block of a cold file:
/// exactly one device read per block may happen (dedup), and everyone gets
/// the right data.
async fn concurrent_miss_dedup_test() -> Result<()> {
    const FILE_BLOCKS: u64 = 4;
    const NUM_READERS: usize = 16;

    let (fs, file_id, reads, _) =
        create_concurrency_test_fs("motor_fs_concurrent_miss_dedup_test", FILE_BLOCKS).await?;

    let mut join_handles = vec![];
    for _ in 0..NUM_READERS {
        let fs = fs.clone();
        join_handles.push(tokio::task::spawn_local(async move {
            let mut buf = [0_u8; 4096];
            for key in 0..FILE_BLOCKS {
                let read = fs
                    .read(Role::System, file_id, key * 4096, &mut buf)
                    .await
                    .unwrap();
                assert_eq!(read, 4096);
                assert!(buf.iter().all(|b| *b == expected_block_byte(key)));
            }
        }));
    }

    for handle in join_handles {
        handle.await.unwrap();
    }

    for (block_no, count) in reads.borrow().iter() {
        assert_eq!(
            *count, 1,
            "block {block_no} was read {count} times from the device"
        );
    }

    Ok(())
}

#[test]
fn concurrent_miss_dedup() {
    init_logger();
    let rt = tokio::runtime::LocalRuntime::new().unwrap();
    rt.block_on(concurrent_miss_dedup_test()).unwrap();
}
